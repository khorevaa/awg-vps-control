//go:build linux

package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Adapter предоставляет доменные действия AWG без общего Docker API для клиента.
type Adapter struct {
	config   AdapterConfig // Доверенные пути режима adapter.
	docker   *DockerClient // Ограниченные Docker-команды.
	warp     *WarpClient   // Клиент root-границы WARP.
	mutation chan struct{} // Последовательное выполнение мутаций.
}

// forward передаёт ограниченное WARP-действие и сохраняет безопасную ошибку.
func (adapter *Adapter) forward(ctx context.Context, request Request) (json.RawMessage, *APIError) {
	response, apiError := adapter.warp.Call(ctx, request)
	if apiError != nil {
		return nil, apiError
	}
	if !response.OK {
		return nil, response.Error
	}
	return response.Data, nil
}

// health подтверждает Docker и root WARP без раскрытия системных данных.
func (adapter *Adapter) health(ctx context.Context, request Request) (json.RawMessage, *APIError) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	dockerDone := make(chan *APIError, 1)
	go func() { dockerDone <- adapter.docker.Ping(ctx) }()
	response, apiError := adapter.warp.Call(ctx, request)
	var status map[string]json.RawMessage
	var state string
	warpReady := apiError == nil && response.OK && decodeStrict(response.Data, &status) == nil && json.Unmarshal(status["status"], &state) == nil && state == "ok"
	select {
	case dockerError := <-dockerDone:
		if warpReady && dockerError == nil {
			return encodeData(map[string]string{"status": "ok"}), nil
		}
	case <-ctx.Done():
	}
	return nil, failure(503, "dependency_unavailable", "Сервис управления пока не готов.")
}

// restart выполняет только ручной restart pinned AWG и последующую managed repair.
func (adapter *Adapter) restart(ctx context.Context, request Request) (json.RawMessage, *APIError) {
	integration, apiError := adapter.attached(ctx, request.RequestID)
	if apiError != nil {
		return nil, apiError
	}
	container, apiError := adapter.pinnedContainer(ctx, *integration.Installation, false, false)
	if apiError != nil {
		return nil, apiError
	}
	if apiError = adapter.docker.Restart(ctx, container.ID); apiError != nil {
		return nil, apiError
	}
	if !adapter.waitAWG(ctx, *integration.Installation) {
		return nil, failure(502, "mutation_failed", "Работа AWG после ручного перезапуска не подтверждена.")
	}
	if integration.Managed {
		data, apiError := adapter.forward(ctx, Request{RequestID: request.RequestID, Action: "repair", Payload: json.RawMessage(`{}`)})
		if apiError != nil {
			return nil, failure(502, "mutation_failed", "AWG перезапущен, восстановление managed маршрутов не подтверждено.")
		}
		return encodeData(map[string]any{"restarted": true, "recovery": data}), nil
	}
	return encodeData(map[string]bool{"restarted": true}), nil
}

// waitAWG ограниченно ждёт штатной инициализации интерфейса после ручного restart.
func (adapter *Adapter) waitAWG(ctx context.Context, installation AdapterInstallation) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	for attempt := 0; attempt < 10 && ctx.Err() == nil; attempt++ {
		container, apiError := adapter.pinnedContainer(ctx, installation, false, false)
		if apiError == nil && container.State.Running {
			raw, code, apiError := adapter.docker.Read(ctx, container.ID, "interfaces", "")
			if apiError == nil && code == 0 {
				for _, iface := range strings.Fields(string(raw)) {
					if iface == installation.Interface {
						return true
					}
				}
			}
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
	return false
}

// Handle проверяет параметры до сериализации и выполнения доменного действия.
func (adapter *Adapter) Handle(ctx context.Context, request Request) Response {
	if !identifierPattern.MatchString(request.RequestID) {
		return resultResponse("", nil, failure(422, "invalid_request_id", "Некорректный идентификатор запроса."))
	}
	if request.Action == "operations.get" || request.Action == "operations.list" {
		return resultResponse(request.RequestID, nil, failure(404, "unknown_action", "Журнал доступен только через Control."))
	}
	payload, apiError := validatePayload(request.Action, request.Payload)
	if apiError != nil {
		return resultResponse(request.RequestID, nil, apiError)
	}
	request.Payload = payload
	if mutationAction(request.Action) {
		select {
		case adapter.mutation <- struct{}{}:
			defer func() { <-adapter.mutation }()
		default:
			return resultResponse(request.RequestID, nil, failure(409, "busy", "Другая операция уже изменяет установку."))
		}
	}
	var data json.RawMessage
	switch request.Action {
	case "health":
		data, apiError = adapter.health(ctx, request)
	case "overview":
		data, apiError = adapter.overview(ctx, request)
	case "discover":
		data, apiError = adapter.discover(ctx)
	case "peers":
		data, apiError = adapter.peers(ctx, request.RequestID)
	case "configuration":
		data, apiError = adapter.configuration(ctx, request.RequestID)
	case "diagnostics":
		data, apiError = adapter.diagnostics(ctx, request)
	case "logs":
		data, apiError = adapter.logs(ctx, request)
	case "attach":
		request.Action = "integration.attach"
		data, apiError = adapter.forward(ctx, request)
	case "policy.get", "policy.set", "repair", "warp.reconnect", "warp.setup":
		data, apiError = adapter.forward(ctx, request)
	case "awg.restart":
		data, apiError = adapter.restart(ctx, request)
	default:
		apiError = failure(404, "unknown_action", "Действие adapter не поддерживается.")
	}
	if apiError == nil {
		var withinLimit bool
		data, withinLimit = sanitizeData(data, maxMessageBytes/2)
		if !withinLimit {
			apiError = failure(502, "response_too_large", "Результат действия слишком велик.")
		}
	}
	return resultResponse(request.RequestID, data, apiError)
}
