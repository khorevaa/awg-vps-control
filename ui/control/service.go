//go:build linux

package main

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

// Service связывает проверку запросов, журнал и последовательный исполнитель.
type Service struct {
	config Config        // Настройки локального доступа.
	store  *Store        // Постоянный журнал операций.
	host   IHostClient   // Ограниченный клиент Docker adapter.
	wake   chan struct{} // Сигнал появления новых задач.
}

// newService создаёт сервис без автоматического исполнения старых операций.
func newService(config Config, store *Store, host IHostClient) *Service {
	return &Service{config: config, store: store, host: host, wake: make(chan struct{}, 1)}
}

// resultResponse формирует ответ с согласованным идентификатором.
func resultResponse(id string, data json.RawMessage, apiError *APIError) Response {
	if apiError != nil {
		data = nil
	}
	return Response{RequestID: id, OK: apiError == nil, Data: data, Error: apiError}
}

// Handle разрешает только документированные действия и никогда не запускает shell.
func (service *Service) Handle(ctx context.Context, request Request) Response {
	if !identifierPattern.MatchString(request.RequestID) {
		return resultResponse("", nil, failure(422, "invalid_request_id", "Некорректный идентификатор запроса."))
	}
	if request.Action == "operations.create" {
		return service.createOperation(request)
	}
	payload, apiError := validatePayload(request.Action, request.Payload)
	if apiError != nil {
		return resultResponse(request.RequestID, nil, apiError)
	}
	request.Payload = payload
	switch request.Action {
	case "health":
		return service.health(ctx, request)
	case "operations.list":
		return resultResponse(request.RequestID, encodeData(service.store.List()), nil)
	case "operations.get":
		var lookup OperationLookup
		if decodeStrict(payload, &lookup) != nil {
			return resultResponse(request.RequestID, nil, failure(422, "invalid_operation", "Некорректный идентификатор операции."))
		}
		operation, lookupError := service.store.Lookup(lookup.ID)
		return resultResponse(request.RequestID, encodeData(operation), lookupError)
	case "peers.profile.consume":
		return service.consumePeerProfile(ctx, request)
	case "overview", "discover", "peers", "peers.catalog", "diagnostics", "configuration", "logs", "policy.get":
		response, hostError, _ := service.host.Call(ctx, request)
		if hostError != nil {
			return resultResponse(request.RequestID, nil, hostError)
		}
		return response
	default:
		return resultResponse(request.RequestID, nil, failure(404, "unknown_action", "Изменения принимаются только через журнал операций."))
	}
}

// health проверяет готовность всей цепочки без раскрытия сведений о хосте.
func (service *Service) health(ctx context.Context, request Request) Response {
	checkContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	response, hostError, _ := service.host.Call(checkContext, request)
	var snapshot map[string]json.RawMessage
	var status string
	if hostError != nil || !response.OK || decodeStrict(response.Data, &snapshot) != nil || json.Unmarshal(snapshot["status"], &status) != nil || status != "ok" {
		return resultResponse(request.RequestID, nil, failure(503, "dependency_unavailable", "Сервис управления пока не готов."))
	}
	return resultResponse(request.RequestID, encodeData(map[string]string{"status": "ok"}), nil)
}

// createOperation проверяет намерение и подтверждает его только после сохранения.
func (service *Service) createOperation(request Request) Response {
	var operationRequest OperationRequest
	if len(request.Payload) > maxPayloadBytes+512 || decodeStrict(request.Payload, &operationRequest) != nil || !mutationAction(operationRequest.Action) || len(operationRequest.IdempotencyKey) < 16 || !identifierPattern.MatchString(operationRequest.IdempotencyKey) {
		return resultResponse(request.RequestID, nil, failure(422, "invalid_operation", "Некорректное действие или ключ повторного запроса."))
	}
	payload, apiError := validatePayload(operationRequest.Action, operationRequest.Payload)
	if apiError != nil {
		return resultResponse(request.RequestID, nil, apiError)
	}
	operationRequest.Payload = payload
	operation, created, apiError := service.store.Create(operationRequest)
	if apiError != nil {
		return resultResponse(request.RequestID, nil, apiError)
	}
	if created {
		select {
		case service.wake <- struct{}{}:
		default:
		}
	}
	return resultResponse(request.RequestID, encodeData(operation), nil)
}

// safeHostRejection распознаёт только известные отказы до изменения установки.
func safeHostRejection(code string) bool {
	switch code {
	case "invalid_request", "invalid_payload", "invalid_peer", "not_attached", "unsupported", "unsupported_topology", "capability_unavailable", "revision_conflict", "policy_conflict", "configuration_changed", "lock_busy", "busy", "peer_not_found", "peer_conflict", "peer_capacity", "profile_capacity":
		return true
	default:
		return false
	}
}

// execute обрабатывает одну сохранённую операцию и не выдумывает успешный откат.
func (service *Service) execute(ctx context.Context, record OperationRecord) {
	request := Request{RequestID: record.Operation.ID, Action: record.Operation.Action, Payload: record.Payload}
	response, callError, sent := service.host.Call(ctx, request)
	if callError != nil {
		status := "failed"
		if sent {
			status = "manual_recovery_required"
		}
		service.store.Update(record.Operation.ID, status, nil, callError)
		log.Printf("операция %s %s: %s", record.Operation.ID, record.Operation.Action, status)
		return
	}
	if !response.OK {
		if peerMutationAction(record.Operation.Action) {
			// Ошибка peer не имеет документированного результата для постоянного хранения.
			response.Data = nil
		}
		status := "manual_recovery_required"
		if safeHostRejection(response.Error.Code) {
			status = "failed"
		}
		if response.Error.Code == "operation_rolled_back" {
			if !service.store.Update(record.Operation.ID, "rolling_back", nil, response.Error) {
				return
			}
			status = "rolled_back"
		}
		service.store.Update(record.Operation.ID, status, operationResult(response.Data), response.Error)
		log.Printf("операция %s %s: %s", record.Operation.ID, record.Operation.Action, status)
		return
	}
	if peerMutationAction(record.Operation.Action) {
		checked, valid := checkedPeerResult(record.Operation.Action, response.Data)
		if !valid {
			service.store.Update(record.Operation.ID, "manual_recovery_required", nil, failure(502, "invalid_peer_result", "Изменение клиента не подтверждено корректным результатом. Обновите список и проверьте установку."))
			return
		}
		response.Data = checked
	}
	if !service.store.Update(record.Operation.ID, "verifying", nil, nil) {
		return
	}
	var result map[string]json.RawMessage
	var complete *bool
	if json.Unmarshal(response.Data, &result) == nil && json.Unmarshal(result["complete"], &complete) == nil && complete != nil && !*complete {
		apiError := failure(502, "verification_incomplete", "Часть изменений применена, но завершение операции не подтверждено. Проверьте диагностику.")
		if service.store.Update(record.Operation.ID, "manual_recovery_required", operationResult(response.Data), apiError) {
			log.Printf("операция %s %s: manual_recovery_required", record.Operation.ID, record.Operation.Action)
		}
		return
	}
	if service.store.Update(record.Operation.ID, "succeeded", operationResult(response.Data), nil) {
		log.Printf("операция %s %s: succeeded", record.Operation.ID, record.Operation.Action)
	}
}

// RunWorker выполняет только новые операции последовательно до остановки процесса.
func (service *Service) RunWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-service.wake:
			for ctx.Err() == nil {
				record, ok := service.store.Next()
				if !ok {
					break
				}
				service.execute(ctx, record)
			}
		}
	}
}
