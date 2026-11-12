//go:build linux

package main

import (
	"context"
	"time"
)

// IHostClient ограничивает взаимодействие сервиса привилегированным локальным протоколом.
type IHostClient interface {
	Call(context.Context, Request) (Response, *APIError, bool)
}

// HostClient соединяется только с проверенным socket Docker adapter.
type HostClient struct {
	socketPath string // Абсолютный путь socket из доверенной конфигурации.
}

// hostDeadline задаёт предел ожидания для каждого класса операций adapter.
func hostDeadline(action string) time.Duration {
	if action == "health" {
		return 2 * time.Second
	}
	if action == "warp.setup" {
		return 185 * time.Second
	}
	if mutationAction(action) {
		return 95 * time.Second
	}
	return 35 * time.Second
}

// Call проверяет публичный allowlist перед обращением к adapter UID10003.
func (client *HostClient) Call(ctx context.Context, request Request) (Response, *APIError, bool) {
	if request.Action == "operations.get" || request.Action == "operations.list" {
		return Response{}, failure(404, "unknown_action", "Журнал операций не передаётся adapter."), false
	}
	payload, payloadError := validatePayload(request.Action, request.Payload)
	if payloadError != nil {
		return Response{}, payloadError, false
	}
	request.Payload = payload
	return exchangeLocalJSON(ctx, client.socketPath, 10003, request, hostDeadline(request.Action))
}
