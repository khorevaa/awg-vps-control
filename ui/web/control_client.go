//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"time"
)

// controlRequest задаёт один запрос JSON lines.
type controlRequest struct {
	RequestID string          `json:"request_id"` // Случайный идентификатор обмена.
	Action    string          `json:"action"`     // Разрешённое действие Control.
	Payload   json.RawMessage `json:"payload"`    // Параметры действия.
}

// controlResponse задаёт один ограниченный ответ JSON lines.
type controlResponse struct {
	RequestID string          `json:"request_id"` // Идентификатор исходного запроса.
	OK        bool            `json:"ok"`         // Успех обработки запроса.
	Data      json.RawMessage `json:"data"`       // Результат по публичному контракту.
	Error     *apiError       `json:"error"`      // Безопасная ошибка Control.
}

// controlClient передаёт запросы только через Unix socket.
type controlClient struct {
	Socket  string        // Абсолютный путь Control socket.
	Timeout time.Duration // Максимальное время одного обмена.
}

// unavailable возвращает общее сообщение без внутренних команд и путей.
func unavailable() *apiError {
	return &apiError{Code: "control_unavailable", Message: "Control недоступен или вернул некорректный ответ. Состояние сервера не подтверждено.", Status: 503}
}

// Request выполняет ограниченный запрос с проверкой идентификатора ответа.
func (c *controlClient) Request(ctx context.Context, action string, payload json.RawMessage) (json.RawMessage, error) {
	id, err := randomToken()
	if err != nil {
		return nil, unavailable()
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	encoded, err := json.Marshal(controlRequest{RequestID: id, Action: action, Payload: payload})
	if err != nil || len(encoded)+1 > 1024*1024 {
		return nil, unavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	dialer := net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, unavailable()
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	if err = connection.SetDeadline(deadline); err != nil {
		return nil, unavailable()
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	if _, err = connection.Write(append(encoded, '\n')); err != nil {
		return nil, unavailable()
	}
	reader := bufio.NewReader(io.LimitReader(connection, 1024*1024+1))
	line, err := reader.ReadBytes('\n')
	if err != nil || len(line) > 1024*1024 {
		return nil, unavailable()
	}
	var response controlResponse
	if strictJSON(line, &response) != nil || response.RequestID != id {
		return nil, unavailable()
	}
	if !response.OK {
		if response.Error == nil {
			return nil, unavailable()
		}
		status := response.Error.Status
		if status < 400 || status > 599 || len(response.Error.Code) > 80 || len(response.Error.Message) > 1000 {
			return nil, unavailable()
		}
		return nil, response.Error
	}
	if response.Error != nil || len(response.Data) == 0 {
		return nil, unavailable()
	}
	data := bytes.TrimSpace(response.Data)
	if data[0] != '{' && data[0] != '[' && string(data) != "null" {
		return nil, unavailable()
	}
	return response.Data, nil
}
