//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"time"
)

// Server ограничивает число локальных клиентов и проверяет их UID.
type Server struct {
	service     *Service          // Обработчик разрешённых запросов.
	listener    *net.UnixListener // Закрытый Unix listener.
	connections chan struct{}     // Ограничение одновременно занятых соединений.
	workers     sync.WaitGroup    // Ожидание завершения текущих обработчиков.
}

// sendResponse отправляет ровно один ограниченный ответ протокола.
func sendResponse(connection *net.UnixConn, response Response) {
	content, err := json.Marshal(response)
	if err != nil || len(content)+1 > maxMessageBytes {
		content, _ = json.Marshal(resultResponse(response.RequestID, nil, failure(502, "response_too_large", "Результат превышает допустимый размер.")))
	}
	_ = connection.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = connection.Write(append(content, '\n'))
}

// handleConnection проверяет системного отправителя до выполнения действия.
func (server *Server) handleConnection(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	defer server.workers.Done()
	defer func() { <-server.connections }()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	uid, err := peerUID(connection)
	if err != nil || (uid != server.service.config.WebUID && uid != 0 && uid != uint32(os.Geteuid())) {
		sendResponse(connection, resultResponse("", nil, failure(403, "peer_denied", "Недопустимый отправитель запроса.")))
		return
	}
	if err := connection.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return
	}
	line, err := readLine(connection)
	if err != nil {
		sendResponse(connection, resultResponse("", nil, failure(400, "invalid_request", "Недопустимая строка протокола.")))
		return
	}
	var request Request
	if decodeStrict(line, &request) != nil {
		sendResponse(connection, resultResponse("", nil, failure(400, "invalid_request", "Некорректный JSON-запрос.")))
		return
	}
	if !identifierPattern.MatchString(request.RequestID) {
		sendResponse(connection, resultResponse("", nil, failure(422, "invalid_request_id", "Некорректный идентификатор запроса.")))
		return
	}
	if uid != server.service.config.WebUID && request.Action != "health" {
		sendResponse(connection, resultResponse(request.RequestID, nil, failure(403, "peer_denied", "Этот отправитель может проверять только health.")))
		return
	}
	requestContext, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	sendResponse(connection, server.service.Handle(requestContext, request))
}

// Run принимает ограниченные соединения до отмены контекста сервиса.
func (server *Server) Run(ctx context.Context) error {
	stopListener := context.AfterFunc(ctx, func() { _ = server.listener.Close() })
	defer stopListener()
	defer server.listener.Close()
	defer server.workers.Wait()
	for {
		connection, err := server.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		select {
		case server.connections <- struct{}{}:
			server.workers.Add(1)
			go server.handleConnection(ctx, connection)
		default:
			sendResponse(connection, resultResponse("", nil, failure(503, "control_busy", "Control занят; повторите запрос позже.")))
			_ = connection.Close()
		}
	}
}
