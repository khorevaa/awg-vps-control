//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// WarpClient обращается только к root-сервису WARP через ограниченный IPC.
type WarpClient struct {
	socketPath string // Проверяемый абсолютный путь WARP socket.
}

// verifyOwnedSocket проверяет владельца socket и всю цепочку защищённых каталогов.
func verifyOwnedSocket(path string, expectedUID uint32) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("ненормализованный путь socket")
	}
	current := "/"
	directory := filepath.Dir(path)
	for _, part := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("небезопасный каталог socket")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (stat.Uid != 0 && stat.Uid != expectedUID) {
			return errors.New("неверный владелец каталога socket")
		}
		stickyRoot := stat.Uid == 0 && info.Mode()&os.ModeSticky != 0 && current != directory
		if info.Mode().Perm()&0022 != 0 && !stickyRoot {
			return errors.New("каталог socket доступен для сторонней записи")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0007 != 0 {
		return errors.New("небезопасный или недоступный socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != expectedUID {
		return errors.New("неверный владелец socket")
	}
	return nil
}

// exchangeLocalJSON выполняет один ограниченный запрос к подтверждённому Unix peer.
func exchangeLocalJSON(ctx context.Context, socketPath string, expectedUID uint32, request Request, timeout time.Duration) (Response, *APIError, bool) {
	if err := verifyOwnedSocket(socketPath, expectedUID); err != nil {
		return Response{}, failure(503, "host_unavailable", "Сервис управления недоступен."), false
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Response{}, failure(503, "host_unavailable", "Не удалось соединиться с сервисом управления."), false
	}
	defer connection.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		return Response{}, failure(503, "host_unavailable", "Некорректное локальное соединение."), false
	}
	uid, err := peerUID(unixConnection)
	if err != nil || uid != expectedUID {
		return Response{}, failure(503, "unsafe_host_peer", "Подлинность сервиса управления не подтверждена."), false
	}
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return Response{}, failure(503, "host_unavailable", "Не удалось ограничить ожидание ответа."), false
	}
	content, err := json.Marshal(request)
	if err != nil || len(content)+1 > maxMessageBytes {
		return Response{}, failure(422, "invalid_request", "Запрос не прошёл проверку."), false
	}
	content = append(content, '\n')
	written, err := connection.Write(content)
	if err != nil || written != len(content) {
		return Response{}, failure(503, "host_transport_error", "Передача запроса не подтверждена."), written > 0
	}
	line, err := readLine(connection)
	if err != nil {
		code, status := "host_protocol_error", 502
		var networkError net.Error
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || (errors.As(err, &networkError) && networkError.Timeout()) {
			code, status = "host_timeout", 504
		}
		return Response{}, failure(status, code, "Результат локального действия не подтверждён."), true
	}
	var response Response
	if decodeStrict(line, &response) != nil || response.RequestID != request.RequestID || (response.OK && response.Error != nil) || (!response.OK && response.Error == nil) {
		return Response{}, failure(502, "host_protocol_error", "Сервис вернул некорректный ответ."), true
	}
	response.Error = sanitizeError(response.Error)
	data, withinLimit := sanitizeData(response.Data, maxMessageBytes/2)
	if !withinLimit {
		return Response{}, failure(502, "response_too_large", "Результат действия превышает допустимый размер."), true
	}
	response.Data = data
	return response, nil, true
}

// Call передаёт WARP только внутренний allowlist, не предоставляя общий exec.
func (client *WarpClient) Call(ctx context.Context, request Request) (Response, *APIError) {
	switch request.Action {
	case "health", "integration.get", "integration.attach", "peers.defaults", "warp.overview", "diagnostics", "policy.get", "policy.set", "repair", "warp.reconnect", "warp.setup", "logs":
	default:
		return Response{}, failure(404, "unknown_action", "Действие WARP не поддерживается.")
	}
	timeout := hostDeadline(request.Action)
	if request.Action == "integration.attach" {
		timeout = 90 * time.Second
	}
	response, apiError, _ := exchangeLocalJSON(ctx, client.socketPath, 0, request, timeout)
	return response, apiError
}
