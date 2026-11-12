//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// AdapterServer ограничивает входящие соединения и проверяет kernel UID.
type AdapterServer struct {
	adapter     *Adapter          // Обработчик ограниченных доменных действий.
	listener    *net.UnixListener // Listener в защищённом каталоге.
	connections chan struct{}     // Ограничение числа обработчиков.
	workers     sync.WaitGroup    // Завершение начатых запросов при shutdown.
}

// loadAdapterConfig читает только абсолютные доверенные пути окружения.
func loadAdapterConfig() (AdapterConfig, error) {
	config := AdapterConfig{SocketPath: envDefault("AWG_ADAPTER_SOCKET", "/run/awg_vps_adapter/adapter.sock"), WarpSocket: envDefault("AWG_WARP_SOCKET", "/run/awg_vps_warp/warp.sock"), DockerSocket: envDefault("AWG_DOCKER_SOCKET", "/var/run/docker.sock"), StateDirectory: envDefault("AWG_ADAPTER_STATE", "/var/lib/awg_vps_control/adapter"), MetricsDirectory: envDefault("AWG_HOST_METRICS", "/run/awg_vps_metrics")}
	for _, path := range []string{config.SocketPath, config.WarpSocket, config.DockerSocket, config.StateDirectory, config.MetricsDirectory} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return AdapterConfig{}, errors.New("пути adapter должны быть абсолютными и нормализованными")
		}
	}
	for _, path := range []string{config.SocketPath, config.WarpSocket, config.DockerSocket} {
		if len(path) > 100 {
			return AdapterConfig{}, errors.New("путь socket слишком длинный")
		}
	}
	return config, nil
}

// connection допускает root/Control; собственному UID разрешена только готовность.
func (server *AdapterServer) connection(ctx context.Context, connection *net.UnixConn) {
	defer connection.Close()
	defer server.workers.Done()
	defer func() { <-server.connections }()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	uid, err := peerUID(connection)
	if err != nil || (uid != 0 && uid != 10002 && uid != 10003) {
		sendResponse(connection, resultResponse("", nil, failure(403, "peer_denied", "Недопустимый отправитель запроса.")))
		return
	}
	if connection.SetReadDeadline(time.Now().Add(5*time.Second)) != nil {
		return
	}
	line, err := readLine(connection)
	if err != nil {
		sendResponse(connection, resultResponse("", nil, failure(400, "invalid_request", "Недопустимая строка запроса.")))
		return
	}
	var request Request
	if decodeStrict(line, &request) != nil || !identifierPattern.MatchString(request.RequestID) {
		sendResponse(connection, resultResponse("", nil, failure(400, "invalid_request", "Некорректный JSON-запрос.")))
		return
	}
	if uid == 10003 && request.Action != "health" {
		sendResponse(connection, resultResponse(request.RequestID, nil, failure(403, "peer_denied", "Этот UID может выполнять только health.")))
		return
	}
	timeout := hostDeadline(request.Action)
	requestContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sendResponse(connection, server.adapter.Handle(requestContext, request))
}

// Run обслуживает ограниченный Unix API до остановки процесса.
func (server *AdapterServer) Run(ctx context.Context) error {
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
			go server.connection(ctx, connection)
		default:
			sendResponse(connection, resultResponse("", nil, failure(503, "adapter_busy", "Adapter занят; повторите запрос позже.")))
			_ = connection.Close()
		}
	}
}

// runAdapter реализует serve, readiness healthcheck и ограниченный локальный CLI.
func runAdapter(args []string) error {
	config, err := loadAdapterConfig()
	if err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "healthcheck" {
		request := Request{RequestID: "healthcheck", Action: "health", Payload: json.RawMessage(`{}`)}
		response, apiError, _ := exchangeLocalJSON(context.Background(), config.SocketPath, 10003, request, 3*time.Second)
		if apiError != nil {
			return errors.New("adapter не подтвердил готовность")
		}
		var data map[string]json.RawMessage
		var status string
		if !response.OK || decodeStrict(response.Data, &data) != nil || json.Unmarshal(data["status"], &status) != nil || status != "ok" {
			return errors.New("adapter не подтвердил готовность")
		}
		return nil
	}
	if len(args) == 2 && args[0] == "request" {
		var request Request
		if len(args[1])+1 > maxMessageBytes || decodeStrict([]byte(args[1]), &request) != nil || !identifierPattern.MatchString(request.RequestID) {
			return errors.New("некорректный JSON CLI-запроса")
		}
		payload, apiError := validatePayload(request.Action, request.Payload)
		if apiError != nil || request.Action == "operations.get" || request.Action == "operations.list" {
			return errors.New("CLI-действие не поддерживается")
		}
		request.Payload = payload
		response, apiError, _ := exchangeLocalJSON(context.Background(), config.SocketPath, 10003, request, hostDeadline(request.Action))
		if apiError != nil {
			response = resultResponse(request.RequestID, nil, apiError)
		}
		if err := json.NewEncoder(os.Stdout).Encode(response); err != nil {
			return err
		}
		if !response.OK {
			return errors.New("adapter отклонил действие")
		}
		return nil
	}
	if len(args) != 1 || args[0] != "serve" {
		return errors.New("доступны adapter serve, healthcheck и request JSON")
	}
	if os.Geteuid() != 10003 {
		return errors.New("adapter serve должен работать от UID10003")
	}
	if err := verifyDirectoryPath(config.StateDirectory, true, 0700); err != nil {
		return err
	}
	lock, err := openPrivateFile(filepath.Join(config.StateDirectory, "adapter.lock"), syscall.O_CREAT|syscall.O_RDWR)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("adapter уже использует каталог состояния")
	}
	listener, err := listenControl(Config{SocketPath: config.SocketPath, WebGID: 10002})
	if err != nil {
		return err
	}
	adapter := &Adapter{config: config, docker: newDockerClient(config.DockerSocket), warp: &WarpClient{socketPath: config.WarpSocket}, mutation: make(chan struct{}, 1)}
	defer adapter.docker.http.CloseIdleConnections()
	server := &AdapterServer{adapter: adapter, listener: listener, connections: make(chan struct{}, 16)}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	profilesDone := make(chan struct{})
	go func() { defer close(profilesDone); adapter.profiles.Run(ctx) }()
	defer func() { cancel(); <-profilesDone }()
	log.Printf("Docker adapter %s запущен", version)
	if err := server.Run(ctx); err != nil {
		return fmt.Errorf("adapter завершён: %w", err)
	}
	return nil
}
