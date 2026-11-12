//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// runWarp запускает root WARP API, ранний guard, проверку конфигурации либо локальный CLI запрос.
func runWarp(args []string) error {
	if len(args) == 0 {
		return errors.New("нужен режим warp: serve, guard, safety, check-config, request или probe-dns")
	}
	mode := args[0]
	if mode == "probe-dns" {
		return warpDNSProbe(args[1:])
	}
	configDefault := os.Getenv("AWG_WARP_CONFIG")
	if configDefault == "" {
		configDefault = "/etc/awg_vps_control/host.json"
	}
	socketDefault := os.Getenv("AWG_WARP_SOCKET")
	if socketDefault == "" {
		socketDefault = "/run/awg_vps_warp/warp.sock"
	}
	flags := flag.NewFlagSet("warp "+mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", configDefault, "root configuration")
	socketPath := flags.String("socket", socketDefault, "Unix socket")
	if err := flags.Parse(args[1:]); err != nil {
		return errors.New("некорректные параметры warp")
	}
	if !filepath.IsAbs(*socketPath) || filepath.Clean(*socketPath) != *socketPath {
		return errors.New("некорректный путь WARP socket")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if mode == "request" {
		if flags.NArg() != 1 {
			return errors.New("request требует одну JSON-строку")
		}
		return warpCLIRequest(ctx, *socketPath, flags.Arg(0))
	}
	if mode != "safety" && flags.NArg() != 0 {
		return errors.New("лишние параметры warp")
	}
	runtime, err := warpLoadConfig(*configPath)
	if err != nil {
		return err
	}
	switch mode {
	case "safety":
		return runtime.safetyCLI(ctx, *configPath, flags.Args())
	case "check-config":
		session := runtime.newSession()
		session.validateStoredState()
		if session.Err != nil {
			return session.Err
		}
		fmt.Fprintln(os.Stdout, "configuration ok")
		return nil
	case "guard":
		guardCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		if err := runtime.safetyBoot(guardCtx); err != nil {
			return err
		}
		lock, err := runtime.lock(guardCtx)
		if err != nil {
			return err
		}
		defer lock.Close()
		session := runtime.newSession()
		session.bootGuard(guardCtx)
		if session.Err != nil {
			return session.Err
		}
		return nil
	case "serve":
		if err := runtime.safetyBoot(ctx); err != nil {
			return err
		}
		return runtime.serve(ctx, *socketPath)
	default:
		return errors.New("неподдерживаемый режим warp")
	}
}

// warpDNSProbe отправляет один ограниченный UDP DNS запрос с заданного клиентского IPv4.
func warpDNSProbe(args []string) error {
	flags := flag.NewFlagSet("probe-dns", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	source := flags.String("source", "", "source IPv4")
	server := flags.String("server", "", "DNS IPv4")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !warpIPv4(*source) || !warpIPv4(*server) {
		return errors.New("некорректные IPv4 параметры DNS-пробы")
	}
	connection, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(*source)}, &net.UDPAddr{IP: net.ParseIP(*server), Port: 53})
	if err != nil {
		return errors.New("DNS-проба не подключилась")
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}
	query := make([]byte, 12)
	if _, err := rand.Read(query[:2]); err != nil {
		return err
	}
	query[2] = 1
	query[5] = 1
	for _, label := range strings.Split("cloudflare.com", ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 1, 0, 1)
	if _, err := connection.Write(query); err != nil {
		return errors.New("DNS-проба не отправлена")
	}
	response := make([]byte, 4096)
	n, err := connection.Read(response)
	if err != nil || n < 12 || response[0] != query[0] || response[1] != query[1] || response[2]&0x80 == 0 || response[3]&0x0f != 0 || binary.BigEndian.Uint16(response[6:8]) == 0 {
		return errors.New("DNS-ответ не подтверждён")
	}
	fmt.Fprintln(os.Stdout, "dns ok")
	return nil
}

// warpCLIRequest отправляет ровно одну JSON-lines команду локальному root socket.
func warpCLIRequest(ctx context.Context, socketPath, raw string) error {
	if len(raw) > maxMessageBytes || strings.ContainsAny(raw, "\r\n") {
		return errors.New("неверный размер или формат запроса")
	}
	var request Request
	if decodeStrict([]byte(raw), &request) != nil {
		return errors.New("неверный JSON запрос")
	}
	timeout := 190 * time.Second
	if request.Action == "health" {
		timeout = 3 * time.Second
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	connection, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return errors.New("WARP socket недоступен")
	}
	defer connection.Close()
	unix, ok := connection.(*net.UnixConn)
	if !ok {
		return errors.New("ожидался Unix socket")
	}
	uid, err := peerUID(unix)
	if err != nil || uid != 0 {
		return errors.New("WARP socket не принадлежит root процессу")
	}
	if err := connection.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	if _, err := io.WriteString(connection, raw+"\n"); err != nil {
		return err
	}
	line, err := readLine(connection)
	if err != nil {
		return err
	}
	var response Response
	if decodeStrict(line, &response) != nil || response.RequestID != request.RequestID {
		return errors.New("неверный ответ WARP socket")
	}
	fmt.Fprintln(os.Stdout, string(line))
	if !response.OK {
		if response.Error != nil {
			return response.Error
		}
		return errors.New("операция WARP не завершилась")
	}
	return nil
}

// dispatch проверяет allowlist и сериализует операции; health не ждёт host.lock.
func (r *WarpRuntime) dispatch(ctx context.Context, request Request) Response {
	response := Response{RequestID: request.RequestID, Data: json.RawMessage("null")}
	if !identifierPattern.MatchString(request.RequestID) || len(request.Action) > 80 {
		response.Error = failure(400, "invalid_request", "Некорректный идентификатор запроса.")
		return response
	}
	payload, err := canonicalObject(request.Payload)
	if err != nil || len(payload) > maxPayloadBytes {
		response.Error = failure(400, "invalid_payload", "Некорректный payload.")
		return response
	}
	if request.Action == "health" {
		if requireEmpty(payload) != nil {
			response.Error = failure(400, "invalid_payload", "health не принимает параметры.")
			return response
		}
		response.OK = true
		response.Data = encodeData(map[string]any{"status": "ok", "service": "warp", "observed_at": warpNow()})
		return response
	}
	mutation := false
	switch request.Action {
	case "integration.get", "warp.overview", "diagnostics", "policy.get", "logs":
	case "integration.attach", "policy.set", "repair", "warp.reconnect", "warp.setup":
		mutation = true
	default:
		response.Error = failure(400, "unsupported", "Действие не разрешено WARP runtime.")
		return response
	}
	if mutation && r.safetyHeld() {
		response.Error = failure(409, "emergency_hold", "Действует аварийная блокировка WARP. Проверьте warp-safety status; возобновление выполняется явно через SSH.")
		return response
	}
	timeout := 30 * time.Second
	if mutation {
		timeout = 90 * time.Second
	}
	if request.Action == "warp.setup" {
		timeout = 180 * time.Second
	}
	operationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lock, lockErr := r.lock(operationCtx)
	if lockErr != nil {
		response.Error = failure(409, "busy", "Другая операция уже выполняется.")
		return response
	}
	defer lock.Close()
	s := r.newSession()
	var data any
	if s.Err == nil {
		switch request.Action {
		case "integration.attach":
			var value AttachRequest
			if decodeStrict(payload, &value) != nil {
				s.fail("invalid_payload", "Некорректные параметры подключения.", 400)
			} else {
				data = s.attach(operationCtx, value)
			}
		case "policy.set":
			var value PolicyUpdate
			if decodeStrict(payload, &value) != nil {
				s.fail("invalid_payload", "Некорректные параметры политики.", 400)
			} else {
				data = s.policySet(operationCtx, value)
			}
		case "logs":
			var value LogRequest
			if decodeStrict(payload, &value) != nil {
				s.fail("invalid_payload", "Некорректные параметры журнала.", 400)
			} else {
				data = s.logs(operationCtx, value)
			}
		default:
			if requireEmpty(payload) != nil {
				s.fail("invalid_payload", "Действие не принимает параметры.", 400)
			} else {
				switch request.Action {
				case "integration.get":
					var value *WarpInstallation
					s.read("installation.json", &value)
					data = map[string]any{"installation": value, "managed": s.Manifest != nil}
				case "policy.get":
					data = s.policy()
				case "warp.overview":
					data = s.overview(operationCtx)
				case "diagnostics":
					data = s.diagnostics(operationCtx)
				case "repair":
					data = s.reconcile(operationCtx, true)
				case "warp.reconnect":
					data = s.reconnect(operationCtx)
				case "warp.setup":
					data = s.setup(operationCtx)
				}
			}
		}
	}
	s.finishSafetyOperation(ctx)
	if s.Err != nil {
		if s.Mutated {
			// Независимый короткий бюджет сохраняет fail-closed после истёкшей операции.
			guardCtx, guardCancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
			s.emergencyBlock(guardCtx, "Операция не завершена; клиентский путь закрыт до проверки.")
			guardCancel()
			s.finishSafetyOperation(ctx)
			response.Error = failure(s.Err.Status, "mutation_failed", s.Err.Message)
		} else {
			response.Error = s.Err
		}
		return response
	}
	response.OK = true
	response.Data = encodeData(data)
	if len(response.Data) > maxMessageBytes-4096 {
		response.OK = false
		response.Data = json.RawMessage("null")
		response.Error = failure(502, "output_limit", "Ответ превысил допустимый размер.")
	}
	return response
}

// serve объединяет Unix API и supervisor в одном отменяемом процессе.
func (r *WarpRuntime) serve(ctx context.Context, socketPath string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	listener, err := listenControl(Config{SocketPath: socketPath, WebGID: r.Config.SocketGID})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chown(filepath.Dir(socketPath), 0, r.Config.SocketGID); err != nil {
		return err
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() { defer workers.Done(); r.supervise(ctx) }()
	stopListener := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopListener()
	semaphore := make(chan struct{}, 16)
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return err
		}
		uid, peerErr := peerUID(connection)
		if peerErr != nil || (uid != 0 && uid != uint32(r.Config.AdapterUID)) {
			_ = connection.Close()
			continue
		}
		select {
		case semaphore <- struct{}{}:
		default:
			_ = connection.Close()
			continue
		}
		workers.Add(1)
		go func(connection *net.UnixConn) {
			defer workers.Done()
			defer func() { <-semaphore }()
			defer connection.Close()
			stopConnection := context.AfterFunc(ctx, func() { _ = connection.Close() })
			defer stopConnection()
			_ = connection.SetDeadline(time.Now().Add(200 * time.Second))
			line, err := readLine(connection)
			if err != nil {
				return
			}
			var request Request
			if decodeStrict(line, &request) != nil {
				_ = json.NewEncoder(connection).Encode(Response{OK: false, Data: json.RawMessage("null"), Error: failure(400, "invalid_request", "Некорректный JSON-lines запрос.")})
				return
			}
			response := r.dispatch(ctx, request)
			_ = json.NewEncoder(connection).Encode(response)
		}(connection)
	}
	workers.Wait()
	return nil
}

// supervise периодически проверяет только принятую интеграцию и никогда не перезапускает AWG.
func (r *WarpRuntime) supervise(ctx context.Context) {
	ticker := time.NewTicker(time.Duration(r.Config.SupervisorInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		operationCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
		lock, err := r.lock(operationCtx)
		if err != nil {
			cancel()
			continue
		}
		s := r.newSession()
		if s.Err == nil && s.Manifest != nil {
			s.reconcile(operationCtx, false)
		}
		s.finishSafetyOperation(ctx)
		if s.Err != nil && s.Manifest != nil {
			guardCtx, guardCancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
			s.emergencyBlock(guardCtx, "Supervisor не подтвердил безопасное состояние; выход закрыт.")
			guardCancel()
			s.finishSafetyOperation(ctx)
			fmt.Fprintln(os.Stderr, "WARP supervisor: "+s.Err.Code)
		}
		_ = lock.Close()
		cancel()
	}
}
