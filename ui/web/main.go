//go:build linux

// Панель awg-vps-control предоставляет HTTP только через защищённый Unix socket.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
)

var version = "dev"

// safeSocket проверяет владельца и права Unix socket.
func safeSocket(path string) error {
	if err := ownedDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("unsafe web socket")
	}
	return nil
}

// listenUnix создаёт Unix listener и удаляет только доказанно устаревший собственный socket.
func listenUnix(path string) (*net.UnixListener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := ownedDirectory(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if err = safeSocket(path); err != nil {
			return nil, err
		}
		connection, dialErr := net.DialTimeout("unix", path, time.Second)
		if dialErr == nil {
			connection.Close()
			return nil, fmt.Errorf("web socket is already active")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("cannot prove web socket is stale")
		}
		if err = os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err = os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

// healthcheck проверяет собственный HTTP socket и цепочку Control/Host без секрета доступа.
func healthcheck(path string) error {
	if err := safeSocket(path); err != nil {
		return err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, "unix", path)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Get("http://localhost/api/v1/health")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 1024))
	if err != nil {
		return err
	}
	if response.StatusCode != 200 || string(content) != "{\"status\":\"ok\"}\n" {
		return fmt.Errorf("unhealthy web response")
	}
	control := &controlClient{Socket: env("AWG_CONTROL_SOCKET", "/run/awg_vps_control/control.sock"), Timeout: 3 * time.Second}
	data, err := control.Request(context.Background(), "health", nil)
	if err != nil {
		return fmt.Errorf("Control/Host dependency is unavailable")
	}
	var status map[string]string
	if strictJSON(data, &status) != nil || len(status) != 1 || status["status"] != "ok" {
		return fmt.Errorf("unhealthy Control/Host response")
	}
	return nil
}

// run собирает зависимости и обслуживает запросы до сигнала завершения.
func run() error {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		return healthcheck(env("AWG_WEB_SOCKET", "/run/awg_vps_web/web.sock"))
	}
	if len(os.Args) == 2 && (os.Args[1] == "--version" || os.Args[1] == "version") {
		fmt.Println(version)
		return nil
	}
	if len(os.Args) > 2 || (len(os.Args) == 2 && os.Args[1] != "serve") {
		return fmt.Errorf("usage: awg_web [serve|healthcheck|version]")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	listener, err := listenUnix(cfg.WebSocket)
	if err != nil {
		return err
	}
	defer listener.Close()
	store, err := newSessionStore(cfg)
	if err != nil {
		return err
	}
	app := &application{Config: cfg, Store: store, Control: &controlClient{Socket: cfg.ControlSocket, Timeout: 35 * time.Second}}
	server := &http.Server{Handler: app, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("не удалось завершить HTTP-сервер")
		}
	}()
	slog.Info("Web готов, доступ через Unix socket", "version", version)
	err = server.Serve(listener)
	stop()
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// main завершает процесс при ошибке запуска без вывода секретных значений.
func main() {
	if err := run(); err != nil {
		slog.Error("Web остановлен", "error", err)
		os.Exit(1)
	}
}
