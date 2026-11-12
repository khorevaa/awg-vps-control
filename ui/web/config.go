//go:build linux

package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// config содержит пути и единственный разрешённый origin панели.
type config struct {
	WebSocket     string        // Unix socket HTTP-сервера.
	ControlSocket string        // Unix socket Control.
	SecretFile    string        // Защищённый файл секрета входа.
	StateFile     string        // Файл хешей сессий и аудита.
	AllowedHost   string        // Точный Host локального SSH-туннеля.
	AllowedOrigin string        // Точный Origin браузера.
	SessionTTL    time.Duration // Срок жизни сессии, максимум 12 часов.
}

// env возвращает заданное окружением значение либо безопасное значение по умолчанию.
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// loadConfig проверяет пути и выделенный localhost origin без публичного HTTP listener.
func loadConfig() (config, error) {
	cfg := config{
		WebSocket:     env("AWG_WEB_SOCKET", "/run/awg_vps_web/web.sock"),
		ControlSocket: env("AWG_CONTROL_SOCKET", "/run/awg_vps_control/control.sock"),
		SecretFile:    env("AWG_ACCESS_SECRET_FILE", "/run/secrets/access_secret"),
		StateFile:     env("AWG_WEB_STATE", "/var/lib/awg_vps_control/web/state.json"),
		AllowedHost:   os.Getenv("AWG_ALLOWED_HOST"),
		AllowedOrigin: os.Getenv("AWG_ALLOWED_ORIGIN"),
		SessionTTL:    12 * time.Hour,
	}
	for _, path := range []string{cfg.WebSocket, cfg.ControlSocket, cfg.SecretFile, cfg.StateFile} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return cfg, fmt.Errorf("managed paths must be absolute and clean")
		}
	}
	u, err := url.Parse(cfg.AllowedOrigin)
	if err != nil {
		return cfg, fmt.Errorf("invalid allowed origin: %w", err)
	}
	if u.Scheme != "http" || u.Host != cfg.AllowedHost || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return cfg, fmt.Errorf("allowed origin must match the exact local host")
	}
	host, port, err := net.SplitHostPort(cfg.AllowedHost)
	if err != nil {
		return cfg, fmt.Errorf("allowed host requires a port: %w", err)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return cfg, fmt.Errorf("invalid local port")
	}
	if !strings.HasPrefix(host, "awg-") || !strings.HasSuffix(host, ".localhost") {
		return cfg, fmt.Errorf("allowed host must use an isolated awg- hostname under localhost")
	}
	label := strings.TrimSuffix(strings.TrimPrefix(host, "awg-"), ".localhost")
	if len(label) < 8 || len(label) > 48 {
		return cfg, fmt.Errorf("invalid isolated host label")
	}
	for _, ch := range label {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-", ch) {
			return cfg, fmt.Errorf("invalid isolated host label")
		}
	}
	return cfg, nil
}
