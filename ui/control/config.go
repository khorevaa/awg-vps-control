//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// envDefault возвращает явную настройку или безопасное значение по умолчанию.
func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// loadConfig читает настройки без автоматического изменения файлов установки.
func loadConfig() (Config, error) {
	config := Config{
		SocketPath: envDefault("AWG_CONTROL_SOCKET", "/run/awg_vps_control/control.sock"),
		HostSocket: envDefault("AWG_HOST_SOCKET", "/run/awg_vps_adapter/adapter.sock"),
		StatePath:  envDefault("AWG_CONTROL_STATE", "/var/lib/awg_vps_control/control/state.json"),
		WebUID:     10001,
		WebGID:     10001,
	}
	uid, err := strconv.ParseUint(envDefault("AWG_WEB_UID", "10001"), 10, 32)
	if err != nil || uid == 0 || uid == uint64(os.Geteuid()) {
		return Config{}, fmt.Errorf("AWG_WEB_UID должен отличаться от root и UID Control")
	}
	config.WebUID = uint32(uid)
	for _, path := range []string{config.SocketPath, config.HostSocket, config.StatePath} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return Config{}, fmt.Errorf("пути Control должны быть абсолютными и нормализованными")
		}
	}
	if len(config.SocketPath) > 100 || len(config.HostSocket) > 100 {
		return Config{}, fmt.Errorf("слишком длинный путь Unix-сокета")
	}
	return config, nil
}
