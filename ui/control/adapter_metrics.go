//go:build linux

package main

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// readMetric открывает только фиксированный root-owned файл mount без symlink.
func (adapter *Adapter) readMetric(name string) ([]byte, error) {
	switch name {
	case "hostname", "uptime", "loadavg", "meminfo":
	default:
		return nil, os.ErrInvalid
	}
	if err := verifyDirectoryPath(adapter.config.MetricsDirectory, false, 0); err != nil {
		return nil, err
	}
	path := filepath.Join(adapter.config.MetricsDirectory, name)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
		return nil, os.ErrPermission
	}
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, os.ErrInvalid
	}
	return raw, nil
}

// hostMetrics читает явно переданные данные VPS, не выдавая метрики контейнера.
func (adapter *Adapter) hostMetrics() (map[string]any, []any) {
	result := map[string]any{"hostname": nil, "uptime_seconds": nil, "load_average": nil, "memory": nil, "disk": nil}
	checks := make([]any, 0)
	metricError := func(name string) {
		checks = append(checks, adapterCheck("metrics."+name, "warning", "Метрика VPS недоступна или не прошла проверку."))
	}
	if raw, err := adapter.readMetric("hostname"); err == nil {
		name := strings.TrimSpace(safeText(string(raw)))
		if name != "" && len(name) <= 255 {
			result["hostname"] = name
		} else {
			metricError("hostname")
		}
	} else {
		metricError("hostname")
	}
	if raw, err := adapter.readMetric("uptime"); err == nil {
		parts := strings.Fields(string(raw))
		if len(parts) >= 1 {
			if value, err := strconv.ParseFloat(parts[0], 64); err == nil && value >= 0 && !math.IsNaN(value) && !math.IsInf(value, 0) {
				result["uptime_seconds"] = value
			}
		}
		if result["uptime_seconds"] == nil {
			metricError("uptime")
		}
	} else {
		metricError("uptime")
	}
	if raw, err := adapter.readMetric("loadavg"); err == nil {
		parts := strings.Fields(string(raw))
		loads := make([]float64, 0, 3)
		if len(parts) >= 3 {
			for _, part := range parts[:3] {
				value, err := strconv.ParseFloat(part, 64)
				if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
					break
				}
				loads = append(loads, value)
			}
		}
		if len(loads) == 3 {
			result["load_average"] = loads
		} else {
			metricError("loadavg")
		}
	} else {
		metricError("loadavg")
	}
	if raw, err := adapter.readMetric("meminfo"); err == nil {
		memory := make(map[string]uint64)
		for _, line := range strings.Split(string(raw), "\n") {
			parts := strings.Fields(line)
			if len(parts) != 3 || (parts[0] != "MemTotal:" && parts[0] != "MemAvailable:") || parts[2] != "kB" {
				continue
			}
			value, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil || value > math.MaxUint64/1024 {
				continue
			}
			key := "total_bytes"
			if parts[0] == "MemAvailable:" {
				key = "available_bytes"
			}
			memory[key] = value * 1024
		}
		if len(memory) == 2 {
			result["memory"] = memory
		} else {
			metricError("meminfo")
		}
	} else {
		metricError("meminfo")
	}
	var disk syscall.Statfs_t
	if err := syscall.Statfs(adapter.config.StateDirectory, &disk); err == nil && disk.Bsize > 0 && disk.Blocks <= math.MaxUint64/uint64(disk.Bsize) && disk.Bavail <= math.MaxUint64/uint64(disk.Bsize) {
		result["disk"] = map[string]uint64{"total_bytes": disk.Blocks * uint64(disk.Bsize), "free_bytes": disk.Bavail * uint64(disk.Bsize)}
	} else {
		metricError("disk")
	}
	return result, checks
}

// overview объединяет pinned AWG, root WARP и явные метрики VPS.
func (adapter *Adapter) overview(ctx context.Context, request Request) (json.RawMessage, *APIError) {
	integration, apiError := adapter.integration(ctx, request.RequestID)
	if apiError != nil {
		return nil, apiError
	}
	response, apiError := adapter.warp.Call(ctx, Request{RequestID: request.RequestID, Action: "warp.overview", Payload: json.RawMessage(`{}`)})
	if apiError != nil {
		return nil, apiError
	}
	if !response.OK {
		return nil, response.Error
	}
	var warp map[string]json.RawMessage
	if decodeStrict(response.Data, &warp) != nil || warp == nil {
		return nil, failure(502, "host_protocol_error", "Некорректный обзор WARP.")
	}
	result, metricChecks := adapter.hostMetrics()
	result["observed_at"], result["attached"], result["installation"] = nowText(), integration.Installation != nil, integration.Installation
	awg := map[string]any{"running": false, "message": "Установка не подключена."}
	if integration.Installation != nil {
		container, apiError := adapter.pinnedContainer(ctx, *integration.Installation, false, false)
		if apiError != nil {
			awg["message"] = apiError.Message
		} else {
			awg["running"], awg["started_at"] = container.State.Running, container.State.StartedAt
			if container.State.Running {
				awg["message"] = "Контейнер работает."
			} else {
				awg["message"] = "Контейнер остановлен; автоматический запуск запрещён."
			}
		}
	}
	result["awg"] = awg
	for _, key := range []string{"warp", "policy", "egress"} {
		if len(warp[key]) == 0 {
			return nil, failure(502, "host_protocol_error", "Обзор WARP неполон.")
		}
		result[key] = warp[key]
	}
	var checks []any
	if len(warp["checks"]) != 0 && json.Unmarshal(warp["checks"], &checks) != nil {
		return nil, failure(502, "host_protocol_error", "Неподдерживаемый формат проверок WARP.")
	}
	result["checks"] = append(checks, metricChecks...)
	return encodeData(result), nil
}

// diagnostics добавляет проверку AWG к независимым root-проверкам WARP.
func (adapter *Adapter) diagnostics(ctx context.Context, request Request) (json.RawMessage, *APIError) {
	checks := make([]any, 0)
	integration, apiError := adapter.attached(ctx, request.RequestID)
	if apiError != nil {
		checks = append(checks, adapterCheck("awg.container", "error", apiError.Message))
	} else {
		container, apiError := adapter.pinnedContainer(ctx, *integration.Installation, false, true)
		if apiError != nil {
			checks = append(checks, adapterCheck("awg.container", "error", apiError.Message))
		} else {
			checks = append(checks, adapterCheck("awg.container", "ok", "Закреплённый AWG-контейнер работает."))
			raw, code, apiError := adapter.docker.Read(ctx, container.ID, "interfaces", "")
			found := false
			if apiError == nil && code == 0 {
				for _, iface := range strings.Fields(string(raw)) {
					if iface == integration.Installation.Interface {
						found = true
					}
				}
			}
			status, message := "error", "AWG-интерфейс не подтверждён."
			if found {
				status, message = "ok", "Закреплённый AWG-интерфейс доступен."
			}
			checks = append(checks, adapterCheck("awg.interface", status, message))
		}
	}
	data, apiError := adapter.forward(ctx, request)
	if apiError != nil {
		return nil, apiError
	}
	var snapshot map[string]json.RawMessage
	var warpChecks []any
	if decodeStrict(data, &snapshot) != nil || json.Unmarshal(snapshot["checks"], &warpChecks) != nil {
		return nil, failure(502, "host_protocol_error", "Некорректный результат диагностики WARP.")
	}
	return encodeData(map[string]any{"observed_at": nowText(), "checks": append(checks, warpChecks...)}), nil
}
