//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var encodedKeyPattern = regexp.MustCompile(`[A-Za-z0-9+/]{43}=`)
var secretConfigLine = regexp.MustCompile(`(?i)(private[ _-]?key|preshared[ _-]?key|headerprotectionkey|password|passwd|authorization|bearer|license[ _-]?key|token|secret)\s*[:=]`)
var configHookLine = regexp.MustCompile(`(?i)^\s*(PreUp|PostUp|PreDown|PostDown)\s*=`)

// adapterCheck создаёт диагностический факт без внутренних ошибок или секретов.
func adapterCheck(id, status, message string) map[string]any {
	return map[string]any{"id": id, "status": status, "message": message, "checked_at": nowText()}
}

// redactAWG исключает секретные строки, команды hooks и ключи из read-only снимков.
func redactAWG(value string) string {
	lines := strings.Split(value, "\n")
	for index, line := range lines {
		switch {
		case secretConfigLine.MatchString(line):
			lines[index] = "[строка с секретом скрыта]"
		case configHookLine.MatchString(line):
			lines[index] = strings.SplitN(line, "=", 2)[0] + "= [команда скрыта]"
		default:
			line = encodedKeyPattern.ReplaceAllString(safeText(line), "[ключ скрыт]")
			runes := []rune(line)
			if len(runes) > 4096 {
				line = string(runes[:4096]) + "…"
			}
			lines[index] = line
		}
	}
	return strings.Join(lines, "\n")
}

// integration читает единственный источник привязки из root-состояния WARP.
func (adapter *Adapter) integration(ctx context.Context, requestID string) (AdapterIntegration, *APIError) {
	response, apiError := adapter.warp.Call(ctx, Request{RequestID: requestID, Action: "integration.get", Payload: json.RawMessage(`{}`)})
	if apiError != nil {
		return AdapterIntegration{}, apiError
	}
	if !response.OK {
		return AdapterIntegration{}, response.Error
	}
	var envelope map[string]json.RawMessage
	if decodeStrict(response.Data, &envelope) != nil || len(envelope) != 2 || len(envelope["installation"]) == 0 || (string(envelope["managed"]) != "true" && string(envelope["managed"]) != "false") {
		return AdapterIntegration{}, failure(502, "host_protocol_error", "Root не подтвердил состояние привязки и маршрутизации.")
	}
	var result AdapterIntegration
	if dockerDecode(response.Data, &result) != nil {
		return AdapterIntegration{}, failure(502, "host_protocol_error", "Не удалось прочитать привязку установки.")
	}
	if result.Installation != nil {
		value := result.Installation
		if !resourcePattern.MatchString(value.ContainerName) || !dockerIDPattern.MatchString(value.ContainerID) || !awgInterfacePattern.MatchString(value.Interface) || value.ConfigPath != "/opt/amnezia/awg/"+value.Interface+".conf" || !resourcePattern.MatchString(value.DockerNetwork) {
			return AdapterIntegration{}, failure(502, "host_protocol_error", "Root-привязка не прошла проверку.")
		}
		if value.DNSContainerName != "" && (!resourcePattern.MatchString(value.DNSContainerName) || !dockerIDPattern.MatchString(value.DNSContainerID)) {
			return AdapterIntegration{}, failure(502, "host_protocol_error", "DNS-привязка не прошла проверку.")
		}
	}
	return result, nil
}

// pinnedContainer повторно сверяет имя и ID перед каждым штатным чтением или restart.
func (adapter *Adapter) pinnedContainer(ctx context.Context, value AdapterInstallation, dns bool, requireRunning bool) (DockerContainer, *APIError) {
	name, id := value.ContainerName, value.ContainerID
	if dns {
		name, id = value.DNSContainerName, value.DNSContainerID
	}
	if name == "" || !dockerIDPattern.MatchString(id) {
		return DockerContainer{}, failure(409, "not_attached", "Нужный контейнер не подключён.")
	}
	container, apiError := adapter.docker.Inspect(ctx, name)
	if apiError != nil {
		return DockerContainer{}, apiError
	}
	if container.ID != id || strings.TrimPrefix(container.Name, "/") != name {
		return DockerContainer{}, failure(409, "configuration_changed", "Контейнер пересоздан; требуется повторная привязка.")
	}
	if requireRunning && !container.State.Running {
		return DockerContainer{}, failure(409, "awg_stopped", "Контейнер остановлен; автоматический запуск запрещён.")
	}
	return container, nil
}

// attached возвращает проверенную root-привязку для доменного действия.
func (adapter *Adapter) attached(ctx context.Context, requestID string) (AdapterIntegration, *APIError) {
	integration, apiError := adapter.integration(ctx, requestID)
	if apiError != nil {
		return AdapterIntegration{}, apiError
	}
	if integration.Installation == nil {
		return AdapterIntegration{}, failure(409, "not_attached", "Сначала подключите существующую установку AWG.")
	}
	return integration, nil
}

// discover перечисляет поддерживаемые интерфейсы только работающих контейнеров.
func (adapter *Adapter) discover(ctx context.Context) (json.RawMessage, *APIError) {
	containers, apiError := adapter.docker.List(ctx)
	if apiError != nil {
		return nil, apiError
	}
	candidates := make([]AdapterInstallation, 0)
	for _, summary := range containers {
		if ctx.Err() != nil {
			return nil, failure(504, "discovery_timeout", "Обнаружение не завершилось в установленный срок.")
		}
		container, apiError := adapter.docker.Inspect(ctx, summary.ID)
		if apiError != nil {
			return nil, apiError
		}
		if !container.State.Running {
			continue
		}
		raw, code, apiError := adapter.docker.Read(ctx, container.ID, "interfaces", "")
		if apiError != nil {
			return nil, apiError
		}
		if code != 0 {
			continue
		}
		interfaces := strings.Fields(string(raw))
		if len(interfaces) > 8 {
			continue
		}
		for _, iface := range interfaces {
			if !awgInterfacePattern.MatchString(iface) {
				continue
			}
			_, code, apiError := adapter.docker.Read(ctx, container.ID, "config_exists", iface)
			if apiError != nil {
				return nil, apiError
			}
			networks := make([]string, 0, len(container.NetworkSettings.Networks))
			for name := range container.NetworkSettings.Networks {
				if resourcePattern.MatchString(name) {
					networks = append(networks, name)
				}
			}
			sort.Strings(networks)
			capabilities, reason := []string{"observe"}, "Штатный конфиг Amnezia не найден."
			if code == 0 {
				capabilities, reason = []string{"observe", "manual_restart"}, ""
			}
			candidates = append(candidates, AdapterInstallation{ContainerName: strings.TrimPrefix(container.Name, "/"), ContainerID: container.ID, Interface: iface, ConfigPath: "/opt/amnezia/awg/" + iface + ".conf", Networks: networks, Capabilities: capabilities, Supported: code == 0, Reason: reason})
		}
	}
	return encodeData(map[string]any{"observed_at": nowText(), "candidates": candidates, "dependencies": []any{adapterCheck("dependency.docker", "ok", "Docker API доступен.")}}), nil
}

// configuration читает только закреплённый штатный конфиг и маскирует его до ответа.
func (adapter *Adapter) configuration(ctx context.Context, requestID string) (json.RawMessage, *APIError) {
	integration, apiError := adapter.attached(ctx, requestID)
	if apiError != nil {
		return nil, apiError
	}
	value := *integration.Installation
	container, apiError := adapter.pinnedContainer(ctx, value, false, true)
	if apiError != nil {
		return nil, apiError
	}
	raw, code, apiError := adapter.docker.Read(ctx, container.ID, "configuration", value.Interface)
	if apiError != nil {
		return nil, apiError
	}
	if code != 0 {
		return nil, failure(502, "awg_read_failed", "Не удалось прочитать штатный конфиг AWG.")
	}
	return encodeData(map[string]any{"filename": value.ConfigPath, "revision": digestText(string(raw)), "content": redactAWG(string(raw)), "read_only": true}), nil
}

// peers читает native dump и clientsTable без собственного хранилища пользователей.
func (adapter *Adapter) peers(ctx context.Context, requestID string) (json.RawMessage, *APIError) {
	integration, apiError := adapter.attached(ctx, requestID)
	if apiError != nil {
		return nil, apiError
	}
	value := *integration.Installation
	container, apiError := adapter.pinnedContainer(ctx, value, false, true)
	if apiError != nil {
		return nil, apiError
	}
	raw, code, apiError := adapter.docker.Read(ctx, container.ID, "peers", value.Interface)
	if apiError != nil {
		return nil, apiError
	}
	if code != 0 {
		return nil, failure(502, "awg_read_failed", "Не удалось прочитать состояние peers.")
	}
	names := make(map[string]string)
	table, tableCode, tableError := adapter.docker.Read(ctx, container.ID, "clients", "")
	if tableError != nil {
		return nil, tableError
	}
	if tableCode == 0 {
		var clients []NativeClient
		if dockerDecode(table, &clients) == nil {
			for _, client := range clients {
				runes := []rune(safeText(client.UserData.ClientName))
				if len(runes) > 200 {
					runes = runes[:200]
				}
				names[client.ClientID] = string(runes)
			}
		}
	}
	result := make([]AdapterPeer, 0)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for _, line := range lines[1:] {
		parts := strings.Split(line, "\t")
		if len(parts) < 8 {
			return nil, failure(502, "awg_protocol", "Неподдерживаемый формат AWG peers.")
		}
		key, keyError := base64.StdEncoding.DecodeString(parts[0])
		handshake, handshakeError := strconv.ParseInt(parts[4], 10, 64)
		rx, rxError := strconv.ParseUint(parts[5], 10, 64)
		tx, txError := strconv.ParseUint(parts[6], 10, 64)
		if keyError != nil || len(key) != 32 || handshakeError != nil || handshake < 0 || rxError != nil || txError != nil {
			return nil, failure(502, "awg_protocol", "Некорректное состояние AWG peer.")
		}
		allowed := make([]string, 0)
		if parts[3] != "(none)" {
			for _, address := range strings.Split(parts[3], ",") {
				if _, err := netip.ParsePrefix(address); err != nil {
					return nil, failure(502, "awg_protocol", "Некорректные адреса peer.")
				}
				allowed = append(allowed, address)
			}
		}
		endpoint := parts[2]
		if endpoint == "(none)" {
			endpoint = ""
		} else if _, err := netip.ParseAddrPort(endpoint); err != nil {
			return nil, failure(502, "awg_protocol", "Некорректный endpoint peer.")
		}
		result = append(result, AdapterPeer{PublicKey: parts[0], Name: names[parts[0]], AllowedIPs: allowed, Endpoint: endpoint, LatestHandshake: handshake, RXBytes: rx, TXBytes: tx})
	}
	return encodeData(result), nil
}

// logs возвращает только выбранный очищенный хвост штатного журнала.
func (adapter *Adapter) logs(ctx context.Context, request Request) (json.RawMessage, *APIError) {
	var value LogRequest
	if decodeStrict(request.Payload, &value) != nil {
		return nil, failure(422, "invalid_payload", "Некорректный источник журнала.")
	}
	if value.Source != "awg" && value.Source != "dns" {
		if value.Source == "bridge" {
			value.Source = "supervisor"
			request.Payload = encodeData(value)
		}
		return adapter.forward(ctx, request)
	}
	integration, apiError := adapter.attached(ctx, request.RequestID)
	if apiError != nil {
		return nil, apiError
	}
	container, apiError := adapter.pinnedContainer(ctx, *integration.Installation, value.Source == "dns", false)
	if apiError != nil {
		return nil, apiError
	}
	if container.HostConfig.LogConfig.Type == "none" {
		return encodeData(map[string]any{
			"source": value.Source, "observed_at": nowText(), "available": false,
			"reason": "Контейнер запущен без записи журнала (log-driver none).",
			"lines":  []string{}, "truncated": false,
		}), nil
	}
	raw, apiError := adapter.docker.Logs(ctx, container, value.Limit)
	if apiError != nil {
		return nil, apiError
	}
	text := strings.TrimRight(redactAWG(string(raw)), "\n")
	lines := make([]string, 0)
	if text != "" {
		lines = strings.Split(text, "\n")
	}
	truncated := len(lines) >= value.Limit
	if len(lines) > value.Limit {
		lines = lines[len(lines)-value.Limit:]
	}
	return encodeData(map[string]any{"source": value.Source, "observed_at": nowText(), "available": true, "lines": lines, "truncated": truncated}), nil
}
