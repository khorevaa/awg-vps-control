//go:build linux

package main

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// adapterSetting нормализует только документированные эквивалентные значения AWG.
func adapterSetting(key, value string) (string, bool) {
	value = strings.TrimSpace(value)
	if key == "endpoint" {
		return "", true
	}
	if key == "allowedips" {
		prefixes, valid := adapterAllowed(value)
		if !valid {
			return "", false
		}
		items := make([]string, 0, len(prefixes))
		for _, prefix := range prefixes {
			items = append(items, prefix.String())
		}
		return strings.Join(items, ","), true
	}
	if key == "randomtrailers" || key == "disablecookies" {
		switch strings.ToLower(value) {
		case "on", "true", "1":
			return "true", true
		case "off", "false", "0":
			return "", true
		default:
			return "", false
		}
	}
	if key == "fwmark" {
		if value == "off" {
			return "", true
		}
		number, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return "", false
		}
		if number == 0 {
			return "", true
		}
		return strconv.FormatUint(number, 10), true
	}
	if key == "presharedkey" && (value == "(none)" || value == strings.Repeat("A", 43)+"=") {
		return "", true
	}
	numeric := []string{"listenport", "persistentkeepalive", "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts"}
	if slices.Contains(numeric, key) {
		if key == "persistentkeepalive" && value == "off" {
			return "", true
		}
		parts := strings.Split(value, "-")
		if len(parts) > 2 || len(parts) == 0 {
			return "", false
		}
		for index, part := range parts {
			number, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
			if err != nil {
				return "", false
			}
			parts[index] = strconv.FormatUint(number, 10)
		}
		result := strings.Join(parts, "-")
		if result == "0" || result == "0-0" {
			return "", true
		}
		return result, true
	}
	return value, true
}

// adapterExpectedSettings исключает wg-quick поля, которые syncconf не применяет.
func adapterExpectedSettings(config AdapterNativeConfig) (map[string]map[string]string, bool) {
	result := map[string]map[string]string{"interface": {}}
	quick := []string{"Address", "DNS", "MTU", "Table", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig"}
	for index, section := range config.Sections {
		identity := "interface"
		if index > 0 {
			identity = section.Values["PublicKey"]
			result[identity] = make(map[string]string)
		}
		for key, raw := range section.Values {
			if index == 0 && slices.Contains(quick, key) {
				continue
			}
			key = strings.ToLower(key)
			value, valid := adapterSetting(key, raw)
			if !valid {
				return nil, false
			}
			if value != "" {
				result[identity][key] = value
			}
		}
	}
	return result, true
}

// adapterReadSettings проверяет полный showconf/strip, не принимая пустой или частичный файл.
func adapterReadSettings(raw []byte) (map[string]map[string]string, bool) {
	if len(raw) == 0 || len(raw) > adapterPeerFileLimit {
		return nil, false
	}
	var sections []map[string]string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if line == "[Interface]" || line == "[Peer]" {
			if len(sections) == 0 && line != "[Interface]" || len(sections) > 0 && line != "[Peer]" {
				return nil, false
			}
			sections = append(sections, make(map[string]string))
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if !found || len(sections) == 0 || key == "" || value == "" {
			return nil, false
		}
		section := sections[len(sections)-1]
		if _, exists := section[key]; exists {
			return nil, false
		}
		section[key] = value
	}
	if len(sections) == 0 || !validPeerKey(sections[0]["privatekey"]) {
		return nil, false
	}
	result := make(map[string]map[string]string, len(sections))
	for index, section := range sections {
		identity := "interface"
		if index > 0 {
			identity = section["publickey"]
			if !validPeerKey(identity) {
				return nil, false
			}
		}
		if _, exists := result[identity]; exists {
			return nil, false
		}
		result[identity] = make(map[string]string)
		for key, raw := range section {
			value, valid := adapterSetting(key, raw)
			if !valid {
				return nil, false
			}
			if value != "" {
				result[identity][key] = value
			}
		}
	}
	return result, true
}

// adapterSettingsMatch сравнивает весь набор persistent настроек, кроме динамического Endpoint.
func adapterSettingsMatch(raw []byte, config AdapterNativeConfig) bool {
	expected, expectedOK := adapterExpectedSettings(config)
	actual, actualOK := adapterReadSettings(raw)
	if !expectedOK || !actualOK || len(actual) != len(expected) {
		return false
	}
	for key, fields := range expected {
		if !maps.Equal(fields, actual[key]) {
			return false
		}
	}
	return true
}

// peerRuntimeSettings не допускает перезаписи обнаруженных runtime-only параметров.
func (adapter *Adapter) peerRuntimeSettings(ctx context.Context, id, iface string, configs ...AdapterNativeConfig) *APIError {
	raw, code, apiError := adapter.docker.Read(ctx, id, "runtime_configuration", iface)
	defer clear(raw)
	if apiError != nil {
		return apiError
	}
	if code != 0 {
		return adapterNativeError()
	}
	for _, config := range configs {
		if adapterSettingsMatch(raw, config) {
			return nil
		}
	}
	return failure(409, "configuration_changed", "Runtime параметры AWG отличаются от native; автоматическая перезапись запрещена.")
}

// adapterProfileIdentity привязывает профиль к серверным параметрам и конкретному persistent peer.
func adapterProfileIdentity(config AdapterNativeConfig, publicKey string) string {
	peer, exists := config.Peers[publicKey]
	if !exists {
		return ""
	}
	raw, err := json.Marshal([]any{config.Interface, config.ProfileParameters, peer.PublicKey, peer.PSK, peer.Allowed})
	if err != nil {
		return ""
	}
	defer clear(raw)
	return digestText(string(raw))
}
