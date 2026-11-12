//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

const adapterPeerFileLimit = 256 * 1024

// AdapterNativeSection сохраняет исходные границы и однозначные присваивания native секции.
type AdapterNativeSection struct {
	Name   string            // Имя поддержанной секции.
	Start  int               // Индекс строки заголовка.
	End    int               // Индекс следующего заголовка либо конца файла.
	Values map[string]string // Проверенные неповторяющиеся поля.
}

// AdapterNativeConfig содержит приватный разбор native файла без потери исходных строк.
type AdapterNativeConfig struct {
	Raw               []byte                       // Исходные байты только в памяти.
	Lines             []string                     // Строки вместе с исходными переводами.
	Sections          []AdapterNativeSection       // Границы native секций.
	Interface         map[string]string            // Параметры серверного интерфейса.
	Peers             map[string]AdapterNativePeer // Peers по публичному ключу.
	Address           netip.Prefix                 // Единственный серверный IPv4 с подсетью.
	ListenPort        int                          // Серверный UDP порт.
	ProfileParameters []string                     // Штатные параметры AWG без server private key.
}

// AdapterNativePeer представляет persistent настройки одного клиента.
type AdapterNativePeer struct {
	PublicKey string         // Публичный ключ клиента.
	PSK       string         // PSK только для сравнения в памяти.
	Allowed   []netip.Prefix // Native AllowedIPs.
	Section   int            // Индекс секции для точечного удаления.
}

// AdapterPeerSnapshot объединяет проверенные native файлы и runtime без отдельной базы клиентов.
type AdapterPeerSnapshot struct {
	Installation AdapterInstallation          // Закреплённая root-привязка.
	Container    DockerContainer              // ID и PID проверенного контейнера.
	Config       AdapterNativeConfig          // Приватный native конфиг.
	Table        []byte                       // Исходные bytes clientsTable.
	TableExists  bool                         // Отсутствие файла отличается от пустого массива.
	Clients      []map[string]json.RawMessage // Metadata с сохранением неизвестных полей.
	Runtime      []AdapterPeer                // Публичные runtime данные.
	Revision     string                       // Общий CAS token файлов и установки.
	PSK          string                       // Штатный общий PSK только в памяти.
}

// AdapterPeerFiles передаёт только подготовленные native файлы без client private key.
type AdapterPeerFiles struct {
	Config []byte // Новая версия серверного конфига.
	Table  []byte // Новая версия native metadata.
}

var adapterProfileKeys = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5", "HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout", "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies"}

// adapterNativeError скрывает содержимое конфигурации при неподдержанной схеме.
func adapterNativeError() *APIError {
	return failure(409, "unsupported_topology", "Native конфигурация или metadata не поддерживают безопасное изменение клиентов.")
}

// adapterParseConfig разбирает заголовки, сохраняя исходные байты нетронутых секций.
func adapterParseConfig(raw []byte) (AdapterNativeConfig, *APIError) {
	result := AdapterNativeConfig{Raw: bytes.Clone(raw), Lines: strings.SplitAfter(string(raw), "\n"), Peers: make(map[string]AdapterNativePeer)}
	if len(raw) == 0 || len(raw) > adapterPeerFileLimit || bytes.IndexByte(raw, 0) >= 0 || !utf8.Valid(raw) {
		return result, adapterNativeError()
	}
	commented := make(map[string]string)
	for index, original := range result.Lines {
		line := strings.TrimSpace(original)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			if len(result.Sections) > 0 && result.Sections[len(result.Sections)-1].Name == "Interface" && strings.HasPrefix(line, "#") {
				key, value, found := strings.Cut(strings.TrimSpace(strings.TrimPrefix(line, "#")), "=")
				key, value = strings.TrimSpace(key), strings.TrimSpace(value)
				if found && slices.Contains([]string{"I1", "I2", "I3", "I4", "I5"}, key) && value != "" {
					if _, exists := commented[key]; exists {
						return result, adapterNativeError()
					}
					commented[key] = value
				}
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			if line != "[Interface]" && line != "[Peer]" {
				return result, adapterNativeError()
			}
			if len(result.Sections) > 0 {
				result.Sections[len(result.Sections)-1].End = index
			}
			result.Sections = append(result.Sections, AdapterNativeSection{Name: line[1 : len(line)-1], Start: index, End: len(result.Lines), Values: make(map[string]string)})
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key, value = strings.TrimSpace(key), strings.TrimSpace(value)
		if !found || len(result.Sections) == 0 || key == "" || value == "" || len(value) > 8192 {
			return result, adapterNativeError()
		}
		section := &result.Sections[len(result.Sections)-1]
		if _, exists := section.Values[key]; exists {
			return result, adapterNativeError()
		}
		section.Values[key] = value
	}
	if len(result.Sections) == 0 || result.Sections[0].Name != "Interface" {
		return result, adapterNativeError()
	}
	result.Interface = result.Sections[0].Values
	for key := range result.Interface {
		if !slices.Contains(adapterProfileKeys, key) && !slices.Contains([]string{"PrivateKey", "Address", "ListenPort", "DNS", "MTU", "Table", "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig", "FwMark"}, key) {
			return result, adapterNativeError()
		}
	}
	if !validPeerKey(result.Interface["PrivateKey"]) || strings.EqualFold(result.Interface["SaveConfig"], "true") {
		return result, adapterNativeError()
	}
	address, err := netip.ParsePrefix(result.Interface["Address"])
	if err != nil || !address.Addr().Is4() || address.Bits() < 16 || address.Bits() > 30 {
		return result, adapterNativeError()
	}
	result.Address = address
	port, err := strconv.Atoi(result.Interface["ListenPort"])
	if err != nil || port < 1 || port > 65535 {
		return result, adapterNativeError()
	}
	result.ListenPort = port
	for _, key := range adapterProfileKeys {
		value := result.Interface[key]
		if other := commented[key]; other != "" {
			if value != "" && value != other {
				return result, adapterNativeError()
			}
			value = other
		}
		if value != "" {
			result.ProfileParameters = append(result.ProfileParameters, key+" = "+value)
		}
	}
	for index, section := range result.Sections[1:] {
		if section.Name != "Peer" {
			return result, adapterNativeError()
		}
		for key := range section.Values {
			if !slices.Contains([]string{"PublicKey", "PresharedKey", "AllowedIPs", "Endpoint", "PersistentKeepalive"}, key) {
				return result, adapterNativeError()
			}
		}
		key, psk := section.Values["PublicKey"], section.Values["PresharedKey"]
		if !validPeerKey(key) || psk != "" && !validPeerKey(psk) {
			return result, adapterNativeError()
		}
		if _, exists := result.Peers[key]; exists {
			return result, adapterNativeError()
		}
		allowed, ok := adapterAllowed(section.Values["AllowedIPs"])
		if !ok || len(allowed) == 0 {
			return result, adapterNativeError()
		}
		result.Peers[key] = AdapterNativePeer{PublicKey: key, PSK: psk, Allowed: allowed, Section: index + 1}
	}
	if len(result.Peers) > 2048 {
		return result, adapterNativeError()
	}
	return result, nil
}

// adapterAllowed нормализует ограниченный список native AllowedIPs без неоднозначных дублей.
func adapterAllowed(value string) ([]netip.Prefix, bool) {
	if value == "" || value == "(none)" {
		return nil, true
	}
	var result []netip.Prefix
	for _, item := range strings.Split(value, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil || prefix != prefix.Masked() || len(result) >= 256 || slices.Contains(result, prefix) {
			return nil, false
		}
		result = append(result, prefix)
	}
	slices.SortFunc(result, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return result, true
}

// adapterNativeClients сохраняет все неизвестные JSON-поля родной таблицы.
func adapterNativeClients(raw []byte, exists bool) ([]map[string]json.RawMessage, *APIError) {
	clients := make([]map[string]json.RawMessage, 0)
	if !exists {
		return clients, nil
	}
	if len(raw) > adapterPeerFileLimit || decodeStrict(raw, &clients) != nil || clients == nil || len(clients) > 2048 {
		return nil, adapterNativeError()
	}
	seen := make(map[string]bool)
	for _, item := range clients {
		var key string
		var user map[string]json.RawMessage
		var name string
		if json.Unmarshal(item["clientId"], &key) != nil || !validPeerKey(key) || seen[key] || decodeStrict(item["userData"], &user) != nil || user == nil || json.Unmarshal(user["clientName"], &name) != nil {
			return nil, adapterNativeError()
		}
		seen[key] = true
	}
	return clients, nil
}

// adapterClientName читает только отображаемое имя, оставляя остальные metadata неизменными.
func adapterClientName(clients []map[string]json.RawMessage, key string) string {
	for _, item := range clients {
		var id string
		if json.Unmarshal(item["clientId"], &id) == nil && id == key {
			var user map[string]json.RawMessage
			var name string
			if json.Unmarshal(item["userData"], &user) == nil && json.Unmarshal(user["clientName"], &name) == nil {
				return name
			}
		}
	}
	return ""
}

// adapterPeerRevision связывает точные native bytes с закреплённой установкой.
func adapterPeerRevision(value AdapterInstallation, config, table []byte, tableExists bool) string {
	return digestText(value.ContainerID + "\n" + value.Interface + "\n" + digestText(string(config)) + "\n" + strconv.FormatBool(tableExists) + "\n" + digestText(string(table)))
}

// adapterRuntimePeers сверяет persistent peers, PSK и серверную идентичность с runtime.
func adapterRuntimePeers(raw []byte, config AdapterNativeConfig, clients []map[string]json.RawMessage) ([]AdapterPeer, *APIError) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	header := strings.Split(lines[0], "\t")
	private, _ := base64.StdEncoding.DecodeString(config.Interface["PrivateKey"])
	defer clear(private)
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil || len(header) < 4 || header[0] != config.Interface["PrivateKey"] || header[1] != base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()) || header[2] != strconv.Itoa(config.ListenPort) {
		return nil, failure(409, "configuration_changed", "Runtime AWG не соответствует native конфигурации.")
	}
	result := make([]AdapterPeer, 0, len(lines)-1)
	seen := make(map[string]bool)
	for _, line := range lines[1:] {
		parts := strings.Split(line, "\t")
		if len(parts) < 8 {
			return nil, adapterNativeError()
		}
		peer, exists := config.Peers[parts[0]]
		psk := parts[1]
		if psk == "(none)" {
			psk = ""
		}
		allowed, valid := adapterAllowed(parts[3])
		if !exists || seen[parts[0]] || psk != peer.PSK || !valid || !slices.Equal(allowed, peer.Allowed) {
			return nil, failure(409, "configuration_changed", "Runtime peers отличаются от постоянной конфигурации; перечитайте Amnezia.")
		}
		seen[parts[0]] = true
		handshake, hErr := strconv.ParseInt(parts[4], 10, 64)
		rx, rErr := strconv.ParseUint(parts[5], 10, 64)
		tx, tErr := strconv.ParseUint(parts[6], 10, 64)
		endpoint := parts[2]
		if endpoint == "(none)" {
			endpoint = ""
		}
		if hErr != nil || rErr != nil || tErr != nil || handshake < 0 {
			return nil, adapterNativeError()
		}
		if endpoint != "" {
			if _, err := netip.ParseAddrPort(endpoint); err != nil {
				return nil, adapterNativeError()
			}
		}
		addresses := make([]string, 0, len(allowed))
		for _, prefix := range allowed {
			addresses = append(addresses, prefix.String())
		}
		result = append(result, AdapterPeer{PublicKey: peer.PublicKey, Name: adapterClientName(clients, peer.PublicKey), AllowedIPs: addresses, Endpoint: endpoint, LatestHandshake: handshake, RXBytes: rx, TXBytes: tx})
	}
	if len(seen) != len(config.Peers) {
		return nil, failure(409, "configuration_changed", "Часть native peers отсутствует в runtime AWG.")
	}
	return result, nil
}

// peerSnapshot читает защищённые native файлы и проверяет согласованность runtime.
func (adapter *Adapter) peerSnapshot(ctx context.Context, requestID string, allowActive bool) (AdapterPeerSnapshot, *APIError) {
	var result AdapterPeerSnapshot
	integration, apiError := adapter.attached(ctx, requestID)
	if apiError != nil {
		return result, apiError
	}
	result.Installation = *integration.Installation
	result.Container, apiError = adapter.pinnedContainer(ctx, result.Installation, false, true)
	if apiError != nil {
		return result, apiError
	}
	if result.Container.State.PID <= 0 {
		return result, adapterNativeError()
	}
	_, code, apiError := adapter.docker.peerCommand(ctx, result.Container.ID, "check", result.Installation.Interface, "", "", "", "", "", allowActive)
	if apiError != nil {
		return result, apiError
	}
	if code == 73 {
		return result, failure(409, "native_recovery_required", "Незавершённая native транзакция требует ручной проверки по SSH.")
	}
	if code != 0 {
		return result, adapterNativeError()
	}
	raw, code, apiError := adapter.docker.Read(ctx, result.Container.ID, "configuration", result.Installation.Interface)
	if apiError != nil || code != 0 {
		if apiError == nil {
			apiError = adapterNativeError()
		}
		return result, apiError
	}
	result.Config, apiError = adapterParseConfig(raw)
	clear(raw)
	if apiError != nil {
		return result, apiError
	}
	table, code, apiError := adapter.docker.Read(ctx, result.Container.ID, "clients", "")
	if apiError != nil {
		return result, apiError
	}
	if code == 0 {
		result.Table, result.TableExists = table, true
	} else if code != 1 {
		return result, adapterNativeError()
	}
	result.Clients, apiError = adapterNativeClients(result.Table, result.TableExists)
	if apiError != nil {
		return result, apiError
	}
	raw, code, apiError = adapter.docker.Read(ctx, result.Container.ID, "peers", result.Installation.Interface)
	if apiError != nil || code != 0 {
		if apiError == nil {
			apiError = adapterNativeError()
		}
		return result, apiError
	}
	result.Runtime, apiError = adapterRuntimePeers(raw, result.Config, result.Clients)
	clear(raw)
	if apiError != nil {
		return result, apiError
	}
	if apiError := adapter.peerRuntimeSettings(ctx, result.Container.ID, result.Installation.Interface, result.Config); apiError != nil {
		return result, apiError
	}
	result.Revision = adapterPeerRevision(result.Installation, result.Config.Raw, result.Table, result.TableExists)
	return result, nil
}
