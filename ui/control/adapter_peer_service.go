//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"time"
)

// peerDefaults читает root-предложения без права менять WARP или маршруты.
func (adapter *Adapter) peerDefaults(ctx context.Context, requestID string) (PeerDefaults, *APIError) {
	raw, apiError := adapter.forward(ctx, Request{RequestID: requestID, Action: "peers.defaults", Payload: json.RawMessage(`{}`)})
	var result PeerDefaults
	if apiError != nil {
		return result, apiError
	}
	if decodeStrict(raw, &result) != nil || result.ListenPort < 1 || result.ListenPort > 65535 || !validPeerDNS(result.DNS) || len(result.ReservedIPs) == 0 || len(result.ReservedIPs) > 64 || result.EndpointHost != "" && !validPeerEndpoint(result.EndpointHost) {
		return result, failure(502, "host_protocol_error", "Root вернул неподдержанные параметры профиля.")
	}
	return result, nil
}

// peerCatalog показывает причину запрета записи, сохраняя обычное чтение клиентов.
func (adapter *Adapter) peerCatalog(ctx context.Context, requestID string) (json.RawMessage, *APIError) {
	snapshot, apiError := adapter.peerSnapshot(ctx, requestID, false)
	if apiError != nil {
		if apiError.Code == "not_attached" {
			return nil, apiError
		}
		var peers []AdapterPeer
		raw, readError := adapter.peers(ctx, requestID)
		if readError != nil {
			return nil, readError
		}
		if decodeStrict(raw, &peers) != nil {
			return nil, failure(502, "awg_protocol", "Не удалось прочитать список клиентов.")
		}
		return encodeData(PeerCatalog{CanManage: false, Reason: apiError.Message, Peers: peers}), nil
	}
	defaults, defaultsError := adapter.peerDefaults(ctx, requestID)
	result := PeerCatalog{Revision: snapshot.Revision, CanManage: true, Peers: snapshot.Runtime, Defaults: defaults}
	if defaultsError != nil {
		result.CanManage = false
		result.Reason = defaultsError.Message
	}
	if defaultsError == nil && defaults.ListenPort != snapshot.Config.ListenPort {
		result.CanManage = false
		result.Reason = "Порт native конфигурации отличается от опубликованного порта."
	}
	return encodeData(result), nil
}

// adapterPeerTable меняет только целевую metadata, сохраняя дополнительные поля объектов.
func adapterPeerTable(clients []map[string]json.RawMessage, action, key, name string) ([]byte, *APIError) {
	result := make([]map[string]json.RawMessage, 0, len(clients)+1)
	found := false
	for _, item := range clients {
		var id string
		if json.Unmarshal(item["clientId"], &id) != nil {
			return nil, adapterNativeError()
		}
		if id == key {
			found = true
			if action == "peer.revoke" {
				continue
			}
			if action == "peer.create" {
				return nil, failure(409, "peer_conflict", "Клиент с этим public key уже существует.")
			}
			var user map[string]json.RawMessage
			if decodeStrict(item["userData"], &user) != nil || user == nil {
				return nil, adapterNativeError()
			}
			user["clientName"] = encodeData(name)
			copyItem := make(map[string]json.RawMessage, len(item))
			for field, value := range item {
				copyItem[field] = value
			}
			copyItem["userData"] = encodeData(user)
			item = copyItem
		}
		result = append(result, item)
	}
	if !found && action != "peer.revoke" {
		user := map[string]json.RawMessage{"clientName": encodeData(name)}
		if action == "peer.create" {
			user["creationDate"] = encodeData(time.Now().UTC().Format("Mon Jan 2 15:04:05 2006"))
		}
		result = append(result, map[string]json.RawMessage{"clientId": encodeData(key), "userData": encodeData(user)})
	}
	raw, err := json.MarshalIndent(result, "", "    ")
	if err != nil || len(raw)+1 > adapterPeerFileLimit {
		return nil, failure(409, "peer_capacity", "Native таблица достигла поддержанного размера.")
	}
	return append(raw, '\n'), nil
}

// peerIdentity запрещает дальнейшую запись при пересоздании или перезапуске установки.
func (adapter *Adapter) peerIdentity(ctx context.Context, requestID string, snapshot AdapterPeerSnapshot) *APIError {
	integration, apiError := adapter.attached(ctx, requestID)
	if apiError != nil {
		return apiError
	}
	if integration.Installation.ContainerID != snapshot.Installation.ContainerID || integration.Installation.Interface != snapshot.Installation.Interface {
		return failure(409, "configuration_changed", "Привязка изменилась во время операции.")
	}
	current, apiError := adapter.pinnedContainer(ctx, snapshot.Installation, false, true)
	if apiError != nil {
		return apiError
	}
	if current.State.PID != snapshot.Container.State.PID || current.State.StartedAt != snapshot.Container.State.StartedAt {
		return failure(409, "configuration_changed", "AWG был перезапущен во время операции.")
	}
	return nil
}

// peerTransaction выполняет CAS, проверку результата и только подтверждённый откат.
func (adapter *Adapter) peerTransaction(ctx context.Context, operationID string, snapshot AdapterPeerSnapshot, files AdapterPeerFiles) (string, *APIError) {
	beforeConfig, beforeTable := digestText(string(snapshot.Config.Raw)), "absent"
	if snapshot.TableExists {
		beforeTable = digestText(string(snapshot.Table))
	}
	afterConfig, afterTable := digestText(string(files.Config)), digestText(string(files.Table))
	beforeStrip, afterStrip := "", ""
	nextConfig, parseError := adapterParseConfig(files.Config)
	if parseError != nil {
		return "", parseError
	}
	command := func(commandContext context.Context, mode string) (int, *APIError) {
		_, code, apiError := adapter.docker.peerCommand(commandContext, snapshot.Container.ID, mode, snapshot.Installation.Interface, operationID, beforeConfig, beforeTable, afterConfig, afterTable, true, beforeStrip, afterStrip)
		return code, apiError
	}
	uncertain := func() (string, *APIError) {
		return "", failure(502, "mutation_failed", "Native изменение не подтверждено. Сохранён закрытый intent/backup; проверьте установку по SSH.")
	}
	abort := func() bool {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
		defer cancel()
		code, apiError := command(cleanup, "abort")
		return apiError == nil && code == 0
	}
	if apiError := adapter.peerIdentity(ctx, operationID, snapshot); apiError != nil {
		return "", apiError
	}
	code, apiError := command(ctx, "prepare")
	if apiError != nil {
		return uncertain()
	}
	if code != 0 {
		if code == 73 {
			return "", failure(409, "native_recovery_required", "Существует незавершённая native транзакция.")
		}
		if code == 53 && abort() {
			return "", failure(409, "revision_conflict", "Native файлы изменились перед записью.")
		}
		return uncertain()
	}
	if apiError = adapter.docker.peerArchive(ctx, snapshot.Container.ID, files); apiError != nil {
		return uncertain()
	}
	if beforeConfig != afterConfig {
		for _, mode := range []string{"strip_old", "strip_next"} {
			raw, code, stripError := adapter.docker.peerCommand(ctx, snapshot.Container.ID, mode, snapshot.Installation.Interface, operationID, beforeConfig, beforeTable, afterConfig, afterTable, true)
			if stripError != nil {
				clear(raw)
				return uncertain()
			}
			expected := snapshot.Config
			if mode == "strip_next" {
				expected = nextConfig
			}
			valid := code == 0 && adapterSettingsMatch(raw, expected)
			if valid {
				if mode == "strip_old" {
					beforeStrip = digestText(string(raw))
				} else {
					afterStrip = digestText(string(raw))
				}
			}
			clear(raw)
			if !valid {
				if abort() {
					return "", failure(409, "capability_unavailable", "Результат awg-quick strip не совпадает с полной ожидаемой конфигурацией.")
				}
				return uncertain()
			}
		}
	}
	current, apiError := adapter.peerSnapshot(ctx, operationID, true)
	if apiError != nil || current.Revision != snapshot.Revision || adapter.peerIdentity(ctx, operationID, snapshot) != nil {
		if abort() {
			return "", failure(409, "revision_conflict", "Native состояние изменилось во время подготовки; запись отменена.")
		}
		return uncertain()
	}
	code, apiError = command(ctx, "apply")
	if apiError != nil {
		return uncertain()
	}
	if code != 0 && abort() {
		if code == 53 {
			return "", failure(409, "revision_conflict", "Native файлы изменились перед применением.")
		}
		return "", failure(409, "capability_unavailable", "Native конфигурация не прошла предварительную подготовку syncconf.")
	}
	expectedRevision := adapterPeerRevision(snapshot.Installation, files.Config, files.Table, true)
	if code == 0 {
		current, apiError = adapter.peerSnapshot(ctx, operationID, true)
		if apiError == nil && current.Revision == expectedRevision && adapter.peerIdentity(ctx, operationID, snapshot) == nil {
			code, apiError = command(ctx, "finish")
			if apiError == nil && code == 0 {
				return expectedRevision, nil
			}
			return uncertain()
		}
	}
	rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
	defer cancel()
	if adapter.peerIdentity(rollback, operationID, snapshot) != nil {
		return uncertain()
	}
	if adapter.peerRuntimeSettings(rollback, snapshot.Container.ID, snapshot.Installation.Interface, snapshot.Config, nextConfig) != nil {
		return uncertain()
	}
	code, apiError = command(rollback, "rollback")
	if apiError != nil || code != 0 {
		return uncertain()
	}
	current, apiError = adapter.peerSnapshot(rollback, operationID, true)
	if apiError != nil || current.Revision != snapshot.Revision || adapter.peerIdentity(rollback, operationID, snapshot) != nil {
		return uncertain()
	}
	code, apiError = command(rollback, "rollback_finish")
	if apiError != nil || code != 0 {
		return uncertain()
	}
	return "", failure(409, "operation_rolled_back", "Изменение не прошло проверку; native файлы и runtime восстановлены.")
}

// peerMutation применяет одну штатную операцию и выдаёт только публичный результат.
func (adapter *Adapter) peerMutation(ctx context.Context, request Request) (json.RawMessage, *APIError) {
	if !operationIDPattern.MatchString(request.RequestID) {
		return nil, failure(422, "invalid_request_id", "Для native записи нужен ID операции Control.")
	}
	if apiError := validatePeerPayload(request.Action, request.Payload); apiError != nil {
		return nil, apiError
	}
	var create PeerCreateRequest
	var rename PeerRenameRequest
	var revoke PeerRevokeRequest
	key, name, revision := "", "", ""
	switch request.Action {
	case "peer.create":
		_ = decodeStrict(request.Payload, &create)
		name, revision = create.Name, create.ExpectedRevision
	case "peer.rename":
		_ = decodeStrict(request.Payload, &rename)
		key, name, revision = rename.PublicKey, rename.Name, rename.ExpectedRevision
	case "peer.revoke":
		_ = decodeStrict(request.Payload, &revoke)
		key, revision = revoke.PublicKey, revoke.ExpectedRevision
	default:
		return nil, failure(422, "invalid_payload", "Native операция не поддержана.")
	}
	snapshot, apiError := adapter.peerSnapshot(ctx, request.RequestID, false)
	if apiError != nil {
		return nil, apiError
	}
	if snapshot.Revision != revision {
		return nil, failure(409, "revision_conflict", "Список изменился; перечитайте клиентов перед записью.")
	}
	files := AdapterPeerFiles{Config: bytes.Clone(snapshot.Config.Raw)}
	result := PeerMutationResult{Complete: true, PublicKey: key, Name: name}
	var profile []byte
	defer func() { clear(profile); clear(files.Config); clear(files.Table) }()
	if request.Action == "peer.create" {
		defaults, apiError := adapter.peerDefaults(ctx, request.RequestID)
		if apiError != nil {
			return nil, apiError
		}
		if defaults.ListenPort != snapshot.Config.ListenPort {
			return nil, failure(409, "configuration_changed", "Native и опубликованный UDP порты отличаются.")
		}
		address, apiError := adapterAllocatePeer(snapshot, defaults)
		if apiError != nil {
			return nil, apiError
		}
		raw, code, apiError := adapter.docker.Read(ctx, snapshot.Container.ID, "native_psk", snapshot.Installation.Interface)
		if apiError != nil {
			return nil, apiError
		}
		psk := strings.TrimSpace(string(raw))
		clear(raw)
		if code != 0 || !validPeerKey(psk) {
			return nil, adapterNativeError()
		}
		profile, key, apiError = adapterBuildProfile(snapshot.Config, create, address, psk)
		if apiError != nil {
			return nil, apiError
		}
		if _, exists := snapshot.Config.Peers[key]; exists {
			return nil, failure(409, "peer_conflict", "Сгенерированный public key уже занят.")
		}
		if apiError := adapter.profiles.reserve(request.RequestID); apiError != nil {
			return nil, apiError
		}
		published := false
		defer func() {
			if !published {
				adapter.profiles.discard(request.RequestID)
			}
		}()
		result.PublicKey, result.Address = key, address.String()+"/32"
		files.Config = append(files.Config, []byte("\n\n[Peer]\nPublicKey = "+key+"\nPresharedKey = "+psk+"\nAllowedIPs = "+result.Address+"\n")...)
		files.Table, apiError = adapterPeerTable(snapshot.Clients, request.Action, key, name)
		if apiError != nil {
			return nil, apiError
		}
		if len(files.Config) > adapterPeerFileLimit {
			return nil, failure(409, "peer_capacity", "Native конфигурация достигла поддержанного размера.")
		}
		result.Revision, apiError = adapter.peerTransaction(ctx, request.RequestID, snapshot, files)
		if apiError != nil {
			return nil, apiError
		}
		createdConfig, parseError := adapterParseConfig(files.Config)
		if parseError != nil {
			return nil, failure(502, "mutation_failed", "Клиент создан, но его профиль не подтверждён.")
		}
		expires, ok := adapter.profiles.publish(request.RequestID, key, snapshot.Container.ID, snapshot.Installation.Interface, adapterProfileIdentity(createdConfig, key), profile)
		if !ok {
			return nil, failure(502, "mutation_failed", "Клиент создан, но профиль недоступен; отзовите его и создайте заново.")
		}
		published = true
		result.ProfileAvailable, result.ProfileExpiresAt = true, expires.UTC().Format(time.RFC3339Nano)
		return encodeData(result), nil
	}
	peer, exists := snapshot.Config.Peers[key]
	if !exists {
		return nil, failure(404, "peer_not_found", "Клиент уже отсутствует; перечитайте список.")
	}
	if request.Action == "peer.revoke" {
		runes := []rune(safeText(adapterClientName(snapshot.Clients, key)))
		if len(runes) > 80 {
			runes = runes[:80]
		}
		result.Name = string(runes)
		section := snapshot.Config.Sections[peer.Section]
		lines := append(append([]string(nil), snapshot.Config.Lines[:section.Start]...), snapshot.Config.Lines[section.End:]...)
		files.Config = []byte(strings.Join(lines, ""))
	}
	files.Table, apiError = adapterPeerTable(snapshot.Clients, request.Action, key, name)
	if apiError != nil {
		return nil, apiError
	}
	result.Revision, apiError = adapter.peerTransaction(ctx, request.RequestID, snapshot, files)
	if apiError != nil {
		return nil, apiError
	}
	if request.Action == "peer.revoke" {
		adapter.profiles.revoke(key)
	}
	return encodeData(result), nil
}

// peerConsume обслуживает только отдельную одноразовую выдачу, минуя operation result.
func (adapter *Adapter) peerConsume(ctx context.Context, request Request) (json.RawMessage, *APIError) {
	var lookup OperationLookup
	if decodeStrict(request.Payload, &lookup) != nil || !operationIDPattern.MatchString(lookup.ID) {
		return nil, failure(422, "invalid_payload", "Некорректный ID профиля.")
	}
	entry, available := adapter.profiles.peek(lookup.ID)
	if !available {
		return nil, failure(410, "profile_unavailable", "Разовый профиль уже выдан или истёк.")
	}
	snapshot, apiError := adapter.peerSnapshot(ctx, request.RequestID, false)
	if apiError != nil {
		return nil, apiError
	}
	if snapshot.Container.ID != entry.ContainerID || snapshot.Installation.Interface != entry.Interface || adapterProfileIdentity(snapshot.Config, entry.PublicKey) != entry.Identity {
		adapter.profiles.discard(lookup.ID)
		return nil, failure(410, "profile_unavailable", "Установка или клиент изменились; прежний профиль недоступен.")
	}
	profile, apiError := adapter.profiles.consume(lookup.ID)
	if apiError != nil {
		return nil, apiError
	}
	return encodeData(profile), nil
}
