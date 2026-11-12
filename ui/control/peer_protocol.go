//go:build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxPeerProfileBytes = 64 * 1024

// validPeerName запрещает пустые, неоднозначные и управляющие имена.
func validPeerName(value string) bool {
	if !utf8.ValidString(value) || value != strings.TrimSpace(value) || utf8.RuneCountInString(value) < 1 || utf8.RuneCountInString(value) > 80 {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

// validPeerKey принимает канонический непустой публичный ключ WireGuard.
func validPeerKey(value string) bool {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	return err == nil && len(key) == 32 && base64.StdEncoding.EncodeToString(key) == value && strings.Trim(string(key), "\x00") != ""
}

// validPeerEndpoint проверяет адрес без URL, scope, порта и shell-синтаксиса.
func validPeerEndpoint(value string) bool {
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && address.IsGlobalUnicast() && address.String() == value && !address.Is4In6()
	}
	if len(value) == 0 || len(value) > 253 || strings.HasSuffix(value, ".") {
		return false
	}
	letters := false
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' {
				letters = true
			} else if !(character >= '0' && character <= '9') && character != '-' {
				return false
			}
		}
	}
	return letters
}

// validPeerDNS принимает один или два различных IPv4 адреса текущего профиля.
func validPeerDNS(values []string) bool {
	if len(values) < 1 || len(values) > 2 {
		return false
	}
	for index, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || address.Zone() != "" || !address.IsGlobalUnicast() || address.Is4In6() || address.String() != value || index > 0 && values[0] == value {
			return false
		}
	}
	return true
}

// validatePeerPayload проверяет строгие формы мутаций без секретных входных полей.
func validatePeerPayload(action string, payload json.RawMessage) *APIError {
	valid := false
	switch action {
	case "peer.create":
		var value PeerCreateRequest
		valid = decodeStrict(payload, &value) == nil && validPeerName(value.Name) && validPeerEndpoint(value.EndpointHost) && validPeerDNS(value.DNS) && revisionPattern.MatchString(value.ExpectedRevision)
	case "peer.rename":
		var value PeerRenameRequest
		valid = decodeStrict(payload, &value) == nil && validPeerKey(value.PublicKey) && validPeerName(value.Name) && revisionPattern.MatchString(value.ExpectedRevision)
	case "peer.revoke":
		var value PeerRevokeRequest
		valid = decodeStrict(payload, &value) == nil && validPeerKey(value.PublicKey) && revisionPattern.MatchString(value.ExpectedRevision)
	}
	if !valid {
		return failure(422, "invalid_peer", "Проверьте имя клиента, адрес сервера, DNS и актуальность списка клиентов.")
	}
	return nil
}

// peerMutationAction выделяет операции с дополнительной защитой журнала от секретов.
func peerMutationAction(action string) bool {
	return action == "peer.create" || action == "peer.rename" || action == "peer.revoke"
}

// checkedPeerResult запрещает неизвестные поля и некорректный публичный результат.
func checkedPeerResult(action string, raw json.RawMessage) (json.RawMessage, bool) {
	var result PeerMutationResult
	if len(raw) > maxOperationResult || decodeStrict(raw, &result) != nil || !result.Complete || !validPeerKey(result.PublicKey) || !revisionPattern.MatchString(result.Revision) {
		return nil, false
	}
	if len(result.Name) > 320 || strings.ContainsAny(result.Name, "\r\n\x00") {
		return nil, false
	}
	if result.Address != "" {
		address, err := netip.ParsePrefix(result.Address)
		if err != nil || !address.Addr().Is4() || address.Bits() != 32 || address.String() != result.Address {
			return nil, false
		}
	}
	if action == "peer.create" {
		_, err := time.Parse(time.RFC3339Nano, result.ProfileExpiresAt)
		if !result.ProfileAvailable || err != nil || result.Address == "" {
			return nil, false
		}
	} else if result.ProfileAvailable || result.ProfileExpiresAt != "" {
		return nil, false
	}
	return encodeData(result), true
}

// checkedPeerProfile ограничивает отдельную секретную выдачу и очищает временную копию.
func checkedPeerProfile(raw json.RawMessage, operationID string) bool {
	var profile PeerProfile
	if len(raw) > 2*maxPeerProfileBytes || decodeStrict(raw, &profile) != nil || !operationIDPattern.MatchString(operationID) || profile.Filename != "awg_client_"+operationID[:12]+".conf" {
		return false
	}
	content, err := base64.StdEncoding.Strict().DecodeString(profile.ContentBase64)
	defer clear(content)
	return err == nil && len(content) > 0 && len(content) <= maxPeerProfileBytes && utf8.Valid(content)
}
