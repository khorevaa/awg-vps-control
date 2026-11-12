//go:build linux

package main

import (
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

const maxPeerProfileBytes = 64 * 1024

var peerProfileNamePattern = regexp.MustCompile(`^awg_client_[a-f0-9]{8,32}\.conf$`)
var peerHostLabelPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

// peerCreateRequest задаёт публичные параметры создания native клиента Amnezia.
type peerCreateRequest struct {
	Name             string   `json:"name"`              // Отображаемое имя клиента.
	EndpointHost     string   `json:"endpoint_host"`     // Входящий IP или DNS-имя VPS без порта.
	DNS              []string `json:"dns"`               // Один или два адреса DNS для профиля.
	ExpectedRevision string   `json:"expected_revision"` // Ожидаемая ревизия native файлов.
}

// peerRenameRequest изменяет только имя существующего native клиента.
type peerRenameRequest struct {
	PublicKey        string `json:"public_key"`        // Публичный ключ нужного клиента.
	Name             string `json:"name"`              // Новое отображаемое имя.
	ExpectedRevision string `json:"expected_revision"` // Ожидаемая ревизия native файлов.
}

// peerRevokeRequest отзывает доступ существующего native клиента.
type peerRevokeRequest struct {
	PublicKey        string `json:"public_key"`        // Публичный ключ нужного клиента.
	ExpectedRevision string `json:"expected_revision"` // Ожидаемая ревизия native файлов.
}

// peerProfile передаёт разовый профиль только через защищённый download endpoint.
type peerProfile struct {
	Filename      string `json:"filename"`       // Проверяемое безопасное имя attachment.
	ContentBase64 string `json:"content_base64"` // Секретный профиль только в памяти запроса.
}

// validPeerName запрещает пустое имя, управляющие символы и скрытые крайние пробелы.
func validPeerName(value string) bool {
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value || len(value) == 0 || utf8.RuneCountInString(value) > 80 {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) || unicode.In(char, unicode.Cf) {
			return false
		}
	}
	return true
}

// validPeerIP проверяет нормализованный IP без zone, multicast и unspecified.
func validPeerIP(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Zone() == "" && address.String() == value && address.IsGlobalUnicast() && !address.Is4In6()
}

// validPeerHost принимает входящий адрес сервера без URL, порта или shell-синтаксиса.
func validPeerHost(value string) bool {
	if validPeerIP(value) {
		return true
	}
	if len(value) == 0 || len(value) > 253 || strings.ContainsAny(value, ":/[] \\@") {
		return false
	}
	hasLetter := false
	for _, char := range value {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') {
			hasLetter = true
		}
	}
	for _, label := range strings.Split(value, ".") {
		if !peerHostLabelPattern.MatchString(label) {
			return false
		}
	}
	return hasLetter
}

// validPeerDNS ограничивает список уникальными IP-адресами DNS.
func validPeerDNS(values []string) bool {
	if len(values) < 1 || len(values) > 2 {
		return false
	}
	for index, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() || !validPeerIP(value) || (index == 1 && value == values[0]) {
			return false
		}
	}
	return true
}

// validPeerKey проверяет канонический публичный ключ WireGuard длиной 32 байта.
func validPeerKey(value string) bool {
	if len(value) != 44 {
		return false
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return false
	}
	for _, char := range decoded {
		if char != 0 {
			return true
		}
	}
	return false
}

// validatePeerOperation ограничивает payload клиентских действий до передачи Control.
func validatePeerOperation(action string, data json.RawMessage) bool {
	switch action {
	case "peer.create":
		var payload peerCreateRequest
		return strictJSON(data, &payload) == nil && validPeerName(payload.Name) && validPeerHost(payload.EndpointHost) && validPeerDNS(payload.DNS) && revisionPattern.MatchString(payload.ExpectedRevision)
	case "peer.rename":
		var payload peerRenameRequest
		return strictJSON(data, &payload) == nil && validPeerName(payload.Name) && validPeerKey(payload.PublicKey) && revisionPattern.MatchString(payload.ExpectedRevision)
	case "peer.revoke":
		var payload peerRevokeRequest
		return strictJSON(data, &payload) == nil && validPeerKey(payload.PublicKey) && revisionPattern.MatchString(payload.ExpectedRevision)
	}
	return false
}

// consumePeerProfile выдаёт один ограниченный attachment без записи содержимого в журналы.
func (a *application) consumePeerProfile(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		reject(writer, 400, "invalid_query", "Параметры запроса не поддерживаются.")
		return
	}
	var lookup operationLookup
	if !decodeBody(writer, request, &lookup) {
		return
	}
	if !operationIDPattern.MatchString(lookup.ID) {
		reject(writer, 422, "invalid_operation_id", "Некорректный идентификатор создания клиента.")
		return
	}
	if err := a.Store.audit("peer.profile.requested", true); err != nil {
		writeError(writer, err)
		return
	}
	payload, err := json.Marshal(lookup)
	if err != nil {
		writeError(writer, err)
		return
	}
	data, err := a.Control.Request(request.Context(), "peers.profile.consume", payload)
	if err != nil {
		writeError(writer, err)
		return
	}
	defer clear(data)
	var profile peerProfile
	if len(data) > maxPeerProfileBytes*2 || strictJSON(data, &profile) != nil || !peerProfileNamePattern.MatchString(profile.Filename) || profile.Filename != "awg_client_"+lookup.ID[:12]+".conf" || len(profile.ContentBase64) > base64.StdEncoding.EncodedLen(maxPeerProfileBytes) {
		reject(writer, 502, "invalid_profile", "Сервис вернул некорректный профиль. Повторная выдача не гарантируется.")
		return
	}
	content, err := base64.StdEncoding.Strict().DecodeString(profile.ContentBase64)
	defer clear(content)
	if err != nil || len(content) == 0 || len(content) > maxPeerProfileBytes || !utf8.Valid(content) || base64.StdEncoding.EncodeToString(content) != profile.ContentBase64 {
		reject(writer, 502, "invalid_profile", "Сервис вернул некорректный профиль. Повторная выдача не гарантируется.")
		return
	}
	writer.Header().Set("Content-Type", "application/octet-stream")
	writer.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": profile.Filename}))
	writer.Header().Set("Content-Length", strconv.Itoa(len(content)))
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(content); err != nil {
		slog.Warn("не удалось отправить разовый профиль клиента")
	}
}
