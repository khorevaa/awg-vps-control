package connection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const maxProfileBytes = 65536
const maxHTTPBody = 4 * 1024 * 1024

// safePath отклоняет неоднозначные пути, способные изменить смысл запроса после rewrite.
func safePath(value *url.URL) bool {
	return value != nil && value.Opaque == "" && value.User == nil && value.Fragment == "" && value.RawPath == "" && strings.HasPrefix(value.Path, "/") && !strings.Contains(value.Path, "//") && !strings.Contains(value.Path, "\\") && !strings.ContainsFunc(value.Path, unicode.IsControl) && path.Clean(value.Path) == value.Path && len(value.Path) <= 4096 && len(value.RawQuery) <= 8192
}

// stripHeaders удаляет hop-by-hop и любые входные proxy/forwarding полномочия.
func stripHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Forwarded"} {
		header.Del(name)
	}
	for name := range header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "x-original-") || strings.HasPrefix(lower, "access-control-") {
			header.Del(name)
		}
	}
}

// proxyError возвращает безопасную локальную ошибку без SSH/HTTP реквизитов и секретов.
func proxyError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{"ok": false, "error": map[string]string{"code": "desktop_proxy", "message": message}})
}

// reserveDownload проверяет ID и резервирует единственное место до серверного consume.
func (connection *Connection) reserveDownload(data []byte) (string, error) {
	var payload map[string]string
	decoder := json.NewDecoder(bytes.NewReader(data))
	if len(data) > 512 || decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF || len(payload) != 1 || !operationPattern.MatchString(payload["id"]) {
		return "", errors.New("Некорректный запрос разового профиля.")
	}
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	connection.expireLocked()
	if connection.closed || connection.downloading || connection.saving || connection.pending != nil {
		return "", errors.New("Сначала сохраните ожидающий профиль через кнопку desktop-приложения.")
	}
	connection.downloading = true
	return payload["id"], nil
}

// releaseDownload снимает резервирование после любого результата HTTP-запроса.
func (connection *Connection) releaseDownload() {
	connection.mutex.Lock()
	connection.downloading = false
	connection.mutex.Unlock()
}

// captureDownload принимает только штатный ограниченный ответ именно данной операции.
func (connection *Connection) captureDownload(response *http.Response, operationID string, data []byte) error {
	contentType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	disposition, names, nameError := mime.ParseMediaType(response.Header.Get("Content-Disposition"))
	filename := "awg_client_" + operationID[:12] + ".conf"
	if err != nil || contentType != "application/octet-stream" || len(parameters) != 0 || nameError != nil || disposition != "attachment" || len(names) != 1 || names["filename"] != filename || len(data) == 0 || len(data) > maxProfileBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return errors.New("Серверный разовый профиль не прошёл проверку. Автоматического повтора нет.")
	}
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if connection.closed || connection.pending != nil || !connection.downloading {
		return errors.New("Соединение закрыто либо профиль уже ожидает сохранения.")
	}
	connection.pending = &PendingProfileDownload{OperationID: operationID, Filename: filename, Data: bytes.Clone(data), ExpiresAt: time.Now().Add(10 * time.Minute)}
	return nil
}

// rewriteLocation разрешает только переход внутри исходной панели и возвращает локальный URL.
func (connection *Connection) rewriteLocation(location string) (string, error) {
	target, err := url.Parse(location)
	if err != nil || target.User != nil || target.Opaque != "" || strings.HasPrefix(location, "//") || strings.ContainsFunc(location, unicode.IsControl) {
		return "", errors.New("Внешний redirect запрещён.")
	}
	if target.IsAbs() && target.Scheme+"://"+target.Host != connection.remoteOrigin || !target.IsAbs() && target.Host != "" {
		return "", errors.New("Внешний redirect запрещён.")
	}
	if target.Path == "" {
		target.Path = "/"
	}
	if !safePath(target) {
		return "", errors.New("Неоднозначный redirect запрещён.")
	}
	target.Scheme, target.Host = "http", connection.localHost
	return target.String(), nil
}

// serveHTTP проверяет локальную границу до преобразования Host/Origin и туннелирования.
func (connection *Connection) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Host != connection.localHost || request.URL.IsAbs() || request.URL.Host != "" || !safePath(request.URL) || !strings.HasPrefix(request.RequestURI, "/") {
		proxyError(writer, http.StatusForbidden, "Недопустимый адрес локальной панели.")
		return
	}
	origins := request.Header.Values("Origin")
	if len(origins) > 1 || len(origins) == 1 && origins[0] != connection.localOrigin {
		proxyError(writer, http.StatusForbidden, "Посторонний Origin запрещён.")
		return
	}
	if request.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade") || request.Method != http.MethodGet && request.Method != http.MethodHead && request.Method != http.MethodPost {
		proxyError(writer, http.StatusMethodNotAllowed, "Метод или upgrade не поддержан desktop-туннелем.")
		return
	}
	connection.mutex.Lock()
	closed := connection.closed
	connection.mutex.Unlock()
	if closed {
		proxyError(writer, http.StatusServiceUnavailable, "SSH-соединение закрыто.")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1024*1024)
	defer request.Body.Close()
	var operationID string
	if request.Method == http.MethodPost && request.URL.Path == "/api/v1/peers/profile" {
		data, err := io.ReadAll(io.LimitReader(request.Body, 513))
		if err != nil || len(data) > 512 {
			proxyError(writer, http.StatusBadRequest, "Некорректный запрос профиля.")
			return
		}
		operationID, err = connection.reserveDownload(data)
		if err != nil {
			proxyError(writer, http.StatusConflict, err.Error())
			return
		}
		defer connection.releaseDownload()
		request.Body = io.NopCloser(bytes.NewReader(data))
		request.ContentLength = int64(len(data))
	}
	proxyContext, cancel := context.WithTimeout(request.Context(), 35*time.Second)
	defer cancel()
	outgoing := request.Clone(proxyContext)
	outgoing.RequestURI = ""
	outgoing.URL.Scheme, outgoing.URL.Host = "http", connection.remoteHost
	outgoing.Host = connection.remoteHost
	stripHeaders(outgoing.Header)
	if len(origins) == 1 {
		outgoing.Header.Set("Origin", connection.remoteOrigin)
	}
	if referer := outgoing.Header.Get("Referer"); referer != "" {
		parsed, err := url.Parse(referer)
		if err != nil || parsed.Scheme+"://"+parsed.Host != connection.localOrigin || !safePath(parsed) {
			outgoing.Header.Del("Referer")
		} else {
			parsed.Scheme, parsed.Host = "http", connection.remoteHost
			outgoing.Header.Set("Referer", parsed.String())
		}
	}
	response, err := connection.transport.RoundTrip(outgoing)
	if err != nil {
		proxyError(writer, http.StatusBadGateway, "SSH-туннель не подтвердил ответ панели. Повтор изменений не выполняется.")
		return
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusSwitchingProtocols {
		proxyError(writer, http.StatusBadGateway, "Смена протокола запрещена.")
		return
	}
	limit := int64(maxHTTPBody)
	if operationID != "" && response.StatusCode == http.StatusOK {
		limit = maxProfileBytes
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	defer clear(data)
	if err != nil || int64(len(data)) > limit {
		proxyError(writer, http.StatusBadGateway, "Ответ панели неполный либо превышает допустимый размер.")
		return
	}
	if location := response.Header.Get("Location"); location != "" {
		location, err = connection.rewriteLocation(location)
		if err != nil {
			proxyError(writer, http.StatusBadGateway, "Панель попыталась перейти на посторонний адрес.")
			return
		}
		response.Header.Set("Location", location)
	}
	if response.Header.Get("Refresh") != "" {
		proxyError(writer, http.StatusBadGateway, "Автоматический redirect запрещён.")
		return
	}
	if operationID != "" && response.StatusCode == http.StatusOK {
		if err := connection.captureDownload(response, operationID, data); err != nil {
			proxyError(writer, http.StatusBadGateway, err.Error())
			return
		}
	}
	stripHeaders(response.Header)
	for name, values := range response.Header {
		if strings.EqualFold(name, "Set-Cookie") || strings.EqualFold(name, "Content-Length") {
			continue
		}
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	for _, cookie := range response.Cookies() {
		if cookie.Domain != "" {
			continue
		}
		http.SetCookie(writer, cookie)
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Length", strconv.Itoa(len(data)))
	writer.WriteHeader(response.StatusCode)
	if request.Method != http.MethodHead {
		_, _ = writer.Write(data)
	}
}

// expireLocked уничтожает просроченный буфер; вызывается только под mutex.
func (connection *Connection) expireLocked() {
	if connection.pending != nil && !time.Now().Before(connection.pending.ExpiresAt) {
		clear(connection.pending.Data)
		connection.pending = nil
	}
}

// PendingDownload сообщает native UI только безопасное имя ещё доступного файла.
func (connection *Connection) PendingDownload() (string, bool) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	connection.expireLocked()
	if connection.closed || connection.pending == nil {
		return "", false
	}
	return connection.pending.Filename, true
}

// TakeDownload передаёт единственное владение секретным буфером вызывающему native UI.
func (connection *Connection) TakeDownload() (*PendingProfileDownload, error) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	connection.expireLocked()
	if connection.closed || connection.pending == nil {
		return nil, errors.New("Разовый профиль уже передан, истёк либо соединение закрыто.")
	}
	result := connection.pending
	connection.pending = nil
	connection.saving = true
	return result, nil
}

// FinishDownload снимает запрет новой выдачи после очистки буфера native UI.
func (connection *Connection) FinishDownload() {
	connection.mutex.Lock()
	connection.saving = false
	connection.mutex.Unlock()
}
