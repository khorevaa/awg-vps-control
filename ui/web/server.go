//go:build linux

package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed app/static/*
var uiFiles embed.FS

var resourceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var revisionPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var operationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var idempotencyPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{16,128}$`)

const sessionCookie = "__Host-awg_vps_session"

// application объединяет проверенные зависимости HTTP-приложения.
type application struct {
	Config  config         // Пути и разрешённый origin.
	Store   *sessionStore  // Защищённое хранилище сессий и аудита.
	Control IControlClient // Изолированный транспорт Control.
}

// validateJSONTokens отклоняет повторные ключи и чрезмерную вложенность JSON.
func validateJSONTokens(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("duplicate JSON key")
			}
			seen[key] = true
			if err := validateJSONTokens(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := validateJSONTokens(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

// strictJSON отклоняет неверный UTF-8, повторные/неизвестные поля и лишние значения JSON.
func strictJSON(content []byte, target any) error {
	if !utf8.Valid(content) {
		return errors.New("invalid JSON UTF-8")
	}
	tokens := json.NewDecoder(bytes.NewReader(content))
	tokens.UseNumber()
	if err := validateJSONTokens(tokens, 0); err != nil {
		return err
	}
	if _, err := tokens.Token(); !errors.Is(err, io.EOF) {
		return errors.New("extra JSON value")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("extra JSON value")
	}
	return nil
}

// writeJSON отправляет JSON без кеширования и без записи содержимого в логи.
func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		slog.Warn("не удалось отправить HTTP-ответ")
	}
}

// writeError ограничивает сообщение ошибкой публичного контракта.
func writeError(writer http.ResponseWriter, err error) {
	var safe *apiError
	if !errors.As(err, &safe) {
		slog.Error("операция Web не выполнена: защищённое состояние недоступно")
		safe = &apiError{Code: "state_unavailable", Message: "Не удалось безопасно сохранить или проверить состояние панели. Действие не подтверждено.", Status: 503}
	}
	writeJSON(writer, safe.Status, map[string]any{"error": safe})
}

// reject возвращает фиксированную безопасную ошибку запроса.
func reject(writer http.ResponseWriter, status int, code, message string) {
	writeError(writer, &apiError{Code: code, Message: message, Status: status})
}

// securityHeaders запрещает кеширование, внешние ресурсы и встраивание панели.
func securityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("X-Frame-Options", "DENY")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
}

// ServeHTTP проверяет границы доверия до исполнения любого API-действия.
func (a *application) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	securityHeaders(writer.Header())
	path := request.URL.Path
	if path == "/api/v1/health" && request.Method == http.MethodGet {
		writeJSON(writer, 200, map[string]string{"status": "ok"})
		return
	}
	if request.Host != a.Config.AllowedHost {
		reject(writer, 400, "invalid_host", "Неверный адрес панели. Откройте адрес из команды SSH-туннеля.")
		return
	}
	if request.Method == http.MethodGet && a.serveAsset(writer, path) {
		return
	}
	if !strings.HasPrefix(path, "/api/v1/") {
		reject(writer, 404, "not_found", "Ресурс не найден.")
		return
	}
	mutation := request.Method != http.MethodGet && request.Method != http.MethodHead
	if mutation && request.Header.Get("Origin") != a.Config.AllowedOrigin {
		reject(writer, 403, "invalid_origin", "Источник запроса не разрешён.")
		return
	}
	if path == "/api/v1/access" && request.Method == http.MethodPost {
		a.access(writer, request)
		return
	}
	cookie, err := request.Cookie(sessionCookie)
	if err != nil {
		reject(writer, 401, "unauthorized", "Войдите в панель.")
		return
	}
	current, err := a.Store.authenticate(cookie.Value, request.Header.Get("X-CSRF-Token"), mutation)
	if err != nil {
		writeError(writer, err)
		return
	}
	switch {
	case path == "/api/v1/auth/me" && request.Method == http.MethodGet:
		writeJSON(writer, 200, current)
	case path == "/api/v1/auth/logout" && request.Method == http.MethodPost:
		if err := a.Store.logout(cookie.Value); err != nil {
			writeError(writer, err)
			return
		}
		http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		writeJSON(writer, 200, map[string]string{"status": "ok"})
	case path == "/api/v1/operations" && request.Method == http.MethodPost:
		a.createOperation(writer, request)
	case request.Method == http.MethodGet:
		a.readAPI(writer, request)
	default:
		reject(writer, 405, "method_not_allowed", "Метод не поддерживается.")
	}
}

// serveAsset отдаёт только встроенные разрешённые файлы без файловой навигации.
func (a *application) serveAsset(writer http.ResponseWriter, path string) bool {
	files := map[string]string{"/": "index.html", "/static/app.js": "app.js", "/static/styles.css": "styles.css"}
	name, ok := files[path]
	if !ok {
		return false
	}
	content, err := uiFiles.ReadFile("app/static/" + name)
	if err != nil {
		reject(writer, 500, "asset_unavailable", "Файл интерфейса недоступен.")
		return true
	}
	types := map[string]string{"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "styles.css": "text/css; charset=utf-8"}
	writer.Header().Set("Content-Type", types[name])
	if _, err = writer.Write(content); err != nil {
		slog.Warn("не удалось отправить интерфейс")
	}
	return true
}

// decodeBody читает ограниченный JSON-объект нужного Content-Type.
func decodeBody(writer http.ResponseWriter, request *http.Request, target any) bool {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		reject(writer, 415, "invalid_content_type", "Требуется application/json.")
		return false
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 64*1024)
	content, err := io.ReadAll(request.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			reject(writer, 413, "request_too_large", "Запрос слишком большой.")
		} else {
			reject(writer, 400, "invalid_request", "Не удалось прочитать запрос.")
		}
		return false
	}
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 || trimmed[0] != '{' || strictJSON(content, target) != nil {
		reject(writer, 400, "invalid_json", "Некорректный JSON или неизвестные поля.")
		return false
	}
	return true
}

// access обменивает секрет на cookie и токен CSRF.
func (a *application) access(writer http.ResponseWriter, request *http.Request) {
	var input accessRequest
	if !decodeBody(writer, request, &input) {
		return
	}
	token, result, err := a.Store.login(input.Secret)
	if err != nil {
		writeError(writer, err)
		return
	}
	http.SetCookie(writer, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", MaxAge: int(a.Config.SessionTTL.Seconds()), Expires: result.ExpiresAt, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(writer, 200, result)
}

// readAPI переводит разрешённый HTTP-маршрут в действие Control.
func (a *application) readAPI(writer http.ResponseWriter, request *http.Request) {
	routes := map[string]string{
		"/api/v1/overview": "overview", "/api/v1/discovery": "discover", "/api/v1/peers": "peers",
		"/api/v1/diagnostics": "diagnostics", "/api/v1/configuration": "configuration",
		"/api/v1/policy": "policy.get", "/api/v1/operations": "operations.list",
	}
	action := routes[request.URL.Path]
	payload := json.RawMessage(`{}`)
	if request.URL.Path == "/api/v1/logs" {
		query, err := parseLogRequest(request)
		if err != nil {
			writeError(writer, err)
			return
		}
		payload, err = json.Marshal(query)
		if err != nil {
			writeError(writer, err)
			return
		}
		action = "logs"
	} else if len(request.URL.RawQuery) != 0 {
		reject(writer, 400, "invalid_query", "Параметры запроса не поддерживаются.")
		return
	}
	if strings.HasPrefix(request.URL.Path, "/api/v1/operations/") {
		id := strings.TrimPrefix(request.URL.Path, "/api/v1/operations/")
		if !operationIDPattern.MatchString(id) {
			reject(writer, 400, "invalid_operation_id", "Некорректный идентификатор операции.")
			return
		}
		var err error
		payload, err = json.Marshal(operationLookup{ID: id})
		if err != nil {
			writeError(writer, err)
			return
		}
		action = "operations.get"
	}
	if action == "" {
		reject(writer, 404, "not_found", "Ресурс не найден.")
		return
	}
	data, err := a.Control.Request(request.Context(), action, payload)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, 200, data)
}

// parseLogRequest отклоняет неизвестные источники, повторные query и чрезмерные лимиты.
func parseLogRequest(request *http.Request) (logRequest, error) {
	input := logRequest{Source: "awg", Limit: 100}
	bad := &apiError{Code: "invalid_query", Message: "Некорректный источник или лимит журнала.", Status: 400}
	query, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		return input, bad
	}
	for key, values := range query {
		if (key != "source" && key != "limit") || len(values) != 1 {
			return input, bad
		}
	}
	if query.Has("source") {
		input.Source = query.Get("source")
	}
	if query.Has("limit") {
		limit, err := strconv.Atoi(query.Get("limit"))
		if err != nil {
			return input, bad
		}
		input.Limit = limit
	}
	allowedSource := false
	switch input.Source {
	case "awg", "dns", "warp", "supervisor", "bridge":
		allowedSource = true
	}
	if !allowedSource || input.Limit < 1 || input.Limit > 200 {
		return input, bad
	}
	return input, nil
}

// validateOperation проверяет все поля до передачи на следующую границу полномочий.
func validateOperation(input operationRequest) error {
	bad := &apiError{Code: "invalid_operation", Message: "Параметры операции некорректны.", Status: 422}
	if !idempotencyPattern.MatchString(input.IdempotencyKey) {
		return bad
	}
	data := bytes.TrimSpace(input.Payload)
	if len(data) == 0 || data[0] != '{' {
		return bad
	}
	switch input.Action {
	case "attach":
		var payload attachRequest
		if strictJSON(data, &payload) != nil {
			return bad
		}
		if !resourceName.MatchString(payload.ContainerName) || !resourceName.MatchString(payload.DockerNetwork) {
			return bad
		}
		if payload.DNSContainerName != "" && !resourceName.MatchString(payload.DNSContainerName) {
			return bad
		}
	case "policy.set":
		var payload policyUpdate
		if strictJSON(data, &payload) != nil {
			return bad
		}
		if payload.WarpEnabled == nil || payload.AllowDirectWithoutWarp == nil || !revisionPattern.MatchString(payload.ExpectedRevision) {
			return bad
		}
	case "repair", "warp.reconnect", "warp.setup", "awg.restart":
		var payload map[string]json.RawMessage
		if strictJSON(data, &payload) != nil || len(payload) != 0 {
			return bad
		}
	default:
		return &apiError{Code: "operation_forbidden", Message: "Операция не разрешена.", Status: 403}
	}
	return nil
}

// createOperation сохраняет намерение в аудите и возвращает принятую Control операцию.
func (a *application) createOperation(writer http.ResponseWriter, request *http.Request) {
	var input operationRequest
	if !decodeBody(writer, request, &input) {
		return
	}
	if err := validateOperation(input); err != nil {
		writeError(writer, err)
		return
	}
	if err := a.Store.audit(input.Action+".requested", true); err != nil {
		writeError(writer, err)
		return
	}
	payload, err := json.Marshal(input)
	if err != nil {
		writeError(writer, err)
		return
	}
	data, err := a.Control.Request(request.Context(), "operations.create", payload)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusAccepted, data)
}
