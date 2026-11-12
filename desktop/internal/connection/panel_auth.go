package connection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const panelCookieName = "__Host-awg_vps_session"
const secretCommand = `set -eu
f=/etc/awg_vps_control/web/access_secret
for d in /etc /etc/awg_vps_control /etc/awg_vps_control/web; do [ -d "$d" ] && [ ! -L "$d" ]; done
[ -f "$f" ] && [ ! -L "$f" ]
[ "$(stat -c %s "$f")" -le 512 ]
dd if="$f" iflag=nofollow,nonblock,count_bytes count=513 status=none`

// validSecretBytes проверяет только ограниченный base64url алфавит без padding.
func validSecretBytes(value []byte, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	for _, ch := range value {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-", rune(ch)) {
			return false
		}
	}
	return true
}

// remoteAccessSecret читает один фиксированный файл без shell source и без вывода в журнал.
func remoteAccessSecret(client *ssh.Client) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, errors.New("Не удалось открыть SSH-сессию для входа в панель.")
	}
	defer session.Close()
	output := &boundedBuffer{limit: 512}
	diagnostic := &boundedBuffer{limit: 4096}
	defer func() { clear(output.buffer.Bytes()); clear(diagnostic.buffer.Bytes()) }()
	session.Stdout, session.Stderr = output, diagnostic
	if session.Run(secretCommand) != nil {
		return nil, errors.New("SSH-пользователь не может безопасно прочитать секрет установленной панели. Подключение остановлено.")
	}
	secret := bytes.TrimSpace(output.buffer.Bytes())
	if !validSecretBytes(secret, 43, 256) {
		return nil, errors.New("Формат секрета установленной панели не поддержан. Подключение остановлено.")
	}
	return bytes.Clone(secret), nil
}

// panelTransport разрешает HTTP dial исключительно к фиксированному socket по этому SSH.
func panelTransport(client *ssh.Client, tcp net.Conn, remoteHost string) *http.Transport {
	return &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 8, IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: 32768, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != remoteHost {
			return nil, errors.New("Произвольный адрес туннеля запрещён.")
		}
		dialContext, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		channel, err := client.DialContext(dialContext, "unix", webSocket)
		if err != nil && dialContext.Err() != nil {
			_ = tcp.Close()
		}
		return channel, err
	}}
}

// checkedPanelCookie отклоняет неоднозначные или ослабленные атрибуты серверной сессии.
func checkedPanelCookie(response *http.Response) (*http.Cookie, error) {
	badCookie := errors.New("Панель не выдала проверенную защищённую сессию. Подключение остановлено.")
	values := response.Header.Values("Set-Cookie")
	cookies := response.Cookies()
	if len(values) != 1 || len(cookies) != 1 || len(values[0]) > 2048 {
		return nil, badCookie
	}
	seen := make(map[string]bool)
	for _, attribute := range strings.Split(values[0], ";")[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(attribute), "=")
		name = strings.ToLower(name)
		if seen[name] {
			return nil, badCookie
		}
		seen[name] = true
		switch name {
		case "path", "expires", "max-age", "secure", "httponly", "samesite":
		default:
			return nil, badCookie
		}
	}
	cookie := cookies[0]
	now := time.Now()
	remaining := cookie.Expires.Sub(now)
	maxAge := time.Duration(cookie.MaxAge) * time.Second
	if cookie.Valid() != nil || cookie.Name != panelCookieName || !validSecretBytes([]byte(cookie.Value), 43, 43) || cookie.Path != "/" || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Quoted || cookie.Partitioned || len(cookie.Unparsed) != 0 || cookie.MaxAge < 1 || cookie.MaxAge > 43200 || remaining <= 0 || remaining > 12*time.Hour+2*time.Minute || remaining-maxAge > 2*time.Minute || maxAge-remaining > 2*time.Minute {
		return nil, badCookie
	}
	return &http.Cookie{Name: cookie.Name, Value: cookie.Value, Path: "/", Expires: cookie.Expires, MaxAge: cookie.MaxAge, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}, nil
}

// authenticatePanel обменивает секрет на cookie один раз, без redirect и автоматического повтора.
func authenticatePanel(ctx context.Context, transport *http.Transport, host, origin string, secret []byte) (*http.Cookie, error) {
	body := make([]byte, 0, len(secret)+13)
	body = append(body, []byte(`{"secret":"`)...)
	body = append(body, secret...)
	body = append(body, []byte(`"}`)...)
	defer clear(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/api/v1/access", bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("Не удалось подготовить вход в панель.")
	}
	request.Host = host
	request.GetBody = nil
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := transport.RoundTrip(request)
	if err != nil {
		return nil, errors.New("Вход в панель через SSH не подтверждён. Подключитесь заново; автоматического повтора нет.")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	defer clear(data)
	contentType, _, typeError := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || len(data) > 4096 || response.StatusCode != http.StatusOK || typeError != nil || contentType != "application/json" || response.Header.Get("Location") != "" || response.Header.Get("Refresh") != "" || response.Header.Get("Content-Encoding") != "" {
		return nil, errors.New("Панель отклонила автоматический вход либо вернула неподдержанный ответ. Подключение остановлено.")
	}
	cookie, err := checkedPanelCookie(response)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var expires string
	if decoder.Decode(&fields) != nil || decoder.Decode(new(any)) != io.EOF || len(fields) != 2 || len(fields["csrf_token"]) != 45 || fields["csrf_token"][0] != '"' || fields["csrf_token"][44] != '"' || !validSecretBytes(fields["csrf_token"][1:44], 43, 43) || json.Unmarshal(fields["expires_at"], &expires) != nil {
		return nil, errors.New("Ответ входа в панель не соответствует поддержанной сессии.")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, expires)
	if err != nil || !expiresAt.Truncate(time.Second).Equal(cookie.Expires) {
		return nil, errors.New("Время серверной сессии не подтверждено.")
	}
	return cookie, nil
}

// TakePanelCookie передаёт сессию native WebView один раз, исключая постоянное хранение.
func (connection *Connection) TakePanelCookie() (*http.Cookie, error) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()
	if connection.closed || connection.panelCookie == nil || !time.Now().Before(connection.panelCookie.Expires) {
		if connection.panelCookie != nil {
			*connection.panelCookie = http.Cookie{}
			connection.panelCookie = nil
		}
		return nil, errors.New("Сессия панели уже передана, истекла или соединение закрыто.")
	}
	cookie := *connection.panelCookie
	*connection.panelCookie = http.Cookie{}
	connection.panelCookie = nil
	return &cookie, nil
}
