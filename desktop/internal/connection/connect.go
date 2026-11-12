package connection

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const webSocket = "/run/awg_vps_web/web.sock"
const bootstrapCommand = `set -eu
f=/etc/awg_vps_control/ui.env
[ -f "$f" ] && [ ! -L "$f" ]
[ "$(wc -c < "$f")" -le 16384 ]
LC_ALL=C awk '/^AWG_ALLOWED_HOST=/ || /^AWG_ALLOWED_ORIGIN=/ { print }' "$f"`

// boundedBuffer прекращает накопление SSH-вывода после фиксированного лимита.
type boundedBuffer struct {
	buffer bytes.Buffer // Содержимое ограниченного вывода.
	limit  int          // Максимальное количество сохраняемых байтов.
}

// Write не позволяет удалённому процессу увеличивать локальный буфер без ограничения.
func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > buffer.limit-buffer.buffer.Len() {
		return 0, errors.New("SSH-вывод превысил допустимый размер.")
	}
	return buffer.buffer.Write(data)
}

// authentication создаёт только явно выбранный способ входа без ssh-agent и ssh_config.
func authentication(profile SSHProfile, credentials Credentials) (ssh.AuthMethod, error) {
	if len(credentials.Password) > 16384 || len(credentials.Passphrase) > 16384 {
		return nil, errors.New("Секрет SSH превышает поддержанный размер.")
	}
	if profile.AuthMode == "password" {
		if credentials.Password == "" {
			return nil, errors.New("Введите пароль SSH для этой попытки.")
		}
		return ssh.Password(credentials.Password), nil
	}
	data, err := readFile(profile.KeyPath, 1024*1024)
	defer clear(data)
	if err != nil {
		return nil, errors.New("Не удалось прочитать выбранный SSH-ключ.")
	}
	var signer ssh.Signer
	if credentials.Passphrase == "" {
		signer, err = ssh.ParsePrivateKey(data)
	} else {
		passphrase := []byte(credentials.Passphrase)
		defer clear(passphrase)
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, passphrase)
	}
	if err != nil {
		return nil, errors.New("SSH-ключ не поддержан либо требуется другой passphrase; PuTTY PPK не поддерживается.")
	}
	return ssh.PublicKeys(signer), nil
}

// remoteConfiguration читает только две фиксированные настройки, без shell source и access secret.
func remoteConfiguration(client *ssh.Client) (string, string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", "", errors.New("Не удалось открыть SSH bootstrap-сессию.")
	}
	defer session.Close()
	output := &boundedBuffer{limit: 16384}
	diagnostic := &boundedBuffer{limit: 4096}
	defer func() { clear(diagnostic.buffer.Bytes()) }()
	session.Stdout, session.Stderr = output, diagnostic
	if err := session.Run(bootstrapCommand); err != nil {
		return "", "", errors.New("Не удалось прочитать настройки установленной панели. Нужен доступ к ui.env и web.sock.")
	}
	values := make(map[string]string, 2)
	for _, line := range strings.Split(strings.TrimSuffix(output.buffer.String(), "\n"), "\n") {
		key, value, found := strings.Cut(line, "=")
		if !found || key != "AWG_ALLOWED_HOST" && key != "AWG_ALLOWED_ORIGIN" || values[key] != "" || value == "" || strings.TrimSpace(value) != value {
			return "", "", errors.New("Настройки origin панели неоднозначны или не поддержаны.")
		}
		values[key] = value
	}
	host, origin := values["AWG_ALLOWED_HOST"], values["AWG_ALLOWED_ORIGIN"]
	parsed, err := url.Parse(origin)
	if err != nil || origin != "http://"+host || parsed.Host != host || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" || parsed.ForceQuery {
		return "", "", errors.New("Origin панели должен быть точным http localhost origin.")
	}
	hostname, port, err := net.SplitHostPort(host)
	number, portError := strconv.Atoi(port)
	label := strings.TrimSuffix(strings.TrimPrefix(hostname, "awg-"), ".localhost")
	if err != nil || portError != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port || !strings.HasPrefix(hostname, "awg-") || !strings.HasSuffix(hostname, ".localhost") || len(label) < 8 || len(label) > 48 {
		return "", "", errors.New("Панель должна использовать изолированный awg-*.localhost адрес.")
	}
	for _, ch := range label {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789-", ch) {
			return "", "", errors.New("Некорректный localhost адрес панели.")
		}
	}
	return host, origin, nil
}

// Connect открывает одну отменяемую SSH-сессию и изолированный loopback HTTP origin.
func Connect(ctx context.Context, dir string, profile SSHProfile, credentials Credentials) (*Connection, error) {
	if err := validateProfile(profile); err != nil {
		return nil, err
	}
	callback, err := knownHostsCallback(dir)
	if err != nil {
		return nil, err
	}
	auth, err := authentication(profile, credentials)
	if err != nil {
		return nil, err
	}
	authMethods := []ssh.AuthMethod{auth}
	defer clear(authMethods)
	connectContext, cancelConnect := context.WithTimeout(ctx, 25*time.Second)
	defer cancelConnect()
	address := net.JoinHostPort(profile.Host, strconv.Itoa(profile.Port))
	tcp, err := (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext(connectContext, "tcp", address)
	if err != nil {
		return nil, errors.New("Не удалось открыть SSH TCP-соединение; проверьте адрес и порт.")
	}
	success := false
	defer func() {
		if !success {
			_ = tcp.Close()
		}
	}()
	stopConnect := context.AfterFunc(connectContext, func() { _ = tcp.Close() })
	defer stopConnect()
	deadline, _ := connectContext.Deadline()
	if err := tcp.SetDeadline(deadline); err != nil {
		return nil, errors.New("Не удалось ограничить время SSH-подключения.")
	}
	verification := checkedHostKey(callback)
	var hostKeyError error
	sshConnection, channels, requests, err := ssh.NewClientConn(tcp, address, &ssh.ClientConfig{User: profile.User, Auth: authMethods, HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		hostKeyError = verification(hostname, remote, key)
		return hostKeyError
	}, Timeout: 15 * time.Second})
	clear(authMethods)
	if err != nil {
		if hostKeyError != nil {
			return nil, hostKeyError
		}
		return nil, errors.New("SSH-подключение отклонено: проверьте доверие ключу сервера и данные входа.")
	}
	client := ssh.NewClient(sshConnection, channels, requests)
	defer func() {
		if !success {
			_ = client.Close()
		}
	}()
	remoteHost, remoteOrigin, err := remoteConfiguration(client)
	if err != nil {
		return nil, err
	}
	probe, err := client.DialContext(connectContext, "unix", webSocket)
	if err != nil {
		return nil, errors.New("SSH-пользователь не может открыть фиксированный Unix socket панели.")
	}
	_ = probe.Close()
	if !stopConnect() || connectContext.Err() != nil {
		return nil, errors.New("Время SSH-подключения истекло либо попытка отменена.")
	}
	if err := tcp.SetDeadline(time.Time{}); err != nil {
		return nil, errors.New("Не удалось завершить SSH bootstrap.")
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("Не удалось открыть локальную панель на loopback.")
	}
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		_ = listener.Close()
		return nil, errors.New("Не удалось создать изолированный origin.")
	}
	_, localPort, _ := net.SplitHostPort(listener.Addr().String())
	localHost := "awg-" + hex.EncodeToString(token) + ".localhost:" + localPort
	sessionContext, cancel := context.WithCancel(ctx)
	connection := &Connection{tcp: tcp, ssh: client, listener: listener, localOrigin: "http://" + localHost, localHost: localHost, remoteHost: remoteHost, remoteOrigin: remoteOrigin, cancel: cancel, done: make(chan struct{})}
	connection.transport = &http.Transport{Proxy: nil, DisableCompression: true, MaxIdleConns: 8, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 8, IdleConnTimeout: 60 * time.Second, ResponseHeaderTimeout: 30 * time.Second, MaxResponseHeaderBytes: 32768, DialContext: connection.dialSocket}
	connection.server = &http.Server{Handler: http.HandlerFunc(connection.serveHTTP), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 35 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 32768, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return sessionContext }}
	go func() {
		select {
		case <-sessionContext.Done():
			_ = connection.Close()
		case <-connection.done:
		}
	}()
	go func() { _ = client.Wait(); _ = connection.Close() }()
	go func() { _ = connection.server.Serve(listener); _ = connection.Close() }()
	go connection.maintain(sessionContext)
	success = true
	if ctx.Err() != nil {
		_ = connection.Close()
		return nil, errors.New("Подключение отменено.")
	}
	select {
	case <-connection.done:
		return nil, errors.New("SSH-соединение завершилось во время подключения.")
	default:
	}
	return connection, nil
}

// dialSocket запрещает обычный TCP proxy и ограничивает ожидание SSH channel.
func (connection *Connection) dialSocket(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" || address != connection.remoteHost {
		return nil, errors.New("Произвольный адрес туннеля запрещён.")
	}
	dialContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	channel, err := connection.ssh.DialContext(dialContext, "unix", webSocket)
	if err != nil && dialContext.Err() != nil {
		_ = connection.Close()
	}
	return channel, err
}

// maintain удаляет просроченный профиль и выявляет исчезнувший SSH transport.
func (connection *Connection) maintain(ctx context.Context) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			connection.mutex.Lock()
			connection.expireLocked()
			connection.mutex.Unlock()
			timer := time.AfterFunc(10*time.Second, func() { _ = connection.Close() })
			_, _, err := connection.ssh.SendRequest("keepalive@openssh.com", true, nil)
			stopped := timer.Stop()
			if err != nil || !stopped {
				_ = connection.Close()
				return
			}
		}
	}
}

// URL возвращает единственный origin, разрешённый embedded WebView.
func (connection *Connection) URL() string { return connection.localOrigin }

// Done уведомляет native UI о закрытии ресурсов сессии.
func (connection *Connection) Done() <-chan struct{} { return connection.done }

// Close отменяет HTTP/SSH и уничтожает секретный pending профиль ровно один раз.
func (connection *Connection) Close() error {
	connection.once.Do(func() {
		connection.mutex.Lock()
		connection.closed = true
		connection.saving = false
		if connection.pending != nil {
			clear(connection.pending.Data)
			connection.pending = nil
		}
		connection.mutex.Unlock()
		connection.cancel()
		_ = connection.tcp.Close()
		_ = connection.ssh.Close()
		_ = connection.server.Close()
		_ = connection.listener.Close()
		connection.transport.CloseIdleConnections()
		close(connection.done)
	})
	return nil
}
