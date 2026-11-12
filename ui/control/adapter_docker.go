//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const dockerAPIPrefix = "/v1.45"
const maxDockerJSON = 2 * 1024 * 1024

var dockerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var awgInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)

// DockerClient предоставляет только фиксированные методы Docker Engine API.
type DockerClient struct {
	socketPath string       // Доверенный Docker socket.
	http       *http.Client // Клиент без proxy, redirect и удалённых адресов.
}

// newDockerClient создаёт HTTP transport только к подтверждённому root Unix socket.
func newDockerClient(socketPath string) *DockerClient {
	transport := &http.Transport{MaxConnsPerHost: 8, MaxIdleConnsPerHost: 4, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: 45 * time.Second, MaxResponseHeaderBytes: 65536}
	transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		if err := verifyOwnedSocket(socketPath, 0); err != nil {
			return nil, err
		}
		dialer := net.Dialer{Timeout: 2 * time.Second}
		connection, err := dialer.DialContext(ctx, "unix", socketPath)
		if err != nil {
			return nil, err
		}
		unixConnection, ok := connection.(*net.UnixConn)
		if !ok {
			_ = connection.Close()
			return nil, errors.New("неверный Docker transport")
		}
		uid, err := peerUID(unixConnection)
		if err != nil || uid != 0 {
			_ = connection.Close()
			return nil, errors.New("неподтверждённый Docker peer")
		}
		return connection, nil
	}
	return &DockerClient{socketPath: socketPath, http: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// request обращается к сформированному внутри adapter endpoint и ограничивает тело.
func (client *DockerClient) request(ctx context.Context, method, path string, payload any, limit int64) ([]byte, *APIError) {
	var content io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, failure(500, "docker_request", "Не удалось сформировать Docker-запрос.")
		}
		content = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, content)
	if err != nil {
		return nil, failure(500, "docker_request", "Некорректный внутренний Docker-запрос.")
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, failure(503, "docker_unavailable", "Docker не подтвердил результат запроса.")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, failure(502, "docker_rejected", "Docker отклонил разрешённое действие; сырые данные скрыты.")
	}
	if response.ContentLength > limit {
		return nil, failure(502, "response_too_large", "Docker вернул слишком много данных.")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, failure(502, "docker_transport", "Ответ Docker не подтверждён полностью.")
	}
	if int64(len(raw)) > limit {
		return nil, failure(502, "response_too_large", "Docker вернул слишком много данных.")
	}
	return raw, nil
}

// dockerDecode допускает расширение официальной схемы, отклоняя неоднозначный JSON.
func dockerDecode(raw []byte, value any) error {
	var projection any
	if decodeStrict(raw, &projection) != nil {
		return errors.New("некорректный Docker JSON")
	}
	return json.Unmarshal(raw, value)
}

// Ping проверяет Docker API без списка контейнеров или системных данных.
func (client *DockerClient) Ping(ctx context.Context) *APIError {
	raw, apiError := client.request(ctx, http.MethodGet, "/_ping", nil, 32)
	if apiError != nil {
		return apiError
	}
	if strings.TrimSpace(string(raw)) != "OK" {
		return failure(503, "docker_unavailable", "Docker не подтвердил готовность.")
	}
	return nil
}

// List возвращает ограниченный список уже работающих контейнеров.
func (client *DockerClient) List(ctx context.Context) ([]DockerSummary, *APIError) {
	raw, apiError := client.request(ctx, http.MethodGet, dockerAPIPrefix+"/containers/json?all=false&limit=32", nil, maxDockerJSON)
	if apiError != nil {
		return nil, apiError
	}
	var containers []DockerSummary
	if dockerDecode(raw, &containers) != nil || len(containers) > 32 {
		return nil, failure(502, "docker_protocol", "Неподдерживаемый список Docker-контейнеров.")
	}
	for _, container := range containers {
		if !dockerIDPattern.MatchString(container.ID) {
			return nil, failure(502, "docker_protocol", "Docker вернул некорректный идентификатор.")
		}
	}
	return containers, nil
}

// Inspect читает существующий контейнер по проверенному ID или имени ресурса.
func (client *DockerClient) Inspect(ctx context.Context, id string) (DockerContainer, *APIError) {
	if !resourcePattern.MatchString(id) {
		return DockerContainer{}, failure(422, "invalid_payload", "Недопустимый Docker resource.")
	}
	raw, apiError := client.request(ctx, http.MethodGet, dockerAPIPrefix+"/containers/"+url.PathEscape(id)+"/json", nil, maxDockerJSON)
	if apiError != nil {
		return DockerContainer{}, apiError
	}
	var container DockerContainer
	if dockerDecode(raw, &container) != nil || !dockerIDPattern.MatchString(container.ID) || !resourcePattern.MatchString(strings.TrimPrefix(container.Name, "/")) {
		return DockerContainer{}, failure(502, "docker_protocol", "Docker не подтвердил идентичность контейнера.")
	}
	if dockerIDPattern.MatchString(id) && container.ID != id {
		return DockerContainer{}, failure(409, "installation_changed", "Идентичность контейнера изменилась.")
	}
	return container, nil
}

// dockerStreams проверяет Docker multiplex и выдаёт только разрешённые потоки.
func dockerStreams(raw []byte, includeStderr bool) ([]byte, *APIError) {
	var output bytes.Buffer
	for len(raw) > 0 {
		if len(raw) < 8 || raw[1] != 0 || raw[2] != 0 || raw[3] != 0 || (raw[0] != 1 && raw[0] != 2) {
			return nil, failure(502, "docker_protocol", "Некорректный поток Docker.")
		}
		length := uint64(binary.BigEndian.Uint32(raw[4:8]))
		if length > uint64(len(raw)-8) {
			return nil, failure(502, "docker_protocol", "Неполный поток Docker.")
		}
		if raw[0] == 1 || includeStderr {
			output.Write(raw[8 : 8+int(length)])
		}
		raw = raw[8+int(length):]
	}
	return output.Bytes(), nil
}

// readCommand строит конечный allowlist argv и не принимает произвольный path.
func readCommand(kind, iface string) ([]string, bool) {
	if kind != "interfaces" && kind != "clients" && !awgInterfacePattern.MatchString(iface) {
		return nil, false
	}
	var command []string
	switch kind {
	case "interfaces":
		command = []string{"awg", "show", "interfaces"}
	case "config_exists":
		command = []string{"test", "-f", "/opt/amnezia/awg/" + iface + ".conf"}
	case "configuration":
		command = []string{"cat", "--", "/opt/amnezia/awg/" + iface + ".conf"}
	case "clients":
		command = []string{"cat", "--", "/opt/amnezia/awg/clientsTable"}
	case "peers":
		command = []string{"awg", "show", iface, "dump"}
	default:
		return nil, false
	}
	return append([]string{"timeout", "-s", "KILL", "8"}, command...), true
}

// Read выполняет только короткую фиксированную команду и подтверждает exit code.
func (client *DockerClient) Read(ctx context.Context, id, kind, iface string) ([]byte, int, *APIError) {
	command, allowed := readCommand(kind, iface)
	if !allowed || !dockerIDPattern.MatchString(id) {
		return nil, -1, failure(422, "invalid_payload", "Чтение Docker не поддерживается.")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	raw, apiError := client.request(ctx, http.MethodPost, dockerAPIPrefix+"/containers/"+id+"/exec", DockerExecRequest{AttachStdout: true, AttachStderr: true, User: "0", Cmd: command}, 4096)
	if apiError != nil {
		return nil, -1, apiError
	}
	var execID DockerIdentifier
	if dockerDecode(raw, &execID) != nil || !dockerIDPattern.MatchString(execID.ID) {
		return nil, -1, failure(502, "docker_protocol", "Docker не подтвердил exec ID.")
	}
	raw, apiError = client.request(ctx, http.MethodPost, dockerAPIPrefix+"/exec/"+execID.ID+"/start", DockerExecStart{}, maxMessageBytes)
	if apiError != nil {
		return nil, -1, apiError
	}
	stdout, streamError := dockerStreams(raw, false)
	if streamError != nil {
		return nil, -1, streamError
	}
	statusRaw, apiError := client.request(ctx, http.MethodGet, dockerAPIPrefix+"/exec/"+execID.ID+"/json", nil, 16384)
	if apiError != nil {
		return nil, -1, apiError
	}
	var status DockerExecStatus
	if dockerDecode(statusRaw, &status) != nil || status.Running || status.ContainerID != id {
		return nil, -1, failure(502, "docker_protocol", "Docker не подтвердил завершение чтения.")
	}
	if status.ExitCode != 0 {
		return nil, status.ExitCode, nil
	}
	return stdout, 0, nil
}

// Logs читает хвост штатного журнала без streaming/follow.
func (client *DockerClient) Logs(ctx context.Context, container DockerContainer, limit int) ([]byte, *APIError) {
	if !dockerIDPattern.MatchString(container.ID) || limit < 1 || limit > 200 {
		return nil, failure(422, "invalid_payload", "Недопустимый запрос журнала.")
	}
	path := dockerAPIPrefix + "/containers/" + container.ID + "/logs?stdout=true&stderr=true&follow=false&tail=" + strconv.Itoa(limit)
	raw, apiError := client.request(ctx, http.MethodGet, path, nil, 512*1024)
	if apiError != nil {
		return nil, apiError
	}
	if container.Config.TTY {
		return raw, nil
	}
	return dockerStreams(raw, true)
}

// Restart выполняет единственное разрешённое изменение Docker по pinned ID.
func (client *DockerClient) Restart(ctx context.Context, id string) *APIError {
	if !dockerIDPattern.MatchString(id) {
		return failure(422, "invalid_payload", "Недопустимый pinned ID.")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	_, apiError := client.request(ctx, http.MethodPost, dockerAPIPrefix+"/containers/"+id+"/restart?t=10", nil, 4096)
	if apiError != nil {
		return failure(502, "mutation_failed", "Результат ручного перезапуска AWG не подтверждён; выполните диагностику.")
	}
	return nil
}
