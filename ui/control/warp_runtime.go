//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

const warpSafePath = "/usr/sbin:/usr/bin:/sbin:/bin"

// WarpConfig описывает совместимые настройки root runtime согласно warp_data_model.md.
type WarpConfig struct {
	SchemaVersion      int    `json:"schema_version"`              // Версия совместимого файла.
	StateDir           string `json:"state_dir"`                   // Каталог приватного состояния.
	ControlUID         int    `json:"control_uid"`                 // Устаревшее поле, не предоставляет доступ.
	AdapterUID         int    `json:"adapter_uid"`                 // UID Docker-адаптера, только 10003.
	SocketGID          int    `json:"socket_gid"`                  // Группа локального сокета, только 10002.
	SupervisorInterval int    `json:"supervisor_interval_seconds"` // Интервал проверки состояния.
	ProbeInterval      int    `json:"probe_interval_seconds"`      // Интервал внешних проб.
}

// WarpRuntime содержит неизменяемые настройки процесса.
type WarpRuntime struct {
	Config     WarpConfig // Проверенная конфигурация.
	Executable string     // Текущий Go-бинарник для DNS-пробы.
}

// WarpSession изолирует ошибку и проверенные ресурсы одной операции.
type WarpSession struct {
	Runtime  *WarpRuntime  // Общие неизменяемые настройки.
	Err      *APIError     // Первая ошибка, останавливающая последующие команды.
	Mutated  bool          // Признак начала изменения состояния.
	Manifest *WarpManifest // Проверенный manifest собственных ресурсов.
	PID      int           // PID сетевого namespace AWG.
	DNSPID   int           // PID сетевого namespace DNS.
}

// WarpPolicy содержит явное намерение пользователя.
type WarpPolicy struct {
	Configured  bool   `json:"configured"`                // Режим выбран пользователем.
	WarpEnabled bool   `json:"warp_enabled"`              // Требуется использовать WARP.
	AllowDirect bool   `json:"allow_direct_without_warp"` // Явное разрешение общего direct fallback.
	Revision    string `json:"revision"`                  // Ревизия трёх сохранённых boolean.
}

// WarpInstallation закрепляет существующие ресурсы без секретов.
type WarpInstallation struct {
	ContainerName    string   `json:"container_name"`             // Имя контейнера AWG.
	ContainerID      string   `json:"container_id"`               // Закреплённый Docker ID.
	Interface        string   `json:"interface"`                  // Имя AWG-интерфейса.
	ConfigPath       string   `json:"config_path"`                // Native путь, без содержимого файла.
	DNSName          string   `json:"dns_container_name"`         // Имя необязательного DNS-контейнера.
	DNSID            string   `json:"dns_container_id,omitempty"` // Закреплённый ID DNS.
	DockerNetwork    string   `json:"docker_network"`             // Явно выбранная сеть.
	Networks         []string `json:"networks"`                   // Наблюдаемые сети AWG.
	Capabilities     []string `json:"capabilities"`               // Совместимые публичные возможности.
	Supported        bool     `json:"supported"`                  // Native layout поддержан.
	Reason           string   `json:"reason"`                     // Безопасное пояснение.
	BaselineRevision string   `json:"baseline_revision"`          // Хеш native конфигурации.
}

// WarpCheck описывает одну диагностическую проверку.
type WarpCheck struct {
	ID        string `json:"id"`         // Стабильный идентификатор проверки.
	Status    string `json:"status"`     // Результат ok/error/warning/unknown.
	Message   string `json:"message"`    // Безопасное пояснение.
	CheckedAt string `json:"checked_at"` // Время проверки.
}

// WarpEgress содержит подтверждённый результат проверки передачи данных.
type WarpEgress struct {
	Path       string  `json:"path"`        // Фактический подтверждённый путь.
	VerifiedAt *string `json:"verified_at"` // Время успешной HTTPS-пробы.
	Message    string  `json:"message"`     // Пояснение результата.
	ObservedAt string  `json:"observed_at"` // Время обновления.
}

// WarpStatus содержит наблюдаемый статус установленного WARP.
type WarpStatus struct {
	Installed     bool   `json:"installed"`      // Наличие warp-cli.
	ServiceActive bool   `json:"service_active"` // Активность systemd службы.
	Connected     bool   `json:"connected"`      // Подтверждённый CLI статус Connected.
	ObservedAt    string `json:"observed_at"`    // Время наблюдения.
}

// WarpBoundedOutput ограничивает суммарный вывод дочернего процесса.
type WarpBoundedOutput struct {
	Mutex    sync.Mutex         // Защита двух потоков вывода.
	Buffer   bytes.Buffer       // Сохраняемый безопасно обрабатываемый поток.
	Total    int                // Суммарное число прочитанных байт.
	Limit    int                // Максимальный разрешённый объём.
	Exceeded bool               // Достигнуто ограничение вывода.
	Cancel   context.CancelFunc // Немедленная остановка процесса.
}

// WarpOutputWriter привязывает поток к общему ограничению.
type WarpOutputWriter struct {
	Output *WarpBoundedOutput // Общий ограничитель stdout и stderr.
	Save   bool               // Нужно сохранить содержимое этого потока.
}

// Write прерывает процесс при превышении суммарного ограничения.
func (w WarpOutputWriter) Write(data []byte) (int, error) {
	w.Output.Mutex.Lock()
	defer w.Output.Mutex.Unlock()
	w.Output.Total += len(data)
	if w.Output.Total > w.Output.Limit {
		w.Output.Exceeded = true
		w.Output.Cancel()
		return 0, errors.New("превышен предел вывода")
	}
	if w.Save {
		_, _ = w.Output.Buffer.Write(data)
	}
	return len(data), nil
}

// warpNow возвращает время UTC в совместимом формате.
func warpNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// warpTimestamp возвращает совместимую Unix-метку для cooldown.
func warpTimestamp() float64 { return float64(time.Now().UnixMilli()) / 1000 }

// warpHash вычисляет SHA-256 канонического JSON со стабильным порядком map-ключей.
func warpHash(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// warpCheck создаёт безопасный диагностический результат.
func warpCheck(id, status, message string) WarpCheck {
	return WarpCheck{ID: id, Status: status, Message: message, CheckedAt: warpNow()}
}

// warpProgram ищет только доверенные системные исполняемые файлы.
func warpProgram(name string) string {
	for _, directory := range strings.Split(warpSafePath, ":") {
		path := filepath.Join(directory, name)
		info, err := os.Stat(path)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			return path
		}
	}
	return ""
}

// warpExecute выполняет один argv без shell, с дедлайном, kill process group и ограничением вывода.
func warpExecute(ctx context.Context, args []string, timeout time.Duration, input string, limit int, stderr bool) (int, string, *APIError) {
	if len(args) == 0 {
		return -1, "", failure(500, "invalid_command", "Пустая системная команда.")
	}
	binary := args[0]
	if !filepath.IsAbs(binary) {
		binary = warpProgram(binary)
	}
	if binary == "" {
		return 127, "", nil
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output := &WarpBoundedOutput{Limit: limit, Cancel: cancel}
	command := exec.CommandContext(commandCtx, binary, args[1:]...)
	command.Env = []string{"PATH=" + warpSafePath, "LANG=C", "LC_ALL=C", "HOME=/root", "DEBIAN_FRONTEND=noninteractive"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdin = strings.NewReader(input)
	command.Stdout = WarpOutputWriter{Output: output, Save: true}
	command.Stderr = WarpOutputWriter{Output: output, Save: stderr}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	err := command.Run()
	if output.Exceeded {
		return -1, "", failure(502, "output_limit", "Системная команда превысила предел вывода.")
	}
	if commandCtx.Err() != nil {
		return -1, "", failure(504, "command_timeout", "Системная команда не завершилась вовремя.")
	}
	if err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode(), output.Buffer.String(), nil
		}
		return -1, "", failure(502, "command_failed", "Не удалось запустить системную команду.")
	}
	return 0, output.Buffer.String(), nil
}

// fail фиксирует первую безопасную ошибку текущей операции.
func (s *WarpSession) fail(code, message string, status int) {
	if s.Err == nil {
		s.Err = failure(status, code, message)
	}
}

// run выполняет команду только пока операция не завершилась ошибкой.
func (s *WarpSession) run(ctx context.Context, args []string, timeout time.Duration, input string, allow bool) (int, string) {
	if s.Err != nil {
		return -1, ""
	}
	aptCommand := len(args) > 0 && filepath.Base(args[0]) == "apt-get"
	code, output, err := warpExecute(ctx, args, timeout, input, maxMessageBytes, aptCommand)
	if err != nil {
		s.Err = err
		return -1, ""
	}
	if code != 0 && !allow {
		program := filepath.Base(args[0])
		if !warpSafeName(program) {
			program = "system_command"
		}
		message := fmt.Sprintf("Системная команда %s завершилась с кодом %d; аргументы и сырые данные скрыты.", program, code)
		if aptCommand {
			for _, cause := range []string{"Permission denied", "Could not get lock", "Unable to locate package", "Temporary failure resolving", "Could not resolve", "dpkg was interrupted", "NO_PUBKEY", "not enough free space", "Unable to fetch some archives", "Sub-process", "Could not open lock file"} {
				if strings.Contains(output, cause) {
					message += " APT: " + cause + "."
				}
			}
		}
		s.fail("command_failed", message, 502)
	}
	return code, output
}

// command выполняет ограниченную штатную команду.
func (s *WarpSession) command(ctx context.Context, args ...string) string {
	_, output := s.run(ctx, args, 8*time.Second, "", false)
	return output
}

// optional выполняет команду, допускающую штатный ненулевой код.
func (s *WarpSession) optional(ctx context.Context, args ...string) (int, string) {
	return s.run(ctx, args, 8*time.Second, "", true)
}

// jsonCommand читает ограниченный JSON Docker/ip только во внутреннюю память.
func (s *WarpSession) jsonCommand(ctx context.Context, args ...string) any {
	raw := s.command(ctx, args...)
	if s.Err != nil {
		return nil
	}
	var value any
	if err := decodeStrict([]byte(raw), &value); err != nil {
		s.fail("invalid_system_state", "Системная команда вернула некорректный JSON.", 502)
	}
	return value
}

// read загружает совместимый приватный JSON без выполнения недоверенных данных.
func (s *WarpSession) read(name string, target any) bool {
	if s.Err != nil {
		return false
	}
	raw, err := readPrivateFile(filepath.Join(s.Runtime.Config.StateDir, name), maxMessageBytes)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil || decodeStrict(raw, target) != nil {
		s.fail("invalid_state", "Невозможно безопасно прочитать состояние WARP runtime.", 500)
		return false
	}
	return true
}

// readMap загружает совместимую вспомогательную запись.
func (s *WarpSession) readMap(name string) map[string]any {
	value := map[string]any{}
	s.read(name, &value)
	if value == nil {
		s.fail("invalid_state", "Повреждена запись состояния WARP runtime.", 500)
		return map[string]any{}
	}
	return value
}

// write атомарно сохраняет приватный JSON и останавливает операцию при ошибке.
func (s *WarpSession) write(name string, value any) {
	if s.Err != nil {
		return
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxMessageBytes {
		s.fail("invalid_state", "Состояние WARP runtime не может быть сохранено.", 500)
		return
	}
	if err := atomicPrivateFile(filepath.Join(s.Runtime.Config.StateDir, name), append(raw, '\n')); err != nil {
		s.fail("state_write_failed", "Не удалось атомарно сохранить состояние WARP runtime.", 500)
	}
}

// event сохраняет ограниченный безопасный журнал без выводов системных команд.
func (s *WarpSession) event(action, status, message string) {
	var events []map[string]any
	s.read("events.json", &events)
	events = append(events, map[string]any{"at": warpNow(), "action": action, "status": status, "message": message})
	if len(events) > 200 {
		events = events[len(events)-200:]
	}
	s.write("events.json", events)
}

// mutation отмечает границу, после которой нельзя заявлять безопасный preflight-отказ.
func (s *WarpSession) mutation(action string) {
	s.Mutated = true
	s.write("mutation_started.json", map[string]any{"action": action, "at": warpNow()})
}

// policy строго проверяет три boolean; повреждение не разрешает direct.
func (s *WarpSession) policy() WarpPolicy {
	value := map[string]any{}
	present := s.read("policy.json", &value)
	if !present && s.Err == nil {
		if s.Manifest != nil {
			s.fail("invalid_policy", "Политика управляемой интеграции отсутствует; прямой выход не разрешён.", 409)
		} else {
			value = map[string]any{"configured": false, "warp_enabled": false, "allow_direct_without_warp": false}
		}
	}
	if len(value) != 3 {
		s.fail("invalid_policy", "Политика повреждена; прямой выход не разрешён.", 409)
	}
	for _, key := range []string{"configured", "warp_enabled", "allow_direct_without_warp"} {
		if _, ok := value[key].(bool); !ok {
			s.fail("invalid_policy", "Политика повреждена; прямой выход не разрешён.", 409)
		}
	}
	return WarpPolicy{Configured: warpBool(value["configured"]), WarpEnabled: warpBool(value["warp_enabled"]), AllowDirect: warpBool(value["allow_direct_without_warp"]), Revision: warpHash(value)}
}

// savePolicy сохраняет только совместимые обязательные поля намерения.
func (s *WarpSession) savePolicy(p WarpPolicy) {
	s.write("policy.json", map[string]any{"configured": p.Configured, "warp_enabled": p.WarpEnabled, "allow_direct_without_warp": p.AllowDirect})
}

// newSession читает только собственный manifest без запросов к Docker.
func (r *WarpRuntime) newSession() *WarpSession {
	s := &WarpSession{Runtime: r}
	var manifest WarpManifest
	if s.read("routing_manifest.json", &manifest) {
		if !manifest.valid() {
			s.fail("invalid_state", "Manifest сетевых ресурсов повреждён.", 500)
		} else {
			s.Manifest = &manifest
		}
	} else if s.Err == nil {
		// Потерянный manifest управляемой интеграции не означает новую установку.
		for _, marker := range []string{"integration_state.json", "integration_baseline.json", "boot_dependencies.json", "guard_state.json"} {
			if _, err := os.Lstat(filepath.Join(r.Config.StateDir, marker)); err == nil || !errors.Is(err, os.ErrNotExist) {
				s.fail("invalid_state", "Manifest управляемых ресурсов отсутствует; запуск требует локального восстановления.", 500)
				break
			}
		}
	}
	return s
}

// validateStoredState проверяет совместимость сохранённой интеграции без команд и записей.
func (s *WarpSession) validateStoredState() {
	if s.Err != nil || s.Manifest == nil {
		return
	}
	policy := s.policy()
	if !policy.Configured {
		s.fail("invalid_policy", "Управляемая интеграция требует явно сохранённой политики.", 409)
	}
	var installation WarpInstallation
	if !s.read("installation.json", &installation) {
		s.fail("invalid_state", "Привязка управляемой интеграции отсутствует или повреждена.", 500)
		return
	}
	m := s.Manifest
	identityMatches := installation.ContainerID == m.ContainerID &&
		installation.ContainerName == m.ContainerName && installation.Interface == m.Interface
	dnsMatches := installation.DNSID == m.DNSID &&
		((installation.DNSName == "" && m.DNSID == "") ||
			(warpSafeName(installation.DNSName) && m.DNSID != ""))
	nativeMatches := installation.ConfigPath == "/opt/amnezia/awg/"+m.Interface+".conf" &&
		installation.Supported && revisionPattern.MatchString(installation.BaselineRevision)
	networkMatches := false
	for _, network := range m.Networks {
		if network.Name == installation.DockerNetwork && network.Bridge == m.DNSBridge {
			networkMatches = true
		}
	}
	if !identityMatches || !dnsMatches || !nativeMatches || !networkMatches {
		s.fail("invalid_state", "Сохранённая привязка не соответствует manifest интеграции.", 500)
	}
}

// warpLoadConfig проверяет root-only настройки и создаёт защищённый каталог состояния.
func warpLoadConfig(path string) (*WarpRuntime, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("WARP runtime требует root")
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("некорректный путь конфигурации")
	}
	if err := verifyDirectoryPath(filepath.Dir(path), false, 0700); err != nil {
		return nil, err
	}
	raw, err := readPrivateFile(path, 16384)
	if err != nil {
		return nil, errors.New("конфигурация WARP runtime недоступна")
	}
	config := WarpConfig{SchemaVersion: 1, StateDir: "/var/lib/awg_vps_control/host", ControlUID: 10002, AdapterUID: 10003, SocketGID: 10002, SupervisorInterval: 15, ProbeInterval: 60}
	if len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
		return nil, errors.New("конфигурация WARP runtime должна быть JSON объектом")
	}
	if err := decodeStrict(raw, &config); err != nil {
		return nil, errors.New("некорректный формат конфигурации WARP runtime")
	}
	if config.SchemaVersion != 1 || config.AdapterUID != 10003 || config.SocketGID != 10002 || config.SupervisorInterval < 5 || config.SupervisorInterval > 300 || config.ProbeInterval < 30 || config.ProbeInterval > 3600 {
		return nil, errors.New("неподдерживаемые настройки WARP runtime")
	}
	if err := verifyDirectoryPath(config.StateDir, true, 0700); err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &WarpRuntime{Config: config, Executable: executable}, nil
}

// lock сериализует API, supervisor и ранний guard посредством flock.
func (r *WarpRuntime) lock(ctx context.Context) (*os.File, error) {
	file, err := openPrivateFile(filepath.Join(r.Config.StateDir, "host.lock"), syscall.O_RDWR|syscall.O_CREAT)
	if err != nil {
		return nil, err
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return file, nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = file.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = file.Close()
			return nil, ctx.Err()
		case <-timer.C:
			_ = file.Close()
			return nil, errors.New("другая операция уже выполняется")
		case <-ticker.C:
		}
	}
}

// warpMap приводит внутренний JSON-объект к map без распространения паник.
func warpMap(value any) map[string]any {
	result, _ := value.(map[string]any)
	if result == nil {
		return map[string]any{}
	}
	return result
}

// warpList возвращает внутренний JSON-массив.
func warpList(value any) []any { result, _ := value.([]any); return result }

// warpString возвращает строковое JSON-поле.
func warpString(value any) string { result, _ := value.(string); return result }

// warpNumber возвращает числовое JSON-поле.
func warpNumber(value any) float64 { result, _ := value.(float64); return result }

// warpBool возвращает логическое JSON-поле.
func warpBool(value any) bool { result, _ := value.(bool); return result }

// warpSafeName проверяет имя Docker-ресурса перед передачей в argv.
func warpSafeName(value string) bool { return resourcePattern.MatchString(value) }

var warpInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
var warpDockerIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// warpPublishFile создаёт публичный fixed файл без перезаписи постороннего содержимого.
func warpPublishFile(path string, content []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0755); err != nil {
		return err
	}
	if err := verifyDirectoryPath(directory, false, 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 {
			return errors.New("небезопасный публичный файл")
		}
		raw, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(raw, content) {
			return errors.New("существующий файл отличается и не будет изменён")
		}
		return os.Chmod(path, 0644)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(directory, ".awg_warp_*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err = file.Chmod(0644); err != nil {
		return err
	}
	if _, err = file.Write(content); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Link(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// warpSafeError возвращает только типизированную ошибку без argv и вывода команд.
func warpSafeError(err error) *APIError {
	var api *APIError
	if errors.As(err, &api) {
		return api
	}
	return failure(500, "runtime_failed", "Операция WARP runtime не завершилась.")
}

// warpReadPublic ограниченно читает системный публичный файл.
func warpReadPublic(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("не удалось прочитать системный файл")
	}
	return raw, nil
}
