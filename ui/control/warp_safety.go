//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const warpSafetyTable = "awg_vps_safety"
const warpSafetyComment = "awg-vps-control safety v1"
const warpSafetyDropin = "/etc/systemd/system/warp-svc.service.d/awg_vps_safety.conf"

// WarpSafetyState хранит независимое разрешение на ограниченное изменение WARP.
type WarpSafetyState struct {
	SchemaVersion         int           `json:"schema_version"`                    // Версия приватной записи.
	ID                    string        `json:"id"`                                // Случайный идентификатор эпохи из 32 hex.
	Status                string        `json:"status"`                            // Armed, confirmed либо held; пусто при отсутствии записи.
	ArmedAt               string        `json:"armed_at"`                          // UTC-время начала ограниченного окна.
	ArmedUptimeTicks      uint64        `json:"armed_uptime_ticks"`                // Монотонная граница создания подтверждающего SSH.
	Deadline              string        `json:"deadline"`                          // UTC-предел подтверждения.
	ConfirmedAt           string        `json:"confirmed_at,omitempty"`            // UTC-время подтверждения новым SSH.
	BootID                string        `json:"boot_id"`                           // Boot, в котором создано окно.
	RescueComplete        bool          `json:"rescue_complete"`                   // Подтверждены остановки служб и конечный blocked guard.
	OriginalSSHConnection string        `json:"original_ssh_connection,omitempty"` // Приватный исходный SSH tuple, скрыт в status.
	Snapshot              *WarpManifest `json:"snapshot,omitempty"`                // Приватный проверенный сетевой snapshot.
	TimerActive           bool          `json:"timer_active"`                      // Наблюдаемая активность timer, не доверяется при чтении файла.
}

// WarpSafetyStep описывает одну независимую попытку аварийного восстановления.
type WarpSafetyStep struct {
	Step      string `json:"step"`      // Фиксированное имя шага.
	Succeeded bool   `json:"succeeded"` // Подтверждённый результат.
	Code      string `json:"code"`      // Безопасный код без вывода команд.
}

// WarpSafetyResult хранит результаты отдельно от политики выхода.
type WarpSafetyResult struct {
	SchemaVersion int              `json:"schema_version"` // Версия журнала аварии.
	ID            string           `json:"id"`             // Эпоха safety state.
	StartedAt     string           `json:"started_at"`     // Начало аварийных попыток.
	FinishedAt    string           `json:"finished_at"`    // Завершение последовательности.
	Steps         []WarpSafetyStep `json:"steps"`          // Ограниченный перечень результатов.
}

// WarpSafetyGuard подтверждает владение только отдельной safety table.
type WarpSafetyGuard struct {
	SchemaVersion int    `json:"schema_version"` // Версия marker владения.
	Table         string `json:"table"`          // Фиксированное имя nft table.
	Comment       string `json:"comment"`        // Фиксированный comment самой таблицы.
}

// WarpSafetyMutation хранит монотонную границу последней опасной команды WARP.
type WarpSafetyMutation struct {
	SchemaVersion     int    `json:"schema_version"`      // Версия приватного marker.
	ID                string `json:"id"`                  // Эпоха разрешения, которой принадлежит отметка.
	BootID            string `json:"boot_id"`             // Загрузка kernel, относительно которой измерены ticks.
	LastMutationTicks uint64 `json:"last_mutation_ticks"` // Конец последней команды или начало незавершённой команды.
	Pending           bool   `json:"pending"`             // Незавершённая полная операция запрещает confirm после crash.
}

// WarpSafetySSH представляет проверенные адреса одного SSH-соединения.
type WarpSafetySSH struct {
	Client       netip.AddrPort // Адрес и порт SSH-клиента.
	Server       netip.AddrPort // Адрес и порт SSH-сервера.
	StartedTicks uint64         // Время создания socket-owning sshd в kernel clock ticks.
}

// safetyFile возвращает путь фиксированной записи в приватном каталоге runtime.
func (r *WarpRuntime) safetyFile(name string) string {
	return filepath.Join(r.Config.StateDir, name)
}

// warpSafetyID проверяет короткий идентификатор, не допускающий systemd specifiers.
func warpSafetyID(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 16 && hex.EncodeToString(raw) == value
}

// warpSafetyNewID создаёт независимую эпоху без пользовательского ввода.
func warpSafetyNewID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("не удалось создать идентификатор защиты")
	}
	return hex.EncodeToString(raw), nil
}

// warpSafetyBootID читает идентичность текущей загрузки из kernel procfs.
func warpSafetyBootID() (string, error) {
	raw, err := warpReadPublic("/proc/sys/kernel/random/boot_id", 64)
	value := strings.TrimSpace(string(raw))
	if err != nil || len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || !warpSafetyID(strings.ReplaceAll(value, "-", "")) {
		return "", errors.New("не подтверждён текущий boot ID")
	}
	return value, nil
}

// safetyLock ограниченно получает отдельную flock, не используя host.lock.
func (r *WarpRuntime) safetyLock(ctx context.Context, rescue bool) (*os.File, error) {
	name := "safety.lock"
	if rescue {
		name = "safety_rescue.lock"
	}
	file, err := openPrivateFile(r.safetyFile(name), syscall.O_RDWR|syscall.O_CREAT)
	if err != nil {
		return nil, errors.New("не удалось открыть блокировку защиты")
	}
	lockCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return file, nil
		}
		if rescue || !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = file.Close()
			return nil, errors.New("другая операция защиты ещё не завершена")
		}
		select {
		case <-lockCtx.Done():
			_ = file.Close()
			return nil, errors.New("защита занята другой операцией")
		case <-ticker.C:
		}
	}
}

// safetyWrite атомарно сохраняет ограниченный JSON без изменения policy.
func (r *WarpRuntime) safetyWrite(name string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxMessageBytes {
		return errors.New("не удалось подготовить состояние защиты")
	}
	if err = atomicPrivateFile(r.safetyFile(name), append(raw, '\n')); err != nil {
		return errors.New("не удалось сохранить состояние защиты")
	}
	return nil
}

// safetyMarker считает любое наличие или ошибку доступа запретом на WARP.
func (r *WarpRuntime) safetyMarker() bool {
	_, err := os.Lstat(r.safetyFile("emergency_hold"))
	return !errors.Is(err, os.ErrNotExist)
}

// safetyPending запрещает resume до завершения отложенного аварийного восстановления.
func (r *WarpRuntime) safetyPending() bool {
	_, err := os.Lstat(r.safetyFile("rescue_pending"))
	return !errors.Is(err, os.ErrNotExist)
}

// safetyQueueRescue делает незавершённую аварию durable прежде отпускания CLI lock.
func (r *WarpRuntime) safetyQueueRescue(state *WarpSafetyState) error {
	state.RescueComplete = false
	holdErr := r.safetyMarkHeld(state)
	pendingErr := atomicPrivateFile(r.safetyFile("rescue_pending"), []byte(state.ID+"\n"))
	return errors.Join(holdErr, pendingErr)
}

// safetyRead проверяет все сохранённые разрешения, не доверяя timer_active из файла.
func (r *WarpRuntime) safetyRead() (WarpSafetyState, error) {
	var state WarpSafetyState
	raw, err := readPrivateFile(r.safetyFile("safety_state.json"), maxMessageBytes)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil || decodeStrict(raw, &state) != nil || state.SchemaVersion != 1 || !warpSafetyID(state.ID) {
		return WarpSafetyState{}, errors.New("повреждено состояние защиты")
	}
	state.TimerActive = false
	if state.Status != "armed" && state.Status != "confirmed" && state.Status != "held" {
		return WarpSafetyState{}, errors.New("неизвестное состояние защиты")
	}
	if state.Snapshot != nil && !state.Snapshot.valid() {
		return WarpSafetyState{}, errors.New("повреждён snapshot защиты")
	}
	if state.Status != "held" {
		start, startErr := time.Parse(time.RFC3339Nano, state.ArmedAt)
		deadline, deadlineErr := time.Parse(time.RFC3339Nano, state.Deadline)
		_, sshErr := warpSafetyParseSSH(state.OriginalSSHConnection)
		boot := strings.ReplaceAll(state.BootID, "-", "")
		if startErr != nil || deadlineErr != nil || start.Location() != time.UTC || deadline.Location() != time.UTC || deadline.Sub(start) < 60*time.Second || deadline.Sub(start) > 600*time.Second || sshErr != nil || state.Snapshot == nil || state.ArmedUptimeTicks == 0 || len(state.BootID) != 36 || !warpSafetyID(boot) {
			return WarpSafetyState{}, errors.New("неполное разрешение защиты")
		}
		if state.Status == "confirmed" {
			confirmed, parseErr := time.Parse(time.RFC3339Nano, state.ConfirmedAt)
			if parseErr != nil || confirmed.Before(start) || !confirmed.Before(deadline) {
				return WarpSafetyState{}, errors.New("неподтверждённое время проверки SSH")
			}
		}
	}
	return state, nil
}

// warpSafetyTimerUnit строит фиксированное имя независимого transient timer.
func warpSafetyTimerUnit(id string) string {
	return "awg_vps_warp_rescue_" + id + ".timer"
}

// safetyTimerActive проверяет живой timer непосредственно у systemd.
func (r *WarpRuntime) safetyTimerActive(ctx context.Context, id string) bool {
	if !warpSafetyID(id) {
		return false
	}
	code, raw, err := warpExecute(ctx, []string{"systemctl", "show", "--property=LoadState", "--property=ActiveState", "--property=SubState", warpSafetyTimerUnit(id)}, 3*time.Second, "", 4096, false)
	properties := "\n" + raw + "\n"
	return err == nil && code == 0 && strings.Contains(properties, "\nLoadState=loaded\n") && strings.Contains(properties, "\nActiveState=active\n") && strings.Contains(properties, "\nSubState=waiting\n")
}

// safetyLease проверяет атомарные записи без flock, перечитывая эпоху после systemd.
func (r *WarpRuntime) safetyLease(ctx context.Context, armedOnly bool) (WarpSafetyState, *APIError) {
	state, err := r.safetyRead()
	if r.safetyMarker() || r.safetyPending() || err != nil || state.Status == "held" {
		return state, failure(409, "safety_held", "Аварийное удержание запрещает изменения WARP.")
	}
	if state.Status == "confirmed" && !armedOnly {
		current, readErr := r.safetyRead()
		if readErr == nil && current.ID == state.ID && current.Status == "confirmed" && !r.safetyMarker() && !r.safetyPending() {
			return state, nil
		}
		return state, failure(409, "safety_held", "Аварийное удержание запрещает изменения WARP.")
	}
	if state.Status != "armed" {
		return state, failure(409, "safety_required", "Сначала вооружите защиту из SSH-сеанса.")
	}
	boot, bootErr := warpSafetyBootID()
	start, _ := time.Parse(time.RFC3339Nano, state.ArmedAt)
	deadline, _ := time.Parse(time.RFC3339Nano, state.Deadline)
	if bootErr != nil || boot != state.BootID || time.Now().Before(start) || !time.Now().Before(deadline) || !r.safetyTimerActive(ctx, state.ID) {
		return state, failure(409, "safety_expired", "Окно защиты истекло или независимый таймер недоступен.")
	}
	current, readErr := r.safetyRead()
	if readErr != nil || current.ID != state.ID || current.Status != state.Status || r.safetyMarker() || r.safetyPending() || !time.Now().Before(deadline) {
		return state, failure(409, "safety_changed", "Разрешение защиты изменилось во время проверки.")
	}
	state.TimerActive = true
	return state, nil
}

// requireSafety не разрешает сетевую мутацию при неизвестном результате проверки.
func (s *WarpSession) requireSafety(ctx context.Context, armedOnly bool) bool {
	if s.Err != nil {
		return false
	}
	_, apiError := s.Runtime.safetyLease(ctx, armedOnly)
	if apiError != nil {
		s.Err = apiError
		return false
	}
	return s.safetyMutationFinished(ctx)
}

// safetyMutationFinished ставит границу без flock; caller удерживает обычный host.lock.
func (s *WarpSession) safetyMutationFinished(ctx context.Context) bool {
	return s.safetyMutationRecord(ctx, true)
}

// safetyOperationFinished снимает pending только у записавшей его текущей сессии.
func (s *WarpSession) safetyOperationFinished(ctx context.Context) bool {
	if !s.SafetyPending {
		return true
	}
	return s.safetyMutationRecord(ctx, false)
}

// safetyMutationRecord сохраняет начало/конец полной операции атомарно без safety flock.
func (s *WarpSession) safetyMutationRecord(ctx context.Context, pending bool) bool {
	state, err := s.Runtime.safetyRead()
	if err != nil || s.Runtime.safetyMarker() || s.Runtime.safetyPending() || state.Status == "held" || state.Status == "" {
		s.fail("safety_held", "Разрешение защиты изменилось во время сетевой операции.", 409)
		return false
	}
	if state.Status == "confirmed" {
		return true
	}
	ticks, err := warpSafetyUptimeTicks(ctx)
	if err == nil {
		err = s.Runtime.safetyWrite("safety_mutation.json", WarpSafetyMutation{SchemaVersion: 1, ID: state.ID, BootID: state.BootID, LastMutationTicks: ticks, Pending: pending})
		if err == nil {
			s.SafetyPending = pending
		}
	}
	current, currentErr := s.Runtime.safetyRead()
	if err != nil || currentErr != nil || current.ID != state.ID || current.Status != "armed" || s.Runtime.safetyMarker() {
		// Неизвестный конец команды не может разрешить преждевременный confirm.
		if err != nil && currentErr == nil && current.ID == state.ID {
			_ = atomicPrivateFile(s.Runtime.safetyFile("emergency_hold"), []byte("held\n"))
		}
		s.fail("safety_changed", "Монотонная граница сетевой операции не подтверждена.", 409)
		return false
	}
	return true
}

// safetyMutationBoundary читает последнюю границу текущей эпохи без доверия старым markers.
func (r *WarpRuntime) safetyMutationBoundary(state WarpSafetyState) (uint64, error) {
	var marker WarpSafetyMutation
	raw, err := readPrivateFile(r.safetyFile("safety_mutation.json"), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return state.ArmedUptimeTicks, nil
	}
	if err != nil || decodeStrict(raw, &marker) != nil || marker.SchemaVersion != 1 || !warpSafetyID(marker.ID) || marker.LastMutationTicks == 0 {
		return 0, errors.New("не подтверждена граница сетевой операции")
	}
	var fields map[string]any
	if decodeStrict(raw, &fields) != nil {
		return 0, errors.New("повреждён marker сетевой операции")
	}
	if _, present := fields["pending"].(bool); !present {
		return 0, errors.New("отсутствует явное состояние завершения сетевой операции")
	}
	if marker.ID != state.ID {
		return state.ArmedUptimeTicks, nil
	}
	if marker.BootID != state.BootID || marker.LastMutationTicks < state.ArmedUptimeTicks {
		return 0, errors.New("граница сетевой операции относится к другой загрузке")
	}
	if marker.Pending {
		return 0, errors.New("сетевая операция не завершена; confirm запрещён")
	}
	return marker.LastMutationTicks, nil
}

// safetyStatus возвращает только безопасную публичную проекцию разрешения.
func (r *WarpRuntime) safetyStatus() (WarpSafetyState, *APIError) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	state, readErr := r.safetyRead()
	if readErr != nil {
		return WarpSafetyState{Status: "held"}, failure(409, "safety_invalid", "Повреждено состояние защиты; изменения запрещены.")
	}
	if r.safetyMarker() || r.safetyPending() {
		state.Status = "held"
	} else if state.Status == "armed" {
		if checked, apiError := r.safetyLease(ctx, true); apiError != nil {
			state.Status = "held"
		} else {
			state.TimerActive = checked.TimerActive
		}
	}
	state.OriginalSSHConnection = ""
	state.Snapshot = nil
	return state, nil
}

// safetyHeld сохраняет старое поведение AWG без WARP при полном отсутствии safety state.
func (r *WarpRuntime) safetyHeld() bool {
	if r.safetyMarker() || r.safetyPending() {
		return true
	}
	state, err := r.safetyStatus()
	return err != nil || state.Status == "held"
}

// warpSafetyParseSSH принимает ровно четыре поля SSH_CONNECTION без shell-синтаксиса.
func warpSafetyParseSSH(raw string) (WarpSafetySSH, error) {
	parts := strings.Fields(raw)
	if len(parts) != 4 || len(raw) > 256 {
		return WarpSafetySSH{}, errors.New("требуется SSH_CONNECTION из текущего SSH-сеанса")
	}
	client, clientErr := netip.ParseAddr(parts[0])
	server, serverErr := netip.ParseAddr(parts[2])
	clientPort, clientPortErr := strconv.ParseUint(parts[1], 10, 16)
	serverPort, serverPortErr := strconv.ParseUint(parts[3], 10, 16)
	if clientErr != nil || serverErr != nil || clientPortErr != nil || serverPortErr != nil || clientPort == 0 || serverPort == 0 || client.Zone() != "" || server.Zone() != "" || client.IsUnspecified() || server.IsUnspecified() || client.IsMulticast() || server.IsMulticast() {
		return WarpSafetySSH{}, errors.New("некорректный SSH_CONNECTION")
	}
	return WarpSafetySSH{Client: netip.AddrPortFrom(client.Unmap(), uint16(clientPort)), Server: netip.AddrPortFrom(server.Unmap(), uint16(serverPort))}, nil
}

// connection возвращает канонический приватный tuple без произвольных полей.
func (ssh WarpSafetySSH) connection() string {
	return fmt.Sprintf("%s %d %s %d", ssh.Client.Addr(), ssh.Client.Port(), ssh.Server.Addr(), ssh.Server.Port())
}

// warpSafetyProcAddress декодирует little-endian слова Linux proc TCP таблицы.
func warpSafetyProcAddress(raw string) (netip.AddrPort, bool) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return netip.AddrPort{}, false
	}
	address, err := hex.DecodeString(parts[0])
	port, portErr := strconv.ParseUint(parts[1], 16, 16)
	if err != nil || portErr != nil || (len(address) != 4 && len(address) != 16) {
		return netip.AddrPort{}, false
	}
	for offset := 0; offset < len(address); offset += 4 {
		address[offset], address[offset+3] = address[offset+3], address[offset]
		address[offset+1], address[offset+2] = address[offset+2], address[offset+1]
	}
	ip, ok := netip.AddrFromSlice(address)
	return netip.AddrPortFrom(ip.Unmap(), uint16(port)), ok
}

// warpSafetyUptimeTicks получает kernel clock ticks без предположения о частоте HZ.
func warpSafetyUptimeTicks(ctx context.Context) (uint64, error) {
	code, output, apiError := warpExecute(ctx, []string{"getconf", "CLK_TCK"}, 3*time.Second, "", 128, false)
	hz, parseErr := strconv.ParseUint(strings.TrimSpace(output), 10, 64)
	raw, readErr := warpReadPublic("/proc/uptime", 128)
	fields := strings.Fields(string(raw))
	if apiError != nil || code != 0 || parseErr != nil || hz == 0 || hz > 1000000 || readErr != nil || len(fields) != 2 {
		return 0, errors.New("не подтверждены монотонные часы SSH")
	}
	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || !(uptime > 0 && uptime < 1e10) {
		return 0, errors.New("не подтверждён uptime SSH")
	}
	return uint64(math.Ceil(uptime*float64(hz))) + 1, nil
}

// warpSafetyCurrentSSH подтверждает socket именно у SSH-предка и сохраняет его starttime.
func warpSafetyCurrentSSH() (WarpSafetySSH, error) {
	ssh, err := warpSafetyParseSSH(os.Getenv("SSH_CONNECTION"))
	if err != nil {
		return ssh, err
	}
	inodes := map[string]bool{}
	for _, name := range []string{"tcp", "tcp6"} {
		raw, readErr := warpReadPublic("/proc/net/"+name, maxMessageBytes)
		if readErr != nil {
			return ssh, errors.New("не удалось подтвердить SSH socket")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "01" {
				continue
			}
			local, localOK := warpSafetyProcAddress(fields[1])
			remote, remoteOK := warpSafetyProcAddress(fields[2])
			if localOK && remoteOK && local == ssh.Server && remote == ssh.Client {
				if _, parseErr := strconv.ParseUint(fields[9], 10, 64); parseErr == nil {
					inodes["socket:["+fields[9]+"]"] = true
				}
			}
		}
	}
	pid := os.Getpid()
	for depth := 0; depth < 64 && pid > 1; depth++ {
		base := "/proc/" + strconv.Itoa(pid)
		comm, _ := warpReadPublic(base+"/comm", 256)
		name := strings.TrimSpace(string(comm))
		sshAncestor := name == "sshd" || name == "sshd-session"
		socketAncestor := false
		entries, readErr := os.ReadDir(base + "/fd")
		if readErr == nil && len(entries) <= 4096 {
			for _, entry := range entries {
				link, linkErr := os.Readlink(base + "/fd/" + entry.Name())
				if linkErr == nil && inodes[link] {
					socketAncestor = true
				}
			}
		}
		stat, statErr := warpReadPublic(base+"/stat", 4096)
		end := strings.LastIndexByte(string(stat), ')')
		if statErr != nil || end < 0 {
			break
		}
		fields := strings.Fields(string(stat)[end+1:])
		if len(fields) < 20 {
			break
		}
		if sshAncestor && socketAncestor {
			started, parseErr := strconv.ParseUint(fields[19], 10, 64)
			if parseErr == nil && started > ssh.StartedTicks {
				ssh.StartedTicks = started
			}
		}
		parent, parentErr := strconv.Atoi(fields[1])
		if parentErr != nil || parent <= 0 || parent == pid {
			break
		}
		pid = parent
	}
	if ssh.StartedTicks == 0 {
		return ssh, errors.New("команда должна выполняться из живого обычного SSH-сеанса")
	}
	return ssh, nil
}

// warpSafetyPath допускает только абсолютный путь без systemd specifiers и подстановок.
func warpSafetyPath(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, char := range path {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || strings.ContainsRune("/._-", char)) {
			return false
		}
	}
	return true
}

// safetyGate устанавливает отдельный drop-in, не меняя зависимость раннего guard.
func (r *WarpRuntime) safetyGate(ctx context.Context, configPath string) error {
	if !warpSafetyPath(configPath) || !warpSafetyPath(r.Config.StateDir) {
		return errors.New("неподдерживаемый путь для systemd защиты")
	}
	directory := filepath.Dir(warpSafetyDropin)
	if err := verifyDirectoryPath(filepath.Dir(directory), false, 0755); err != nil {
		return errors.New("небезопасный родитель systemd drop-in")
	}
	if err := os.Mkdir(directory, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return errors.New("не удалось создать каталог systemd drop-in")
	}
	// Umask 077 допустим: systemd читает drop-in от root; посторонняя запись запрещена.
	if err := verifyDirectoryPath(directory, false, 0755); err != nil {
		return errors.New("небезопасный каталог systemd drop-in")
	}
	content := "[Unit]\nConditionPathExists=!" + r.safetyFile("emergency_hold") + "\n[Service]\nExecCondition=/opt/awg_vps_control/current/bin/awg_control warp safety --config " + configPath + " check\n"
	if err := warpPublishFile(warpSafetyDropin, []byte(content)); err != nil {
		return errors.New("safety drop-in отсутствует или занят другим содержимым")
	}
	code, _, apiError := warpExecute(ctx, []string{"systemctl", "daemon-reload"}, 8*time.Second, "", 4096, false)
	if apiError != nil || code != 0 {
		return errors.New("systemd не подтвердил загрузку safety gate")
	}
	return nil
}

// safetyStartTimer закрепляет реальный executable, не сохраняя изменяемую current-ссылку.
func (r *WarpRuntime) safetyStartTimer(ctx context.Context, configPath string, state WarpSafetyState, seconds int) error {
	executable, err := filepath.EvalSymlinks(r.Executable)
	if err != nil || !warpSafetyPath(executable) || !warpSafetyPath(configPath) {
		return errors.New("не удалось закрепить executable защиты")
	}
	if err := verifyDirectoryPath(filepath.Dir(executable), false, 0755); err != nil {
		return errors.New("небезопасный каталог executable защиты")
	}
	info, err := os.Lstat(executable)
	if err != nil {
		return errors.New("executable защиты недоступен")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
		return errors.New("неподтверждённый executable защиты")
	}
	args := []string{"systemd-run", "--quiet", "--collect", "--unit", "awg_vps_warp_rescue_" + state.ID, "--on-active", strconv.Itoa(seconds) + "s", "--timer-property", "AccuracySec=1s", "--property", "User=root", "--property", "Group=root", "--property", "KillMode=control-group", "--property", "TimeoutStopSec=15s", executable, "warp", "safety", "--config", configPath, "expire", state.ID}
	code, _, apiError := warpExecute(ctx, args, 10*time.Second, "", 4096, false)
	if apiError != nil || code != 0 || !r.safetyTimerActive(ctx, state.ID) {
		return errors.New("независимый timer защиты не подтвердил готовность")
	}
	return nil
}

// safetyMarkHeld сначала фиксирует независимый durable hold, затем held JSON.
func (r *WarpRuntime) safetyMarkHeld(state *WarpSafetyState) error {
	markerErr := atomicPrivateFile(r.safetyFile("emergency_hold"), []byte("held\n"))
	if !warpSafetyID(state.ID) {
		id, err := warpSafetyNewID()
		if err != nil {
			return err
		}
		state.ID = id
	}
	state.SchemaVersion = 1
	state.Status = "held"
	state.TimerActive = false
	if state.Snapshot == nil {
		var snapshot WarpManifest
		raw, err := readPrivateFile(r.safetyFile("routing_manifest.json"), maxMessageBytes)
		if err == nil && decodeStrict(raw, &snapshot) == nil && snapshot.valid() {
			state.Snapshot = &snapshot
		}
	}
	writeErr := r.safetyWrite("safety_state.json", state)
	if markerErr != nil || writeErr != nil {
		return errors.New("не удалось полностью сохранить аварийное удержание")
	}
	return nil
}

// safetyRemoveHold удаляет только проверенный marker после запуска нового timer.
func (r *WarpRuntime) safetyRemoveHold() error {
	path := r.safetyFile("emergency_hold")
	file, err := openPrivateFile(path, syscall.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("не удалось проверить marker удержания")
	}
	if err = file.Close(); err != nil {
		return err
	}
	if err = os.Remove(path); err != nil {
		return err
	}
	directory, err := os.Open(r.Config.StateDir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// safetyCanArm отклоняет повторное вооружение до длительного preflight.
func (r *WarpRuntime) safetyCanArm(resume bool) error {
	previous, readErr := r.safetyRead()
	if r.safetyPending() || resume && (readErr != nil || !previous.RescueComplete) {
		return errors.New("аварийное восстановление не завершено; сначала выполните hold и проверьте результат")
	}
	if previous.Status == "armed" {
		return errors.New("окно уже вооружено; сначала завершите или удержите его")
	}
	held := r.safetyMarker() || previous.Status == "held" || readErr != nil
	if resume != held {
		return errors.New("для удержания требуется resume; для нового окна используется arm")
	}
	return nil
}

// safetyArm создаёт новое окно; внешние команды не выполняются под safety flock.
func (r *WarpRuntime) safetyArm(ctx context.Context, configPath string, seconds int, resume bool) (WarpSafetyState, error) {
	var result WarpSafetyState
	if err := r.safetyCanArm(resume); err != nil {
		return result, err
	}
	ssh, err := warpSafetyCurrentSSH()
	if err != nil {
		return result, err
	}
	boot, err := warpSafetyBootID()
	if err != nil {
		return result, err
	}
	hostLock, err := r.lock(ctx)
	if err != nil {
		return result, err
	}
	defer hostLock.Close()
	session := r.newSession()
	snapshot := session.preflight(ctx)
	if session.Err != nil {
		return result, session.Err
	}
	if snapshot == nil || !snapshot.valid() {
		return result, errors.New("не подтверждён snapshot для аварийной защиты")
	}
	ticks, err := warpSafetyUptimeTicks(ctx)
	if err != nil {
		return result, err
	}
	id, err := warpSafetyNewID()
	if err != nil {
		return result, err
	}
	now := time.Now().UTC()
	result = WarpSafetyState{SchemaVersion: 1, ID: id, Status: "armed", ArmedAt: now.Format(time.RFC3339Nano), ArmedUptimeTicks: ticks, Deadline: now.Add(time.Duration(seconds) * time.Second).Format(time.RFC3339Nano), BootID: boot, OriginalSSHConnection: ssh.connection(), Snapshot: snapshot}
	rescue, err := r.safetyLock(ctx, true)
	if err != nil {
		return WarpSafetyState{}, err
	}
	lock, err := r.safetyLock(ctx, false)
	if err != nil {
		_ = rescue.Close()
		return WarpSafetyState{}, err
	}
	err = r.safetyCanArm(resume)
	if err == nil {
		err = r.safetyWrite("safety_state.json", result)
	}
	_ = lock.Close()
	_ = rescue.Close()
	if err != nil {
		return WarpSafetyState{}, err
	}
	if err == nil {
		err = r.safetyGate(ctx, configPath)
	}
	if err == nil {
		err = r.safetyStartTimer(ctx, configPath, result, seconds)
	}
	lock, lockErr := r.safetyLock(ctx, false)
	if lockErr != nil {
		current, _ := r.safetyRead()
		if current.ID == id {
			_ = atomicPrivateFile(r.safetyFile("emergency_hold"), []byte("held\n"))
			_ = atomicPrivateFile(r.safetyFile("rescue_pending"), []byte(id+"\n"))
		}
		return result, errors.Join(err, lockErr)
	}
	defer lock.Close()
	current, readErr := r.safetyRead()
	deadline, _ := time.Parse(time.RFC3339Nano, result.Deadline)
	if readErr != nil || current.ID != id || current.Status != "armed" {
		return result, errors.New("эпоха защиты изменилась при вооружении; удержание не снимается")
	}
	if !time.Now().Before(deadline) || r.safetyPending() || !resume && r.safetyMarker() {
		err = errors.New("окно истекло или было аварийно удержано при вооружении")
	}
	if err == nil && resume {
		err = r.safetyRemoveHold()
	}
	if err != nil {
		holdErr := r.safetyQueueRescue(&result)
		return result, errors.Join(err, holdErr)
	}
	result.TimerActive = true
	return result, nil
}

// safetyConfirm сохраняет подтверждение прежде остановки timer.
func (r *WarpRuntime) safetyConfirm(ctx context.Context, id string) error {
	hostLock, err := r.lock(ctx)
	if err != nil {
		return errors.New("сетевые операции ещё выполняются; подтверждение SSH отложено")
	}
	defer hostLock.Close()
	ssh, err := warpSafetyCurrentSSH()
	if err != nil {
		return err
	}
	state, apiError := r.safetyLease(ctx, true)
	if apiError != nil {
		return apiError
	}
	// Connect асинхронен: подтверждаем уже проверенный supervisor путь, сохраняя rescue независимым.
	session := r.newSession()
	policy := session.policy()
	if session.Err != nil {
		return session.Err
	}
	if policy.Configured && policy.WarpEnabled {
		status := session.status(ctx)
		var egress WarpEgress
		if !session.read("egress.json", &egress) || session.Err != nil || !status.ServiceActive || !status.Connected || egress.Path != "warp" || egress.VerifiedAt == nil {
			return errors.New("WARP ещё не подтвердил активное подключение и проверенный выход; таймер защиты сохраняется")
		}
		verifiedAt, verifiedErr := time.Parse(time.RFC3339Nano, *egress.VerifiedAt)
		armedAt, armedErr := time.Parse(time.RFC3339Nano, state.ArmedAt)
		now := time.Now()
		if verifiedErr != nil || armedErr != nil || verifiedAt.Before(armedAt) || verifiedAt.After(now) || now.Sub(verifiedAt) > 120*time.Second {
			return errors.New("для подтверждения нужна свежая проверка выхода через WARP после arm; таймер защиты сохраняется")
		}
	}
	lock, err := r.safetyLock(ctx, false)
	if err != nil {
		return err
	}
	current, readErr := r.safetyRead()
	boundary, boundaryErr := r.safetyMutationBoundary(state)
	deadline, _ := time.Parse(time.RFC3339Nano, state.Deadline)
	if readErr != nil || boundaryErr != nil || current.ID != state.ID || current.Status != "armed" || r.safetyMarker() || r.safetyPending() || !time.Now().Before(deadline) || state.ID != id || state.OriginalSSHConnection == ssh.connection() || ssh.StartedTicks <= boundary {
		_ = lock.Close()
		return errors.New("подтверждение требует текущий ID и SSH-соединение, созданное после последней сетевой операции")
	}
	state.Status = "confirmed"
	state.ConfirmedAt = warpNow()
	state.TimerActive = false
	err = r.safetyWrite("safety_state.json", state)
	closeErr := lock.Close()
	if err != nil || closeErr != nil || r.safetyMarker() || r.safetyPending() {
		return errors.New("подтверждение SSH не сохранено")
	}
	code, _, commandErr := warpExecute(ctx, []string{"systemctl", "stop", warpSafetyTimerUnit(id)}, 5*time.Second, "", 4096, false)
	if commandErr != nil || code != 0 {
		return errors.New("SSH подтверждён, но остановка прежнего timer не подтверждена; его expire будет пропущен")
	}
	return nil
}

// safetyCLI обрабатывает только фиксированные root-команды, не принимая shell/пути из args.
func (r *WarpRuntime) safetyCLI(ctx context.Context, configPath string, args []string) error {
	if os.Geteuid() != 0 || len(args) == 0 {
		return errors.New("нужна root-команда safety: arm, confirm, status, check, hold, resume или expire")
	}
	switch args[0] {
	case "arm", "resume":
		seconds := 300
		if len(args) == 3 && args[1] == "--seconds" {
			parsed, err := strconv.Atoi(args[2])
			if err != nil || parsed < 60 || parsed > 600 {
				return errors.New("интервал защиты должен быть 60..600 секунд")
			}
			seconds = parsed
		} else if len(args) != 1 {
			return errors.New("ожидается arm/resume [--seconds N]")
		}
		state, err := r.safetyArm(ctx, configPath, seconds, args[0] == "resume")
		if err != nil {
			if state.Status == "held" {
				_ = r.safetyRescue(ctx, state)
			}
			return err
		}
		return r.safetyPrint()
	case "confirm":
		if len(args) != 2 || !warpSafetyID(args[1]) {
			return errors.New("confirm требует текущий safety ID")
		}
		if err := r.safetyConfirm(ctx, args[1]); err != nil {
			return err
		}
		return r.safetyPrint()
	case "status":
		if len(args) != 1 {
			return errors.New("status не принимает параметры")
		}
		return r.safetyPrint()
	case "check":
		if len(args) != 1 {
			return errors.New("check не принимает параметры")
		}
		_, apiError := r.safetyLease(ctx, false)
		if apiError != nil {
			return apiError
		}
		return nil
	case "hold", "expire":
		id := ""
		if args[0] == "expire" {
			if len(args) != 2 || !warpSafetyID(args[1]) {
				return errors.New("expire требует safety ID")
			}
			id = args[1]
		} else if len(args) != 1 {
			return errors.New("hold не принимает параметры")
		}
		return r.safetyExpire(ctx, id)
	default:
		return errors.New("неизвестная команда safety")
	}
}

// safetyPrint печатает status без приватных SSH/network полей.
func (r *WarpRuntime) safetyPrint() error {
	state, apiError := r.safetyStatus()
	if apiError != nil {
		return apiError
	}
	return json.NewEncoder(os.Stdout).Encode(state)
}

// safetyOwnedTable различает отсутствие таблицы и неподтверждённое владение.
func (r *WarpRuntime) safetyOwnedTable(ctx context.Context) (bool, error) {
	var owner WarpSafetyGuard
	rawOwner, ownerErr := readPrivateFile(r.safetyFile("safety_guard.json"), 4096)
	ownerMissing := errors.Is(ownerErr, os.ErrNotExist)
	if !ownerMissing && (ownerErr != nil || decodeStrict(rawOwner, &owner) != nil || owner.SchemaVersion != 1 || owner.Table != warpSafetyTable || owner.Comment != warpSafetyComment) {
		return false, errors.New("не подтверждено владение safety table")
	}
	code, raw, apiError := warpExecute(ctx, []string{"nft", "--json", "list", "tables"}, 5*time.Second, "", 131072, false)
	var response map[string]any
	if apiError != nil || code != 0 || decodeStrict([]byte(raw), &response) != nil {
		return false, errors.New("не удалось проверить существующие nft tables")
	}
	if _, ok := response["nftables"].([]any); !ok {
		return false, errors.New("неподдерживаемый ответ списка nft tables")
	}
	exists := false
	for _, item := range warpList(response["nftables"]) {
		table := warpMap(warpMap(item)["table"])
		if warpString(table["family"]) == "inet" && warpString(table["name"]) == warpSafetyTable {
			exists = true
		}
	}
	if !exists {
		return false, nil
	}
	if ownerMissing {
		return true, errors.New("имя safety table занято без marker владения")
	}
	code, raw, apiError = warpExecute(ctx, []string{"nft", "--json", "list", "table", "inet", warpSafetyTable}, 5*time.Second, "", 131072, false)
	if apiError != nil || code != 0 || decodeStrict([]byte(raw), &response) != nil {
		return true, errors.New("содержимое safety table не подтверждено")
	}
	for _, item := range warpList(response["nftables"]) {
		table := warpMap(warpMap(item)["table"])
		if warpString(table["family"]) == "inet" && warpString(table["name"]) == warpSafetyTable && warpString(table["comment"]) == warpSafetyComment {
			return true, nil
		}
	}
	return true, errors.New("safety table имеет посторонний comment")
}

// safetyBlock применяет отдельный blocked guard без Docker, host.lock и canonical state writes.
func (r *WarpRuntime) safetyBlock(ctx context.Context, snapshot *WarpManifest) error {
	if snapshot == nil || !snapshot.valid() {
		return errors.New("нет проверенного snapshot для блокировки клиента")
	}
	exists, err := r.safetyOwnedTable(ctx)
	if err != nil {
		return err
	}
	if err := r.safetyWrite("safety_guard.json", WarpSafetyGuard{SchemaVersion: 1, Table: warpSafetyTable, Comment: warpSafetyComment}); err != nil {
		return err
	}
	m := snapshot
	var forward []string
	if m.DNSIP != "" {
		for _, protocol := range []string{"udp", "tcp"} {
			forward = append(forward, fmt.Sprintf("iifname %q ip daddr %s %s dport 53 accept", warpLaneHost, m.DNSIP, protocol), fmt.Sprintf("ip saddr %s ip daddr %s %s sport 53 accept", m.DNSIP, m.ClientNetwork, protocol))
		}
	}
	forward = append(forward, fmt.Sprintf("iifname %q oifname %q ip daddr %s accept", warpLaneHost, warpLaneHost, m.ClientNetwork))
	for _, address := range m.AWGIPs {
		forward = append(forward, fmt.Sprintf("ip saddr %s udp sport %d ct direction reply ct status dnat accept", address, m.AWGPort), fmt.Sprintf("ip daddr %s udp dport %d ct direction original ct status dnat accept", address, m.AWGPort))
	}
	forward = append(forward, fmt.Sprintf("iifname %q drop", warpLaneHost), fmt.Sprintf("oifname %q drop", warpLaneHost))
	input := []string{fmt.Sprintf("iifname %q drop", warpLaneHost)}
	for _, address := range m.AWGIPs {
		input = append(input, fmt.Sprintf("ip saddr %s udp sport %d ct direction reply ct state established accept", address, m.AWGPort))
	}
	for _, bridge := range m.Bridges {
		forward = append(forward, fmt.Sprintf("iifname %q drop", bridge), fmt.Sprintf("oifname %q drop", bridge))
		input = append(input, fmt.Sprintf("iifname %q drop", bridge))
	}
	prefix := ""
	if exists {
		prefix = "delete table inet " + warpSafetyTable + "\n"
	}
	script := prefix + "table inet " + warpSafetyTable + " {\ncomment \"" + warpSafetyComment + "\"\nchain forward {\ntype filter hook forward priority -15; policy accept;\n" + strings.Join(forward, "\n") + "\n}\nchain input {\ntype filter hook input priority -15; policy accept;\n" + strings.Join(input, "\n") + "\n}\n}\n"
	for _, args := range [][]string{{"nft", "--check", "--file", "-"}, {"nft", "--file", "-"}} {
		code, _, apiError := warpExecute(ctx, args, 8*time.Second, script, 8192, false)
		if apiError != nil || code != 0 {
			return errors.New("safety guard не подтвердил применение")
		}
	}
	return nil
}

// clearSafetyGuard снимает только подтверждённую safety table после свежего canonical blocked guard.
func (s *WarpSession) clearSafetyGuard(ctx context.Context) bool {
	if s.Err != nil {
		return false
	}
	exists, err := s.Runtime.safetyOwnedTable(ctx)
	if err != nil {
		s.fail("safety_guard_invalid", "Не подтверждено владение аварийной блокировкой.", 409)
		return false
	}
	if !exists {
		if _, markerErr := os.Lstat(s.Runtime.safetyFile("safety_guard.json")); errors.Is(markerErr, os.ErrNotExist) {
			return true
		}
	}
	if !s.requireSafety(ctx, false) {
		return false
	}
	state, readErr := s.Runtime.safetyRead()
	guard := s.readMap("guard_state.json")
	stamp, stampErr := time.Parse(time.RFC3339Nano, warpString(guard["updated_at"]))
	if s.Err != nil || readErr != nil || state.Snapshot == nil || s.Manifest == nil || !s.Manifest.valid() || warpHash(state.Snapshot) != warpHash(s.Manifest) || warpString(guard["path"]) != "blocked" || stampErr != nil || time.Since(stamp) < 0 || time.Since(stamp) > 15*time.Second {
		s.fail("safety_guard_required", "Перед снятием safety block нужен свежий штатный blocked guard для того же snapshot.", 409)
		return false
	}
	code, _, apiError := warpExecute(ctx, []string{"nft", "list", "table", "inet", warpNFTTable}, 5*time.Second, "", 131072, false)
	if apiError != nil || code != 0 || !s.requireSafety(ctx, false) {
		s.fail("safety_guard_required", "Штатный blocked guard не подтверждён.", 409)
		return false
	}
	if exists {
		// Владение перечитывается непосредственно перед удалением собственного ресурса.
		if _, err = s.Runtime.safetyOwnedTable(ctx); err != nil {
			s.fail("safety_guard_invalid", "Владение safety table изменилось.", 409)
			return false
		}
		code, _, apiError = warpExecute(ctx, []string{"nft", "delete", "table", "inet", warpSafetyTable}, 5*time.Second, "", 4096, false)
		if apiError != nil || code != 0 {
			s.fail("safety_guard_failed", "Safety block не снят; выход остаётся заблокированным.", 502)
			return false
		}
	}
	if err = os.Remove(s.Runtime.safetyFile("safety_guard.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.fail("safety_state_failed", "Не удалось завершить снятие safety block.", 500)
		return false
	}
	return s.requireSafety(ctx, false)
}

// safetyUnitStopped проверяет отсутствие процессов службы, включая её cgroup.
func warpSafetyUnitStopped(ctx context.Context, unit string) bool {
	code, raw, apiError := warpExecute(ctx, []string{"systemctl", "show", "--property=LoadState", "--property=ActiveState", "--property=MainPID", "--property=ControlPID", "--property=ControlGroup", unit}, 3*time.Second, "", 4096, false)
	if apiError != nil {
		return false
	}
	properties := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			properties[key] = value
		}
	}
	if properties["LoadState"] == "not-found" {
		return true
	}
	if code != 0 {
		return false
	}
	if (properties["ActiveState"] != "inactive" && properties["ActiveState"] != "failed") || properties["MainPID"] != "0" || properties["ControlPID"] != "0" {
		return false
	}
	group := properties["ControlGroup"]
	if group == "" {
		return true
	}
	if !warpSafetyPath(group) || filepath.Base(group) != unit {
		return false
	}
	rawEvents, err := warpReadPublic("/sys/fs/cgroup"+group+"/cgroup.events", 4096)
	return errors.Is(err, os.ErrNotExist) || err == nil && strings.Contains("\n"+string(rawEvents)+"\n", "\npopulated 0\n")
}

// warpSafetyWaitStopped ограниченно ждёт завершения уже отправленной systemd stop.
func warpSafetyWaitStopped(ctx context.Context, unit string, duration time.Duration) bool {
	waitCtx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		if warpSafetyUnitStopped(waitCtx, unit) {
			return true
		}
		select {
		case <-waitCtx.Done():
			return false
		case <-ticker.C:
		}
	}
}

// warpSafetyStop останавливает только одну из двух разрешённых служб и её cgroup.
func warpSafetyStop(ctx context.Context, unit string) bool {
	if unit != "awg_vps_warp.service" && unit != "warp-svc.service" {
		return false
	}
	_, _, _ = warpExecute(ctx, []string{"systemctl", "stop", "--no-block", unit}, 5*time.Second, "", 4096, false)
	if warpSafetyWaitStopped(ctx, unit, 8*time.Second) {
		return true
	}
	_, _, _ = warpExecute(ctx, []string{"systemctl", "kill", "--kill-whom=all", "--signal=KILL", unit}, 5*time.Second, "", 4096, false)
	return warpSafetyWaitStopped(ctx, unit, 8*time.Second)
}

// safetyRescue выполняет независимые попытки; runtime никогда не держит её flock.
func (r *WarpRuntime) safetyRescue(parent context.Context, fallback WarpSafetyState) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 150*time.Second)
	defer cancel()
	// Короткая конкуренция с записью root arm допускает bounded повтор.
	rescue, err := r.safetyLock(ctx, true)
	for attempt := 0; err != nil && attempt < 30; attempt++ {
		select {
		case <-ctx.Done():
			return errors.New("аварийное восстановление не получило независимую блокировку")
		case <-time.After(100 * time.Millisecond):
		}
		rescue, err = r.safetyLock(ctx, true)
	}
	if err != nil {
		return err
	}
	defer rescue.Close()
	state, readErr := r.safetyRead()
	if readErr == nil && state.ID != fallback.ID && state.Status != "" {
		return nil
	}
	if readErr == nil && state.Status == "confirmed" && !r.safetyMarker() && !r.safetyPending() {
		return nil
	}
	if readErr != nil || state.Status == "" {
		state = fallback
	}
	result := WarpSafetyResult{SchemaVersion: 1, ID: state.ID, StartedAt: warpNow(), Steps: []WarpSafetyStep{}}
	appendStep := func(name string, success bool) {
		code := "ok"
		if !success {
			code = "not_confirmed"
		}
		result.Steps = append(result.Steps, WarpSafetyStep{Step: name, Succeeded: success, Code: code})
	}
	appendStep("hold_persisted", atomicPrivateFile(r.safetyFile("emergency_hold"), []byte("held\n")) == nil)
	runtimeStopped := warpSafetyStop(ctx, "awg_vps_warp.service")
	appendStep("runtime_stopped", runtimeStopped)
	// После остановки runtime финализируем JSON; неудача не отменяет остальные шаги.
	lock, lockErr := r.safetyLock(ctx, false)
	if lockErr == nil {
		lockErr = r.safetyMarkHeld(&state)
		_ = lock.Close()
	}
	appendStep("held_state_persisted", lockErr == nil)
	appendStep("safety_block_first", r.safetyBlock(ctx, state.Snapshot) == nil)
	if warpProgram("warp-cli") == "" {
		result.Steps = append(result.Steps, WarpSafetyStep{Step: "warp_disconnected", Succeeded: true, Code: "not_installed"})
	} else {
		code, _, apiError := warpExecute(ctx, []string{"warp-cli", "--accept-tos", "disconnect"}, 8*time.Second, "", 4096, false)
		appendStep("warp_disconnected", apiError == nil && code == 0)
	}
	warpStopped := warpSafetyStop(ctx, "warp-svc.service")
	appendStep("warp_service_stopped", warpStopped)
	blocked := r.safetyBlock(ctx, state.Snapshot) == nil
	appendStep("safety_block_final", blocked)
	completed := runtimeStopped && warpStopped && blocked
	if completed {
		completed = r.safetyRescueComplete(ctx, state.ID) == nil
		appendStep("rescue_completed", completed)
	}
	// Новый runtime получает diagnostics в held-режиме, уже без recovery flock.
	_ = rescue.Close()
	if completed && r.safetyMarker() {
		code, _, apiError := warpExecute(ctx, []string{"systemctl", "start", "--no-block", "awg_vps_warp.service"}, 5*time.Second, "", 4096, false)
		appendStep("runtime_held_start_requested", apiError == nil && code == 0)
	}
	result.FinishedAt = warpNow()
	if err := r.safetyWrite("safety_result.json", result); err != nil {
		return err
	}
	for _, step := range result.Steps {
		if !step.Succeeded {
			return errors.New("удержание сохранено, но не все аварийные действия подтверждены")
		}
	}
	return nil
}

// safetyRescueComplete завершает только свою эпоху под уже удерживаемой recovery flock.
func (r *WarpRuntime) safetyRescueComplete(ctx context.Context, id string) error {
	lock, err := r.safetyLock(ctx, false)
	if err != nil {
		return err
	}
	defer lock.Close()
	state, err := r.safetyRead()
	if err != nil || state.ID != id || state.Status != "held" || !r.safetyMarker() {
		return errors.New("изменена эпоха завершения rescue")
	}
	path := r.safetyFile("rescue_pending")
	raw, readErr := readPrivateFile(path, 64)
	missing := errors.Is(readErr, os.ErrNotExist)
	if !missing && (readErr != nil || string(raw) != id+"\n") {
		return errors.New("marker rescue принадлежит другой эпохе")
	}
	state.RescueComplete = true
	if err = r.safetyWrite("safety_state.json", state); err != nil {
		return err
	}
	if !missing {
		if err = os.Remove(path); err != nil {
			return err
		}
		directory, openErr := os.Open(r.Config.StateDir)
		if openErr != nil {
			return openErr
		}
		defer directory.Close()
		return directory.Sync()
	}
	return nil
}

// safetyExpire сначала фиксирует hold; текущий timer не зависит от сдвига wall clock.
func (r *WarpRuntime) safetyExpire(ctx context.Context, id string) error {
	lock, err := r.safetyLock(ctx, false)
	state, readErr := r.safetyRead()
	if id != "" && readErr == nil && (state.ID != id || state.Status == "confirmed" && !r.safetyMarker() && !r.safetyPending()) {
		if lock != nil {
			_ = lock.Close()
		}
		return nil
	}
	var holdErr error
	if err == nil {
		holdErr = r.safetyQueueRescue(&state)
		_ = lock.Close()
	} else {
		// Даже остановленный root writer не мешает независимому marker и остановке runtime.
		holdErr = atomicPrivateFile(r.safetyFile("emergency_hold"), []byte("held\n"))
		if !warpSafetyID(state.ID) {
			state.ID, _ = warpSafetyNewID()
		}
		pendingErr := atomicPrivateFile(r.safetyFile("rescue_pending"), []byte(state.ID+"\n"))
		holdErr = errors.Join(holdErr, pendingErr)
	}
	rescueErr := r.safetyRescue(ctx, state)
	return errors.Join(holdErr, rescueErr)
}

// safetyBoot применяет hold/block до host.lock без systemd stop/start и зависимости от Docker.
func (r *WarpRuntime) safetyBoot(ctx context.Context) error {
	state, readErr := r.safetyRead()
	held := r.safetyMarker() || r.safetyPending() || readErr != nil || state.Status == "held"
	if !held && state.Status == "armed" {
		_, apiError := r.safetyLease(ctx, true)
		held = apiError != nil
	}
	if !held {
		return nil
	}
	// Boot/runtime не держит ни одну блокировку, необходимую независимому rescue.
	current, currentErr := r.safetyRead()
	if readErr == nil && currentErr == nil && (current.ID != state.ID || current.Status != state.Status) {
		return errors.New("состояние защиты изменилось во время boot-проверки")
	}
	var holdErr error
	if state.Status != "held" || readErr != nil {
		holdErr = r.safetyQueueRescue(&state)
	} else {
		holdErr = r.safetyMarkHeld(&state)
	}
	return errors.Join(holdErr, r.safetyBlock(ctx, state.Snapshot))
}
