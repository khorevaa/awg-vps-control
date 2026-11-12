//go:build linux

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// installDirectory описывает фиксированный каталог runtime или состояния панели.
type installDirectory struct {
	path string      // Абсолютный разрешённый путь.
	uid  int         // Владелец каталога.
	gid  int         // Группа доступа.
	mode os.FileMode // Точные права каталога.
}

// installJournalCapabilities описывает поддерживаемые действия постоянного журнала.
type installJournalCapabilities struct {
	JournalVersion int      `json:"journal_version"` // Версия схемы постоянного журнала.
	Actions        []string `json:"actions"`         // Полный перечень принимаемых мутаций.
}

// runInstallTools выполняет только локальные команды установки от root.
func runInstallTools(args []string) error {
	if os.Geteuid() != 0 || len(args) == 0 {
		return fmt.Errorf("инструменты установки требуют root и явную команду")
	}
	switch args[0] {
	case "journal-actions":
		if len(args) != 1 {
			return fmt.Errorf("journal-actions не принимает параметры")
		}
		return json.NewEncoder(os.Stdout).Encode(installJournalCapabilities{JournalVersion: 1, Actions: installJournalActions(true)})
	case "check-control-journal":
		if len(args) != 2 {
			return fmt.Errorf("check-control-journal требует целевой бинарник")
		}
		return installCheckControlJournal(args[1])
	case "verify-release":
		if len(args) != 2 {
			return fmt.Errorf("verify-release требует каталог")
		}
		return installVerifyRelease(args[1])
	case "init":
		return installInitialize()
	case "ui-access":
		if len(args) > 2 {
			return fmt.Errorf("ui-access принимает только необязательный SSH target")
		}
		target := os.Getenv("AWG_SSH_TARGET")
		sshPort := "22"
		if len(args) == 2 {
			target = args[1]
		}
		if target == "" {
			address, detectedPort, err := installSSHAddress()
			if err != nil {
				return err
			}
			if strings.Contains(address, ":") {
				address = "[" + address + "]"
			}
			target, sshPort = "root@"+address, detectedPort
		}
		if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@:\[\]-]*$`).MatchString(target) {
			return fmt.Errorf("недопустимый SSH target")
		}
		values, err := installReadEnvironment()
		if err != nil {
			return err
		}
		secret, err := os.ReadFile("/etc/awg_vps_control/web/access_secret")
		if err != nil {
			return err
		}
		separator := strings.LastIndexByte(values["AWG_ALLOWED_HOST"], ':')
		if separator < 0 {
			return fmt.Errorf("в адресе панели отсутствует порт")
		}
		port := values["AWG_ALLOWED_HOST"][separator+1:]
		if _, err := strconv.ParseUint(port, 10, 16); err != nil {
			return fmt.Errorf("неверный порт панели")
		}
		portOption := ""
		if sshPort != "22" {
			portOption = " -p " + sshPort
		}
		fmt.Printf("ssh -N -o ExitOnForwardFailure=yes%s -L localhost:%s:/run/awg_vps_web/web.sock %s\nOpen: %s\nAccess secret: %s\n", portOption, port, target, values["AWG_ALLOWED_ORIGIN"], strings.TrimSpace(string(secret)))
		return nil
	case "rotate-secret":
		secret, err := installRandomHex(48)
		if err != nil {
			return err
		}
		if err := installAtomicFile("/etc/awg_vps_control/web/access_secret", []byte(secret+"\n"), 10001, 10001); err != nil {
			return err
		}
		fmt.Println("Секрет заменён; прежние сессии отзываются при следующем запросе.")
		return nil
	default:
		return fmt.Errorf("неизвестная команда инструментов установки")
	}
}

// installJournalActions возвращает действия текущего выпуска либо известного первого RC.
func installJournalActions(peers bool) []string {
	actions := []string{"attach", "policy.set", "repair", "warp.reconnect", "warp.setup", "awg.restart"}
	if peers {
		actions = append(actions, "peer.create", "peer.rename", "peer.revoke")
	}
	return actions
}

// installReadCheckedFile читает ограниченный обычный файл без перехода по ссылкам и изменения состояния.
func installReadCheckedFile(path string, limit int, uid uint32, private bool) ([]byte, error) {
	if err := installSafeAncestors(path); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	stat, valid := info.Sys().(*syscall.Stat_t)
	if !valid || !info.Mode().IsRegular() || stat.Uid != uid || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm() != 0600) || info.Size() > int64(limit) {
		return nil, fmt.Errorf("небезопасный тип, владелец, права или размер файла проверки журнала")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(content) > limit {
		return nil, fmt.Errorf("не удалось прочитать файл в допустимых пределах")
	}
	return content, nil
}

// installCheckControlJournal отказывает до смены выпуска, если целевой Control не прочитает действия журнала.
func installCheckControlJournal(target string) error {
	content, err := installReadCheckedFile("/var/lib/awg_vps_control/control/state.json", maxJournalBytes, 10002, true)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("журнал Control недоступен для безопасной проверки совместимости")
	}
	binary, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("неверный путь целевого бинарника")
	}
	binary = filepath.Clean(binary)
	if err := installSafeAncestors(binary); err != nil {
		return err
	}
	info, err := os.Lstat(binary)
	if err != nil {
		return fmt.Errorf("целевой бинарник недоступен")
	}
	stat, valid := info.Sys().(*syscall.Stat_t)
	if !valid || !info.Mode().IsRegular() || stat.Uid != 0 || stat.Nlink != 1 || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0100 == 0 {
		return fmt.Errorf("целевой бинарник должен быть обычным root-owned executable без небезопасных прав")
	}
	version, err := installReadCheckedFile(filepath.Join(filepath.Dir(binary), "..", "version"), 128, 0, false)
	if err != nil {
		return fmt.Errorf("не удалось проверить версию целевого выпуска")
	}
	capabilities := installJournalCapabilities{JournalVersion: 1, Actions: installJournalActions(false)}
	if strings.TrimSpace(string(version)) != "0.1.0-rc.1" {
		capabilities = installJournalCapabilities{}
		code, output, commandError := warpExecute(context.Background(), []string{binary, "install-tools", "journal-actions"}, 5*time.Second, "", 4096, false)
		if commandError != nil || code != 0 || decodeStrict([]byte(output), &capabilities) != nil || capabilities.JournalVersion != 1 || len(capabilities.Actions) == 0 || len(capabilities.Actions) > 64 {
			return fmt.Errorf("целевой выпуск не подтвердил совместимость журнала; переключение запрещено")
		}
	}
	supported := make(map[string]bool, len(capabilities.Actions))
	for _, action := range capabilities.Actions {
		if action == "" || supported[action] || len(action) > 64 {
			return fmt.Errorf("неверный перечень действий целевого выпуска")
		}
		supported[action] = true
	}
	var journal Journal
	if decodeStrict(content, &journal) != nil || journal.Version != capabilities.JournalVersion || len(journal.Operations) > maxOperations {
		return fmt.Errorf("версия или структура журнала Control не поддерживается; переключение запрещено")
	}
	identifiers, keys := make(map[string]bool), make(map[string]bool)
	for _, record := range journal.Operations {
		if !mutationAction(record.Operation.Action) || !supported[record.Operation.Action] {
			return fmt.Errorf("целевой выпуск не поддерживает действия сохранённого журнала Control; переключение запрещено, журнал сохранён")
		}
		_, createdError := time.Parse(time.RFC3339Nano, record.Operation.CreatedAt)
		_, updatedError := time.Parse(time.RFC3339Nano, record.Operation.UpdatedAt)
		payload, payloadError := validatePayload(record.Operation.Action, record.Payload)
		if !operationIDPattern.MatchString(record.Operation.ID) || identifiers[record.Operation.ID] || !revisionPattern.MatchString(record.IdempotencyHash) || keys[record.IdempotencyHash] || !knownStatus(record.Operation.Status) || createdError != nil || updatedError != nil || payloadError != nil || digestText(record.Operation.Action+"\n"+string(payload)) != record.Fingerprint || len(record.Operation.Result) > maxOperationResult {
			return fmt.Errorf("журнал Control содержит недопустимую запись; переключение запрещено")
		}
		if peerMutationAction(record.Operation.Action) && len(record.Operation.Result) != 0 && string(record.Operation.Result) != "null" {
			if _, valid := checkedPeerResult(record.Operation.Action, record.Operation.Result); !valid {
				return fmt.Errorf("журнал Control содержит недопустимый результат операции клиента; переключение запрещено")
			}
		}
		identifiers[record.Operation.ID], keys[record.IdempotencyHash] = true, true
	}
	return nil
}

// installSSHAddress определяет адрес стороны сервера текущего SSH-сеанса либо единственный публичный IP хоста.
func installSSHAddress() (string, string, error) {
	connection := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(connection) == 4 {
		address, addressErr := netip.ParseAddr(connection[2])
		port, portErr := strconv.ParseUint(connection[3], 10, 16)
		if addressErr == nil && address.Zone() == "" && address.IsGlobalUnicast() && portErr == nil && port > 0 {
			return address.Unmap().String(), strconv.FormatUint(port, 10), nil
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", fmt.Errorf("не удалось определить адрес VPS; укажите ui-access root@АДРЕС: %w", err)
	}
	ipv4, ipv6 := map[string]bool{}, map[string]bool{}
	carrierGradeNAT := netip.MustParsePrefix("100.64.0.0/10")
	for _, device := range interfaces {
		if device.Flags&net.FlagUp == 0 || device.Flags&net.FlagLoopback != 0 || device.Name == warpInterface {
			continue
		}
		addresses, addressesErr := device.Addrs()
		if addressesErr != nil {
			return "", "", fmt.Errorf("не удалось прочитать адреса VPS; укажите ui-access root@АДРЕС: %w", addressesErr)
		}
		for _, value := range addresses {
			prefix, parseErr := netip.ParsePrefix(value.String())
			if parseErr != nil {
				continue
			}
			address := prefix.Addr().Unmap()
			if !address.IsGlobalUnicast() || address.IsPrivate() || carrierGradeNAT.Contains(address) || address.Zone() != "" {
				continue
			}
			if address.Is4() {
				ipv4[address.String()] = true
			} else {
				ipv6[address.String()] = true
			}
		}
	}
	for _, candidates := range []map[string]bool{ipv4, ipv6} {
		if len(candidates) == 1 {
			for address := range candidates {
				return address, "22", nil
			}
		}
	}
	return "", "", fmt.Errorf("адрес VPS неоднозначен; укажите ui-access root@АДРЕС или AWG_SSH_TARGET")
}

// installVerifyRelease проверяет полноту manifest, типы файлов и контрольные суммы.
func installVerifyRelease(directory string) error {
	root, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	root = filepath.Clean(root)
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("неверный каталог выпуска")
	}
	manifest, err := os.Open(filepath.Join(root, "manifest.sha256"))
	if err != nil {
		return err
	}
	defer manifest.Close()
	listed := make(map[string]string)
	linePattern := regexp.MustCompile(`^([a-f0-9]{64})  ([A-Za-z0-9_./-]+)$`)
	scanner := bufio.NewScanner(io.LimitReader(manifest, 1024*1024))
	for scanner.Scan() {
		match := linePattern.FindStringSubmatch(scanner.Text())
		if match == nil {
			return fmt.Errorf("некорректная строка manifest")
		}
		name := match[2]
		if filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, "../") || name == ".." || name == "manifest.sha256" {
			return fmt.Errorf("небезопасный путь manifest")
		}
		if _, exists := listed[name]; exists {
			return fmt.Errorf("повтор пути в manifest")
		}
		listed[name] = match[1]
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	required := []string{"install.sh", "awg_vps_control.sh", "compose.yaml", "version", "source_revision", "license", "bin/awg_web", "bin/awg_control", "scripts/awg_vps_control.sh", "scripts/install_awg.sh", "scripts/awg_upstream.sha256", "scripts/runtime_dockerfile", "systemd/awg_vps_guard.service", "systemd/awg_vps_warp.service", "systemd/awg_vps_control.conf"}
	for _, name := range required {
		if _, ok := listed[name]; !ok {
			return fmt.Errorf("неполный manifest: %s", name)
		}
	}
	seen := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink в выпуске запрещён")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 {
			return fmt.Errorf("необычный тип файла выпуска")
		}
		name, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		name = filepath.ToSlash(name)
		if name == "manifest.sha256" {
			return nil
		}
		expected, ok := listed[name]
		if !ok {
			return fmt.Errorf("файл вне manifest: %s", name)
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, readErr := io.Copy(hash, file)
		closeErr := file.Close()
		if err := errors.Join(readErr, closeErr); err != nil {
			return err
		}
		if hex.EncodeToString(hash.Sum(nil)) != expected {
			return fmt.Errorf("контрольная сумма не совпала: %s", name)
		}
		seen++
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(listed) {
		return fmt.Errorf("файлы из manifest отсутствуют")
	}
	return nil
}

// installRandomHex генерирует секрет без внешних утилит и передачи через argv.
func installRandomHex(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// installSafeAncestors запрещает символические ссылки в управляемых путях.
func installSafeAncestors(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink в управляемом пути запрещён")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

// installAtomicFile сохраняет root-проверенные данные с точным владельцем и fsync.
func installAtomicFile(path string, content []byte, uid, gid int) error {
	if err := installSafeAncestors(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.Mode().IsRegular() || stat.Nlink != 1 {
			return fmt.Errorf("небезопасный целевой файл")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".install_*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	err = file.Chmod(0o600)
	if err == nil {
		err = file.Chown(uid, gid)
	}
	if err == nil {
		_, err = file.Write(content)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

// installReadEnvironment читает только известные строки root-конфигурации панели.
func installReadEnvironment() (map[string]string, error) {
	path := "/etc/awg_vps_control/ui.env"
	if err := installSafeAncestors(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.ContainsAny(value, "\r\x00") {
			return nil, fmt.Errorf("некорректный UI environment")
		}
		if key != "AWG_ALLOWED_HOST" && key != "AWG_ALLOWED_ORIGIN" && key != "AWG_DOCKER_GID" {
			return nil, fmt.Errorf("неизвестная настройка UI")
		}
		if _, ok := values[key]; ok {
			return nil, fmt.Errorf("повтор настройки UI")
		}
		values[key] = value
	}
	return values, nil
}

// installInitialize создаёт только ресурсы панели и сохраняет существующий доступ.
func installInitialize() error {
	directories := []installDirectory{
		{"/etc/awg_vps_control", 0, 0, 0o700}, {"/var/lib/awg_vps_control", 0, 0, 0o700},
		{"/etc/awg_vps_control/web", 10001, 10001, 0o700}, {"/var/lib/awg_vps_control/web", 10001, 10001, 0o700},
		{"/var/lib/awg_vps_control/control", 10002, 10001, 0o700}, {"/var/lib/awg_vps_control/adapter", 10003, 10002, 0o700},
		{"/var/lib/awg_vps_control/host", 0, 0, 0o700}, {"/run/awg_vps_web", 10001, 10001, 0o700},
		{"/run/awg_vps_control", 10002, 10001, 0o750}, {"/run/awg_vps_adapter", 10003, 10002, 0o750}, {"/run/awg_vps_warp", 0, 10002, 0o750},
	}
	for _, directory := range directories {
		if err := installSafeAncestors(directory.path); err != nil {
			return err
		}
		if err := os.MkdirAll(directory.path, directory.mode); err != nil {
			return err
		}
		if err := os.Chown(directory.path, directory.uid, directory.gid); err != nil {
			return err
		}
		if err := os.Chmod(directory.path, directory.mode); err != nil {
			return err
		}
	}
	configPath := "/etc/awg_vps_control/host.json"
	if _, err := os.Lstat(configPath); errors.Is(err, os.ErrNotExist) {
		data := []byte("{\"schema_version\":1,\"state_dir\":\"/var/lib/awg_vps_control/host\",\"control_uid\":10002,\"socket_gid\":10002,\"supervisor_interval_seconds\":15,\"probe_interval_seconds\":60}\n")
		if err := installAtomicFile(configPath, data, 0, 0); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	secretPath := "/etc/awg_vps_control/web/access_secret"
	if err := installSafeAncestors(secretPath); err != nil {
		return err
	}
	if _, err := os.Lstat(secretPath); errors.Is(err, os.ErrNotExist) {
		secret, err := installRandomHex(48)
		if err != nil {
			return err
		}
		if err := installAtomicFile(secretPath, []byte(secret+"\n"), 10001, 10001); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	values, err := installReadEnvironment()
	if err != nil {
		return err
	}
	if values["AWG_ALLOWED_HOST"] == "" && values["AWG_ALLOWED_ORIGIN"] == "" {
		label, err := installRandomHex(8)
		if err != nil {
			return err
		}
		values["AWG_ALLOWED_HOST"] = "awg-" + label + ".localhost:8787"
		values["AWG_ALLOWED_ORIGIN"] = "http://" + values["AWG_ALLOWED_HOST"]
	}
	if values["AWG_ALLOWED_HOST"] == "" || values["AWG_ALLOWED_ORIGIN"] != "http://"+values["AWG_ALLOWED_HOST"] {
		return fmt.Errorf("некорректный origin существующей панели")
	}
	info, err := os.Stat("/var/run/docker.sock")
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("существующий Docker socket не найден")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("нельзя определить группу Docker socket")
	}
	if stat.Uid != 0 || info.Mode().Perm()&0o020 == 0 || info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("Docker socket должен принадлежать root, разрешать запись своей группе и запрещать доступ остальным")
	}
	values["AWG_DOCKER_GID"] = strconv.FormatUint(uint64(stat.Gid), 10)
	content := "AWG_ALLOWED_HOST=" + values["AWG_ALLOWED_HOST"] + "\nAWG_ALLOWED_ORIGIN=" + values["AWG_ALLOWED_ORIGIN"] + "\nAWG_DOCKER_GID=" + values["AWG_DOCKER_GID"] + "\n"
	return installAtomicFile("/etc/awg_vps_control/ui.env", []byte(content), 0, 0)
}
