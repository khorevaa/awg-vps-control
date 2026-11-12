//go:build linux

package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// installDirectory описывает фиксированный каталог runtime или состояния панели.
type installDirectory struct {
	path string      // Абсолютный разрешённый путь.
	uid  int         // Владелец каталога.
	gid  int         // Группа доступа.
	mode os.FileMode // Точные права каталога.
}

// runInstallTools выполняет только локальные команды установки от root.
func runInstallTools(args []string) error {
	if os.Geteuid() != 0 || len(args) == 0 {
		return fmt.Errorf("инструменты установки требуют root и явную команду")
	}
	switch args[0] {
	case "verify-release":
		if len(args) != 2 {
			return fmt.Errorf("verify-release требует каталог")
		}
		return installVerifyRelease(args[1])
	case "init":
		return installInitialize()
	case "ui-access":
		target := "root@YOUR_VPS"
		if len(args) == 2 {
			target = args[1]
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
		fmt.Printf("ssh -N -o ExitOnForwardFailure=yes -L localhost:%s:/run/awg_vps_web/web.sock %s\nOpen: %s\nAccess secret: %s\n", port, target, values["AWG_ALLOWED_ORIGIN"], strings.TrimSpace(string(secret)))
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
	required := []string{"install.sh", "awg_vps_control.sh", "compose.yaml", "version", "source_revision", "license", "bin/awg_web", "bin/awg_control", "scripts/awg_vps_control.sh", "scripts/runtime_dockerfile", "systemd/awg_vps_guard.service", "systemd/awg_vps_warp.service", "systemd/awg_vps_control.conf"}
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
