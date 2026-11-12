package connection

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const maxStoreBytes = 128 * 1024

var storeMutex sync.Mutex
var profileIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var userPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var operationPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// validHost принимает IP без зоны либо обычное ASCII DNS-имя, без shell-синтаксиса.
func validHost(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == ""
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-", ch) {
				return false
			}
		}
	}
	return true
}

// validateProfile запрещает неполные или неоднозначные настройки до сетевого обращения.
func validateProfile(profile SSHProfile) error {
	if !profileIDPattern.MatchString(profile.ID) || !utf8.ValidString(profile.Name) || strings.TrimSpace(profile.Name) == "" || utf8.RuneCountInString(profile.Name) > 80 || strings.ContainsFunc(profile.Name, unicode.IsControl) {
		return errors.New("Некорректные ID или название SSH-профиля.")
	}
	if !validHost(profile.Host) || profile.Port < 1 || profile.Port > 65535 || !userPattern.MatchString(profile.User) {
		return errors.New("Проверьте SSH адрес, порт и пользователя.")
	}
	if profile.AuthMode != "password" && profile.AuthMode != "key" {
		return errors.New("Поддерживаются пароль или приватный SSH-ключ.")
	}
	if profile.AuthMode == "key" && (!filepath.IsAbs(profile.KeyPath) || len(profile.KeyPath) > 4096 || strings.ContainsFunc(profile.KeyPath, unicode.IsControl)) {
		return errors.New("Выберите абсолютный путь к SSH-ключу.")
	}
	return nil
}

// prepareDirectory проверяет каталог приложения и не следует символьным ссылкам.
func prepareDirectory(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errors.New("Каталог приложения должен иметь абсолютный нормализованный путь.")
	}
	for path := dir; ; path = filepath.Dir(path) {
		info, err := os.Lstat(path)
		if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
			return errors.New("Каталог приложения не должен содержать ссылки или обычные файлы.")
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("Не удалось проверить каталог приложения.")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.New("Не удалось создать каталог приложения.")
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("Каталог приложения должен быть доступен только текущему пользователю.")
	}
	return nil
}

// readFile ограничивает размер, проверяет обычный файл и идентичность открытого объекта.
func readFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("Файл имеет неподдержанный тип или размер.")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("Не удалось открыть локальный файл.")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("Локальный файл изменился во время чтения.")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		clear(data)
		return nil, errors.New("Не удалось прочитать локальный файл в допустимых пределах.")
	}
	return data, nil
}

// atomicFile записывает обычный файл через fsync и rename в том же каталоге.
func atomicFile(dir, name string, data []byte) error {
	path := filepath.Join(dir, name)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() || err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("Целевой файл настроек небезопасен.")
	}
	file, err := os.CreateTemp(dir, ".pending_*")
	if err != nil {
		return errors.New("Не удалось подготовить настройки.")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	defer file.Close()
	if err := file.Chmod(0600); err != nil {
		return errors.New("Не удалось ограничить доступ к настройкам.")
	}
	if _, err := file.Write(data); err != nil {
		return errors.New("Не удалось записать настройки.")
	}
	if err := file.Sync(); err != nil {
		return errors.New("Не удалось подтвердить запись настроек.")
	}
	if err := file.Close(); err != nil {
		return errors.New("Не удалось закрыть файл настроек.")
	}
	if err := os.Rename(temporary, path); err != nil {
		return errors.New("Не удалось атомарно заменить настройки.")
	}
	return nil
}

// LoadProfiles читает только версионированные настройки без секретов аутентификации.
func LoadProfiles(dir string) ([]SSHProfile, error) {
	storeMutex.Lock()
	defer storeMutex.Unlock()
	if err := prepareDirectory(dir); err != nil {
		return nil, err
	}
	data, err := readFile(filepath.Join(dir, "profiles.json"), maxStoreBytes)
	if errors.Is(err, os.ErrNotExist) {
		return []SSHProfile{}, nil
	}
	if err != nil {
		return nil, errors.New("Не удалось прочитать SSH-профили.")
	}
	var store ProfileStore
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&store) != nil || decoder.Decode(new(any)) != io.EOF || store.Version != 1 {
		return nil, errors.New("Формат SSH-профилей не поддержан.")
	}
	if err := validateProfiles(store.Profiles); err != nil {
		return nil, err
	}
	return store.Profiles, nil
}

// validateProfiles проверяет лимиты и уникальные ID всего сохраняемого набора.
func validateProfiles(profiles []SSHProfile) error {
	if len(profiles) > 64 {
		return errors.New("Поддерживается не более 64 SSH-профилей.")
	}
	seen := make(map[string]bool, len(profiles))
	for _, profile := range profiles {
		if err := validateProfile(profile); err != nil {
			return err
		}
		if seen[profile.ID] {
			return errors.New("ID SSH-профилей не должны повторяться.")
		}
		seen[profile.ID] = true
	}
	return nil
}

// SaveProfiles атомарно сохраняет только проверенные несекретные настройки.
func SaveProfiles(dir string, profiles []SSHProfile) error {
	storeMutex.Lock()
	defer storeMutex.Unlock()
	if err := validateProfiles(profiles); err != nil {
		return err
	}
	if err := prepareDirectory(dir); err != nil {
		return err
	}
	data, err := json.MarshalIndent(ProfileStore{Version: 1, Profiles: profiles}, "", "  ")
	if err != nil || len(data) > maxStoreBytes {
		return errors.New("Размер SSH-профилей превышает допустимый предел.")
	}
	return atomicFile(dir, "profiles.json", append(data, '\n'))
}
