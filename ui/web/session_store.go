//go:build linux

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// sessionRecord хранит только хеши секретных токенов сессии.
type sessionRecord struct {
	TokenHash string    `json:"token_hash"` // SHA-256 токена cookie.
	CSRFHash  string    `json:"csrf_hash"`  // SHA-256 токена CSRF.
	CreatedAt time.Time `json:"created_at"` // Начало сессии UTC.
	ExpiresAt time.Time `json:"expires_at"` // Окончание сессии UTC.
}

// auditRecord содержит безопасное событие без параметров и секретов.
type auditRecord struct {
	OccurredAt time.Time `json:"occurred_at"` // Время события UTC.
	Action     string    `json:"action"`      // Фиксированное имя действия.
	Success    bool      `json:"success"`     // Результат регистрации события.
}

// persistedState задаёт защищённое хранилище сессий и аудита Web.
type persistedState struct {
	Version  int             `json:"version"`  // Версия формата хранилища.
	Sessions []sessionRecord `json:"sessions"` // Не более 64 активных сессий.
	Audit    []auditRecord   `json:"audit"`    // Не более 1000 последних событий.
}

// sessionStore синхронизирует сессии, ротацию секрета и атомарное сохранение.
type sessionStore struct {
	Mutex         sync.Mutex     // Защита состояния между HTTP-запросами.
	Path          string         // Путь к собственному state-файлу.
	SecretFile    string         // Путь к проверяемому файлу access secret.
	SecretHash    [32]byte       // Отпечаток текущего секрета.
	BootKey       []byte         // Случайный ключ CSRF текущего запуска.
	TTL           time.Duration  // Максимальный срок жизни сессии.
	State         persistedState // Подтверждённое сохранённое состояние.
	Attempts      int            // Число входов за текущую минуту.
	AttemptWindow time.Time      // Начало интервала ограничения входов.
}

// secretDigest читает безопасный файл и возвращает только хеш его значения.
func secretDigest(path string) ([32]byte, error) {
	content, err := secureRead(path, 512, true)
	if err != nil {
		return [32]byte{}, err
	}
	secret := strings.TrimSpace(string(content))
	if len(secret) < 43 || len(secret) > 256 {
		return [32]byte{}, fmt.Errorf("invalid access secret length")
	}
	for _, ch := range secret {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-", ch) {
			return [32]byte{}, fmt.Errorf("invalid access secret format")
		}
	}
	return sha256.Sum256([]byte(secret)), nil
}

// newSessionStore загружает аудит и отзывает сессии предыдущего процесса.
func newSessionStore(cfg config) (*sessionStore, error) {
	if err := os.MkdirAll(filepath.Dir(cfg.StateFile), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	if err := ownedDirectory(filepath.Dir(cfg.StateFile)); err != nil {
		return nil, err
	}
	digest, err := secretDigest(cfg.SecretFile)
	if err != nil {
		return nil, fmt.Errorf("load access secret: %w", err)
	}
	boot := make([]byte, 32)
	if _, err = rand.Read(boot); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	s := &sessionStore{
		Path: cfg.StateFile, SecretFile: cfg.SecretFile, SecretHash: digest, BootKey: boot, TTL: cfg.SessionTTL,
		State: persistedState{Version: 1, Sessions: []sessionRecord{}, Audit: []auditRecord{}},
	}
	content, err := secureRead(cfg.StateFile, 2*1024*1024, false)
	if err == nil {
		if err = strictJSON(content, &s.State); err != nil {
			return nil, fmt.Errorf("decode state: %w", err)
		}
		if s.State.Version != 1 || len(s.State.Audit) > 1000 || len(s.State.Sessions) > 64 {
			return nil, fmt.Errorf("unsupported state format")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.State.Sessions = []sessionRecord{}
	if s.State.Audit == nil {
		s.State.Audit = []auditRecord{}
	}
	if err = s.persistLocked(s.State); err != nil {
		return nil, err
	}
	return s, nil
}

// persistLocked сохраняет новое состояние до его принятия в памяти.
func (s *sessionStore) persistLocked(next persistedState) error {
	encoded, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode session state: %w", err)
	}
	if err = atomicWrite(s.Path, append(encoded, '\n')); err != nil {
		return err
	}
	s.State = next
	return nil
}

// refreshLocked отзывает сессии при изменении секрета и удаляет истёкшие записи.
func (s *sessionStore) refreshLocked() error {
	digest, err := secretDigest(s.SecretFile)
	if err != nil {
		return err
	}
	changed := subtle.ConstantTimeCompare(digest[:], s.SecretHash[:]) != 1
	next := s.State
	next.Sessions = make([]sessionRecord, 0, len(s.State.Sessions))
	if !changed {
		for _, record := range s.State.Sessions {
			if time.Now().Before(record.ExpiresAt) {
				next.Sessions = append(next.Sessions, record)
			}
		}
	}
	if changed || len(next.Sessions) != len(s.State.Sessions) {
		// При сбое записи отозванные сессии уже не должны разрешать вход в этом процессе.
		s.State.Sessions = next.Sessions
		if err = s.persistLocked(next); err != nil {
			return err
		}
		s.SecretHash = digest
	}
	return nil
}

// randomToken создаёт непредсказуемый 256-битный токен.
func randomToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// tokenHash возвращает хеш секретного значения для хранения.
func tokenHash(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// csrfFor выводит токен CSRF, связанный с cookie и текущим запуском.
func (s *sessionStore) csrfFor(token string) string {
	mac := hmac.New(sha256.New, s.BootKey)
	// hash.Hash.Write по контракту не возвращает ошибку.
	_, _ = mac.Write([]byte("awg_web_csrf\x00" + token))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// withAudit возвращает копию ограниченного журнала с новым событием.
func withAudit(state persistedState, action string, success bool) persistedState {
	state.Audit = append(slices.Clone(state.Audit), auditRecord{OccurredAt: time.Now().UTC(), Action: action, Success: success})
	if len(state.Audit) > 1000 {
		state.Audit = state.Audit[len(state.Audit)-1000:]
	}
	return state
}

// login проверяет секрет с ограничением частоты и сохраняет сессию до выдачи cookie.
func (s *sessionStore) login(secret string) (string, authResponse, error) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if err := s.refreshLocked(); err != nil {
		return "", authResponse{}, err
	}
	if time.Since(s.AttemptWindow) >= time.Minute {
		s.AttemptWindow = time.Now()
		s.Attempts = 0
	}
	s.Attempts++
	if s.Attempts > 10 {
		return "", authResponse{}, &apiError{Code: "rate_limited", Message: "Слишком много попыток. Повторите вход через минуту.", Status: 429}
	}
	digest := sha256.Sum256([]byte(secret))
	valid := len(secret) >= 43 && len(secret) <= 256 && subtle.ConstantTimeCompare(digest[:], s.SecretHash[:]) == 1
	if !valid {
		if err := s.persistLocked(withAudit(s.State, "access", false)); err != nil {
			return "", authResponse{}, err
		}
		return "", authResponse{}, &apiError{Code: "invalid_secret", Message: "Секрет доступа не подходит.", Status: 401}
	}
	token, err := randomToken()
	if err != nil {
		return "", authResponse{}, err
	}
	csrf := s.csrfFor(token)
	now := time.Now().UTC()
	next := withAudit(s.State, "access", true)
	next.Sessions = slices.Clone(next.Sessions)
	if len(next.Sessions) >= 64 {
		next.Sessions = next.Sessions[1:]
	}
	expires := now.Add(s.TTL)
	next.Sessions = append(next.Sessions, sessionRecord{TokenHash: tokenHash(token), CSRFHash: tokenHash(csrf), CreatedAt: now, ExpiresAt: expires})
	if err = s.persistLocked(next); err != nil {
		return "", authResponse{}, err
	}
	return token, authResponse{CSRFToken: csrf, ExpiresAt: expires}, nil
}

// authenticate проверяет cookie, ротацию секрета и при необходимости CSRF.
func (s *sessionStore) authenticate(token, csrf string, requireCSRF bool) (authResponse, error) {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	if err := s.refreshLocked(); err != nil {
		return authResponse{}, err
	}
	if len(token) != 43 {
		return authResponse{}, &apiError{Code: "unauthorized", Message: "Войдите в панель заново.", Status: 401}
	}
	wanted := tokenHash(token)
	for _, record := range s.State.Sessions {
		if subtle.ConstantTimeCompare([]byte(record.TokenHash), []byte(wanted)) != 1 {
			continue
		}
		if requireCSRF && subtle.ConstantTimeCompare([]byte(record.CSRFHash), []byte(tokenHash(csrf))) != 1 {
			return authResponse{}, &apiError{Code: "invalid_csrf", Message: "Не удалось проверить запрос. Обновите страницу.", Status: 403}
		}
		return authResponse{CSRFToken: s.csrfFor(token), ExpiresAt: record.ExpiresAt}, nil
	}
	return authResponse{}, &apiError{Code: "unauthorized", Message: "Сессия завершена. Войдите заново.", Status: 401}
}

// logout удаляет сессию и фиксирует выход перед ответом.
func (s *sessionStore) logout(token string) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	next := withAudit(s.State, "logout", true)
	wanted := tokenHash(token)
	next.Sessions = []sessionRecord{}
	for _, record := range s.State.Sessions {
		if record.TokenHash != wanted {
			next.Sessions = append(next.Sessions, record)
		}
	}
	s.State.Sessions = next.Sessions
	return s.persistLocked(next)
}

// audit записывает безопасное действие, не сохраняя request payload.
func (s *sessionStore) audit(action string, success bool) error {
	s.Mutex.Lock()
	defer s.Mutex.Unlock()
	return s.persistLocked(withAudit(s.State, action, success))
}
