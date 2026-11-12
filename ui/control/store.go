//go:build linux

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

const maxJournalBytes = 8 * 1024 * 1024
const maxOperations = 512
const maxQueuedOperations = 16
const maxOperationResult = 8 * 1024
const operationRetention = 7 * 24 * time.Hour

// Store сериализует доступ к постоянному журналу и блокирует опасные повторы.
type Store struct {
	mu       sync.Mutex // Защита журнала от конкурентного чтения и записи.
	path     string     // Путь приватного state-файла.
	journal  Journal    // Текущее состояние журнала.
	lockFile *os.File   // Удерживаемая межпроцессная блокировка.
	writable bool       // Признак исправного постоянного хранилища.
}

// nowText возвращает единый формат UTC для постоянных и публичных записей.
func nowText() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// digestText вычисляет хеш идентификаторов без сохранения исходного секрета.
func digestText(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// newIdentifier генерирует непредсказуемый идентификатор операции.
func newIdentifier() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

// terminalStatus отличает завершённые записи от операций с неизвестным итогом.
func terminalStatus(status string) bool {
	switch status {
	case "succeeded", "failed", "rolled_back", "manual_recovery_required":
		return true
	default:
		return false
	}
}

// knownStatus проверяет допустимое состояние схемы журнала.
func knownStatus(status string) bool {
	if terminalStatus(status) {
		return true
	}
	switch status {
	case "queued", "running", "verifying", "rolling_back":
		return true
	default:
		return false
	}
}

// openStore проверяет файлы и переводит незавершённые операции в ручное восстановление.
func openStore(path string) (*Store, error) {
	directory := filepath.Dir(path)
	if err := verifyDirectoryPath(directory, true, 0700); err != nil {
		return nil, err
	}
	lock, err := openPrivateFile(filepath.Join(directory, "control.lock"), syscall.O_RDWR|syscall.O_CREAT)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("журнал Control уже используется")
	}
	store := &Store{path: path, lockFile: lock, writable: true, journal: Journal{Version: 1, Operations: []OperationRecord{}}}
	content, err := readPrivateFile(path, maxJournalBytes)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = lock.Close()
		return nil, err
	}
	if err == nil {
		if decodeStrict(content, &store.journal) != nil || store.journal.Version != 1 || len(store.journal.Operations) > maxOperations {
			_ = lock.Close()
			return nil, errors.New("неподдерживаемый или повреждённый журнал Control")
		}
	}
	identifiers := make(map[string]bool)
	keys := make(map[string]bool)
	for index := range store.journal.Operations {
		record := &store.journal.Operations[index]
		_, createdErr := time.Parse(time.RFC3339Nano, record.Operation.CreatedAt)
		_, updatedErr := time.Parse(time.RFC3339Nano, record.Operation.UpdatedAt)
		payload, payloadError := validatePayload(record.Operation.Action, record.Payload)
		fingerprint := digestText(record.Operation.Action + "\n" + string(payload))
		if !operationIDPattern.MatchString(record.Operation.ID) || identifiers[record.Operation.ID] || !revisionPattern.MatchString(record.IdempotencyHash) || keys[record.IdempotencyHash] || !mutationAction(record.Operation.Action) || !knownStatus(record.Operation.Status) || createdErr != nil || updatedErr != nil || payloadError != nil || fingerprint != record.Fingerprint || len(record.Operation.Result) > maxOperationResult {
			_ = lock.Close()
			return nil, errors.New("журнал содержит недопустимую запись операции")
		}
		identifiers[record.Operation.ID] = true
		keys[record.IdempotencyHash] = true
		if peerMutationAction(record.Operation.Action) && len(record.Operation.Result) != 0 && string(record.Operation.Result) != "null" {
			if _, valid := checkedPeerResult(record.Operation.Action, record.Operation.Result); !valid {
				_ = lock.Close()
				return nil, errors.New("журнал содержит недопустимый результат операции клиента")
			}
		}
		if !terminalStatus(record.Operation.Status) {
			record.Operation.Status = "manual_recovery_required"
			record.Operation.UpdatedAt = nowText()
			record.Operation.Error = failure(503, "operation_interrupted", "Control был перезапущен; выполните диагностику перед новым действием.")
		}
	}
	if err := store.saveLocked(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return store, nil
}

// Close освобождает блокировку после остановки обработчиков.
func (store *Store) Close() error { return store.lockFile.Close() }

// saveLocked сохраняет журнал и запрещает будущие мутации после ошибки записи.
func (store *Store) saveLocked() error {
	if !store.writable {
		return errors.New("хранилище Control требует восстановления")
	}
	content, err := json.Marshal(store.journal)
	if err == nil && len(content) > maxJournalBytes {
		err = errors.New("журнал Control превышает допустимый размер")
	}
	if err == nil {
		err = atomicPrivateFile(store.path, append(content, '\n'))
	}
	if err != nil {
		store.writable = false
	}
	return err
}

// cloneOperation копирует изменяемые поля снимка перед снятием блокировки.
func cloneOperation(operation Operation) Operation {
	result := operation
	result.Result = append(json.RawMessage(nil), operation.Result...)
	if operation.Error != nil {
		copied := *operation.Error
		result.Error = &copied
	}
	return result
}

// pruneLocked удаляет только завершённые записи за пределами срока удержания.
func (store *Store) pruneLocked() {
	cutoff := time.Now().Add(-operationRetention)
	retained := make([]OperationRecord, 0, len(store.journal.Operations))
	for _, record := range store.journal.Operations {
		updated, err := time.Parse(time.RFC3339Nano, record.Operation.UpdatedAt)
		if err == nil && terminalStatus(record.Operation.Status) && updated.Before(cutoff) {
			continue
		}
		retained = append(retained, record)
	}
	store.journal.Operations = retained
}

// Create записывает намерение до появления операции в очереди исполнения.
func (store *Store) Create(request OperationRequest) (Operation, bool, *APIError) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.writable {
		return Operation{}, false, failure(503, "journal_unavailable", "Журнал операций требует восстановления.")
	}
	key := digestText(request.IdempotencyKey)
	fingerprint := digestText(request.Action + "\n" + string(request.Payload))
	for _, record := range store.journal.Operations {
		if record.IdempotencyHash == key {
			if record.Fingerprint != fingerprint {
				return Operation{}, false, failure(409, "idempotency_conflict", "Этот ключ уже использован для другого действия.")
			}
			return cloneOperation(record.Operation), false, nil
		}
	}
	store.pruneLocked()
	pending := 0
	for _, record := range store.journal.Operations {
		if !terminalStatus(record.Operation.Status) {
			pending++
		}
	}
	if len(store.journal.Operations) >= maxOperations || pending >= maxQueuedOperations {
		return Operation{}, false, failure(429, "operation_limit", "Лимит журнала или очереди операций достигнут.")
	}
	identifier, err := newIdentifier()
	if err != nil {
		return Operation{}, false, failure(500, "random_unavailable", "Не удалось создать идентификатор операции.")
	}
	timestamp := nowText()
	operation := Operation{ID: identifier, Action: request.Action, Status: "queued", CreatedAt: timestamp, UpdatedAt: timestamp}
	record := OperationRecord{Operation: operation, Payload: append(json.RawMessage(nil), request.Payload...), IdempotencyHash: key, Fingerprint: fingerprint}
	store.journal.Operations = append(store.journal.Operations, record)
	if err := store.saveLocked(); err != nil {
		return Operation{}, false, failure(503, "journal_unavailable", "Намерение не подтверждено журналом; действие не запущено.")
	}
	return cloneOperation(operation), true, nil
}

// Next переводит одну ожидающую операцию в running с обязательной записью на диск.
func (store *Store) Next() (OperationRecord, bool) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if !store.writable {
		return OperationRecord{}, false
	}
	for index := range store.journal.Operations {
		record := &store.journal.Operations[index]
		if record.Operation.Status != "queued" {
			continue
		}
		record.Operation.Status = "running"
		record.Operation.UpdatedAt = nowText()
		if err := store.saveLocked(); err != nil {
			record.Operation.Status = "manual_recovery_required"
			record.Operation.Error = failure(503, "journal_unavailable", "Не удалось подтвердить запуск; действие не отправлено хосту.")
			return OperationRecord{}, false
		}
		result := *record
		result.Operation = cloneOperation(record.Operation)
		result.Payload = append(json.RawMessage(nil), record.Payload...)
		return result, true
	}
	return OperationRecord{}, false
}

// Update сохраняет переход состояния и помечает непроверяемый результат при ошибке диска.
func (store *Store) Update(id, status string, result json.RawMessage, apiError *APIError) bool {
	store.mu.Lock()
	defer store.mu.Unlock()
	for index := range store.journal.Operations {
		operation := &store.journal.Operations[index].Operation
		if operation.ID != id {
			continue
		}
		operation.Status = status
		operation.UpdatedAt = nowText()
		operation.Result = append(json.RawMessage(nil), result...)
		operation.Error = apiError
		if err := store.saveLocked(); err != nil {
			operation.Status = "manual_recovery_required"
			operation.Error = failure(503, "journal_unavailable", "Результат не подтверждён постоянным журналом; требуется диагностика.")
			return false
		}
		return true
	}
	return false
}

// Lookup возвращает снимок одной операции без внутренних ключей и параметров.
func (store *Store) Lookup(id string) (Operation, *APIError) {
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, record := range store.journal.Operations {
		if record.Operation.ID == id {
			return cloneOperation(record.Operation), nil
		}
	}
	return Operation{}, failure(404, "operation_not_found", "Операция не найдена.")
}

// List возвращает не более ста последних операций в обратном порядке времени.
func (store *Store) List() []Operation {
	store.mu.Lock()
	defer store.mu.Unlock()
	operations := make([]Operation, 0, len(store.journal.Operations))
	for _, record := range store.journal.Operations {
		operations = append(operations, cloneOperation(record.Operation))
	}
	sort.SliceStable(operations, func(i, j int) bool {
		first, _ := time.Parse(time.RFC3339Nano, operations[i].CreatedAt)
		second, _ := time.Parse(time.RFC3339Nano, operations[j].CreatedAt)
		return first.After(second)
	})
	if len(operations) > 100 {
		operations = operations[:100]
	}
	return operations
}
