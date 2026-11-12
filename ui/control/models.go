//go:build linux

package main

import "encoding/json"

// Config содержит настройки процесса согласно control_data_model.md.
type Config struct {
	SocketPath string // Путь Unix-сокета Control.
	HostSocket string // Путь Unix-сокета Docker adapter.
	StatePath  string // Путь постоянного журнала операций.
	WebUID     uint32 // Разрешённый UID сервиса Web.
	WebGID     int    // Группа сокета, доступная сервису Web.
}

// Request описывает один запрос локального протокола.
type Request struct {
	RequestID string          `json:"request_id"` // Идентификатор запроса.
	Action    string          `json:"action"`     // Разрешённое действие.
	Payload   json.RawMessage `json:"payload"`    // Проверенные параметры действия.
}

// Response описывает результат одного запроса локального протокола.
type Response struct {
	RequestID string          `json:"request_id"` // Идентификатор исходного запроса.
	OK        bool            `json:"ok"`         // Признак успешного выполнения.
	Data      json.RawMessage `json:"data"`       // Безопасный результат без секретов.
	Error     *APIError       `json:"error"`      // Ошибка при неуспешном выполнении.
}

// APIError содержит безопасное описание ошибки для Web.
type APIError struct {
	Code    string `json:"code"`    // Стабильный машинный код.
	Message string `json:"message"` // Сообщение без содержимого команд и ключей.
	Status  int    `json:"status"`  // Соответствующий HTTP-статус.
}

// OperationRequest описывает намерение изменить состояние установки.
type OperationRequest struct {
	Action         string          `json:"action"`          // Разрешённая административная операция.
	Payload        json.RawMessage `json:"payload"`         // Параметры согласно контракту операции.
	IdempotencyKey string          `json:"idempotency_key"` // Ключ безопасного повторного запроса.
}

// Operation является публичным снимком операции.
type Operation struct {
	ID        string          `json:"id"`         // Случайный идентификатор операции.
	Action    string          `json:"action"`     // Выполняемое действие.
	Status    string          `json:"status"`     // Состояние выполнения.
	CreatedAt string          `json:"created_at"` // Время создания UTC RFC3339Nano.
	UpdatedAt string          `json:"updated_at"` // Время последнего изменения.
	Result    json.RawMessage `json:"result"`     // Ограниченный безопасный результат.
	Error     *APIError       `json:"error"`      // Причина неуспешного выполнения.
}

// OperationRecord хранит операцию и данные защиты от повторного исполнения.
type OperationRecord struct {
	Operation       Operation       `json:"operation"`        // Публичная часть записи.
	Payload         json.RawMessage `json:"payload"`          // Нормализованные параметры.
	IdempotencyHash string          `json:"idempotency_hash"` // Хеш ключа повторного запроса.
	Fingerprint     string          `json:"fingerprint"`      // Хеш действия и параметров.
}

// Journal является версионированным постоянным журналом.
type Journal struct {
	Version    int               `json:"version"`    // Версия схемы данных.
	Operations []OperationRecord `json:"operations"` // Сохранённые операции.
}

// OperationLookup задаёт идентификатор операции для чтения.
type OperationLookup struct {
	ID string `json:"id"` // Идентификатор существующей операции.
}

// PolicyUpdate проверяет наличие обоих логических параметров политики.
type PolicyUpdate struct {
	WarpEnabled            *bool  `json:"warp_enabled"`              // Намерение использовать WARP, отсутствие запрещено.
	AllowDirectWithoutWARP *bool  `json:"allow_direct_without_warp"` // Явное разрешение прямого выхода.
	ExpectedRevision       string `json:"expected_revision"`         // Ревизия изменяемой политики.
}

// AttachRequest содержит имена обнаруженных ресурсов установки.
type AttachRequest struct {
	ContainerName    string `json:"container_name"`     // Контейнер существующего AWG.
	DNSContainerName string `json:"dns_container_name"` // Необязательный DNS-контейнер.
	DockerNetwork    string `json:"docker_network"`     // Явно выбранная сеть Docker.
}

// LogRequest ограничивает источник и размер снимка журнала.
type LogRequest struct {
	Source string `json:"source"` // Разрешённый источник журнала.
	Limit  int    `json:"limit"`  // Количество строк от 1 до 200.
}

// Error возвращает только безопасное сообщение ошибки.
func (e *APIError) Error() string { return e.Message }

// failure создаёт ошибку с фиксированным безопасным сообщением.
func failure(status int, code, message string) *APIError {
	return &APIError{Code: code, Message: message, Status: status}
}
