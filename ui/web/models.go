//go:build linux

package main

import (
	"context"
	"encoding/json"
	"time"
)

// apiError описывает безопасную ошибку согласно docs/data_model.md.
type apiError struct {
	Code    string `json:"code"`    // Стабильный код ошибки.
	Message string `json:"message"` // Сообщение без секретов.
	Status  int    `json:"status"`  // HTTP-статус ошибки.
}

// Error возвращает безопасное сообщение для вызывающего кода.
func (e *apiError) Error() string { return e.Message }

// accessRequest содержит одноразово переданный секрет входа.
type accessRequest struct {
	Secret string `json:"secret"` // Секрет из защищённого файла.
}

// authResponse описывает текущую сессию без сессионного токена.
type authResponse struct {
	CSRFToken string    `json:"csrf_token"` // Токен защиты изменяющих запросов.
	ExpiresAt time.Time `json:"expires_at"` // Время окончания сессии UTC.
}

// operationRequest соответствует публичному запросу запуска операции.
type operationRequest struct {
	Action         string          `json:"action"`          // Разрешённое действие.
	Payload        json.RawMessage `json:"payload"`         // Строго проверяемые параметры.
	IdempotencyKey string          `json:"idempotency_key"` // Ключ повторного запроса.
}

// policyUpdate задаёт явно выбранную политику выхода.
type policyUpdate struct {
	WarpEnabled            *bool  `json:"warp_enabled"`              // Намерение использовать WARP.
	AllowDirectWithoutWarp *bool  `json:"allow_direct_without_warp"` // Явное разрешение прямого выхода.
	ExpectedRevision       string `json:"expected_revision"`         // Ревизия ранее прочитанной политики.
}

// attachRequest выбирает существующую установку и её обнаруженную сеть.
type attachRequest struct {
	ContainerName    string `json:"container_name"`     // Имя существующего контейнера AWG.
	DNSContainerName string `json:"dns_container_name"` // Необязательное имя контейнера DNS.
	DockerNetwork    string `json:"docker_network"`     // Явно выбранная сеть Docker.
}

// logRequest ограничивает источник и размер снимка журналов.
type logRequest struct {
	Source string `json:"source"` // Разрешённый источник журнала.
	Limit  int    `json:"limit"`  // Максимум строк от 1 до 200.
}

// operationLookup адресует одну сохранённую операцию.
type operationLookup struct {
	ID string `json:"id"` // Идентификатор операции Control.
}

// IControlClient определяет транспорт к изолированному Control.
type IControlClient interface {
	Request(context.Context, string, json.RawMessage) (json.RawMessage, error)
}
