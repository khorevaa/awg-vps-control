//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
)

var secretLinePattern = regexp.MustCompile(`(?im)(private[_-]?key|preshared[_-]?key|headerprotectionkey|password|access[_-]?secret|auth[_-]?token|registration[_-]?key)\s*[:=]\s*[^\r\n]+`)

// safeText удаляет чувствительные присваивания и управляющие символы из результата.
func safeText(value string) string {
	value = secretLinePattern.ReplaceAllString(value, "$1=[redacted]")
	return strings.Map(func(character rune) rune {
		if unicode.IsControl(character) && character != '\n' && character != '\t' {
			return -1
		}
		return character
	}, value)
}

// sanitizeValue очищает дерево JSON, не записывая сырые командные ответы в журнал.
func sanitizeValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if secretField(key) {
				result[key] = "[redacted]"
			} else {
				result[key] = sanitizeValue(item)
			}
		}
		return result
	case []any:
		for index := range typed {
			typed[index] = sanitizeValue(typed[index])
		}
		return typed
	case string:
		return safeText(typed)
	default:
		return typed
	}
}

// sanitizeData ограничивает и очищает результат доверенного хостового моста.
func sanitizeData(raw json.RawMessage, limit int) (json.RawMessage, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage(`null`), true
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return nil, false
	}
	result, err := json.Marshal(sanitizeValue(value))
	if err != nil {
		return nil, false
	}
	if len(result) > limit {
		return nil, false
	}
	return result, true
}

// operationResult ограничивает только документированный результат записи журнала.
func operationResult(raw json.RawMessage) json.RawMessage {
	if len(raw) > maxOperationResult {
		return json.RawMessage(`{"truncated":true,"message":"Результат слишком велик; перечитайте диагностику."}`)
	}
	return append(json.RawMessage(nil), raw...)
}

// sanitizeError сохраняет код и статус без необработанного сообщения внешней команды.
func sanitizeError(apiError *APIError) *APIError {
	if apiError == nil {
		return nil
	}
	code := apiError.Code
	if !identifierPattern.MatchString(code) || len(code) > 64 {
		code = "host_error"
	}
	status := apiError.Status
	if status < 400 || status > 599 {
		status = 502
	}
	message := "Сервис управления отклонил действие. Проверьте диагностику."
	switch code {
	case "not_attached":
		message = "Сначала подключите существующую установку AWG."
	case "revision_conflict", "policy_conflict", "configuration_changed":
		message = "Настройки изменились; перечитайте их перед повторным действием."
	case "unsupported", "unsupported_topology", "capability_unavailable":
		message = "Эта установка пока не поддерживает выбранное действие."
	case "lock_busy", "busy":
		message = "Установка занята другой операцией."
	case "operation_rolled_back":
		message = "Изменение не прошло проверку и было отменено хостовым мостом."
	case "rollback_failed":
		message = "Не удалось подтвердить восстановление. Требуется ручная диагностика."
	}
	return failure(status, code, message)
}
