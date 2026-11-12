//go:build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxMessageBytes = 1024 * 1024
const maxPayloadBytes = 4096

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
var operationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var resourcePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var revisionPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// readLine читает ровно одну ограниченную JSON-строку с обязательным LF.
func readLine(reader io.Reader) ([]byte, error) {
	buffer := bufio.NewReaderSize(io.LimitReader(reader, maxMessageBytes+1), maxMessageBytes+1)
	line, err := buffer.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("неполная строка протокола: %w", err)
	}
	if len(line) > maxMessageBytes {
		return nil, fmt.Errorf("недопустимая строка протокола")
	}
	return bytes.TrimSpace(line), nil
}

// validateJSONTokens отвергает повторные ключи и чрезмерную вложенность JSON.
func validateJSONTokens(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("слишком глубокий JSON")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("повторный или недопустимый ключ JSON")
			}
			seen[key] = true
			if err := validateJSONTokens(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := validateJSONTokens(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("недопустимый JSON")
	}
	_, err = decoder.Token()
	return err
}

// decodeStrict отклоняет повторные ключи, неизвестные поля и второй JSON-объект.
func decodeStrict(content []byte, target any) error {
	if !utf8.Valid(content) {
		return errors.New("JSON должен содержать допустимый UTF-8")
	}
	tokens := json.NewDecoder(bytes.NewReader(content))
	tokens.UseNumber()
	if err := validateJSONTokens(tokens, 0); err != nil {
		return err
	}
	if _, err := tokens.Token(); !errors.Is(err, io.EOF) {
		return errors.New("лишнее содержимое JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return nil
}

// canonicalObject проверяет объект параметров и нормализует порядок ключей.
func canonicalObject(payload json.RawMessage) (json.RawMessage, *APIError) {
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if len(payload) > maxPayloadBytes {
		return nil, failure(413, "payload_too_large", "Параметры операции слишком велики.")
	}
	var object map[string]json.RawMessage
	if decodeStrict(payload, &object) != nil || object == nil {
		return nil, failure(422, "invalid_payload", "Параметры должны быть JSON-объектом.")
	}
	canonical, err := json.Marshal(object)
	if err != nil {
		return nil, failure(422, "invalid_payload", "Некорректные параметры.")
	}
	return canonical, nil
}

// requireEmpty отклоняет параметры действий, не принимающих пользовательские поля.
func requireEmpty(payload json.RawMessage) *APIError {
	if string(payload) != "{}" {
		return failure(422, "invalid_payload", "Это действие не принимает параметры.")
	}
	return nil
}

// validatePayload проверяет поля каждого действия до обращения к хосту.
func validatePayload(action string, payload json.RawMessage) (json.RawMessage, *APIError) {
	canonical, apiError := canonicalObject(payload)
	if apiError != nil {
		return nil, apiError
	}
	switch action {
	case "health", "overview", "discover", "peers", "peers.catalog", "diagnostics", "configuration", "policy.get", "operations.list", "repair", "warp.reconnect", "warp.setup", "awg.restart":
		return canonical, requireEmpty(canonical)
	case "peer.create", "peer.rename", "peer.revoke":
		return canonical, validatePeerPayload(action, canonical)
	case "logs":
		var value LogRequest
		if decodeStrict(canonical, &value) != nil || value.Limit < 1 || value.Limit > 200 {
			return nil, failure(422, "invalid_logs", "Нужен источник журнала и limit от 1 до 200.")
		}
		switch value.Source {
		case "awg", "dns", "warp", "supervisor", "bridge":
			return canonical, nil
		}
	case "attach":
		var value AttachRequest
		if decodeStrict(canonical, &value) == nil && resourcePattern.MatchString(value.ContainerName) && resourcePattern.MatchString(value.DockerNetwork) && (value.DNSContainerName == "" || resourcePattern.MatchString(value.DNSContainerName)) {
			return canonical, nil
		}
	case "policy.set":
		var value PolicyUpdate
		if decodeStrict(canonical, &value) == nil && value.WarpEnabled != nil && value.AllowDirectWithoutWARP != nil && revisionPattern.MatchString(value.ExpectedRevision) {
			return canonical, nil
		}
	case "operations.get", "peers.profile.consume":
		var value OperationLookup
		if decodeStrict(canonical, &value) == nil && operationIDPattern.MatchString(value.ID) {
			return canonical, nil
		}
	default:
		return nil, failure(404, "unknown_action", "Действие не поддерживается.")
	}
	return nil, failure(422, "invalid_payload", "Параметры действия не прошли проверку.")
}

// encodeData сериализует внутренний результат без изменения протокольной формы.
func encodeData(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return data
}

// mutationAction определяет конечный перечень привилегированных изменений.
func mutationAction(action string) bool {
	switch action {
	case "attach", "policy.set", "repair", "warp.reconnect", "warp.setup", "awg.restart", "peer.create", "peer.rename", "peer.revoke":
		return true
	default:
		return false
	}
}

// secretField распознаёт ключи, запрещённые для передачи и постоянного журнала.
func secretField(key string) bool {
	value := strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.ToLower(key))
	for _, part := range []string{"privatekey", "preshared", "headerprotectionkey", "password", "accesstoken", "secret", "registrationkey", "authkey", "authtoken", "credential"} {
		if strings.Contains(value, part) {
			return true
		}
	}
	return value == "psk" || value == "token" || value == "secret"
}
