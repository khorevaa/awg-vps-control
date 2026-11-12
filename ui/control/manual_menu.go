//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// manualPolicy содержит текущий режим перед явным выбором в ручном меню.
type manualPolicy struct {
	Configured  bool   `json:"configured"`                // Признак ранее сохранённого выбора.
	WarpEnabled bool   `json:"warp_enabled"`              // Намерение использовать WARP.
	AllowDirect bool   `json:"allow_direct_without_warp"` // Разрешение прямого резервного выхода.
	Revision    string `json:"revision"`                  // Ревизия перед изменением.
}

// manualCall передаёт фиксированное ручное действие через проверенный адаптер.
func manualCall(action string, payload any) (Response, error) {
	config, err := loadConfig()
	if err != nil {
		return Response{}, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return Response{}, err
	}
	client := &HostClient{socketPath: config.HostSocket}
	request := Request{RequestID: fmt.Sprintf("manual_%d", time.Now().UnixNano()), Action: action, Payload: data}
	var response Response
	var transportError *APIError
	if action == "policy.get" || action == "policy.set" {
		response, transportError, _ = exchangeLocalJSON(context.Background(), envDefault("AWG_WARP_SOCKET", "/run/awg_vps_warp/warp.sock"), 0, request, hostDeadline(action))
	} else {
		response, transportError, _ = client.Call(context.Background(), request)
	}
	if transportError != nil {
		return Response{}, transportError
	}
	if response.Error != nil {
		return response, response.Error
	}
	return response, nil
}

// runManual обслуживает безопасный ввод имён и политики без shell-интерполяции JSON.
func runManual(args []string) error {
	if os.Geteuid() != 0 || len(args) == 0 {
		return fmt.Errorf("ручные команды требуют root")
	}
	if args[0] == "status" || args[0] == "doctor" || args[0] == "clients" || args[0] == "settings" || args[0] == "logs" {
		return manualView(args[0])
	}
	if args[0] == "attach" {
		if len(args) != 4 {
			return fmt.Errorf("attach требует контейнер, сеть и DNS-контейнер")
		}
		response, err := manualCall("attach", AttachRequest{ContainerName: args[1], DockerNetwork: args[2], DNSContainerName: args[3]})
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(response)
	}
	if args[0] != "policy" {
		return fmt.Errorf("неизвестная ручная команда")
	}
	response, err := manualCall("policy.get", map[string]any{})
	if err != nil {
		return err
	}
	var current manualPolicy
	if err := json.Unmarshal(response.Data, &current); err != nil {
		return err
	}
	fmt.Printf("Текущая политика: настроена=%t, WARP=%t, резервный прямой выход=%t\n", current.Configured, current.WarpEnabled, current.AllowDirect)
	fmt.Println("1) Работать без WARP\n2) WARP: блокировать выход при отказе\n3) WARP: разрешить автоматический прямой выход при отказе\n0) Отмена")
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Режим: ")
	choice, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	choice = strings.TrimSpace(choice)
	if choice == "0" || choice == "" {
		return nil
	}
	if choice != "1" && choice != "2" && choice != "3" {
		return fmt.Errorf("неизвестный режим")
	}
	warp, direct := choice != "1", choice == "3"
	fmt.Println("Переключение может оборвать соединения. Разрешение direct не меняется автоматически.")
	fmt.Print("Сохранить выбранную политику? Напишите «да»: ")
	answer, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(answer) != "да" {
		return nil
	}
	updated, err := manualCall("policy.set", PolicyUpdate{WarpEnabled: &warp, AllowDirectWithoutWARP: &direct, ExpectedRevision: current.Revision})
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(updated)
}

// manualNested извлекает необязательное поле снимка без предположений о его наличии.
func manualNested(value any, names ...string) any {
	for _, name := range names {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[name]
	}
	return value
}

// manualLabel отображает неизвестное значение явно, сохраняя булевы false.
func manualLabel(value any) string {
	if value == nil {
		return "неизвестно"
	}
	if text, ok := value.(string); ok && text == "" {
		return "—"
	}
	return fmt.Sprint(value)
}

// manualView печатает предназначенное для человека состояние без сырых секретов.
func manualView(command string) error {
	actions := map[string]string{"status": "overview", "doctor": "diagnostics", "clients": "peers", "settings": "policy.get", "logs": "logs"}
	payload := any(map[string]any{})
	if command == "logs" {
		payload = LogRequest{Source: "supervisor", Limit: 100}
	}
	response, err := manualCall(actions[command], payload)
	if err != nil {
		return err
	}
	var data any
	decoder := json.NewDecoder(bytes.NewReader(response.Data))
	decoder.UseNumber()
	if err := decoder.Decode(&data); err != nil {
		return err
	}
	switch command {
	case "status":
		fmt.Printf("VPS: %s\nСнимок: %s\nAWG подключён к панели: %s\nAWG: %s\n", manualLabel(manualNested(data, "hostname")), manualLabel(manualNested(data, "observed_at")), manualLabel(manualNested(data, "attached")), manualLabel(manualNested(data, "awg", "message")))
		fmt.Printf("WARP установлен: %s; служба активна: %s; подключён: %s\n", manualLabel(manualNested(data, "warp", "installed")), manualLabel(manualNested(data, "warp", "service_active")), manualLabel(manualNested(data, "warp", "connected")))
		fmt.Printf("Клиентский выход: %s\n%s\n", manualLabel(manualNested(data, "egress", "path")), manualLabel(manualNested(data, "egress", "message")))
		fmt.Printf("Политика: выбрана=%s, WARP=%s, direct при отказе=%s\n", manualLabel(manualNested(data, "policy", "configured")), manualLabel(manualNested(data, "policy", "warp_enabled")), manualLabel(manualNested(data, "policy", "allow_direct_without_warp")))
	case "doctor":
		checks, ok := manualNested(data, "checks").([]any)
		if !ok {
			return fmt.Errorf("снимок проверок недоступен")
		}
		for _, check := range checks {
			fmt.Printf("[%s] %s: %s\n", manualLabel(manualNested(check, "status")), manualLabel(manualNested(check, "id")), manualLabel(manualNested(check, "message")))
		}
	case "clients":
		peers, ok := data.([]any)
		if !ok {
			return fmt.Errorf("снимок клиентов недоступен")
		}
		fmt.Printf("Клиентов: %d\n", len(peers))
		for _, peer := range peers {
			fmt.Printf("%s | %s | handshake=%s | RX=%s TX=%s\n", manualLabel(manualNested(peer, "name")), manualLabel(manualNested(peer, "allowed_ips")), manualLabel(manualNested(peer, "latest_handshake")), manualLabel(manualNested(peer, "rx_bytes")), manualLabel(manualNested(peer, "tx_bytes")))
		}
	case "settings":
		fmt.Printf("Режим выбран: %s\nИспользовать WARP: %s\nРазрешить direct при отказе: %s\nРевизия: %s\n", manualLabel(manualNested(data, "configured")), manualLabel(manualNested(data, "warp_enabled")), manualLabel(manualNested(data, "allow_direct_without_warp")), manualLabel(manualNested(data, "revision")))
	case "logs":
		lines, ok := manualNested(data, "lines").([]any)
		if !ok {
			return fmt.Errorf("снимок журнала недоступен")
		}
		for _, line := range lines {
			fmt.Println(manualLabel(line))
		}
	}
	return nil
}
