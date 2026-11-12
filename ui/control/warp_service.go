//go:build linux

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var warpTracePattern = regexp.MustCompile(`(?m)^warp=(on|plus)\r?$`)
var warpDirectPattern = regexp.MustCompile(`(?m)^warp=off\r?$`)
var warpConnectedPattern = regexp.MustCompile(`(?m)^Status update: Connected\s*$`)

// status получает только булевы признаки WARP, скрывая регистрацию и сырые ответы.
func (s *WarpSession) status(ctx context.Context) WarpStatus {
	code, active, _ := warpExecute(ctx, []string{"systemctl", "is-active", "warp-svc.service"}, 2*time.Second, "", 8192, false)
	statusCode, status, _ := warpExecute(ctx, []string{"warp-cli", "--accept-tos", "status"}, 5*time.Second, "", 8192, false)
	return WarpStatus{Installed: warpProgram("warp-cli") != "", ServiceActive: code == 0 && strings.TrimSpace(active) == "active", Connected: statusCode == 0 && warpConnectedPattern.MatchString(status), ObservedAt: warpNow()}
}

// saveEgress сохраняет только подтверждённый путь и nullable время проверки.
func (s *WarpSession) saveEgress(path, message string, verified bool) WarpEgress {
	value := WarpEgress{Path: path, Message: message, ObservedAt: warpNow()}
	if verified {
		stamp := warpNow()
		value.VerifiedAt = &stamp
	}
	s.write("egress.json", value)
	return value
}

// warpProbe проверяет WARP независимо от выбранного клиентского default route.
func (s *WarpSession) warpProbe(ctx context.Context) bool {
	if code, _ := s.optional(ctx, "ip", "link", "show", "dev", warpInterface); code != 0 {
		return false
	}
	s.command(ctx, "ip", "-4", "route", "replace", "default", "dev", warpInterface, "metric", "10", "table", warpProbeTable)
	if s.Err != nil {
		return false
	}
	code, trace, _ := warpExecute(ctx, []string{"curl", "-4", "--silent", "--show-error", "--fail", "--noproxy", "*", "--interface", warpInterface, "--connect-timeout", "3", "--max-time", "6", warpProbeURL}, 8*time.Second, "", 8192, false)
	return code == 0 && warpTracePattern.MatchString(trace)
}

// pathProbe подтверждает HTTPS и UDP DNS из клиентской подсети без изменения peers.
func (s *WarpSession) pathProbe(ctx context.Context, expected string) (bool, *bool) {
	m := s.Manifest
	if m == nil {
		m = s.topology(ctx)
	}
	if m == nil || s.Err != nil {
		return false, nil
	}
	if s.PID <= 0 {
		s.installation(ctx)
	}
	prefix := []string{"nsenter", "--target", strconv.Itoa(s.PID), "--net", "--"}
	args := append(append([]string{}, prefix...), "curl", "-4", "--silent", "--show-error", "--fail", "--noproxy", "*", "--interface", m.ProbeIP, "--connect-timeout", "3", "--max-time", "6", warpProbeURL)
	code, trace, _ := warpExecute(ctx, args, 8*time.Second, "", 8192, false)
	https := code == 0 && warpDirectPattern.MatchString(trace)
	if expected == "warp" {
		https = code == 0 && warpTracePattern.MatchString(trace)
	}
	var dns *bool
	if m.DNSIP != "" {
		args = append(append([]string{}, prefix...), s.Runtime.Executable, "warp", "probe-dns", "--source", m.ProbeIP, "--server", m.DNSIP)
		code, _, _ = warpExecute(ctx, args, 5*time.Second, "", 4096, false)
		ok := code == 0
		dns = &ok
	}
	return https, dns
}

// attemptRecovery оставляет резерв времени для применения blocked/direct после отказа WARP.
func (s *WarpSession) attemptRecovery(ctx context.Context, timeout time.Duration, args ...string) bool {
	if s.Err != nil {
		return false
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < 35*time.Second {
			return false
		}
		if timeout > remaining-30*time.Second {
			timeout = remaining - 30*time.Second
		}
	}
	code, _, err := warpExecute(ctx, args, timeout, "", 8192, false)
	if err == nil && code == 0 {
		return true
	}
	s.event("supervisor", "warning", "Попытка восстановления WARP не завершилась; применяется сохранённая политика выхода.")
	return false
}

// policySet применяет новое намерение только после закрытия прежнего клиентского выхода.
func (s *WarpSession) policySet(ctx context.Context, request PolicyUpdate) any {
	if request.WarpEnabled == nil || request.AllowDirectWithoutWARP == nil || !revisionPattern.MatchString(request.ExpectedRevision) {
		s.fail("invalid_payload", "Нужны два boolean и текущая ревизия политики.", 400)
		return nil
	}
	previous := s.policy()
	if request.ExpectedRevision != previous.Revision {
		s.fail("revision_conflict", "Политика уже изменилась; перечитайте её.", 409)
		return nil
	}
	s.installation(ctx)
	candidate := WarpPolicy{Configured: true, WarpEnabled: *request.WarpEnabled, AllowDirect: *request.AllowDirectWithoutWARP}
	if s.Err != nil {
		return nil
	}
	if s.Manifest == nil && !candidate.WarpEnabled {
		if s.status(ctx).Connected {
			s.fail("unsupported_topology", "Активный внешний WARP требует отдельной интеграции перед выбором direct.", 409)
			return nil
		}
		s.mutation("policy.set")
		s.savePolicy(candidate)
		return map[string]any{"policy": s.policy(), "egress": s.saveEgress("unknown", "Выбран существующий прямой выход; подтверждение доступно в диагностике.", false)}
	}
	s.preflight(ctx)
	if candidate.WarpEnabled && warpProgram("warp-cli") == "" {
		s.fail("capability_unavailable", "Сначала выполните отдельную установку WARP.", 409)
	}
	if s.Err != nil {
		return nil
	}
	s.mutation("policy.set")
	if s.Manifest != nil {
		s.guard(ctx, "blocked")
		s.clearOwnedFlows(ctx)
	}
	s.enable(ctx)
	// До успешного guard старая политика остаётся действующим намерением.
	s.savePolicy(candidate)
	return s.reconcile(ctx, true)
}

// reconnect переподключает только WARP, предварительно соблюдая сохранённую политику выхода.
func (s *WarpSession) reconnect(ctx context.Context) any {
	policy := s.policy()
	if !policy.Configured || !policy.WarpEnabled || s.Manifest == nil {
		s.fail("policy_conflict", "Переподключение требует включённой управляемой WARP интеграции.", 409)
		return nil
	}
	s.preflight(ctx)
	if s.Err != nil {
		return nil
	}
	s.mutation("warp.reconnect")
	if !policy.AllowDirect {
		s.guard(ctx, "blocked")
		s.clearOwnedFlows(ctx)
	}
	s.attemptRecovery(ctx, 8*time.Second, "warp-cli", "--accept-tos", "disconnect")
	s.attemptRecovery(ctx, 8*time.Second, "warp-cli", "--accept-tos", "mode", "warp")
	s.attemptRecovery(ctx, 8*time.Second, "warp-cli", "--accept-tos", "connect")
	return s.reconcile(ctx, true)
}

// emergencyBlock закрывает сохранённый путь даже после ошибки текущей операции.
func (s *WarpSession) emergencyBlock(ctx context.Context, message string) {
	if s.Manifest == nil {
		return
	}
	guard := &WarpSession{Runtime: s.Runtime, Manifest: s.Manifest, PID: s.PID, DNSPID: s.DNSPID, Mutated: true}
	guard.guard(ctx, "blocked")
	guard.saveEgress("blocked", message, false)
	s.Mutated = true
	if guard.Err != nil {
		s.Err = failure(500, "guard_failed", "Защитный guard не подтверждён; требуется немедленная локальная проверка.")
	}
}

// reconcile восстанавливает собственный путь и выбирает egress по явной политике и data-plane пробе.
func (s *WarpSession) reconcile(ctx context.Context, explicit bool) any {
	if s.Err != nil {
		return nil
	}
	policy := s.policy()
	if s.Err != nil {
		s.emergencyBlock(ctx, "Политика повреждена; прямой выход закрыт.")
		return nil
	}
	if !policy.Configured {
		s.fail("policy_conflict", "Сначала явно выберите использование WARP и разрешение direct.", 409)
		if s.Manifest != nil {
			s.emergencyBlock(ctx, "Политика управляемой интеграции не подтверждена; прямой выход закрыт.")
		}
		return nil
	}
	if s.Manifest == nil {
		if policy.WarpEnabled {
			s.fail("capability_unavailable", "Сетевая интеграция не принята под управление.", 409)
			return nil
		}
		return map[string]any{"policy": policy, "egress": s.saveEgress("unknown", "Существующие маршруты не изменены; управляемая интеграция отсутствует.", false)}
	}
	s.preflight(ctx)
	if s.Err != nil {
		s.emergencyBlock(ctx, "Топология или возможности изменены; требуется локальная проверка.")
		return nil
	}
	oldPath := warpString(s.readMap("guard_state.json")["path"])
	saved := warpString(s.readMap("routing_fingerprint.json")["fingerprint"])
	actual := s.fingerprint(ctx)
	damaged := saved == "" || actual != saved
	if s.Err != nil {
		s.emergencyBlock(ctx, "Состояние правил не подтверждено; требуется проверка.")
		return nil
	}
	s.mutation("repair")
	if damaged || explicit {
		s.guard(ctx, "blocked")
		s.configureNamespace(ctx)
		s.configureHost(ctx, "blocked")
	}
	if s.Err != nil {
		return nil
	}
	healthy := false
	if policy.WarpEnabled {
		status := s.status(ctx)
		cooldown := s.readMap("recovery.json")
		timestamp := warpTimestamp()
		if !status.Connected && timestamp >= warpNumber(cooldown["retry_at"]) {
			failureSince := warpNumber(cooldown["failure_since"])
			if failureSince == 0 {
				failureSince = timestamp
			}
			if timestamp-failureSince >= 120 && timestamp >= warpNumber(cooldown["restart_at"]) {
				s.attemptRecovery(ctx, 10*time.Second, "systemctl", "restart", "warp-svc.service")
				cooldown["restart_at"] = timestamp + 300
			} else {
				s.attemptRecovery(ctx, 8*time.Second, "systemctl", "start", "warp-svc.service")
			}
			s.attemptRecovery(ctx, 8*time.Second, "warp-cli", "--accept-tos", "mode", "warp")
			s.attemptRecovery(ctx, 8*time.Second, "warp-cli", "--accept-tos", "connect")
			cooldown["retry_at"] = timestamp + 30
			cooldown["failure_since"] = failureSince
			s.write("recovery.json", cooldown)
		}
		cache := s.readMap("warp_probe.json")
		if explicit || damaged || !status.Connected || timestamp-warpNumber(cache["at"]) >= float64(s.Runtime.Config.ProbeInterval) {
			healthy = s.warpProbe(ctx)
			s.write("warp_probe.json", map[string]any{"at": warpTimestamp(), "healthy": healthy})
			if !healthy && status.Connected {
				cooldown["data_failures"] = warpNumber(cooldown["data_failures"]) + 1
				if warpNumber(cooldown["failure_since"]) == 0 {
					cooldown["failure_since"] = timestamp
				}
				if warpNumber(cooldown["data_failures"]) >= 3 && timestamp >= warpNumber(cooldown["retry_at"]) {
					if timestamp-warpNumber(cooldown["failure_since"]) >= 120 && timestamp >= warpNumber(cooldown["restart_at"]) {
						s.attemptRecovery(ctx, 10*time.Second, "systemctl", "restart", "warp-svc.service")
						cooldown["restart_at"] = timestamp + 300
					} else {
						s.attemptRecovery(ctx, 8*time.Second, "warp-cli", "--accept-tos", "disconnect")
					}
					s.attemptRecovery(ctx, 8*time.Second, "warp-cli", "--accept-tos", "connect")
					cooldown["retry_at"] = timestamp + 120
				}
				s.write("recovery.json", cooldown)
			}
		} else {
			healthy = warpBool(cache["healthy"])
		}
		if healthy {
			s.write("recovery.json", map[string]any{"retry_at": 0, "failure_since": 0, "restart_at": cooldown["restart_at"]})
		}
	}
	target := "blocked"
	if healthy {
		target = "warp"
	} else if !policy.WarpEnabled || policy.AllowDirect {
		target = "direct"
	}
	switched := oldPath != target || damaged || explicit
	if switched {
		s.guard(ctx, "blocked")
		s.configureHost(ctx, target)
		s.clearOwnedFlows(ctx)
		s.guard(ctx, target)
		s.rememberFingerprint(ctx)
	}
	if s.Err != nil {
		return nil
	}
	if target == "blocked" {
		return map[string]any{"policy": policy, "egress": s.saveEgress("blocked", "WARP не подтверждён; прямой выход запрещён.", false)}
	}
	lastProbe := warpNumber(s.readMap("path_probe_time.json")["at"])
	if !switched && warpTimestamp()-lastProbe < float64(s.Runtime.Config.ProbeInterval) {
		return map[string]any{"policy": policy, "egress": s.readMap("egress.json"), "checks": s.readMap("path_checks.json")["checks"]}
	}
	httpsOK, dnsOK := s.pathProbe(ctx, target)
	s.write("path_probe_time.json", map[string]any{"at": warpTimestamp()})
	checks := []WarpCheck{warpCheck("egress.https", "error", "HTTPS выбранного выхода не подтверждён."), warpCheck("egress.dns", "unknown", "DNS-контейнер не выбран.")}
	if httpsOK {
		checks[0] = warpCheck("egress.https", "ok", "HTTPS через выбранный выход подтверждён.")
	}
	if dnsOK != nil {
		if *dnsOK {
			checks[1] = warpCheck("egress.dns", "ok", "UDP DNS отвечает.")
		} else {
			checks[1] = warpCheck("egress.dns", "error", "Ответ UDP DNS не подтверждён.")
		}
	}
	s.write("path_checks.json", map[string]any{"checks": checks, "observed_at": warpNow()})
	result := WarpEgress{}
	if !httpsOK {
		result = s.saveEgress("unknown", "Правила применены, но HTTPS выбранного выхода не подтверждён.", false)
	} else {
		message := "Выход подтверждён."
		if dnsOK != nil && !*dnsOK {
			message = "HTTPS подтверждён, DNS требует внимания."
		}
		result = s.saveEgress(target, message, true)
	}
	status := "warning"
	if httpsOK && (dnsOK == nil || *dnsOK) {
		status = "succeeded"
	}
	s.event("supervisor", status, result.Message)
	if explicit && (!httpsOK || (dnsOK != nil && !*dnsOK)) {
		s.fail("verification_failed", "Правила применены, но проверка HTTPS/DNS не завершилась успешно; восстановление не подтверждено.", 502)
	}
	return map[string]any{"policy": policy, "egress": result, "checks": checks}
}

// setup устанавливает только WARP из официального APT источника после защиты административного пути.
func (s *WarpSession) setup(ctx context.Context) any {
	policy := s.policy()
	if !policy.Configured {
		s.fail("policy_conflict", "До установки WARP явно выберите политику выхода.", 409)
		return nil
	}
	s.preflight(ctx)
	if s.Err != nil {
		return nil
	}
	installed := warpProgram("warp-cli") != ""
	_, registrationErr := os.Lstat("/var/lib/cloudflare-warp")
	registrationExists := !os.IsNotExist(registrationErr)
	var codename string
	if !installed {
		raw, err := warpReadPublic("/etc/os-release", 16384)
		if err != nil {
			s.fail("capability_unavailable", "Не удалось определить поддерживаемую Ubuntu.", 409)
			return nil
		}
		values := map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(line, "=")
			if ok {
				values[key] = strings.Trim(value, "\"'")
			}
		}
		codename = values["VERSION_CODENAME"]
		if values["ID"] != "ubuntu" || (codename != "jammy" && codename != "noble" && codename != "resolute") {
			s.fail("capability_unavailable", "Автоматический WARP setup поддерживает проверенные Ubuntu codename.", 409)
			return nil
		}
		for _, program := range []string{"apt-get", "curl", "gpg"} {
			if warpProgram(program) == "" {
				s.fail("capability_unavailable", "Для отдельной установки WARP требуется "+program+".", 409)
			}
		}
		if s.Err != nil {
			return nil
		}
	}
	s.mutation("warp.setup")
	// Guard/admin защищены до apt postinst, который способен автоматически запустить daemon.
	s.enable(ctx)
	initial := "blocked"
	if !policy.WarpEnabled || policy.AllowDirect {
		initial = "direct"
	}
	s.configureHost(ctx, initial)
	s.clearOwnedFlows(ctx)
	s.guard(ctx, initial)
	if s.Err != nil {
		return nil
	}
	if !installed {
		code, key, err := warpExecute(ctx, []string{"curl", "--fail", "--silent", "--show-error", "--proto", "=https", "--tlsv1.2", "--max-time", "20", "https://pkg.cloudflareclient.com/pubkey.gpg"}, 25*time.Second, "", 65536, false)
		if err != nil || code != 0 {
			s.fail("command_failed", "Не удалось получить официальный ключ APT Cloudflare.", 502)
			return nil
		}
		code, binaryKey, err := warpExecute(ctx, []string{"gpg", "--batch", "--yes", "--dearmor"}, 8*time.Second, key, 65536, false)
		if err != nil || code != 0 || binaryKey == "" {
			s.fail("command_failed", "Не удалось проверить формат ключа APT Cloudflare.", 502)
			return nil
		}
		keyPath := "/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg"
		source := "deb [signed-by=" + keyPath + "] https://pkg.cloudflareclient.com/ " + codename + " main\n"
		if err := warpPublishFile(keyPath, []byte(binaryKey)); err != nil {
			s.fail("configuration_changed", "APT key отличается от официального источника или небезопасен; он не перезаписан.", 409)
			return nil
		}
		if err := warpPublishFile("/etc/apt/sources.list.d/cloudflare-client.list", []byte(source)); err != nil {
			s.fail("configuration_changed", "APT source отличается или небезопасен; он не перезаписан.", 409)
			return nil
		}
		s.run(ctx, []string{"apt-get", "-o", "DPkg::Lock::Timeout=15", "update"}, 55*time.Second, "", false)
		if s.Err != nil {
			s.Err.Message = "Обновление индексов APT: " + s.Err.Message
			return nil
		}
		s.run(ctx, []string{"apt-get", "-o", "DPkg::Lock::Timeout=15", "install", "--no-install-recommends", "--yes", "cloudflare-warp"}, 80*time.Second, "", false)
		if s.Err != nil {
			s.Err.Message = "Установка пакета WARP: " + s.Err.Message
			return nil
		}
	}
	s.run(ctx, []string{"systemctl", "enable", "--now", "warp-svc.service"}, 15*time.Second, "", false)
	code, _ := s.optional(ctx, "warp-cli", "--accept-tos", "registration", "show")
	if code != 0 {
		if installed || registrationExists {
			s.fail("registration_unavailable", "Существующая регистрация WARP не подтверждена; credentials не сбрасываются.", 409)
			return nil
		}
		s.command(ctx, "warp-cli", "--accept-tos", "registration", "new")
	}
	if s.Err != nil {
		return nil
	}
	result := s.reconcile(ctx, true)
	if s.Err == nil {
		s.event("warp.setup", "succeeded", "WARP подготовлен; выбранный выход и DNS проверены. AWG/Docker не устанавливались.")
	}
	return result
}

// diagnostics возвращает WARP и routing проверки; общие AWG показатели добавляет Docker-адаптер.
func (s *WarpSession) diagnostics(ctx context.Context) any {
	policy := s.policy()
	status := s.status(ctx)
	severity := "warning"
	if policy.WarpEnabled {
		severity = "error"
	}
	checks := []WarpCheck{warpCheck("warp.service", severity, "Служба WARP не запущена."), warpCheck("warp.tunnel", severity, "Подключение WARP не подтверждено.")}
	if status.ServiceActive {
		checks[0] = warpCheck("warp.service", "ok", "Служба WARP работает.")
	}
	if status.Connected {
		checks[1] = warpCheck("warp.tunnel", "ok", "WARP сообщает Connected.")
	}
	observation := &WarpSession{Runtime: s.Runtime, Manifest: s.Manifest}
	observation.topology(ctx)
	if observation.Err != nil {
		checks = append(checks, warpCheck("routing.capability", "warning", observation.Err.Message))
	} else if s.Manifest == nil {
		checks = append(checks, warpCheck("routing.managed", "unknown", "Собственная интеграция не включена; маршруты наблюдаются."))
		if policy.Configured && !policy.WarpEnabled {
			httpsOK, dnsOK := observation.pathProbe(ctx, "direct")
			if httpsOK {
				checks = append(checks, warpCheck("egress.https", "ok", "Прямой HTTPS подтверждён."))
				s.saveEgress("direct", "Существующий прямой выход подтверждён; маршруты не менялись.", true)
			} else {
				checks = append(checks, warpCheck("egress.https", "error", "Прямой HTTPS не подтверждён."))
			}
			if dnsOK == nil {
				checks = append(checks, warpCheck("egress.dns", "unknown", "DNS-контейнер не выбран."))
			} else if *dnsOK {
				checks = append(checks, warpCheck("egress.dns", "ok", "UDP DNS отвечает."))
			} else {
				checks = append(checks, warpCheck("egress.dns", "error", "UDP DNS не подтверждён."))
			}
		}
	} else {
		code, _, _ := warpExecute(ctx, []string{"nft", "list", "table", "inet", warpNFTTable}, 4*time.Second, "", maxMessageBytes, false)
		if code == 0 {
			checks = append(checks, warpCheck("routing.guard", "ok", "Собственная защитная таблица присутствует."))
		} else {
			checks = append(checks, warpCheck("routing.guard", "error", "Защитная таблица отсутствует."))
		}
		value := s.readMap("path_checks.json")
		raw, _ := json.Marshal(value["checks"])
		var cached []WarpCheck
		if json.Unmarshal(raw, &cached) == nil {
			checks = append(checks, cached...)
		}
	}
	result := map[string]any{"observed_at": warpNow(), "checks": checks}
	s.write("diagnostics.json", result)
	return result
}

// overview возвращает WARP снимок без VPS метрик и доступа к AWG секретам.
func (s *WarpSession) overview(ctx context.Context) any {
	egress := WarpEgress{Path: "unknown", Message: "Выход ещё не проверен.", ObservedAt: warpNow()}
	s.read("egress.json", &egress)
	checks := s.readMap("diagnostics.json")["checks"]
	if checks == nil {
		checks = []any{}
	}
	return map[string]any{"warp": s.status(ctx), "policy": s.policy(), "egress": egress, "checks": checks}
}

// logs возвращает только безопасные события supervisor либо отредактированный WARP journal.
func (s *WarpSession) logs(ctx context.Context, request LogRequest) any {
	if request.Limit < 1 || request.Limit > 200 || (request.Source != "warp" && request.Source != "supervisor") {
		s.fail("invalid_payload", "Допускаются журналы warp/supervisor и limit 1..200.", 400)
		return nil
	}
	lines := []string{}
	if request.Source == "supervisor" {
		var events []map[string]any
		s.read("events.json", &events)
		if len(events) > request.Limit {
			events = events[len(events)-request.Limit:]
		}
		for _, event := range events {
			lines = append(lines, warpString(event["at"])+" "+warpString(event["action"])+" "+warpString(event["status"])+" "+warpString(event["message"]))
		}
	} else {
		code, raw, err := warpExecute(ctx, []string{"journalctl", "--no-pager", "--output=short-iso", "-u", "warp-svc.service", "-n", strconv.Itoa(request.Limit)}, 8*time.Second, "", 262144, false)
		if err != nil || code != 0 {
			s.fail("command_failed", "Журнал WARP недоступен.", 502)
			return nil
		}
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			lines = append(lines, warpRedact(line))
		}
	}
	return map[string]any{"source": request.Source, "lines": lines, "observed_at": warpNow()}
}

var warpSecretPattern = regexp.MustCompile(`(?i)([A-Za-z0-9+/]{43}=|[A-Za-z0-9_-]{48,}|(?:private|preshared|secret|token|password|credential|license)[^\r\n]*)`)

// warpRedact скрывает потенциальные ключи и ограничивает одну строку журнала.
func warpRedact(value string) string {
	value = warpSecretPattern.ReplaceAllString(value, "[скрыто]")
	if len(value) > 2000 {
		value = value[:2000]
	}
	return strings.ToValidUTF8(value, "")
}

// warpStatePath возвращает только фиксированное имя root состояния.
func warpStatePath(runtime *WarpRuntime, name string) string {
	return filepath.Join(runtime.Config.StateDir, name)
}
