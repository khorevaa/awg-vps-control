//go:build linux

package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var warpHostHooks = [][3]string{{"raw", "PREROUTING", "AVPS_RAW"}, {"filter", "FORWARD", "AVPS_FORWARD"}, {"mangle", "PREROUTING", "AVPS_PREROUTING"}, {"mangle", "OUTPUT", "AVPS_OUTPUT"}, {"nat", "POSTROUTING", "AVPS_NAT"}}
var warpNSHooks = [][3]string{{"filter", "FORWARD", "AVPS_CLIENT"}, {"filter", "OUTPUT", "AVPS_DOCKER_DNS"}, {"nat", "POSTROUTING", "AVPS_CLIENT_NAT"}}

// guard атомарно заменяет независимую от Docker защиту клиентского пути.
func (s *WarpSession) guard(ctx context.Context, path string) {
	if s.Err != nil {
		return
	}
	m := s.Manifest
	if m == nil || !m.valid() || (path != "blocked" && path != "direct" && path != "warp") {
		s.fail("invalid_state", "Нет доверенного manifest защитных ресурсов.", 409)
		return
	}
	if path == "direct" {
		policy := s.policy()
		if !policy.Configured || (policy.WarpEnabled && !policy.AllowDirect) {
			s.fail("policy_conflict", "Прямой выход не разрешён сохранённой политикой.", 409)
			return
		}
	}
	out := m.HostInterface
	if path == "warp" {
		out = warpInterface
	}
	var rules []string
	if m.DNSIP != "" {
		for _, protocol := range []string{"udp", "tcp"} {
			rules = append(rules, fmt.Sprintf("iifname %q ip daddr %s %s dport 53 accept", warpLaneHost, m.DNSIP, protocol), fmt.Sprintf("ip saddr %s ip daddr %s %s sport 53 accept", m.DNSIP, m.ClientNetwork, protocol))
		}
	}
	rules = append(rules, fmt.Sprintf("iifname %q oifname %q ip daddr %s accept", warpLaneHost, warpLaneHost, m.ClientNetwork))
	if path != "blocked" {
		rules = append(rules, fmt.Sprintf("iifname %q oifname %q meta nfproto ipv4 accept", warpLaneHost, out), fmt.Sprintf("iifname %q oifname %q meta nfproto ipv4 ct state established,related accept", out, warpLaneHost))
		if m.DNSIP != "" {
			rules = append(rules, fmt.Sprintf("iifname %q ip saddr %s oifname %q accept", m.DNSBridge, m.DNSIP, out), fmt.Sprintf("iifname %q ip daddr %s ct state established,related accept", out, m.DNSIP))
		}
	}
	for _, address := range m.AWGIPs {
		rules = append(rules, fmt.Sprintf("ip saddr %s udp sport %d ct direction reply ct status dnat accept", address, m.AWGPort), fmt.Sprintf("ip daddr %s udp dport %d ct direction original ct status dnat accept", address, m.AWGPort))
	}
	rules = append(rules, fmt.Sprintf("iifname %q drop", warpLaneHost), fmt.Sprintf("oifname %q drop", warpLaneHost))
	for _, bridge := range m.Bridges {
		rules = append(rules, fmt.Sprintf("iifname %q drop", bridge), fmt.Sprintf("oifname %q drop", bridge))
	}
	inputRules := []string{fmt.Sprintf("iifname %q drop", warpLaneHost)}
	for _, address := range m.AWGIPs {
		inputRules = append(inputRules, fmt.Sprintf("ip saddr %s udp sport %d ct direction reply ct state established accept", address, m.AWGPort))
	}
	for _, bridge := range m.Bridges {
		inputRules = append(inputRules, fmt.Sprintf("iifname %q drop", bridge))
	}
	prefix := ""
	if code, _ := s.optional(ctx, "nft", "list", "table", "inet", warpNFTTable); code == 0 {
		prefix = "delete table inet " + warpNFTTable + "\n"
	}
	script := prefix + "table inet " + warpNFTTable + " {\n chain forward {\n type filter hook forward priority -10; policy accept;\n" + strings.Join(rules, "\n") + "\n }\n chain input {\n type filter hook input priority -10; policy accept;\n" + strings.Join(inputRules, "\n") + "\n }\n}\n"
	s.run(ctx, []string{"nft", "--check", "--file", "-"}, 8*time.Second, script, false)
	s.run(ctx, []string{"nft", "--file", "-"}, 8*time.Second, script, false)
	s.write("guard_state.json", map[string]any{"path": path, "updated_at": warpNow()})
}

// ensureRule создаёт только незанятый приоритет и сверяет сохранённый ownership.
func (s *WarpSession) ensureRule(ctx context.Context, family, priority int, args ...string) {
	_, current := s.optional(ctx, "ip", "-"+strconv.Itoa(family), "rule", "show", "pref", strconv.Itoa(priority))
	expected := s.readMap("rule_manifest.json")
	observed := s.readMap("rule_observed.json")
	key := strconv.Itoa(priority)
	if family == 6 {
		key = "v6_" + key
	}
	desired := strings.Join(args, " ")
	current = strings.TrimSpace(current)
	if current != "" {
		if warpString(expected[key]) != desired || warpString(observed[key]) != current {
			s.fail("configuration_changed", "Приоритет собственного маршрута изменён извне.", 409)
		}
		return
	}
	s.command(ctx, append([]string{"ip", "-" + strconv.Itoa(family), "rule", "add", "pref", strconv.Itoa(priority)}, args...)...)
	expected[key] = desired
	s.write("rule_manifest.json", expected)
	observed[key] = strings.TrimSpace(s.command(ctx, "ip", "-"+strconv.Itoa(family), "rule", "show", "pref", strconv.Itoa(priority)))
	s.write("rule_observed.json", observed)
}

// networkCommand выбирает host либо прикреплённый namespace, не вызывая shell.
func (s *WarpSession) networkCommand(ctx context.Context, namespace bool, args []string, input string, allow bool) (int, string) {
	if namespace {
		return s.ns(ctx, args, input, allow)
	}
	return s.run(ctx, args, 8*time.Second, input, allow)
}

// warpRuleLines возвращает только реальные правила цепочки без её объявления.
func warpRuleLines(raw string) []string {
	var result []string
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "-A ") {
			result = append(result, line)
		}
	}
	return result
}

// ensureJump ставит собственный hook первым, удаляя лишь собственные дубликаты.
func (s *WarpSession) ensureJump(ctx context.Context, table, parent, chain string, namespace, ipv6 bool) {
	binary := "iptables"
	if ipv6 {
		binary = "ip6tables"
	}
	base := []string{binary, "-w", "3", "-t", table}
	s.networkCommand(ctx, namespace, append(append([]string{}, base...), "-N", chain), "", true)
	_, raw := s.networkCommand(ctx, namespace, append(append([]string{}, base...), "-S", parent), "", false)
	actual := warpRuleLines(raw)
	expected := "-A " + parent + " -j " + chain
	if len(actual) == 0 || actual[0] != expected {
		s.networkCommand(ctx, namespace, append(append([]string{}, base...), "-I", parent, "1", "-j", chain), "", false)
	}
	_, raw = s.networkCommand(ctx, namespace, append(append([]string{}, base...), "-S", parent), "", false)
	actual = warpRuleLines(raw)
	for index := len(actual) - 1; index >= 1; index-- {
		if actual[index] == expected {
			s.networkCommand(ctx, namespace, append(append([]string{}, base...), "-D", parent, strconv.Itoa(index+1)), "", false)
		}
	}
}

// configureNamespace выделяет клиентский payload в veth, сохраняя AWG процесс и native конфиг.
func (s *WarpSession) configureNamespace(ctx context.Context) {
	if s.Err != nil || s.Manifest == nil {
		return
	}
	m := s.Manifest
	s.installation(ctx)
	hostCode, _ := s.optional(ctx, "ip", "link", "show", "dev", warpLaneHost)
	peerCode, _ := s.ns(ctx, []string{"ip", "link", "show", "dev", warpLanePeer}, "", true)
	if (hostCode == 0) != (peerCode == 0) {
		s.fail("configuration_changed", "Выделенный veth повреждён; требуется локальная проверка владения.", 409)
		return
	}
	if hostCode != 0 {
		s.command(ctx, "ip", "link", "add", warpLaneHost, "type", "veth", "peer", "name", warpLanePeer)
		s.command(ctx, "ip", "link", "set", warpLanePeer, "netns", strconv.Itoa(s.PID))
	}
	s.command(ctx, "ip", "address", "replace", warpLaneHostIP+"/30", "dev", warpLaneHost)
	s.command(ctx, "ip", "link", "set", warpLaneHost, "up")
	s.ns(ctx, []string{"ip", "address", "replace", warpLanePeerIP + "/30", "dev", warpLanePeer}, "", false)
	s.ns(ctx, []string{"ip", "link", "set", warpLanePeer, "up"}, "", false)
	s.command(ctx, "sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv4.conf."+warpLaneHost+".rp_filter=2")
	s.ns(ctx, []string{"sysctl", "-q", "-w", "net.ipv4.conf." + warpLanePeer + ".rp_filter=2"}, "", false)
	for _, hook := range warpNSHooks {
		s.ensureJump(ctx, hook[0], hook[1], hook[2], true, false)
	}
	script := fmt.Sprintf("*filter\n-F AVPS_CLIENT\n-F AVPS_DOCKER_DNS\n-A AVPS_DOCKER_DNS -d 127.0.0.11/32 -j REJECT\n-A AVPS_CLIENT -i %s -o %s -d %s -j ACCEPT\n-A AVPS_CLIENT -i %s -o %s -j ACCEPT\n-A AVPS_CLIENT -i %s -j REJECT\n-A AVPS_CLIENT -i %s -o %s -j ACCEPT\n-A AVPS_CLIENT -i %s -j REJECT\nCOMMIT\n*nat\n-F AVPS_CLIENT_NAT\n-A AVPS_CLIENT_NAT -o %s -j ACCEPT\nCOMMIT\n", m.Interface, m.Interface, m.ClientNetwork, m.Interface, warpLanePeer, m.Interface, warpLanePeer, m.Interface, warpLanePeer, warpLanePeer)
	s.ns(ctx, []string{"iptables-restore", "-w", "5", "--noflush"}, script, false)
	for _, chain := range []string{"FORWARD", "INPUT", "OUTPUT"} {
		s.ensureJump(ctx, "filter", chain, "AVPS_IPV6_"+chain, true, true)
	}
	ipv6 := fmt.Sprintf("*filter\n-F AVPS_IPV6_FORWARD\n-F AVPS_IPV6_INPUT\n-F AVPS_IPV6_OUTPUT\n-A AVPS_IPV6_FORWARD -i %s -j DROP\n-A AVPS_IPV6_FORWARD -o %s -j DROP\n-A AVPS_IPV6_INPUT -i %s -j DROP\n-A AVPS_IPV6_OUTPUT -o %s -j DROP\nCOMMIT\n", m.Interface, m.Interface, m.Interface, m.Interface)
	s.ns(ctx, []string{"ip6tables-restore", "-w", "5", "--noflush"}, ipv6, false)
	s.ns(ctx, []string{"ip", "-4", "route", "replace", "default", "via", warpLaneHostIP, "dev", warpLanePeer, "table", warpNSTable}, "", false)
	s.ns(ctx, []string{"ip", "-4", "route", "replace", m.ClientNetwork, "dev", m.Interface, "scope", "link", "table", warpNSTable}, "", false)
	previousPID := int(warpNumber(s.readMap("namespace_state.json")["pid"]))
	for index, args := range [][]string{{"iif", m.Interface, "lookup", warpNSTable}, {"from", m.ClientNetwork, "lookup", warpNSTable}} {
		priority := strconv.Itoa(42 + index)
		_, current := s.ns(ctx, []string{"ip", "-4", "rule", "show", "pref", priority}, "", false)
		saved := s.readMap("namespace_rules.json")
		if strings.TrimSpace(current) != "" {
			if previousPID != s.PID || warpString(saved[priority]) != strings.TrimSpace(current) {
				s.fail("configuration_changed", "Правило AWG namespace изменено извне.", 409)
			}
		} else {
			s.ns(ctx, append([]string{"ip", "-4", "rule", "add", "pref", priority}, args...), "", false)
			_, observed := s.ns(ctx, []string{"ip", "-4", "rule", "show", "pref", priority}, "", false)
			saved[priority] = strings.TrimSpace(observed)
			s.write("namespace_rules.json", saved)
		}
	}
	s.write("namespace_state.json", map[string]any{"pid": s.PID})
	if m.DNSID != "" {
		s.dnsNS(ctx, []string{"iptables", "-w", "3", "-N", "AVPS_DNS_OUTPUT"}, "", true)
		_, raw := s.dnsNS(ctx, []string{"iptables", "-w", "3", "-S", "OUTPUT"}, "", false)
		rules := warpRuleLines(raw)
		if len(rules) == 0 || rules[0] != "-A OUTPUT -j AVPS_DNS_OUTPUT" {
			s.dnsNS(ctx, []string{"iptables", "-w", "3", "-I", "OUTPUT", "1", "-j", "AVPS_DNS_OUTPUT"}, "", false)
		}
		s.dnsNS(ctx, []string{"iptables-restore", "-w", "5", "--noflush"}, "*filter\n-F AVPS_DNS_OUTPUT\n-A AVPS_DNS_OUTPUT -d 127.0.0.11/32 -j REJECT\nCOMMIT\n", false)
	}
}

// prepareAdmin защищает host/SSH и внешний AWG transport до запуска WARP.
func (s *WarpSession) prepareAdmin(ctx context.Context) {
	if s.Err != nil || s.Manifest == nil {
		return
	}
	m := s.Manifest
	s.ensureRule(ctx, 4, 41, "iif", "lo", "lookup", "main")
	s.ensureRule(ctx, 6, 41, "iif", "lo", "lookup", "main")
	for index, address := range m.AWGIPs {
		s.ensureRule(ctx, 4, 45+index, "from", address+"/32", "lookup", "main")
	}
	s.ensureJump(ctx, "mangle", "OUTPUT", "AVPS_OUTPUT", false, false)
	s.ensureJump(ctx, "mangle", "PREROUTING", "AVPS_PREROUTING", false, false)
	lines := []string{"*mangle", "-F AVPS_OUTPUT", "-F AVPS_PREROUTING", "-A AVPS_OUTPUT -j MARK --set-mark " + warpMark}
	for _, iface := range append(append([]string{warpLaneHost}, m.Bridges...), warpInterface) {
		lines = append(lines, "-A AVPS_PREROUTING -i "+iface+" -j MARK --set-mark "+warpMark)
	}
	lines = append(lines, fmt.Sprintf("-A AVPS_PREROUTING -i %s -p udp --dport %d -j MARK --set-mark %s", m.HostInterface, m.AWGPort, warpMark), "COMMIT")
	s.run(ctx, []string{"iptables-restore", "-w", "5", "--noflush"}, 8*time.Second, strings.Join(lines, "\n")+"\n", false)
	s.ensureJump(ctx, "mangle", "OUTPUT", "AVPS_OUTPUT", false, true)
	s.run(ctx, []string{"ip6tables-restore", "-w", "5", "--noflush"}, 8*time.Second, "*mangle\n-F AVPS_OUTPUT\n-A AVPS_OUTPUT -j MARK --set-mark "+warpMark+"\nCOMMIT\n", false)
}

// configureHost восстанавливает только собственные таблицы, цепочки и клиентский маршрут.
func (s *WarpSession) configureHost(ctx context.Context, path string) {
	if s.Err != nil || s.Manifest == nil {
		return
	}
	m := s.Manifest
	s.prepareAdmin(ctx)
	out := m.HostInterface
	if path == "warp" {
		out = warpInterface
	}
	s.command(ctx, "ip", "-4", "route", "replace", m.ClientNetwork, "via", warpLanePeerIP, "dev", warpLaneHost)
	for _, table := range []string{warpTable, warpProbeTable} {
		s.command(ctx, "ip", "-4", "route", "replace", "unreachable", "default", "metric", "32760", "table", table)
	}
	s.command(ctx, "ip", "-4", "route", "replace", m.ClientNetwork, "via", warpLanePeerIP, "dev", warpLaneHost, "table", warpTable)
	s.command(ctx, "ip", "-4", "route", "replace", warpLaneNet, "dev", warpLaneHost, "scope", "link", "table", warpTable)
	for _, network := range m.Networks {
		s.command(ctx, "ip", "-4", "route", "replace", network.Subnet, "dev", network.Bridge, "scope", "link", "table", warpTable)
	}
	s.ensureRule(ctx, 4, 40, "oif", warpInterface, "lookup", warpProbeTable)
	s.ensureRule(ctx, 4, 42, "to", m.ClientNetwork, "lookup", "main")
	s.ensureRule(ctx, 4, 43, "iif", warpLaneHost, "lookup", warpTable)
	if m.DNSIP != "" {
		s.ensureRule(ctx, 4, 44, "from", m.DNSIP+"/32", "lookup", warpTable)
	}
	for index, address := range m.AWGIPs {
		s.ensureRule(ctx, 4, 45+index, "from", address+"/32", "lookup", "main")
	}
	for _, hook := range warpHostHooks {
		s.ensureJump(ctx, hook[0], hook[1], hook[2], false, false)
	}
	lines := []string{"*raw", "-F AVPS_RAW"}
	if m.DNSIP != "" {
		for _, protocol := range []string{"udp", "tcp"} {
			lines = append(lines, fmt.Sprintf("-A AVPS_RAW -i %s -d %s/32 -p %s --dport 53 -j ACCEPT", warpLaneHost, m.DNSIP, protocol))
		}
	}
	lines = append(lines, "COMMIT", "*filter", "-F AVPS_FORWARD")
	if m.DNSIP != "" {
		for _, protocol := range []string{"udp", "tcp"} {
			lines = append(lines, fmt.Sprintf("-A AVPS_FORWARD -i %s -d %s/32 -p %s --dport 53 -j ACCEPT", warpLaneHost, m.DNSIP, protocol), fmt.Sprintf("-A AVPS_FORWARD -s %s/32 -d %s -p %s --sport 53 -j ACCEPT", m.DNSIP, m.ClientNetwork, protocol))
		}
	}
	lines = append(lines, fmt.Sprintf("-A AVPS_FORWARD -i %s -o %s -d %s -j ACCEPT", warpLaneHost, warpLaneHost, m.ClientNetwork), fmt.Sprintf("-A AVPS_FORWARD -i %s -o %s -j ACCEPT", warpLaneHost, out), fmt.Sprintf("-A AVPS_FORWARD -i %s -o %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", out, warpLaneHost))
	if m.DNSIP != "" {
		lines = append(lines, fmt.Sprintf("-A AVPS_FORWARD -s %s/32 -o %s -j ACCEPT", m.DNSIP, out), fmt.Sprintf("-A AVPS_FORWARD -i %s -d %s/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT", out, m.DNSIP))
	}
	for _, address := range m.AWGIPs {
		lines = append(lines, fmt.Sprintf("-A AVPS_FORWARD -s %s/32 -p udp --sport %d -m conntrack --ctstate DNAT --ctdir REPLY -j ACCEPT", address, m.AWGPort), fmt.Sprintf("-A AVPS_FORWARD -d %s/32 -p udp --dport %d -m conntrack --ctstate DNAT --ctdir ORIGINAL -j ACCEPT", address, m.AWGPort))
	}
	lines = append(lines, "COMMIT", "*mangle", "-F AVPS_PREROUTING", "-F AVPS_OUTPUT")
	for _, iface := range append(append([]string{warpLaneHost}, m.Bridges...), warpInterface) {
		lines = append(lines, "-A AVPS_PREROUTING -i "+iface+" -j MARK --set-mark "+warpMark)
	}
	lines = append(lines, fmt.Sprintf("-A AVPS_PREROUTING -i %s -p udp --dport %d -j MARK --set-mark %s", m.HostInterface, m.AWGPort, warpMark), "-A AVPS_OUTPUT -j MARK --set-mark "+warpMark, "COMMIT", "*nat", "-F AVPS_NAT")
	sources := []string{m.ClientNetwork, warpLanePeerIP + "/32"}
	if m.DNSIP != "" {
		sources = append(sources, m.DNSIP+"/32")
	}
	for _, source := range sources {
		lines = append(lines, fmt.Sprintf("-A AVPS_NAT -s %s -o %s -j MASQUERADE", source, out))
	}
	lines = append(lines, "COMMIT")
	s.run(ctx, []string{"iptables-restore", "-w", "5", "--noflush"}, 8*time.Second, strings.Join(lines, "\n")+"\n", false)
	s.optional(ctx, "ip", "-4", "route", "del", "default", "metric", "10", "table", warpTable)
	if path == "direct" {
		s.command(ctx, "ip", "-4", "route", "add", "default", "via", m.HostGateway, "dev", m.HostInterface, "onlink", "metric", "10", "table", warpTable)
	} else if path == "warp" {
		s.command(ctx, "ip", "-4", "route", "add", "default", "dev", warpInterface, "metric", "10", "table", warpTable)
	}
	if code, _ := s.optional(ctx, "ip", "link", "show", "dev", warpInterface); code == 0 {
		s.command(ctx, "ip", "-4", "route", "replace", "default", "dev", warpInterface, "metric", "10", "table", warpProbeTable)
	}
}

// clearOwnedFlows прекращает прежние клиентские соединения, сохраняя SSH и чужие flows.
func (s *WarpSession) clearOwnedFlows(ctx context.Context) {
	if s.Manifest == nil || s.Err != nil {
		return
	}
	sources := []string{s.Manifest.ClientNetwork, warpLanePeerIP + "/32"}
	if s.Manifest.DNSIP != "" {
		sources = append(sources, s.Manifest.DNSIP+"/32")
	}
	for _, source := range sources {
		code, _ := s.optional(ctx, "conntrack", "--delete", "--orig-src", source)
		if code != 0 && code != 1 {
			s.fail("command_failed", "Не удалось прекратить прежние клиентские соединения.", 502)
		}
	}
	code, _ := s.ns(ctx, []string{"conntrack", "--delete", "--orig-src", s.Manifest.ClientNetwork}, "", true)
	if code != 0 && code != 1 {
		s.fail("command_failed", "Не удалось сбросить прежний клиентский NAT.", 502)
	}
}

// installBootDependencies связывает запуск Docker/WARP с успешным ранним guard без рестарта Docker.
func (s *WarpSession) installBootDependencies(ctx context.Context) {
	if s.Err != nil {
		return
	}
	for _, path := range warpDropinPaths {
		if err := warpPublishFile(path, []byte(warpGuardDropin)); err != nil {
			s.fail("configuration_changed", "Не удалось безопасно установить systemd зависимость guard.", 409)
			return
		}
	}
	s.run(ctx, []string{"systemctl", "daemon-reload"}, 10*time.Second, "", false)
	s.write("boot_dependencies.json", map[string]any{"paths": warpDropinPaths, "installed_at": warpNow()})
}

// enable принимает ресурсы под управление, предварительно фиксируя baseline и закрывая egress.
func (s *WarpSession) enable(ctx context.Context) {
	if s.Err != nil {
		return
	}
	if s.Manifest == nil {
		manifest := s.preflight(ctx)
		if s.Err != nil {
			return
		}
		baseline := map[string]any{"created_at": warpNow(), "policy": s.policy(), "host_rules": s.command(ctx, "ip", "-4", "rule", "show"), "host_routes": s.command(ctx, "ip", "-4", "route", "show", "table", "all"), "host_forwarding": strings.TrimSpace(s.command(ctx, "sysctl", "-n", "net.ipv4.ip_forward"))}
		s.write("integration_baseline.json", baseline)
		s.write("routing_manifest.json", manifest)
		if s.Err != nil {
			return
		}
		s.Manifest = manifest
		s.write("integration_state.json", map[string]any{"status": "preparing", "created_at": warpNow()})
	}
	s.installBootDependencies(ctx)
	s.guard(ctx, "blocked")
	s.configureNamespace(ctx)
	s.configureHost(ctx, "blocked")
	s.write("integration_state.json", map[string]any{"status": "managed", "updated_at": warpNow()})
}

// bootGuard блокирует клиентский выход до Docker, не обращаясь к его API.
func (s *WarpSession) bootGuard(ctx context.Context) {
	if s.Manifest == nil {
		return
	}
	s.guard(ctx, "blocked")
	s.prepareAdmin(ctx)
	s.saveEgress("blocked", "Ранняя загрузочная защита установлена; ожидается supervisor.", false)
}

// fingerprint вычисляет состояние только собственных правил, hook order и veth адресов.
func (s *WarpSession) fingerprint(ctx context.Context) string {
	if s.Manifest == nil || s.Err != nil {
		return ""
	}
	var parts []string
	commands := [][]string{{"nft", "--json", "list", "table", "inet", warpNFTTable}, {"ip", "-4", "route", "show", "table", warpTable}, {"ip", "-4", "rule", "show"}, {"ip", "-6", "rule", "show"}, {"ip6tables", "-w", "2", "-t", "mangle", "-S", "AVPS_OUTPUT"}, {"ip", "-j", "address", "show", "dev", warpLaneHost}, {"ip", "-4", "route", "show", "exact", s.Manifest.ClientNetwork}}
	for _, args := range commands {
		code, raw := s.optional(ctx, args...)
		if code != 0 {
			return ""
		}
		parts = append(parts, raw)
	}
	for _, namespace := range []bool{false, true} {
		hooks := warpHostHooks
		if namespace {
			hooks = warpNSHooks
		}
		for _, hook := range hooks {
			code, raw := s.networkCommand(ctx, namespace, []string{"iptables", "-w", "2", "-t", hook[0], "-S", hook[2]}, "", true)
			if code != 0 {
				return ""
			}
			parts = append(parts, raw)
			code, raw = s.networkCommand(ctx, namespace, []string{"iptables", "-w", "2", "-t", hook[0], "-S", hook[1]}, "", true)
			rules := warpRuleLines(raw)
			if code != 0 || len(rules) == 0 || rules[0] != "-A "+hook[1]+" -j "+hook[2] {
				return ""
			}
		}
	}
	for _, args := range [][]string{{"ip", "-4", "route", "show", "table", warpNSTable}, {"ip", "-4", "rule", "show"}, {"ip", "-j", "address", "show", "dev", warpLanePeer}} {
		code, raw := s.ns(ctx, args, "", true)
		if code != 0 {
			return ""
		}
		parts = append(parts, raw)
	}
	for _, chain := range []string{"FORWARD", "INPUT", "OUTPUT"} {
		code, raw := s.ns(ctx, []string{"ip6tables", "-w", "2", "-S", "AVPS_IPV6_" + chain}, "", true)
		if code != 0 {
			return ""
		}
		parts = append(parts, raw)
		code, raw = s.ns(ctx, []string{"ip6tables", "-w", "2", "-S", chain}, "", true)
		rules := warpRuleLines(raw)
		if code != 0 || len(rules) == 0 || rules[0] != "-A "+chain+" -j AVPS_IPV6_"+chain {
			return ""
		}
	}
	if s.Manifest.DNSID != "" {
		code, raw := s.dnsNS(ctx, []string{"iptables", "-w", "2", "-S", "AVPS_DNS_OUTPUT"}, "", true)
		if code != 0 {
			return ""
		}
		parts = append(parts, raw)
		code, raw = s.dnsNS(ctx, []string{"iptables", "-w", "2", "-S", "OUTPUT"}, "", true)
		rules := warpRuleLines(raw)
		if code != 0 || len(rules) == 0 || rules[0] != "-A OUTPUT -j AVPS_DNS_OUTPUT" {
			return ""
		}
	}
	return warpHash(strings.Join(parts, "\n"))
}

// rememberFingerprint запоминает только подтверждённое собственное состояние.
func (s *WarpSession) rememberFingerprint(ctx context.Context) {
	s.write("routing_fingerprint.json", map[string]any{"fingerprint": s.fingerprint(ctx), "checked_at": warpNow()})
}
