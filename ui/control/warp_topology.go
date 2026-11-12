//go:build linux

package main

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	warpTable       = "43001"
	warpProbeTable  = "43002"
	warpNSTable     = "43003"
	warpLaneHost    = "avps_host"
	warpLanePeer    = "avps_peer"
	warpLaneHostIP  = "169.254.217.1"
	warpLanePeerIP  = "169.254.217.2"
	warpLaneNet     = "169.254.217.0/30"
	warpInterface   = "CloudflareWARP"
	warpMark        = "0x100cf"
	warpNFTTable    = "awg_vps_guard"
	warpProbeURL    = "https://1.1.1.1/cdn-cgi/trace"
	warpGuardDropin = "[Unit]\nRequires=awg_vps_guard.service\nAfter=awg_vps_guard.service\n"
)

var warpDropinPaths = []string{"/etc/systemd/system/docker.service.d/awg_vps_guard.conf", "/etc/systemd/system/warp-svc.service.d/awg_vps_guard.conf"}

// WarpNetwork описывает одну выделенную Docker bridge-сеть.
type WarpNetwork struct {
	Name   string `json:"name"`   // Проверенное имя Docker-сети.
	Subnet string `json:"subnet"` // Непересекающаяся IPv4 подсеть.
	Bridge string `json:"bridge"` // Linux bridge интерфейс.
}

// WarpManifest сохраняет владение ресурсами и не содержит ключей VPN.
type WarpManifest struct {
	SchemaVersion int           `json:"schema_version"`   // Версия совместимого manifest.
	ContainerID   string        `json:"container_id"`     // Закреплённый ID AWG.
	ContainerName string        `json:"container_name"`   // Проверенное имя AWG.
	Interface     string        `json:"interface"`        // Native AWG интерфейс.
	ClientNetwork string        `json:"client_network"`   // Клиентская IPv4 подсеть.
	ProbeIP       string        `json:"probe_ip"`         // IPv4 адрес интерфейса для проб.
	AWGPort       int           `json:"awg_port"`         // Опубликованный UDP порт AWG.
	AWGIPs        []string      `json:"awg_ips"`          // Docker IPv4 адреса внешнего AWG транспорта.
	Bridges       []string      `json:"bridges"`          // Выделенные Linux bridges.
	Networks      []WarpNetwork `json:"networks"`         // Непересекающиеся Docker сети.
	DNSIP         string        `json:"dns_ip"`           // Необязательный DNS адрес.
	DNSBridge     string        `json:"dns_bridge"`       // Bridge выбранной сети.
	DNSID         string        `json:"dns_container_id"` // Закреплённый DNS ID.
	HostInterface string        `json:"host_interface"`   // Физический default interface.
	HostGateway   string        `json:"host_gateway"`     // Физический IPv4 gateway.
	LaneHost      string        `json:"lane_host"`        // Собственное имя veth на хосте.
	LanePeer      string        `json:"lane_peer"`        // Собственное имя veth в namespace.
	LaneNetwork   string        `json:"lane_network"`     // Собственная транспортная подсеть.
	TableID       int           `json:"table_id"`         // Собственная таблица маршрутизации.
}

// warpIPv4 проверяет одиночный нормализованный IPv4 адрес.
func warpIPv4(value string) bool {
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is4() && address.String() == value
}

// warpPrefix проверяет нормализованную IPv4 подсеть.
func warpPrefix(value string) (netip.Prefix, bool) {
	prefix, err := netip.ParsePrefix(value)
	return prefix, err == nil && prefix.Addr().Is4() && prefix.Masked().String() == value
}

// valid проверяет persisted manifest до генерации правил, включая раннюю загрузку.
func (m *WarpManifest) valid() bool {
	client, ok := warpPrefix(m.ClientNetwork)
	if !ok || client.Bits() < 16 || client.Overlaps(netip.MustParsePrefix(warpLaneNet)) {
		return false
	}
	validConstants := m.SchemaVersion == 1 && m.TableID == 43001 &&
		m.LaneHost == warpLaneHost && m.LanePeer == warpLanePeer && m.LaneNetwork == warpLaneNet
	validNames := warpDockerIDPattern.MatchString(m.ContainerID) && warpSafeName(m.ContainerName) &&
		warpInterfacePattern.MatchString(m.Interface) && warpInterfacePattern.MatchString(m.HostInterface)
	validAddresses := warpIPv4(m.HostGateway) && warpIPv4(m.ProbeIP)
	validSizes := len(m.AWGIPs) >= 1 && len(m.AWGIPs) <= 2 &&
		len(m.Networks) == len(m.AWGIPs) && len(m.Bridges) == len(m.Networks)
	if !validConstants || !validNames || !validAddresses || !validSizes {
		return false
	}
	if !client.Contains(netip.MustParseAddr(m.ProbeIP)) || m.AWGPort < 1 || m.AWGPort > 65535 {
		return false
	}
	if m.HostInterface == "lo" || m.HostInterface == warpInterface ||
		m.HostInterface == warpLaneHost || m.HostInterface == warpLanePeer {
		return false
	}
	bridges := map[string]bool{}
	for _, bridge := range m.Bridges {
		validBridge := warpInterfacePattern.MatchString(bridge) && !bridges[bridge] &&
			bridge != m.HostInterface && bridge != "lo" && bridge != warpInterface &&
			bridge != warpLaneHost && bridge != warpLanePeer
		if !validBridge {
			return false
		}
		bridges[bridge] = true
	}
	names := map[string]bool{}
	usedBridges := map[string]bool{}
	addresses := map[string]bool{}
	prefixes := []netip.Prefix{}
	dnsMatches := m.DNSIP == "" && m.DNSID == ""
	for index, network := range m.Networks {
		prefix, valid := warpPrefix(network.Subnet)
		validNetwork := valid && warpSafeName(network.Name) && !names[network.Name] &&
			bridges[network.Bridge] && !usedBridges[network.Bridge]
		if !validNetwork || prefix.Overlaps(client) || prefix.Overlaps(netip.MustParsePrefix(warpLaneNet)) {
			return false
		}
		address := m.AWGIPs[index]
		if !warpIPv4(address) || addresses[address] || !prefix.Contains(netip.MustParseAddr(address)) {
			return false
		}
		for _, previous := range prefixes {
			if previous.Overlaps(prefix) {
				return false
			}
		}
		if m.DNSIP != "" && warpIPv4(m.DNSIP) && network.Bridge == m.DNSBridge {
			dnsMatches = prefix.Contains(netip.MustParseAddr(m.DNSIP)) && m.DNSIP != address
		}
		names[network.Name] = true
		usedBridges[network.Bridge] = true
		addresses[address] = true
		prefixes = append(prefixes, prefix)
	}
	if !bridges[m.DNSBridge] || !dnsMatches {
		return false
	}
	if m.DNSIP != "" && (!warpDockerIDPattern.MatchString(m.DNSID) || m.DNSID == m.ContainerID) {
		return false
	}
	return true
}

// inspect читает только выбранный контейнер и не публикует содержимое Docker inspect.
func (s *WarpSession) inspect(ctx context.Context, name string) map[string]any {
	if !warpSafeName(name) {
		s.fail("invalid_payload", "Некорректное имя Docker-ресурса.", 400)
		return map[string]any{}
	}
	values := warpList(s.jsonCommand(ctx, "docker", "inspect", "--type", "container", name))
	if s.Err != nil {
		return map[string]any{}
	}
	if len(values) != 1 {
		s.fail("invalid_docker_state", "Docker не вернул однозначный контейнер.", 502)
		return map[string]any{}
	}
	container := warpMap(values[0])
	if !warpDockerIDPattern.MatchString(warpString(container["Id"])) {
		s.fail("invalid_docker_state", "Некорректный ID контейнера.", 502)
	}
	return container
}

// installation повторно подтверждает закреплённый ID и запрещает автозапуск AWG.
func (s *WarpSession) installation(ctx context.Context) (*WarpInstallation, map[string]any) {
	var installation WarpInstallation
	if !s.read("installation.json", &installation) {
		s.fail("not_attached", "Сначала подключите существующую установку AWG.", 409)
		return &installation, map[string]any{}
	}
	container := s.inspect(ctx, installation.ContainerName)
	if s.Err != nil {
		return &installation, container
	}
	if warpString(container["Id"]) != installation.ContainerID {
		s.fail("installation_changed", "Контейнер пересоздан; требуется проверка привязки.", 409)
	}
	state := warpMap(container["State"])
	if !warpBool(state["Running"]) || warpNumber(state["Pid"]) <= 0 {
		s.fail("awg_stopped", "AWG остановлен; автоматический запуск запрещён.", 409)
	}
	if !warpInterfacePattern.MatchString(installation.Interface) {
		s.fail("invalid_state", "Некорректный закреплённый интерфейс.", 500)
	}
	s.PID = int(warpNumber(state["Pid"]))
	return &installation, container
}

// attach закрепляет существующие ресурсы без изменения конфигурации или процесса VPN.
func (s *WarpSession) attach(ctx context.Context, request AttachRequest) any {
	if !warpSafeName(request.ContainerName) || !warpSafeName(request.DockerNetwork) || (request.DNSContainerName != "" && !warpSafeName(request.DNSContainerName)) {
		s.fail("invalid_payload", "Требуются корректные имена контейнеров и выбранной сети.", 400)
		return nil
	}
	var previous WarpInstallation
	s.read("installation.json", &previous)
	if s.Manifest != nil && (previous.ContainerName != request.ContainerName || previous.DockerNetwork != request.DockerNetwork || previous.DNSName != request.DNSContainerName) {
		s.fail("configuration_changed", "Существующая сетевая интеграция требует локальной миграции владения.", 409)
		return nil
	}
	container := s.inspect(ctx, request.ContainerName)
	id := warpString(container["Id"])
	if !warpBool(warpMap(container["State"])["Running"]) {
		s.fail("unsupported_topology", "Подключается только работающий существующий AWG.", 409)
		return nil
	}
	interfaces := strings.Fields(s.command(ctx, "docker", "exec", id, "timeout", "-s", "KILL", "8", "awg", "show", "interfaces"))
	if len(interfaces) != 1 || !warpInterfacePattern.MatchString(interfaces[0]) {
		s.fail("unsupported_topology", "Нужен один поддерживаемый AWG-интерфейс.", 409)
		return nil
	}
	networks := warpMap(warpMap(container["NetworkSettings"])["Networks"])
	if _, ok := networks[request.DockerNetwork]; !ok {
		s.fail("unsupported_topology", "AWG не подключён к выбранной сети.", 409)
		return nil
	}
	value := WarpInstallation{ContainerName: request.ContainerName, ContainerID: id, Interface: interfaces[0], ConfigPath: "/opt/amnezia/awg/" + interfaces[0] + ".conf", DNSName: request.DNSContainerName, DockerNetwork: request.DockerNetwork, Supported: true, Capabilities: []string{"observe", "manual_restart"}, Networks: []string{}}
	for name := range networks {
		value.Networks = append(value.Networks, name)
	}
	sort.Strings(value.Networks)
	if value.DNSName != "" {
		dns := s.inspect(ctx, value.DNSName)
		if !warpBool(warpMap(dns["State"])["Running"]) {
			s.fail("unsupported_topology", "DNS-контейнер должен работать.", 409)
			return nil
		}
		if _, ok := warpMap(warpMap(dns["NetworkSettings"])["Networks"])[request.DockerNetwork]; !ok {
			s.fail("unsupported_topology", "DNS должен находиться в выбранной сети.", 409)
			return nil
		}
		value.DNSID = warpString(dns["Id"])
	}
	// sha256sum не передаёт содержимое native конфига в host runtime.
	digestFields := strings.Fields(s.command(ctx, "docker", "exec", id, "timeout", "-s", "KILL", "8", "sha256sum", "--", value.ConfigPath))
	if len(digestFields) < 1 || !revisionPattern.MatchString(digestFields[0]) {
		s.fail("unsupported_topology", "Не найден поддерживаемый native конфиг Amnezia.", 409)
		return nil
	}
	value.BaselineRevision = digestFields[0]
	if s.Manifest != nil && value.ContainerID != s.Manifest.ContainerID {
		s.fail("configuration_changed", "Контейнер управляемой интеграции пересоздан.", 409)
		return nil
	}
	s.mutation(ctx, "integration.attach")
	s.write("installation.json", value)
	s.event("attach", "succeeded", "Существующая установка подключена без изменения VPN.")
	return map[string]any{"installation": value, "policy": s.policy()}
}

// topology вычисляет сетевые ресурсы только из закреплённой установки.
func (s *WarpSession) topology(ctx context.Context) *WarpManifest {
	installation, container := s.installation(ctx)
	if s.Err != nil {
		return nil
	}
	addresses := warpList(s.jsonCommand(ctx, "docker", "exec", installation.ContainerID, "timeout", "-s", "KILL", "8", "ip", "-j", "address", "show", "dev", installation.Interface))
	var ipv4 []map[string]any
	for _, link := range addresses {
		for _, item := range warpList(warpMap(link)["addr_info"]) {
			address := warpMap(item)
			if warpString(address["family"]) == "inet" {
				ipv4 = append(ipv4, address)
			}
			if warpString(address["family"]) == "inet6" {
				ip, err := netip.ParseAddr(warpString(address["local"]))
				if err != nil || !ip.IsLinkLocalUnicast() {
					s.fail("unsupported_topology", "Маршрутизируемый IPv6 AWG пока не поддержан; link-local блокируется отдельно.", 409)
				}
			}
		}
	}
	if len(ipv4) != 1 {
		s.fail("unsupported_topology", "Требуется ровно один IPv4 на AWG.", 409)
		return nil
	}
	client, err := netip.ParsePrefix(fmt.Sprintf("%s/%d", warpString(ipv4[0]["local"]), int(warpNumber(ipv4[0]["prefixlen"]))))
	if err != nil || !client.Addr().Is4() || client.Bits() < 16 || client.Overlaps(netip.MustParsePrefix(warpLaneNet)) {
		s.fail("unsupported_topology", "Клиентская подсеть несовместима с выделенным путём.", 409)
		return nil
	}
	portRaw := strings.TrimSpace(s.command(ctx, "docker", "exec", installation.ContainerID, "timeout", "-s", "KILL", "8", "awg", "show", installation.Interface, "listen-port"))
	port, err := strconv.Atoi(portRaw)
	bindings := warpList(warpMap(warpMap(container["NetworkSettings"])["Ports"])[portRaw+"/udp"])
	if err != nil || port < 1 || port > 65535 || len(bindings) == 0 {
		s.fail("unsupported_topology", "Не найден опубликованный UDP порт AWG.", 409)
		return nil
	}
	for _, binding := range bindings {
		if warpString(warpMap(binding)["HostPort"]) != portRaw {
			s.fail("unsupported_topology", "Преобразование опубликованного AWG порта не поддержано.", 409)
		}
	}
	var dns map[string]any
	if installation.DNSName != "" {
		dns = s.inspect(ctx, installation.DNSName)
		if warpString(dns["Id"]) != installation.DNSID || !warpBool(warpMap(dns["State"])["Running"]) {
			s.fail("configuration_changed", "Закреплённый DNS изменён или остановлен.", 409)
		}
		s.DNSPID = int(warpNumber(warpMap(dns["State"])["Pid"]))
	}
	m := &WarpManifest{SchemaVersion: 1, ContainerID: installation.ContainerID, ContainerName: installation.ContainerName, Interface: installation.Interface, ClientNetwork: client.Masked().String(), ProbeIP: client.Addr().String(), AWGPort: port, LaneHost: warpLaneHost, LanePeer: warpLanePeer, LaneNetwork: warpLaneNet, TableID: 43001, Networks: []WarpNetwork{}, AWGIPs: []string{}, Bridges: []string{}}
	networks := warpMap(warpMap(container["NetworkSettings"])["Networks"])
	if len(networks) < 1 || len(networks) > 2 {
		s.fail("unsupported_topology", "Поддерживаются одна или две выделенные AWG сети.", 409)
	}
	if _, ok := networks[installation.DockerNetwork]; !ok {
		s.fail("unsupported_topology", "AWG больше не подключён к выбранной сети.", 409)
	}
	var names []string
	for name := range networks {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !warpSafeName(name) {
			s.fail("unsupported_topology", "Некорректное имя Docker сети.", 409)
			break
		}
		result := warpList(s.jsonCommand(ctx, "docker", "network", "inspect", name))
		if len(result) != 1 {
			s.fail("unsupported_topology", "Неоднозначная Docker сеть.", 409)
			break
		}
		network := warpMap(result[0])
		if warpString(network["Driver"]) != "bridge" || warpBool(network["EnableIPv6"]) {
			s.fail("unsupported_topology", "Поддерживается выделенная IPv4 Docker bridge сеть.", 409)
		}
		for id := range warpMap(network["Containers"]) {
			if id != installation.ContainerID && id != installation.DNSID {
				s.fail("unsupported_topology", "В Docker сети есть посторонние контейнеры; безопасная изоляция невозможна.", 409)
			}
		}
		ipam := warpList(warpMap(network["IPAM"])["Config"])
		if len(ipam) != 1 {
			s.fail("unsupported_topology", "Неоднозначная подсеть Docker.", 409)
			break
		}
		subnet, valid := warpPrefix(warpString(warpMap(ipam[0])["Subnet"]))
		if !valid || subnet.Overlaps(client) || subnet.Overlaps(netip.MustParsePrefix(warpLaneNet)) {
			s.fail("unsupported_topology", "Подсети Docker, клиентов и veth пересекаются.", 409)
			break
		}
		bridge := warpString(warpMap(network["Options"])["com.docker.network.bridge.name"])
		if bridge == "" {
			if name == "bridge" {
				bridge = "docker0"
			} else {
				id := warpString(network["Id"])
				if len(id) < 12 {
					s.fail("unsupported_topology", "Некорректный ID Docker сети.", 409)
					break
				}
				bridge = "br-" + id[:12]
			}
		}
		address := warpString(warpMap(networks[name])["IPAddress"])
		ip, parseErr := netip.ParseAddr(address)
		if !warpInterfacePattern.MatchString(bridge) || parseErr != nil || !ip.Is4() || !subnet.Contains(ip) {
			s.fail("unsupported_topology", "Некорректный адрес или имя Docker bridge.", 409)
			break
		}
		m.Bridges = append(m.Bridges, bridge)
		m.AWGIPs = append(m.AWGIPs, ip.String())
		m.Networks = append(m.Networks, WarpNetwork{Name: name, Subnet: subnet.String(), Bridge: bridge})
		if name == installation.DockerNetwork {
			m.DNSBridge = bridge
		}
	}
	sort.Strings(m.Bridges)
	if dns != nil {
		dnsNetworks := warpMap(warpMap(dns["NetworkSettings"])["Networks"])
		if len(dnsNetworks) != 1 {
			s.fail("unsupported_topology", "DNS должен использовать только выбранную выделенную сеть.", 409)
		}
		m.DNSIP = warpString(warpMap(dnsNetworks[installation.DockerNetwork])["IPAddress"])
		m.DNSID = installation.DNSID
		if !warpIPv4(m.DNSIP) {
			s.fail("unsupported_topology", "Неверный IPv4 выбранного DNS.", 409)
		}
	}
	defaults := warpList(s.jsonCommand(ctx, "ip", "-j", "-4", "route", "show", "table", "main", "default"))
	var routes []map[string]any
	for _, value := range defaults {
		route := warpMap(value)
		if warpString(route["gateway"]) != "" && warpString(route["dev"]) != warpInterface {
			routes = append(routes, route)
		}
	}
	if len(routes) != 1 {
		s.fail("unsupported_topology", "Нужен один однозначный физический IPv4 default route.", 409)
		return nil
	}
	m.HostInterface = warpString(routes[0]["dev"])
	m.HostGateway = warpString(routes[0]["gateway"])
	if s.Err == nil && !m.valid() {
		s.fail("unsupported_topology", "Неподдерживаемая топология IPv4 интеграции.", 409)
	}
	if s.Err != nil {
		return nil
	}
	return m
}

// ns выполняет host-бинарник в проверенном AWG network namespace.
func (s *WarpSession) ns(ctx context.Context, args []string, input string, allow bool) (int, string) {
	if s.PID <= 0 {
		s.installation(ctx)
	}
	if s.PID <= 0 {
		s.fail("not_attached", "AWG namespace недоступен.", 409)
	}
	prefix := []string{"nsenter", "--target", strconv.Itoa(s.PID), "--net", "--"}
	return s.run(ctx, append(prefix, args...), 8*time.Second, input, allow)
}

// dnsNS выполняет команду только в закреплённом DNS namespace.
func (s *WarpSession) dnsNS(ctx context.Context, args []string, input string, allow bool) (int, string) {
	if s.DNSPID <= 0 && s.Manifest != nil {
		dns := s.inspect(ctx, s.Manifest.DNSID)
		if !warpBool(warpMap(dns["State"])["Running"]) {
			s.fail("configuration_changed", "DNS namespace недоступен.", 409)
		}
		s.DNSPID = int(warpNumber(warpMap(dns["State"])["Pid"]))
	}
	if s.DNSPID <= 0 {
		s.fail("configuration_changed", "DNS namespace недоступен.", 409)
	}
	return s.run(ctx, append([]string{"nsenter", "--target", strconv.Itoa(s.DNSPID), "--net", "--"}, args...), 8*time.Second, input, allow)
}

// preflight подтверждает возможности и отсутствие конфликтов до первой мутации.
func (s *WarpSession) preflight(ctx context.Context) *WarpManifest {
	topology := s.topology(ctx)
	if s.Err != nil {
		return nil
	}
	for _, program := range []string{"ip", "iptables", "iptables-restore", "ip6tables", "ip6tables-restore", "nft", "nsenter", "conntrack", "curl", "sysctl", "systemctl"} {
		if warpProgram(program) == "" {
			s.fail("capability_unavailable", "Для безопасной интеграции требуется "+program+"; AWG/Docker автоматически не устанавливаются.", 409)
		}
	}
	if !strings.Contains(s.command(ctx, "iptables", "--version"), "nf_tables") {
		s.fail("unsupported_topology", "Требуется backend iptables-nft.", 409)
	}
	if code, _ := s.optional(ctx, "systemctl", "is-active", "awg_warp_restore.service"); code == 0 {
		s.fail("unsupported_topology", "Старый WARP supervisor активен; нужна отдельная миграция владения.", 409)
	}
	properties := s.command(ctx, "systemctl", "show", "--property=LoadState", "--property=Type", "--property=RemainAfterExit", "--property=ActiveState", "awg_vps_guard.service")
	for _, required := range []string{"LoadState=loaded", "Type=oneshot", "RemainAfterExit=yes", "ActiveState=active"} {
		if !strings.Contains("\n"+properties+"\n", "\n"+required+"\n") {
			s.fail("capability_unavailable", "Ранний guard должен быть активным oneshot/RemainAfterExit до интеграции.", 409)
		}
	}
	for _, path := range warpDropinPaths {
		raw, err := warpReadPublic(path, 4096)
		if err == nil && string(raw) != warpGuardDropin {
			s.fail("configuration_changed", "Существующий systemd drop-in не принадлежит интеграции.", 409)
		}
	}
	if s.Manifest != nil {
		// Старый manifest мог сохранять порядок Docker networks; сравниваем их по имени.
		previous := *s.Manifest
		candidate := *topology
		previous.Networks = append([]WarpNetwork(nil), previous.Networks...)
		candidate.Networks = append([]WarpNetwork(nil), candidate.Networks...)
		sort.Slice(previous.Networks, func(i, j int) bool { return previous.Networks[i].Name < previous.Networks[j].Name })
		sort.Slice(candidate.Networks, func(i, j int) bool { return candidate.Networks[i].Name < candidate.Networks[j].Name })
		previous.AWGIPs = append([]string(nil), previous.AWGIPs...)
		candidate.AWGIPs = append([]string(nil), candidate.AWGIPs...)
		sort.Strings(previous.AWGIPs)
		sort.Strings(candidate.AWGIPs)
		if !reflect.DeepEqual(previous, candidate) {
			s.fail("configuration_changed", "Топология изменилась; защитные правила сохранены, требуется проверка.", 409)
		}
		return topology
	}
	client := netip.MustParsePrefix(topology.ClientNetwork)
	for _, value := range warpList(s.jsonCommand(ctx, "ip", "-j", "-4", "route", "show", "table", "main")) {
		destination := warpString(warpMap(value)["dst"])
		if destination == "" || destination == "default" {
			continue
		}
		if !strings.Contains(destination, "/") {
			destination += "/32"
		}
		prefix, err := netip.ParsePrefix(destination)
		if err != nil || prefix.Overlaps(client) {
			s.fail("unsupported_topology", "Клиентская подсеть пересекает существующий host/административный маршрут.", 409)
		}
	}
	for _, table := range []string{warpTable, warpProbeTable} {
		_, raw := s.optional(ctx, "ip", "-4", "route", "show", "table", table)
		if strings.TrimSpace(raw) != "" {
			s.fail("unsupported_topology", "Зарезервированная таблица маршрутизации занята.", 409)
		}
	}
	for _, family := range []string{"-4", "-6"} {
		for _, value := range warpList(s.jsonCommand(ctx, "ip", "-j", family, "rule", "show")) {
			priority := int(warpNumber(warpMap(value)["priority"]))
			if (family == "-4" && priority >= 40 && priority <= 46) || (family == "-6" && priority == 41) {
				s.fail("unsupported_topology", "Зарезервированный приоритет маршрутизации занят.", 409)
			}
		}
	}
	collisions := [][]string{{"ip6tables", "-w", "2", "-t", "mangle", "-S", "AVPS_OUTPUT"}, {"ip", "link", "show", "dev", warpLaneHost}, {"nft", "list", "table", "inet", warpNFTTable}}
	for _, hook := range warpHostHooks {
		collisions = append(collisions, []string{"iptables", "-w", "2", "-t", hook[0], "-S", hook[2]})
	}
	for _, args := range collisions {
		if code, _ := s.optional(ctx, args...); code == 0 {
			s.fail("unsupported_topology", "Имя собственного сетевого ресурса уже занято.", 409)
		}
	}
	_, raw := s.ns(ctx, []string{"ip", "-4", "route", "show", "table", warpNSTable}, "", true)
	if strings.TrimSpace(raw) != "" {
		s.fail("unsupported_topology", "В namespace занята таблица маршрутизации панели.", 409)
	}
	_, raw = s.ns(ctx, []string{"ip", "-4", "rule", "show"}, "", false)
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "42:") || strings.HasPrefix(strings.TrimSpace(line), "43:") {
			s.fail("unsupported_topology", "В namespace заняты приоритеты панели.", 409)
		}
	}
	for _, hook := range warpNSHooks {
		if code, _ := s.ns(ctx, []string{"iptables", "-w", "2", "-t", hook[0], "-S", hook[2]}, "", true); code == 0 {
			s.fail("unsupported_topology", "В namespace занято имя управляемой цепочки.", 409)
		}
	}
	for _, chain := range []string{"FORWARD", "INPUT", "OUTPUT"} {
		if code, _ := s.ns(ctx, []string{"ip6tables", "-w", "2", "-S", "AVPS_IPV6_" + chain}, "", true); code == 0 {
			s.fail("unsupported_topology", "В namespace занято имя IPv6 цепочки.", 409)
		}
	}
	if topology.DNSID != "" {
		if code, _ := s.dnsNS(ctx, []string{"iptables", "-w", "2", "-S", "AVPS_DNS_OUTPUT"}, "", true); code == 0 {
			s.fail("unsupported_topology", "В DNS namespace занято имя цепочки панели.", 409)
		}
	}
	for _, word := range strings.Fields(s.command(ctx, "ip", "-4", "route", "show", "table", "all")) {
		if prefix, err := netip.ParsePrefix(word); err == nil && prefix.Bits() > 0 && prefix.Overlaps(netip.MustParsePrefix(warpLaneNet)) {
			s.fail("unsupported_topology", "Подсеть выделенного veth уже занята.", 409)
		}
	}
	return topology
}
