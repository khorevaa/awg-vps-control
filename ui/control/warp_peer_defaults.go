//go:build linux

package main

import (
	"context"
	"net/netip"
	"reflect"
	"sort"
)

// peersDefaults читает предложения профиля без установки WARP или изменения сети.
func (s *WarpSession) peersDefaults(ctx context.Context) PeerDefaults {
	result := PeerDefaults{DNS: []string{"1.1.1.1"}, ReservedIPs: []string{}}
	topology := s.topology(ctx)
	if s.Err != nil || topology == nil {
		return result
	}
	if s.Manifest != nil && !warpPeerTopologyMatches(s.Manifest, topology) {
		s.fail("configuration_changed", "Сетевая топология изменилась; проверьте привязку перед созданием клиента.", 409)
		return result
	}
	result.ListenPort = topology.AWGPort
	result.ReservedIPs = append(result.ReservedIPs, topology.ProbeIP)
	if topology.DNSIP != "" {
		result.DNS = []string{topology.DNSIP}
	}
	links := warpList(s.jsonCommand(ctx, "ip", "-j", "-d", "-4", "address", "show", "dev", topology.HostInterface))
	if s.Err != nil {
		return result
	}
	if len(links) != 1 || warpString(warpMap(links[0])["ifname"]) != topology.HostInterface {
		s.fail("unsupported_topology", "Не подтверждён физический интерфейс входящего адреса VPS.", 409)
		return result
	}
	link := warpMap(links[0])
	if warpString(link["link_type"]) != "ether" || warpString(warpMap(link["linkinfo"])["info_kind"]) != "" {
		return result
	}
	up := false
	for _, flag := range warpList(link["flags"]) {
		if warpString(flag) == "UP" {
			up = true
		}
	}
	if !up || warpString(link["operstate"]) != "UP" {
		return result
	}
	addresses := map[string]bool{}
	for _, value := range warpList(link["addr_info"]) {
		address := warpMap(value)
		if warpString(address["family"]) != "inet" || warpString(address["scope"]) != "global" {
			continue
		}
		ip, err := netip.ParseAddr(warpString(address["local"]))
		if err != nil || !warpPeerPublicIPv4(ip) {
			continue
		}
		if lifetime, ok := address["preferred_life_time"].(float64); ok && lifetime <= 0 {
			continue
		}
		addresses[ip.String()] = true
	}
	if len(addresses) == 1 {
		for address := range addresses {
			result.EndpointHost = address
		}
	}
	return result
}

// warpPeerTopologyMatches сравнивает наблюдаемую топологию без зависимости от порядка Docker сетей.
func warpPeerTopologyMatches(previous, current *WarpManifest) bool {
	if previous == nil || current == nil {
		return false
	}
	left, right := *previous, *current
	for _, value := range []*WarpManifest{&left, &right} {
		value.Networks = append([]WarpNetwork(nil), value.Networks...)
		value.AWGIPs = append([]string(nil), value.AWGIPs...)
		value.Bridges = append([]string(nil), value.Bridges...)
		sort.Slice(value.Networks, func(i, j int) bool { return value.Networks[i].Name < value.Networks[j].Name })
		sort.Strings(value.AWGIPs)
		sort.Strings(value.Bridges)
	}
	return reflect.DeepEqual(left, right)
}

// warpPeerPublicIPv4 исключает непубличные и специальные IPv4 из предложения endpoint.
func warpPeerPublicIPv4(address netip.Addr) bool {
	if !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() {
		return false
	}
	for _, value := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4"} {
		if netip.MustParsePrefix(value).Contains(address) {
			return false
		}
	}
	return true
}
