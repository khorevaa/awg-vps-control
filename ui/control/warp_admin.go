//go:build linux

package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"time"
)

// warpTunnelCommand выделяет команды, способные включить или изменить туннель.
func warpTunnelCommand(args []string) bool {
	if len(args) < 2 || filepath.Base(args[0]) != "warp-cli" {
		return false
	}
	joined := " " + strings.Join(args[1:], " ") + " "
	return strings.Contains(joined, " connect ") || strings.Contains(joined, " mode ")
}

// adminExcluded проверяет штатную схему исключений, не интерпретируя include как exclude.
func (s *WarpSession) adminExcluded(ctx context.Context, address netip.Addr) (bool, bool) {
	code, raw, apiError := warpExecute(ctx, []string{"warp-cli", "--accept-tos", "--json", "tunnel", "ip", "list"}, 5*time.Second, "", 131072, false)
	var data map[string]any
	if apiError != nil || code != 0 || decodeStrict([]byte(raw), &data) != nil || warpString(data["mode"]) != "exclude" {
		s.fail("admin_route_unverified", "Не подтверждён поддержанный режим исключений WARP; подключение остановлено.", 409)
		return false, false
	}
	routes, ok := data["routes"].([]any)
	if !ok || len(routes) > 1024 {
		s.fail("admin_route_unverified", "Не подтверждён список исключений WARP.", 409)
		return false, false
	}
	excluded := false
	for _, route := range routes {
		prefix, err := netip.ParsePrefix(warpString(warpMap(route)["value"]))
		if err != nil || prefix != prefix.Masked() {
			s.fail("admin_route_unverified", "Список исключений WARP имеет неподдержанный формат.", 409)
			return false, false
		}
		excluded = excluded || prefix.Contains(address)
	}
	return excluded, true
}

// protectAdmin сохраняет SSH вне WARP; false без Err означает только неготовность daemon.
func (s *WarpSession) protectAdmin(ctx context.Context) bool {
	if s.Err != nil || !s.requireSafety(ctx, false) {
		return false
	}
	if !s.registrationReady(ctx) {
		return false
	}
	state, err := s.Runtime.safetyRead()
	ssh, sshErr := warpSafetyParseSSH(state.OriginalSSHConnection)
	if err != nil || sshErr != nil {
		s.fail("admin_route_unverified", "Не подтверждён SSH-адрес защитного окна.", 409)
		return false
	}
	excluded, valid := s.adminExcluded(ctx, ssh.Client.Addr())
	if !valid || excluded {
		return valid
	}
	if !s.requireSafety(ctx, false) {
		return false
	}
	code, _, apiError := warpExecute(ctx, []string{"warp-cli", "--accept-tos", "tunnel", "ip", "add", ssh.Client.Addr().String()}, 5*time.Second, "", 8192, false)
	if apiError != nil || code != 0 || !s.safetyMutationFinished(ctx) {
		s.fail("admin_route_unverified", "WARP не подтвердил сохранение SSH-исключения.", 409)
		return false
	}
	excluded, valid = s.adminExcluded(ctx, ssh.Client.Addr())
	if !valid || !excluded {
		s.fail("admin_route_unverified", "SSH-исключение не подтверждено после записи.", 409)
		return false
	}
	return true
}
