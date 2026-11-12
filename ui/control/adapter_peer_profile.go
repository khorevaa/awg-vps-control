//go:build linux

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PeerProfileEntry хранит профиль только в памяти; пустое содержимое резервирует место.
type PeerProfileEntry struct {
	Content     []byte    // Приватный профиль, никогда не записывается в native файлы.
	PublicKey   string    // Публичный ключ для удаления при отзыве.
	ContainerID string    // Закреплённый контейнер создания.
	Interface   string    // Закреплённый интерфейс создания.
	Identity    string    // Хеш серверных параметров и persistent peer.
	ExpiresAt   time.Time // Конец срока разовой выдачи.
}

// PeerProfileVault ограничивает число и время жизни секретных профилей.
type PeerProfileVault struct {
	mutex   sync.Mutex                  // Защита reserve/consume/expire.
	entries map[string]PeerProfileEntry // Записи по ID успешной операции создания.
}

// expireLocked удаляет просроченные буферы под mutex хранилища.
func (vault *PeerProfileVault) expireLocked(now time.Time) {
	for id, entry := range vault.entries {
		if !now.Before(entry.ExpiresAt) {
			clear(entry.Content)
			delete(vault.entries, id)
		}
	}
}

// reserve выделяет место до native mutation без вытеснения живых профилей.
func (vault *PeerProfileVault) reserve(id string) *APIError {
	vault.mutex.Lock()
	defer vault.mutex.Unlock()
	if vault.entries == nil {
		vault.entries = make(map[string]PeerProfileEntry)
	}
	vault.expireLocked(time.Now())
	if _, exists := vault.entries[id]; exists {
		return failure(409, "peer_conflict", "Профиль этой операции уже подготовлен.")
	}
	if len(vault.entries) >= 16 {
		return failure(429, "profile_capacity", "Скачайте подготовленные профили или дождитесь истечения их срока.")
	}
	vault.entries[id] = PeerProfileEntry{ExpiresAt: time.Now().Add(10 * time.Minute)}
	return nil
}

// publish помещает проверенный профиль в заранее зарезервированное место.
func (vault *PeerProfileVault) publish(id, publicKey, containerID, iface, identity string, content []byte) (time.Time, bool) {
	vault.mutex.Lock()
	defer vault.mutex.Unlock()
	entry, exists := vault.entries[id]
	if !exists || !time.Now().Before(entry.ExpiresAt) || len(content) == 0 || len(content) > maxPeerProfileBytes || !validPeerKey(publicKey) || !dockerIDPattern.MatchString(containerID) || !awgInterfacePattern.MatchString(iface) || !revisionPattern.MatchString(identity) {
		return time.Time{}, false
	}
	expires := time.Now().Add(10 * time.Minute)
	vault.entries[id] = PeerProfileEntry{Content: append([]byte(nil), content...), PublicKey: publicKey, ContainerID: containerID, Interface: iface, Identity: identity, ExpiresAt: expires}
	return expires, true
}

// peek возвращает только identity записи без копирования секретного содержимого.
func (vault *PeerProfileVault) peek(id string) (PeerProfileEntry, bool) {
	vault.mutex.Lock()
	defer vault.mutex.Unlock()
	vault.expireLocked(time.Now())
	entry, exists := vault.entries[id]
	available := exists && len(entry.Content) > 0
	entry.Content = nil
	return entry, available
}

// discard уничтожает невыданный профиль конкретной операции.
func (vault *PeerProfileVault) discard(id string) {
	vault.mutex.Lock()
	defer vault.mutex.Unlock()
	entry := vault.entries[id]
	clear(entry.Content)
	delete(vault.entries, id)
}

// revoke удаляет любые ожидающие скачивания профили отозванного public key.
func (vault *PeerProfileVault) revoke(publicKey string) {
	vault.mutex.Lock()
	defer vault.mutex.Unlock()
	for id, entry := range vault.entries {
		if entry.PublicKey == publicKey {
			clear(entry.Content)
			delete(vault.entries, id)
		}
	}
}

// consume удаляет запись перед формированием единственного ответа.
func (vault *PeerProfileVault) consume(id string) (PeerProfile, *APIError) {
	vault.mutex.Lock()
	defer vault.mutex.Unlock()
	vault.expireLocked(time.Now())
	entry, exists := vault.entries[id]
	if !exists || len(entry.Content) == 0 {
		return PeerProfile{}, failure(410, "profile_unavailable", "Разовый профиль недоступен; отзовите клиента и создайте его заново.")
	}
	delete(vault.entries, id)
	defer clear(entry.Content)
	return PeerProfile{Filename: "awg_client_" + id[:12] + ".conf", ContentBase64: base64.StdEncoding.EncodeToString(entry.Content)}, nil
}

// Run освобождает просроченные профили независимо от новых HTTP-запросов.
func (vault *PeerProfileVault) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			vault.mutex.Lock()
			for id, entry := range vault.entries {
				clear(entry.Content)
				delete(vault.entries, id)
			}
			vault.mutex.Unlock()
			return
		case now := <-ticker.C:
			vault.mutex.Lock()
			vault.expireLocked(now)
			vault.mutex.Unlock()
		}
	}
}

// adapterAllocatePeer выбирает свободный IPv4, исключая все native диапазоны и серверные адреса.
func adapterAllocatePeer(snapshot AdapterPeerSnapshot, defaults PeerDefaults) (netip.Addr, *APIError) {
	prefix := snapshot.Config.Address.Masked()
	reserved := map[netip.Addr]bool{snapshot.Config.Address.Addr(): true, prefix.Addr(): true}
	for _, value := range defaults.ReservedIPs {
		address, err := netip.ParseAddr(value)
		if err != nil || !address.Is4() {
			return netip.Addr{}, failure(502, "host_protocol_error", "Root не подтвердил зарезервированные адреса.")
		}
		reserved[address] = true
	}
	for address := prefix.Addr().Next(); prefix.Contains(address) && prefix.Contains(address.Next()); address = address.Next() {
		if reserved[address] {
			continue
		}
		used := false
		for _, peer := range snapshot.Config.Peers {
			for _, occupied := range peer.Allowed {
				if occupied.Contains(address) {
					used = true
					break
				}
			}
			if used {
				break
			}
		}
		if !used {
			return address, nil
		}
	}
	return netip.Addr{}, failure(409, "peer_capacity", "В клиентской подсети нет свободных IPv4 адресов.")
}

// adapterBuildProfile создаёт canonical WireGuard private key исключительно в памяти Go.
func adapterBuildProfile(config AdapterNativeConfig, request PeerCreateRequest, address netip.Addr, psk string) ([]byte, string, *APIError) {
	private := make([]byte, 32)
	defer clear(private)
	if _, err := rand.Read(private); err != nil {
		return nil, "", failure(500, "random_unavailable", "Не удалось создать ключ клиента.")
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	key, err := ecdh.X25519().NewPrivateKey(private)
	if err != nil {
		return nil, "", failure(500, "key_generation_failed", "Не удалось подготовить ключ клиента.")
	}
	serverPrivate, err := base64.StdEncoding.Strict().DecodeString(config.Interface["PrivateKey"])
	defer clear(serverPrivate)
	if err != nil || !validPeerKey(psk) {
		return nil, "", adapterNativeError()
	}
	serverKey, err := ecdh.X25519().NewPrivateKey(serverPrivate)
	if err != nil {
		return nil, "", adapterNativeError()
	}
	lines := []string{"[Interface]", "Address = " + address.String() + "/32", "DNS = " + strings.Join(request.DNS, ", "), "PrivateKey = " + base64.StdEncoding.EncodeToString(private)}
	lines = append(lines, config.ProfileParameters...)
	keepalive := "25"
	if config.Interface["HeaderProtectionKey"] != "" {
		keepalive = "25-35"
	}
	lines = append(lines, "", "[Peer]", "PublicKey = "+base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), "PresharedKey = "+psk, "AllowedIPs = 0.0.0.0/0, ::/0", "Endpoint = "+net.JoinHostPort(request.EndpointHost, strconv.Itoa(config.ListenPort)), "PersistentKeepalive = "+keepalive, "")
	content := []byte(strings.Join(lines, "\n"))
	if len(content) > maxPeerProfileBytes {
		clear(content)
		return nil, "", failure(422, "invalid_payload", "Профиль превышает поддержанный размер.")
	}
	return content, base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}
