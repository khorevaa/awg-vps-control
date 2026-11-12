package connection

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// knownAddress передаёт knownhosts точный подтверждаемый адрес без DNS и подставного IP.
type knownAddress string

// Network обозначает только формат SSH endpoint для проверки knownhosts.
func (address knownAddress) Network() string { return "tcp" }

// String возвращает исходный hostname:port без сетевого разрешения.
func (address knownAddress) String() string { return string(address) }

// knownHostsCallback загружает только bounded app-owned файл доверенных ключей.
func knownHostsCallback(dir string) (ssh.HostKeyCallback, error) {
	storeMutex.Lock()
	defer storeMutex.Unlock()
	if err := prepareDirectory(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "known_hosts")
	data, err := readFile(path, maxStoreBytes)
	if errors.Is(err, os.ErrNotExist) {
		if err := atomicFile(dir, "known_hosts", nil); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, errors.New("Не удалось проверить файл доверенных SSH-ключей.")
	}
	if len(data) > maxStoreBytes {
		return nil, errors.New("Файл доверенных SSH-ключей слишком велик.")
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return nil, errors.New("Формат файла доверенных SSH-ключей повреждён.")
	}
	return callback, nil
}

// checkedHostKey отличает неизвестный ключ от изменённого и не доверяет автоматически.
func checkedHostKey(callback ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(address string, remote net.Addr, key ssh.PublicKey) error {
		err := callback(address, remote, key)
		if err == nil {
			return nil
		}
		var keyError *knownhosts.KeyError
		if errors.As(err, &keyError) && len(keyError.Want) == 0 {
			return &HostKeyChallenge{Address: address, Algorithm: key.Type(), Fingerprint: ssh.FingerprintSHA256(key), Key: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))}
		}
		return errors.New("SSH-ключ сервера изменился или отозван. Подключение запрещено; проверьте сервер независимо.")
	}
}

// TrustHostKey записывает явно подтверждённый неизвестный ключ, не заменяя существующий.
func TrustHostKey(dir string, challenge *HostKeyChallenge) error {
	if challenge == nil || len(challenge.Key) > 16384 {
		return errors.New("Отсутствует допустимый запрос доверия SSH-ключу.")
	}
	host, port, err := net.SplitHostPort(challenge.Address)
	number, portError := strconv.Atoi(port)
	if err != nil || portError != nil || !validHost(host) || number < 1 || number > 65535 || strconv.Itoa(number) != port {
		return errors.New("Некорректный адрес запроса доверия SSH.")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(challenge.Key))
	if err != nil || len(options) != 0 || len(bytes.TrimSpace(rest)) != 0 || key.Type() != challenge.Algorithm || ssh.FingerprintSHA256(key) != challenge.Fingerprint || strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) != challenge.Key {
		return errors.New("Не удалось подтвердить fingerprint выбранного SSH-ключа.")
	}
	storeMutex.Lock()
	defer storeMutex.Unlock()
	if err := prepareDirectory(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, "known_hosts")
	data, err := readFile(path, maxStoreBytes)
	if errors.Is(err, os.ErrNotExist) {
		if err := atomicFile(dir, "known_hosts", nil); err != nil {
			return err
		}
		data = nil
	} else if err != nil {
		return errors.New("Не удалось прочитать app known_hosts.")
	}
	callback, err := knownhosts.New(path)
	if err != nil {
		return errors.New("Формат app known_hosts повреждён.")
	}
	err = callback(challenge.Address, knownAddress(challenge.Address), key)
	if err == nil {
		return nil
	}
	var keyError *knownhosts.KeyError
	if !errors.As(err, &keyError) || len(keyError.Want) != 0 {
		return errors.New("Существующий SSH-ключ не заменяется через подтверждение неизвестного сервера.")
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte(knownhosts.Line([]string{challenge.Address}, key)+"\n")...)
	if len(data) > maxStoreBytes {
		return errors.New("Достигнут предел файла доверенных SSH-ключей.")
	}
	return atomicFile(dir, "known_hosts", data)
}
