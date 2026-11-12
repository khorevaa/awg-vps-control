// Package connection предоставляет ограниченный SSH-транспорт одной desktop-сессии.
package connection

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHProfile содержит только сохраняемые несекретные параметры подключения.
type SSHProfile struct {
	ID       string `json:"id"`        // Стабильный идентификатор профиля.
	Name     string `json:"name"`      // Название для native списка.
	Host     string `json:"host"`      // SSH hostname или IP без порта.
	Port     int    `json:"port"`      // SSH порт в диапазоне 1–65535.
	User     string `json:"user"`      // Имя пользователя SSH.
	AuthMode string `json:"auth_mode"` // Способ аутентификации password или key.
	KeyPath  string `json:"key_path"`  // Путь выбранного приватного ключа, без его содержимого.
}

// ProfileStore задаёт версию формата локального файла настроек.
type ProfileStore struct {
	Version  int          `json:"version"`  // Поддерживается только версия 1.
	Profiles []SSHProfile `json:"profiles"` // Не более 64 проверенных записей.
}

// Credentials содержит секреты только одной попытки и не сериализуется.
type Credentials struct {
	Password   string `json:"-"` // Пароль SSH, переданный native формой.
	Passphrase string `json:"-"` // Пароль приватного ключа, переданный native формой.
}

// HostKeyChallenge сообщает неизвестный публичный ключ без автоматического доверия.
type HostKeyChallenge struct {
	Address     string // Точный SSH адрес с портом.
	Algorithm   string // Алгоритм публичного ключа сервера.
	Fingerprint string // SHA256 fingerprint для явного подтверждения.
	Key         string // Канонический публичный ключ в authorized_keys формате.
}

// Error возвращает безопасное описание запроса доверия без адреса сервера.
func (challenge *HostKeyChallenge) Error() string {
	return "SSH-ключ сервера ещё не подтверждён. Проверьте SHA256 fingerprint."
}

// PendingProfileDownload передаёт native UI единственный буфер для явного сохранения.
type PendingProfileDownload struct {
	OperationID string    // ID создания клиента, которому принадлежит файл.
	Filename    string    // Проверенное штатное имя awg_client_<12hex>.conf.
	Data        []byte    // Секретный файл; получатель обязан очистить после save/cancel/error.
	ExpiresAt   time.Time // Предельный срок хранения в памяти соединения.
}

// Connection владеет SSH, loopback HTTP и секретным ожидающим файлом одной сессии.
type Connection struct {
	tcp          net.Conn                // Исходный TCP для немедленной отмены SSH.
	ssh          *ssh.Client             // Аутентифицированный SSH transport.
	transport    *http.Transport         // HTTP только через фиксированный remote Unix socket.
	server       *http.Server            // Ограниченный локальный HTTP сервер.
	listener     net.Listener            // Только IPv4 loopback и случайный порт.
	localOrigin  string                  // Случайный origin под .localhost.
	localHost    string                  // Точное локальное значение Host.
	remoteOrigin string                  // Проверенный разрешённый origin сервера.
	remoteHost   string                  // Проверенное разрешённое значение Host сервера.
	cancel       context.CancelFunc      // Отмена всех операций сессии.
	once         sync.Once               // Единственное освобождение ресурсов.
	mutex        sync.Mutex              // Защита закрытия и ожидающего профиля.
	closed       bool                    // Запрет новых запросов и выдачи после закрытия.
	done         chan struct{}           // Уведомление UI об окончательном закрытии.
	pending      *PendingProfileDownload // Единственный файл, ещё не переданный UI.
	downloading  bool                    // Резервирование до серверного одноразового consume.
	saving       bool                    // Запрет следующего consume, пока native UI владеет переданным файлом.
}
