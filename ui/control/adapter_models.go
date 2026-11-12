//go:build linux

package main

// AdapterConfig содержит доверенные пути режима Docker adapter.
type AdapterConfig struct {
	SocketPath       string // Путь публичного Unix socket adapter.
	WarpSocket       string // Путь root-сервиса WARP.
	DockerSocket     string // Путь Docker Engine socket.
	StateDirectory   string // Приватный каталог для statfs и process lock.
	MetricsDirectory string // Каталог явных host metric mounts.
}

// DockerSummary представляет минимальную проекцию списка контейнеров.
type DockerSummary struct {
	ID    string   `json:"Id"`    // Полный идентификатор Docker.
	Names []string `json:"Names"` // Имена существующего контейнера.
}

// DockerContainer представляет безопасную проекцию inspect.
type DockerContainer struct {
	ID              string                `json:"Id"`              // Полный идентификатор Docker.
	Name            string                `json:"Name"`            // Имя контейнера с начальным slash.
	State           DockerContainerState  `json:"State"`           // Состояние процесса контейнера.
	Config          DockerContainerConfig `json:"Config"`          // Формат потока журнала.
	HostConfig      DockerHostConfig      `json:"HostConfig"`      // Настройка доступности журнала.
	NetworkSettings DockerNetworkSettings `json:"NetworkSettings"` // Подключённые сети.
}

// DockerContainerState содержит только данные проверки существующего контейнера.
type DockerContainerState struct {
	Running   bool   `json:"Running"`   // Признак запущенного контейнера.
	StartedAt string `json:"StartedAt"` // Время старта Docker.
	PID       int    `json:"Pid"`       // PID namespace, не используется для выполнения команд adapter.
}

// DockerContainerConfig содержит безопасную настройку формата logs.
type DockerContainerConfig struct {
	TTY bool `json:"Tty"` // Признак немультиплексированного потока.
}

// DockerHostConfig содержит только настройку драйвера журналирования контейнера.
type DockerHostConfig struct {
	LogConfig DockerLogConfig `json:"LogConfig"` // Ограниченная проекция настройки журнала.
}

// DockerLogConfig позволяет отличить отключённую запись журнала от ошибки чтения.
type DockerLogConfig struct {
	Type string `json:"Type"` // Имя logging driver; none означает отсутствие записи.
}

// DockerNetworkSettings содержит минимальные сведения о сетевых подключениях.
type DockerNetworkSettings struct {
	Networks map[string]DockerNetworkBinding `json:"Networks"` // Привязки по именам сетей.
}

// DockerNetworkBinding содержит идентичность выбранной сети.
type DockerNetworkBinding struct {
	NetworkID string `json:"NetworkID"` // Идентификатор Docker network.
	IPAddress string `json:"IPAddress"` // Текущий IPv4 адрес контейнера.
}

// DockerExecRequest описывает исключительно фиксированную read-команду.
type DockerExecRequest struct {
	AttachStdout bool     `json:"AttachStdout"` // Чтение ограниченного stdout.
	AttachStderr bool     `json:"AttachStderr"` // Получение stderr без выдачи сырых ошибок.
	TTY          bool     `json:"Tty"`          // Всегда false для строгого multiplex.
	Privileged   bool     `json:"Privileged"`   // Всегда false, привилегии не повышаются.
	User         string   `json:"User"`         // Root существующего AWG-контейнера.
	Cmd          []string `json:"Cmd"`          // Фиксированный argv без shell.
}

// DockerExecStart запускает созданную фиксированную команду.
type DockerExecStart struct {
	Detach bool `json:"Detach"` // Всегда false для проверки завершения.
	TTY    bool `json:"Tty"`    // Всегда false для multiplex.
}

// DockerIdentifier содержит идентификатор, выданный Docker daemon.
type DockerIdentifier struct {
	ID string `json:"Id"` // Проверяемый полный exec ID.
}

// DockerExecStatus подтверждает завершение команды в нужном контейнере.
type DockerExecStatus struct {
	Running     bool   `json:"Running"`     // Признак незавершённого exec.
	ExitCode    int    `json:"ExitCode"`    // Код завершения команды.
	ContainerID string `json:"ContainerID"` // Контейнер, которому принадлежит exec.
}

// AdapterInstallation содержит только публичные метаданные существующей установки.
type AdapterInstallation struct {
	ContainerName    string   `json:"container_name"`              // Штатное имя AWG-контейнера.
	ContainerID      string   `json:"container_id"`                // Закреплённый полный ID AWG.
	Interface        string   `json:"interface"`                   // Проверенный AWG-интерфейс.
	ConfigPath       string   `json:"config_path"`                 // Только штатный путь /opt/amnezia/awg.
	DNSContainerName string   `json:"dns_container_name"`          // Выбранный штатный DNS-контейнер.
	DNSContainerID   string   `json:"dns_container_id,omitempty"`  // Закреплённый полный ID DNS.
	DockerNetwork    string   `json:"docker_network"`              // Выбранная существующая сеть.
	Capabilities     []string `json:"capabilities"`                // Подтверждённые возможности адаптера.
	Supported        bool     `json:"supported"`                   // Наличие поддерживаемого штатного конфига.
	Reason           string   `json:"reason"`                      // Безопасная причина ограничений.
	Networks         []string `json:"networks,omitempty"`          // Сети кандидата discovery.
	BaselineRevision string   `json:"baseline_revision,omitempty"` // Хеш конфига при root-привязке.
}

// AdapterIntegration является проекцией единственной root-owned привязки.
type AdapterIntegration struct {
	Installation *AdapterInstallation `json:"installation"` // Закреплённая установка либо null.
	Managed      bool                 `json:"managed"`      // Наличие управляемого root routing manifest.
}

// AdapterPeer представляет штатного AWG peer без private key или PSK.
type AdapterPeer struct {
	PublicKey       string   `json:"public_key"`       // Публичный ключ клиента.
	Name            string   `json:"name"`             // Имя из clientsTable.
	AllowedIPs      []string `json:"allowed_ips"`      // Штатные разрешённые адреса.
	Endpoint        string   `json:"endpoint"`         // Наблюдаемый endpoint клиента.
	LatestHandshake int64    `json:"latest_handshake"` // Время последнего handshake Unix.
	RXBytes         uint64   `json:"rx_bytes"`         // Полученные байты.
	TXBytes         uint64   `json:"tx_bytes"`         // Отправленные байты.
}

// NativeClient представляет элемент штатного Amnezia clientsTable.
type NativeClient struct {
	ClientID string           `json:"clientId"` // Публичный ключ штатного клиента.
	UserData NativeClientData `json:"userData"` // Штатные пользовательские данные.
}

// NativeClientData содержит отображаемое имя клиента Amnezia.
type NativeClientData struct {
	ClientName string `json:"clientName"` // Имя клиента без собственного хранилища.
}
