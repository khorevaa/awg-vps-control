//go:build linux

package main

// PeerCreateRequest описывает создание native клиента согласно peer_data_model.md.
type PeerCreateRequest struct {
	Name             string   `json:"name"`              // Имя клиента в Amnezia.
	EndpointHost     string   `json:"endpoint_host"`     // Входящий адрес VPS без порта.
	DNS              []string `json:"dns"`               // Один или два адреса DNS в профиле.
	ExpectedRevision string   `json:"expected_revision"` // Ревизия обоих native файлов.
}

// PeerRenameRequest меняет только имя существующего клиента.
type PeerRenameRequest struct {
	PublicKey        string `json:"public_key"`        // Публичный ключ целевого клиента.
	Name             string `json:"name"`              // Новое имя Amnezia.
	ExpectedRevision string `json:"expected_revision"` // Ревизия перед изменением.
}

// PeerRevokeRequest отзывает доступ существующего клиента.
type PeerRevokeRequest struct {
	PublicKey        string `json:"public_key"`        // Публичный ключ целевого клиента.
	ExpectedRevision string `json:"expected_revision"` // Ревизия перед изменением.
}

// PeerDefaults содержит предложения для профиля и исключения распределителя адресов.
type PeerDefaults struct {
	EndpointHost string   `json:"endpoint_host"` // Однозначный входящий адрес VPS либо пустая строка.
	DNS          []string `json:"dns"`           // Предлагаемые адреса DNS.
	ListenPort   int      `json:"listen_port"`   // Подтверждённый опубликованный UDP порт.
	ReservedIPs  []string `json:"reserved_ips"`  // Адреса сервера и диагностической пробы.
}

// PeerCatalog представляет согласованный снимок клиентов для управления.
type PeerCatalog struct {
	Revision  string        `json:"revision"`   // Общая ревизия native файлов и идентичности установки.
	CanManage bool          `json:"can_manage"` // Разрешены ли изменения в текущем состоянии.
	Reason    string        `json:"reason"`     // Безопасная причина ограничений.
	Peers     []AdapterPeer `json:"peers"`      // Клиенты без секретов.
	Defaults  PeerDefaults  `json:"defaults"`   // Начальные параметры нового профиля.
}

// PeerMutationResult допускает в постоянный журнал только публичные поля результата.
type PeerMutationResult struct {
	Complete         bool   `json:"complete"`           // Подтверждены ли файлы и runtime после изменения.
	PublicKey        string `json:"public_key"`         // Публичный ключ клиента.
	Name             string `json:"name"`               // Имя после изменения либо до отзыва.
	Address          string `json:"address"`            // Выделенный клиентский IPv4 с префиксом.
	Revision         string `json:"revision"`           // Подтверждённая новая ревизия.
	ProfileAvailable bool   `json:"profile_available"`  // Профиль был подготовлен для разовой выдачи.
	ProfileExpiresAt string `json:"profile_expires_at"` // Срок доступности профиля RFC3339Nano.
}

// PeerProfile передаёт секретный файл только по отдельному разовому маршруту.
type PeerProfile struct {
	Filename      string `json:"filename"`       // Фиксированное безопасное имя скачиваемого файла.
	ContentBase64 string `json:"content_base64"` // Ограниченный профиль; запрещён для постоянного журнала.
}
