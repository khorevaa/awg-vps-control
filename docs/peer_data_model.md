# Управление клиентами Amnezia

Панель и приложение Amnezia изменяют установку **по очереди**. Источники истины —
`/opt/amnezia/awg/<interface>.conf`, `clientsTable` и runtime AWG. Отдельной базы
клиентов нет. Контракт основан на AmneziaVPN 5.1.0.6
(`ac175c8a8147cfe56f98c8372ec17ea2ba00bb02`).

## API и модели

| Модель | Поля | Назначение |
|---|---|---|
| PeerCreateRequest | name string, endpoint_host string, dns []string, expected_revision string | Создание; имя 1–80 символов без управляющих символов, hostname/IPv4/IPv6 без порта, 1–2 DNS IPv4, SHA-256 ревизия |
| PeerRenameRequest | public_key string, name string, expected_revision string | Изменение только имени |
| PeerRevokeRequest | public_key string, expected_revision string | Удаление native peer и metadata |
| PeerCatalog | revision string, can_manage bool, reason string, peers []AdapterPeer, defaults PeerDefaults | Согласованное состояние перед изменением |
| PeerDefaults | endpoint_host string, dns []string, listen_port int, reserved_ips []string | Предложение входящего адреса VPS, DNS и зарезервированные адреса; пользователь может исправить endpoint/DNS |
| PeerMutationResult | complete bool, public_key string, name string, address string, revision string, profile_available bool, profile_expires_at string | Только публичный результат для постоянного журнала |
| PeerProfile | filename string, content_base64 string | Только отдельная разовая выдача, максимум 64 KiB декодированного профиля; никогда не хранить в журнале |
| PeerProfileEntry | Content []byte, PublicKey/ContainerID/Interface/Identity string, ExpiresAt time.Time | Секретный профиль только в памяти Adapter; ключ записи — ID операции |
| PeerProfileVault | mutex sync.Mutex, entries map[string]PeerProfileEntry | Не более 16 профилей, TTL 10 минут; резервировать место до изменения |

Имена Go-полей и внутренние вспомогательные модели уточняются реализацией в этом
SDD до объявления соответствующих структур. Web использует такие же JSON-поля,
не разделяя Go-модуль с Control.

`GET /api/v1/peers/catalog` → `peers.catalog`. Старый `GET /api/v1/peers`
сохраняет массив. `peer.create`, `peer.rename`, `peer.revoke` принимаются через
`POST /api/v1/operations` с CSRF и idempotency key. Запросы не содержат ключей.
`POST /api/v1/peers/profile` с `{ "id": "<operation id>" }` и CSRF передаёт
`peers.profile.consume`; Control проверяет успешную `peer.create` в журнале.
Web выдаёт `.conf` как attachment с `Cache-Control: no-store`. Профиль удаляется
из памяти перед отправкой: повторная выдача, перезапуск или истечение TTL — 410.
При потере профиля следует отозвать доступ и создать клиента заново.

Base64 используется только как типизированная передача файла по локальному JSON
протоколу. Общая фильтрация секретов остаётся включённой; mutation result строго
проверяется до сохранения, профиль через операции не передаётся.

## Native изменения

Ревизия включает ID контейнера, интерфейс, исходные байты обоих native файлов и
признак существования clientsTable. Перед записью повторно проверяются ревизии,
идентичность контейнера и соответствие runtime peers постоянному конфигу.
Неизвестные поля metadata и нетронутые секции конфигурации сохраняются.

Фиксированный Docker archive endpoint передаёт только подготовленные native
файлы в закрытый staging. Фиксированный transaction script получает проверенные
ID/хеши/интерфейс аргументами; имена и содержимое никогда не становятся shell-кодом.
Закрытый intent/backup фиксирует стадии, каждый файл заменяется atomic rename.
Для create/revoke выполняются раздельные `awg-quick strip` и `awg syncconf` с
проверкой кодов завершения. Rename не применяет runtime. AWG не перезапускается.
Откат допускается лишь для подтверждённых версий собственных изменений;
незавершённая транзакция или чужие изменения требуют ручного восстановления.

IPv4 выделяется из подтверждённой подсети с учётом всех занятых диапазонов,
адресов сервера, network/broadcast и адреса диагностической пробы.
Клиент получает штатный общий PSK и параметры существующей установки, включая
известные закомментированные I1–I5. Новая обфускация не генерируется.
В `.conf` полный туннель `0.0.0.0/0, ::/0`; отдельный IPv6 адрес не выделяется.
Дата создания metadata соответствует Qt TextDate. Client private key генерируется
в памяти Adapter, отсутствует в native файлах, tar, резервных копиях и журналах.

## Значения по умолчанию

Внутреннее чтение `peers.defaults` root runtime возвращает PeerDefaults без
изменения маршрутов. Endpoint предлагается только при однозначном публичном
IPv4 физического uplink; внешний IP через WARP не используется. При NAT или
неоднозначности пользователь вводит входящий адрес. DNS — закреплённый AmneziaDNS,
при его отсутствии явное предложение `1.1.1.1`; фактические значения передаются
в create. ListenPort берётся из проверенной установки, порт не вводится клиентом.

## Обновление и совместимость

Старый Control из v0.1.0-rc.1 не понимает новые действия журнала. После первого
изменения клиентов откат на этот выпуск не поддерживается: старый процесс должен
отказаться читать несовместимый журнал, а не терять операции. Перезапуск новой
версии не повторяет незавершённые мутации и теряет ожидающие скачивания профили.

## Adapter internal structs

| Модель | Внутренние поля и ограничения |
|---|---|
| AdapterNativeSection | `Name`, `Start`, `End`, `Values`: секция native конфига, границы строк и проверенные однозначные присваивания; исходные строки сохраняются |
| AdapterNativeConfig | `Raw`, `Lines`, `Sections`, `Interface`, `Peers`, `Address`, `ListenPort`, `ProfileParameters`: native байты, безопасный разбор и поддержанные клиентские AWG-параметры |
| AdapterNativePeer | `PublicKey`, `PSK`, `Allowed`, `Section`: persistent identity, PSK только в памяти и диапазоны адресов |
| AdapterPeerSnapshot | `Installation`, `Container`, `Config`, `Table`, `TableExists`, `Clients`, `Runtime`, `Revision`, `PSK`: проверенный снимок файлов и runtime; metadata — `[]map[string]json.RawMessage`, дополнительные поля не теряются |
| AdapterPeerFiles | `Config`, `Table`: подготовленные native байты, без клиентского private key |
| PeerProfileEntry | `Content`, `PublicKey`, `ContainerID`, `Interface`, `Identity`, `ExpiresAt`: профиль в памяти, привязка к установке и хеш параметров сервера/peer; пустой Content резервирует место |
| PeerProfileVault | `mutex`, `entries`: mutex и map по operation ID; ленивое создание, удаление просроченных записей, очистка буфера при consume/revoke/shutdown |

Служебный каталог контейнера `/opt/amnezia/awg/.awg_vps_control` root-owned 0700.
Текущая транзакция занимает `active` с root-only owner/phase, копиями старых и новых
native файлов. `active` не удаляется при неизвестном исходе; новые мутации
отказывают до ручного восстановления. После подтверждения остаётся не более
одного `last` backup. Имена каталогов/файлов фиксированы, Docker tar не содержит
symlink, внешних путей или клиентского private key. Перед atomic rename повторно
сверяются SHA файлов, после — native снимок и runtime. Откат не заменяет чужую
ревизию. Все exec имеют внутренний timeout; обрыв HTTP не считается отменой exec.

До применения Adapter проверяет непустой результат `awg-quick strip` по полному
набору persistent параметров и фиксирует его SHA. Syncconf получает только этот
проверенный файл. `awg showconf` дополнительно сверяется с native настройками,
включая AWG-параметры, FWMark и keepalive; динамический Endpoint не сравнивается.
Перед rollback runtime должен целиком совпадать с собственным before или after.
Разовая выдача повторно проверяет установку, наличие peer и его профильные
параметры; профиль отозванного или изменившегося peer не выдаётся.
