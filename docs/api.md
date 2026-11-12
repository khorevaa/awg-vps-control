# API панели

Браузер → Go Web по HTTP через Unix socket и SSH-туннель. Web → Go Control → Go Docker Adapter → хостовый Go WARP agent используют отдельные Unix sockets и протокол из `data_model.md`. Первые три процесса работают в Docker; хостовый agent обслуживает только WARP, его политику, маршруты и восстановление.

Control допускает Web UID 10001; локальный root и собственный UID 10002 могут выполнять только healthcheck. Adapter допускает Control UID 10002 и локальный root для разрешённых действий; собственный UID 10003 — только для healthcheck. WARP agent допускает Adapter UID 10003 и локальный root. Межпроцессная проверка использует `SO_PEERCRED`, владельцев sockets и права каталогов.

## Web HTTP

Точный Host проверяется, кроме локального healthcheck. Мутации требуют точный Origin; кроме обмена секрета, дополнительно сессию и `X-CSRF-Token`. JSON строго проверяется, body ограничен. Ответы и статика `Cache-Control: no-store`. API-ошибка: `{"error":{"code":"...","message":"...","status":400}}`.

| Метод | Путь | Результат |
| --- | --- | --- |
| GET | `/api/v1/health` | `{status:"ok"}`, без host/network информации |
| POST | `/api/v1/access` | тело `{secret}`; cookie и `{csrf_token,expires_at}` |
| GET | `/api/v1/auth/me` | `{csrf_token,expires_at}`, 401 без сессии |
| POST | `/api/v1/auth/logout` | завершить сессию |
| GET | `/api/v1/overview` | action `overview` |
| GET | `/api/v1/discovery` | action `discover` |
| GET | `/api/v1/peers` | action `peers`, массив Peer |
| GET | `/api/v1/diagnostics` | action `diagnostics` (ограниченные активные probes) |
| GET | `/api/v1/configuration` | action `configuration`, маскированный read-only снимок |
| GET | `/api/v1/logs?source=awg&limit=100` | action `logs` с LogRequest |
| GET | `/api/v1/policy` | action `policy.get` |
| POST | `/api/v1/operations` | OperationRequest, 202 + Operation |
| GET | `/api/v1/operations` | недавние операции, массив Operation |
| GET | `/api/v1/operations/{id}` | Operation |

`GET /api/v1/logs` возвращает Logs-снимок. Дополнительные `available`/`reason` совместимы с прежним форматом: `available:false` обозначает известную недоступность источника, HTTP 200, `lines:[]`, `truncated:false` и безопасное пояснение в `reason`. Для штатного AWG/DNS с Docker `log-driver none` журнал не записывается, поэтому Docker logs не запрашивается. Панель показывает причину внутри раздела журнала; контейнер/драйвер не изменяется. Успешно прочитанные Docker journals содержат `available:true`; у legacy WARP/supervisor эти дополнительные поля могут отсутствовать. Другие ошибки Docker и транспорта сохраняют обычные HTTP ошибки.

## Control

Read actions: `health`, `overview`, `discover`, `peers`, `diagnostics`, `configuration`, `logs`, `policy.get`, `operations.list`, `operations.get` (payload `{id}`). Мутация `operations.create` принимает OperationRequest и запускается последовательно с постоянным журналом.

Разрешённые операции: `attach` (AttachRequest), `policy.set` (PolicyUpdate), `repair` (`{}`), `warp.reconnect` (`{}`), `warp.setup` (`{}`), `awg.restart` (`{}`), а в `0.2.0-dev.1` также `peer.create`, `peer.rename`, `peer.revoke` (см. ниже). Перезапуск AWG — только явно созданная пользователем операция. Нет произвольного command/container/path payload.

## Docker Adapter и WARP agent

Adapter — отдельный процесс существующего бинарника `ui/control`: `awg_control adapter serve` и `awg_control adapter healthcheck`. Read actions совпадают с Control, кроме `operations.*`. Control отправляет операцию в Adapter под её именем и получает финальный результат; журнал и HTTP polling остаются в Control. Adapter читает AWG через Docker Engine API и выполняет фиксированные доменные команды внутри закреплённого контейнера. Клиентские операции применяют `syncconf`, `awg.restart` остаётся отдельным ручным действием. Произвольные Docker API paths, команды exec и host paths из пользовательского payload запрещены. Сырые конфиги и stdout/stderr не передаются клиенту; секретный клиентский профиль выдаётся только отдельным защищённым маршрутом.

WARP agent запускается тем же бинарником: `awg_control warp serve`; IPC и supervisor работают в одном процессе. Режимы `warp guard`, `warp check-config`, `warp request <JSON>` и `warp probe-dns` обслуживают boot guard, проверку конфигурации, локальные команды и сетевой probe. Конфигурация `/etc/awg_vps_control/host.json` и существующий host state сохраняются. Legacy `control_uid` не предоставляет доступ к новому socket; разрешённый `adapter_uid` — 10003. Сетевые действия сериализуются с supervisor; автопроцессы не вызывают `awg.restart`. `warp.setup` может занимать до 180 секунд; остальные операции ограничены 90 секундами, чтение — 30 секундами.

Root CLI направляет AWG reads/attach в Adapter, команды WARP — в WARP agent. Readiness проходит всю цепочку Web → Control → Adapter → WARP, включая доступ Adapter к Docker `/_ping`. HTTP `/api/v1/health` остаётся минимальным ответом о процессе Web.

Метрики hostname/uptime/load/memory читаются Adapter из отдельных read-only файлов хоста. `Overview.disk` показывает файловую систему каталога данных панели `/var/lib/awg_vps_control/adapter`, а не корень контейнера; это может отличаться от корневого раздела VPS.

## Развёртывание

- Web socket: `/run/awg_vps_web/web.sock`, Web UID, mode 0600.
- Control socket: `/run/awg_vps_control/control.sock`, UID 10002/GID 10001, mode 0660.
- Adapter socket: `/run/awg_vps_adapter/adapter.sock`, UID 10003/GID 10002, mode 0660.
- WARP socket: `/run/awg_vps_warp/warp.sock`, root/GID 10002, mode 0660.
- Все три контейнера: network none, read-only rootfs, cap_drop ALL, no-new-privileges, свои writable state/socket mounts. Только Adapter получает Docker socket; Web и Control доступа к Docker API не имеют. Нет privileged, host PID/network namespace или mount корня хоста.
- Доступ Adapter к Docker socket остаётся полномочиями уровня root, несмотря на UID 10003 и read-only bind mount. `AWG_DOCKER_GID` — фактическая числовая группа socket из `/etc/awg_vps_control/ui.env`, а не фиксированная группа или имя пользователя.
- Host config: `/etc/awg_vps_control/host.json`; host state: `/var/lib/awg_vps_control/host`; Web/Control state сохраняют прежние пути. Собственный каталог Adapter `/var/lib/awg_vps_control/adapter` имеет mode 0700 и UID 10003; отдельной базы VPN-клиентов в нём нет.
- Runtime-каталоги `/run/awg_vps_web`, `/run/awg_vps_control`, `/run/awg_vps_adapter`, `/run/awg_vps_warp` создаются правилом tmpfiles `awg_vps_control.conf`. Web directory — 0700, остальные — 0750.
- Проект устанавливает только две systemd-службы: `awg_vps_warp.service` и ранний `awg_vps_guard.service`. Web/Control/Adapter запускает Docker Compose; отдельных systemd-служб для них и общего host bridge нет.
- Web env: `AWG_WEB_SOCKET`, `AWG_CONTROL_SOCKET`, `AWG_ACCESS_SECRET_FILE`, `AWG_WEB_STATE`, `AWG_ALLOWED_HOST`, `AWG_ALLOWED_ORIGIN`.
- Control env: `AWG_CONTROL_SOCKET`, `AWG_HOST_SOCKET` (теперь Adapter socket), `AWG_CONTROL_STATE`, `AWG_WEB_UID` (default 10001).
- Adapter env: `AWG_ADAPTER_SOCKET`, `AWG_WARP_SOCKET`, `AWG_DOCKER_SOCKET`, `AWG_ADAPTER_STATE` (каталог), `AWG_HOST_METRICS` (каталог отдельных metric files).
- WARP env: `AWG_WARP_CONFIG`, `AWG_WARP_SOCKET`.

Точная публичная API-форма сохраняется при изменении внутренних функций. Runtime данные тестового VPS не сохраняются в репозитории.

## Управление клиентами Amnezia

Контракт следующего этапа описан в `peer_data_model.md`. Старый массив
`GET /api/v1/peers` сохраняется. `GET /api/v1/peers/catalog` возвращает
`{revision,can_manage,reason,peers,defaults}`; defaults содержит входящий адрес VPS,
DNS, UDP-порт и зарезервированные адреса. `can_manage:false` оставляет просмотр.

Через существующий `POST /api/v1/operations` доступны действия:

| Action | Payload |
| --- | --- |
| `peer.create` | `{name,endpoint_host,dns:["<IP>"],expected_revision}` |
| `peer.rename` | `{public_key,name,expected_revision}` |
| `peer.revoke` | `{public_key,expected_revision}` |

Имя — 1–80 Unicode-символов без управляющих и format-символов, без крайних
пробелов. Endpoint — канонический IP либо ASCII DNS-имя без URL/порта;
DNS — один или два разных канонических IPv4. Публичный ключ — 32 байта Base64.
Ревизия связывает оба native файла и установку. При конфликте операция не
повторяется автоматически: перечитайте каталог, затем подтвердите новое действие.

Успешное создание возвращает в результате операции только публичные поля,
`profile_available:true` и `profile_expires_at`. Для получения файла выполните
`POST /api/v1/peers/profile` с `{id:"<ID успешной peer.create>"}` и CSRF.
Control проверяет журнал и передаёт `peers.profile.consume` в Adapter. HTTP 200
содержит `.conf` как `application/octet-stream`, `Content-Disposition: attachment`
и `Cache-Control: no-store`. В локальном IPC только этот ответ содержит
`{filename,content_base64}`, которое Web строго проверяет и декодирует.

Профиль доступен для одной выдачи в течение 10 минут, хранится только в памяти
Adapter и удаляется до отправки. Повторная выдача, истечение срока, отзыв клиента
или перезапуск Adapter возвращают 410. Если файл не сохранился, отзовите доступ
и создайте клиента заново. Ключи не передаются через журнал операций или аудит.
