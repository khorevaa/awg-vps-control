# Модели Docker AWG adapter

Спецификация создана до Go-моделей. Adapter — отдельный режим Control-модуля, без своего журнала операций или копии привязки установки. Он использует [Docker Engine HTTP API v1.45](https://docs.docker.com/reference/api/engine/version/v1.45/) через Unix socket. Привязка остаётся в root-состоянии WARP-сервиса.

| Модель | Поля и назначение |
| --- | --- |
| AdapterConfig | `SocketPath`, `WarpSocket`, `DockerSocket`, `StateDirectory`, `MetricsDirectory`: доверенные абсолютные пути |
| Adapter | `config`, `docker`, `warp`, `mutation`: конфигурация, ограниченные клиенты Docker/WARP и сериализация мутаций |
| AdapterServer | `adapter`, `listener`, `connections`, `workers`: обработчик, Unix listener, лимит соединений, завершение goroutines |
| DockerClient | `socketPath`, `http`: фиксированный Unix socket и HTTP-клиент без proxy/redirect |
| WarpClient | `socketPath`: root-owned Unix socket WARP-сервиса |
| DockerSummary | `ID`, `Names`: минимальные поля списка контейнеров |
| DockerContainer | `ID`, `Name`, `State`, `Config`, `NetworkSettings`: ограниченная проекция inspect |
| DockerContainerState | `Running`, `StartedAt`, `PID`: состояние существующего контейнера |
| DockerContainerConfig | `TTY`: формат Docker logs |
| DockerNetworkSettings | `Networks`: имена подключённых сетей и минимальные привязки |
| DockerNetworkBinding | `NetworkID`, `IPAddress`: подтверждённые Docker значения без env и volumes |
| DockerExecRequest | `AttachStdout`, `AttachStderr`, `TTY`, `Privileged`, `User`, `Cmd`: фиксированный запуск чтения в существующем AWG-контейнере |
| DockerExecStart | `Detach`, `TTY`: запуск с ограниченным выводом |
| DockerIdentifier | `ID`: идентификатор exec, выданный Docker |
| DockerExecStatus | `Running`, `ExitCode`, `ContainerID`: подтверждение завершения и принадлежности exec |
| AdapterInstallation | `ContainerName`, `ContainerID`, `Interface`, `ConfigPath`, `DNSContainerName`, `DNSContainerID`, `DockerNetwork`, `Capabilities`, `Supported`, `Reason`, `Networks`, `BaselineRevision`: безопасная проекция закреплённой установки и кандидатов discovery |
| AdapterIntegration | `Installation`, `Managed`: root-owned привязка и наличие принадлежащей проекту маршрутизации |
| AdapterPeer | `PublicKey`, `Name`, `AllowedIPs`, `Endpoint`, `LatestHandshake`, `RXBytes`, `TXBytes`: read-only native AWG peer |
| NativeClient | `ClientID`, `UserData`: элемент штатного clientsTable |
| NativeClientData | `ClientName`: пользовательское имя штатного клиента |

Все поля моделей имеют русские inline-комментарии. Ответы Docker допускают новые поля, но в публичный результат попадает только перечисленная проекция. JSON IPC отклоняет неизвестные поля и дубликаты ключей.

## Доступ и конфигурация

Режимы `adapter serve`, `adapter healthcheck` и `adapter request '<Request JSON>'`. Последний ограничивает запрос 1 MiB, проверяет peer UID10003, печатает Response JSON, завершает с ненулевым кодом при отказе. UID сервера 10003, primary GID 10002, supplementary Docker GID. Только adapter получает Docker socket; network none, read-only rootfs, cap_drop ALL. Docker socket предоставляет доверенному adapter полномочия Docker daemon: read-only mount не ограничивает методы API.

| Переменная | Значение по умолчанию |
| --- | --- |
| `AWG_ADAPTER_SOCKET` | `/run/awg_vps_adapter/adapter.sock` |
| `AWG_WARP_SOCKET` | `/run/awg_vps_warp/warp.sock` |
| `AWG_DOCKER_SOCKET` | `/var/run/docker.sock` |
| `AWG_ADAPTER_STATE` | `/var/lib/awg_vps_control/adapter` — каталог для statfs и блокировки процесса, без attachment DB |
| `AWG_HOST_METRICS` | `/run/awg_vps_metrics` |

Adapter socket принадлежит UID10003/GID10002, mode0660, каталог mode0750. State directory UID10003/GID10002 mode0700. Root и Control UID10002 могут выполнять allowlist; UID10003 может только health. SO_PEERCRED проверяется на обоих направлениях. Control ожидает adapter UID10003; adapter ожидает root UID0 у WARP и Docker.

## Привилегированные действия

Публичный allowlist: `health`, `overview`, `discover`, `peers`, `configuration`, `diagnostics`, `logs`, `policy.get`, `attach`, `policy.set`, `repair`, `warp.reconnect`, `warp.setup`, `awg.restart`. Parameters совпадают с `data_model.md`; произвольные `exec`, URL, file path или Docker method отсутствуют.

WARP IPC: `integration.get` → `{installation:null|AdapterInstallation,managed:bool}`; `integration.attach` принимает исходный AttachRequest и повторно проверяет/pins Docker topology на root-границе. `warp.overview` возвращает `{warp,policy,egress,checks}`. Остальные передаваемые действия — `health`, `diagnostics`, `policy.get`, `policy.set`, `repair`, `warp.reconnect`, `warp.setup`, `logs` только WARP/supervisor; публичный source bridge отображается на supervisor. Root WARP не предоставляет AWG restart.

Manual restart адресует только pinned 64-hex container ID. До изменения повторно проверяется identity. При managed integration adapter вызывает WARP `repair` после restart. Неопределённый результат restart/repair возвращает `mutation_failed`; Control сохраняет manual recovery. Автоматических AWG restart нет.

## Docker и ограничения

Фиксированные endpoints: `_ping`, список работающих контейнеров (до 32), inspect выбранных контейнеров, exec create/start/inspect только для фиксированных AWG reads, logs выбранного pinned AWG/DNS, restart pinned AWG. Docker API paths строятся только из проверенных container/exec IDs и известных литералов; HTTP redirects/proxies запрещены.

Exec не использует shell: `timeout -s KILL 8` ограничивает жизнь фиксированных `awg show ...`, `test -f` и `cat -- /opt/amnezia/awg/...` команд. Docker socket cancellation сам по себе не завершает exec, поэтому обязательна утилита timeout в поддерживаемом Amnezia-контейнере. Stdout/stderr Docker multiplex проверяется и ограничивается; сырой stderr не возвращается. Inspect/list ограничены 2 MiB, exec 1 MiB, logs 512 KiB, IPC 1 MiB. HTTP dial — 2 секунды, обычное чтение — до 30 секунд, restart — до 45 секунд; общий запрос имеет deadline. Health проверяет Docker `_ping` и WARP health за 2 секунды, возвращает только status.

Метрики читаются только из смонтированных `hostname`, `uptime`, `loadavg`, `meminfo`, по 64 KiB максимум; disk — statfs раздела adapter state. Отсутствующие метрики дают явные diagnostics и null, а не данные контейнера. PrivateKey/PSK и секретные присваивания маскируются перед выдачей; имена и clientId берутся из native clientsTable, собственной базы пользователей нет.
