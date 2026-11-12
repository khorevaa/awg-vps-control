# Модель WARP runtime

Runtime реализован стандартной библиотекой Go в модуле `ui/control`. Режим `warp serve` объединяет Unix JSON-lines API и supervisor; `warp guard` выполняет раннюю блокировку перед Docker/WARP. Других исполнителей реализации (Python/Bash) нет.

## Внутренние модели

| Модель | Поля и назначение |
|---|---|
| `WarpConfig` | `schema_version=1`, `state_dir`, устаревший `control_uid` (не даёт доступа), `adapter_uid=10003`, `socket_gid=10002`, `supervisor_interval_seconds`, `probe_interval_seconds`. |
| `WarpRuntime` | Проверенная конфигурация процесса и абсолютный путь текущего Go executable для DNS-пробы в namespace. |
| `WarpSession` | Runtime, первый безопасный APIError, признак начавшейся мутации, проверенный manifest, PID AWG/DNS namespace. Ошибка останавливает последующие команды и записи текущей операции. |
| `WarpPolicy` | `configured`, `warp_enabled`, `allow_direct_without_warp`, вычисляемая SHA-256 `revision`. В файле политики сохраняются только три обязательных boolean; ревизия канонического JSON совместима с прежним runtime. |
| `WarpInstallation` | Имена и закреплённые Docker ID AWG/DNS, AWG interface, native config path, выбранная Docker network, список сетей, capabilities, supported/reason, baseline revision. Секреты конфигурации не сохраняются. |
| `WarpManifest` | schema version, закреплённые контейнеры, interface, client subnet/probe IP/listen port, Docker IP/bridges/networks, DNS IP/bridge/ID, физический interface/gateway, собственные veth и routing table. |
| `WarpNetwork` | Имя Docker network, IPv4 subnet, имя Linux bridge. |
| `WarpCheck` | `id`, `status`, безопасное `message`, `checked_at`. |
| `WarpEgress` | `path` (`unknown/blocked/direct/warp`), nullable `verified_at`, `message`, `observed_at`. |
| `WarpStatus` | `installed`, `service_active`, `connected`, `observed_at`. Connected не означает успешную передачу данных. |
| `WarpBoundedOutput` | Общий mutex и ограничение stdout/stderr, буфер stdout, счётчик, признак превышения; отмена процесса при превышении. |
| `WarpOutputWriter` | Ссылка на общий ограниченный вывод, флаг сохранения потока. |

Другие совместимые записи состояния представлены map/массивами JSON: recovery cooldown, fingerprint, namespace PID и правила, observed rule manifest, guard state, baseline, bounded events, diagnostics/probe timestamps. Все файлы root-only, атомарные и ограничены 1 MiB. Полный baseline содержит только правила/маршруты/forwarding, а не ключи AWG/WARP.

## Протокол и границы

Используются общие `Request`, `Response`, `APIError`, `AttachRequest`, `PolicyUpdate`, `LogRequest`. Сокет `/run/awg_vps_warp/warp.sock` принадлежит root:10002, mode 0660; `SO_PEERCRED` допускает UID 0/10003. `control_uid` из старого host.json игнорируется.

Разрешены `health`, `integration.get`, `integration.attach`, `warp.overview`, `diagnostics`, `policy.get`, `policy.set`, `repair`, `warp.reconnect`, `warp.setup`, `logs`. `integration.get` возвращает `{installation: object|null, managed: boolean}`; `integration.attach` повторно проверяет выбранные ресурсы и возвращает `{installation, policy}`. `warp.overview` возвращает `{warp, policy, egress, checks}`. Logs допускает только `warp/supervisor`.

До сетевых изменений сохраняется ownership manifest и baseline. Ошибка после начала мутации возвращается как `mutation_failed`, требуя проверки фактического состояния. Автоматическое восстановление не перезапускает AWG, не устанавливает и не обновляет AWG/Docker. WARP setup — отдельная явная операция. Изменение политики никогда не включается как последствие ошибки.

## Совместимость и ограничения

State directory по умолчанию `/var/lib/awg_vps_control/host`; имена файлов и сетевых ресурсов сохраняются. Поддержаны выделенные IPv4 Docker bridge-сети и AWG с одним IPv4; link-local IPv6 допускается, клиентский IPv6 блокируется собственными namespace/host цепочками. Маршрутизируемый IPv6, пересечения подсетей и конфликт владения блокируют запись.

Решение о direct принимается только по сохранённой явной политике: WARP выключен либо разрешён fallback. При здоровом WARP весь клиентский/DNS трафик возвращается в WARP со сбросом только owned conntrack. Неизвестное/повреждённое состояние не даёт разрешения direct. Сам guard не зависит от Docker или чтения действующей политики для блокировки.
