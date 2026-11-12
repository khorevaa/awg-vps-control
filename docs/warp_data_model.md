# Модель WARP runtime

Runtime реализован стандартной библиотекой Go в модуле `ui/control`. Режим `warp serve` объединяет Unix JSON-lines API и supervisor; `warp guard` выполняет раннюю блокировку перед Docker/WARP. Других исполнителей реализации (Python/Bash) нет.

Независимое аварийное отключение описано в [модели безопасности WARP](warp_safety.md). `warp safety` обслуживает локальные root-команды отдельно от Unix API и `host.lock`. Незавершённая попытка после загрузки переводится в hold до обычного guard. Пока hold действует, API допускает чтение, supervisor поддерживает блокировку, а запуск/подключение WARP и открытие прямого выхода запрещены. Политика пользователя остаётся прежней. Первое включение WARP, setup и ручной reconnect требуют вооружённого таймера; автоматическое восстановление допускается после подтверждения новой SSH-сессией. Диагностика `routing.safety` сообщает о состоянии защиты без публикации адресов SSH или приватного snapshot.

## Внутренние модели

| Модель | Поля и назначение |
|---|---|
| `WarpConfig` | `schema_version=1`, `state_dir`, устаревший `control_uid` (не даёт доступа), `adapter_uid=10003`, `socket_gid=10002`, `supervisor_interval_seconds`, `probe_interval_seconds`. |
| `WarpRuntime` | Проверенная конфигурация процесса и абсолютный путь текущего Go executable для DNS-пробы в namespace. |
| `WarpSession` | Runtime, первый безопасный APIError, признак начавшейся мутации, `SafetyPending` (текущая сессия записала незавершённую safety operation и вправе завершить только её), проверенный manifest, PID AWG/DNS namespace. Ошибка останавливает последующие команды и записи текущей операции. |
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

Перед `warp-cli mode`/`connect` runtime проверяет исключение адреса SSH-клиента из последнего safety-окна. Поддержанный ответ `warp-cli --json tunnel ip list`: объект `mode="exclude"`, `routes` — массив объектов со строкой `value` в формате CIDR. Ответ ограничен по размеру и количеству маршрутов. При отсутствии покрытия добавляется только один адрес через штатную `tunnel ip add`, затем перечитывается список. Чужие исключения не удаляются; include-режим и неизвестная схема не перезаписываются. Адрес не выводится в API/лог. Это дополнение к независимому rescue и проверке нового SSH, а не доказательство совместимости firewall WARP или доступа с других адресов.

Недоступность daemon/регистрации при автоматическом recovery — мягкий отказ: `protectAdmin=false` без `WarpSession.Err` означает только неготовность службы, а `false` с ошибкой означает отказ safety или проверки SSH-исключений. `attemptRecovery` пропускает последующие mode/connect, сохраняет cooldown и выбирает direct/blocked по явной политике. Строгий исполнитель команд переводит мягкую неготовность в `warp_not_ready`. Ошибки safety, владения ресурсами, схемы исключений и приватного state никогда не очищаются. После неуспешного запуска/подключения daemon текущий проход не использует старую WARP probe для объявления healthy.

При выключенном WARP дополнительно проверяется явный `Disconnected` либо остановленное/отсутствующее состояние службы. `Connecting` и неизвестный ответ не считаются отключением. Если bounded disconnect не подтверждён, выбранные direct правила сохраняются, но результат содержит `complete=false`, диагностическую проверку `warp.disconnect=warning` и предупреждение в журнале/egress message. Этот случай не устанавливает `WarpSession.Err`, иначе внешний обработчик обоснованно применил бы emergency block и отменил direct. Отказ проверки клиентского HTTPS/DNS сохраняет прежнюю строгую обработку.

State directory по умолчанию `/var/lib/awg_vps_control/host`; имена файлов и сетевых ресурсов сохраняются. Поддержаны выделенные IPv4 Docker bridge-сети и AWG с одним IPv4; link-local IPv6 допускается, клиентский IPv6 блокируется собственными namespace/host цепочками. Маршрутизируемый IPv6, пересечения подсетей и конфликт владения блокируют запись.

Решение о direct принимается только по сохранённой явной политике: WARP выключен либо разрешён fallback. При здоровом WARP весь клиентский/DNS трафик возвращается в WARP со сбросом только owned conntrack. Неизвестное/повреждённое состояние не даёт разрешения direct. Сам guard не зависит от Docker или чтения действующей политики для блокировки.
