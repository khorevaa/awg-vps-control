# Аварийная защита SSH при изменениях WARP

Спецификация создана до моделей `warp_safety.go`. Root CLI работает независимо от Unix API и `host.lock`; аварийный таймер не принадлежит cgroup основного runtime. Протокол не меняет сохранённую политику выхода и разрешение direct fallback.

## Интерфейсы и команды

`WarpRuntime.safetyCLI(ctx, configPath, args) error` принимает `arm [--seconds N]`, `resume [--seconds N]`, `confirm ID`, `status`, `check`, `hold`, `expire ID`. Внешняя команда: `awg_control warp safety --config /etc/awg_vps_control/host.json ...`. Интервал по умолчанию 300 секунд, допустимо 60–600. Все команды требуют UID 0. `check` не меняет файлы, не требует SSH и возвращает успех только для действующего armed с живым timer либо confirmed.

`safetyStatus() (WarpSafetyState, *APIError)` выдаёт очищенный снимок без исходного SSH tuple и сетевого manifest. `safetyHeld() bool` возвращает true при marker, повреждении записи, истёкшем/перенесённом между boot armed либо пропавшем timer; отсутствие state без marker возвращает false, сохраняя работу AWG без WARP. `requireSafety(ctx, armedOnly) bool` разрешает только подтверждённое состояние; ошибки фиксируются в `WarpSession.Err`.

`safetyBoot(ctx) error` вызывается до `host.lock` в раннем `warp guard` и при запуске `serve`. Незавершённый armed другого boot или без живого таймера превращается в durable hold. Применяется только отдельная блокировка клиента; boot hook не останавливает/запускает systemd units и не создаёт циклических Requires. Transient timer не переживает reboot: один JSON-файл не является разрешением продолжать изменение WARP.

`WarpSession.clearSafetyGuard(ctx) bool` вызывается после успешного штатного `guard(blocked)` и до разрешения клиентского выхода. Если нет marker владения и отдельной safety table, возвращает true без требования lease: обычный direct-режим не требует arm. Для существующей safety table нужны действующий armed/confirmed, совпадающий snapshot, свежий canonical `guard_state=blocked` и существующая canonical table. Удаляется только собственная safety table с проверенным comment и root ownership metadata.

## Модель данных

Все файлы находятся в root-owned state directory `0700`, обычные файлы `0600`, без symlinks/hardlinks; чтение ограничено 1 MiB, JSON строгий. Записи выполняются атомарно с fsync файла и каталога.

| Модель | Поля и смысл |
| --- | --- |
| `WarpSafetyState` | `schema_version=1`, `id` (32 hex), `status` (`armed`, `confirmed`, `held`; пустой status только для отсутствующей записи), `armed_at`, `armed_uptime_ticks` (граница создания SSH в kernel clock ticks), `deadline`, `confirmed_at`, `boot_id`, `rescue_complete` (разрешает resume только после подтверждённых stop/block), приватный `original_ssh_connection`, приватный `snapshot: WarpManifest`; `timer_active` — наблюдаемое поле, никогда не используется как сохранённое разрешение |
| `WarpSafetyStep` | `step`, `succeeded`, `code`: фиксированное имя шага, результат и безопасный код без argv/stdout/адресов |
| `WarpSafetyResult` | `schema_version`, `id`, `started_at`, `finished_at`, `steps`: независимый журнал аварийных попыток в `safety_result.json` |
| `WarpSafetyGuard` | `schema_version`, `table`, `comment`: marker владения отдельной nft table в `safety_guard.json` |
| `WarpSafetyMutation` | `schema_version=1`, `id`, `boot_id`, `last_mutation_ticks`, `pending`: приватная атомарная граница последней опасной операции в `safety_mutation.json`; pending=true сохраняется до завершения всей операции, включая поздние маршруты и guard; root confirm отклоняет pending и сравнивает границу с возрастом SSH под `host.lock` |
| `WarpSafetySSH` | `Client`, `Server`: нормализованные `netip.AddrPort`, извлечённые из четырёх полей `SSH_CONNECTION`; `StartedTicks` — kernel starttime именно socket-owning sshd ancestor; только внутренняя модель |

`safety_state.json` содержит приватный tuple и проверенный snapshot. `emergency_hold` — отдельный durable marker с фиксированным содержимым; любое его наличие или ошибка проверки имеет приоритет над JSON и таймером. Повреждённый JSON не снимает hold. `safety.lock` сериализует короткие root CLI переходы состояния; `safety_rescue.lock` не допускает записи новой эпохи одновременно с незавершённым rescue. Основной runtime, его boot hook, чтения и снятие safety table никогда не держат эти locks. Остановка служб никогда не выполняется под `safety.lock`. Если root CLI writer не отдаёт safety lock, expiry независимо сохраняет marker и выполняет rescue; held JSON завершается после остановки runtime.

## Arm, confirm и resume

Arm требует живой SSH-сеанс: корректный tuple, established TCP-соединение с такими адресами/портами в `/proc/net/tcp{,6}` и соответствующий socket inode именно у SSH-предка `sshd`/`sshd-session`. Его kernel starttime берётся из `/proc/PID/stat`; частота clock ticks определяется bounded `getconf CLK_TCK`, граница arm/команды — из `/proc/uptime`. Root может подменять окружение и `/proc`-контекст; это защита от ошибочного подтверждения, а не граница против root.

После snapshot под `host.lock` создаётся новый ID и сохраняется armed intent. Host lock сохраняется до окончания arm, а короткие safety locks освобождаются до любых внешних команд. Отдельный root drop-in `/etc/systemd/system/warp-svc.service.d/awg_vps_safety.conf` содержит `ConditionPathExists=!<stateDir>/emergency_hold` и `ExecCondition=/opt/awg_vps_control/current/bin/awg_control warp safety --config <config> check`. Чужое содержимое не перезаписывается; штатный guard drop-in не меняется. После bounded daemon-reload создаётся transient unit `awg_vps_warp_rescue_<id>` через `systemd-run --on-active Ns --timer-property AccuracySec=1s --collect`. ExecStart содержит реальный абсолютный путь текущего executable, фиксированный режим `warp safety`, явный config и `expire ID`; `/current` не сохраняется как изменяемая ссылка. До возврата проверяется активность timer. Ошибка вооружения переводит состояние в hold. Откат на старый runtime без `safety check` запрещает запуск WARP через ExecCondition; для возобновления требуется совместимый runtime.

Повторный arm при armed отклоняется. Resume допускается только из hold с `rescue_complete=true`, без `rescue_pending` и после освобождения recovery lock: новый timer должен быть активен до снятия marker. `rescue_pending` — root0600 marker с ID, фиксируемый до освобождения safety lock в expire. Он предотвращает захват новой эпохи в промежутке между записью hold и получением recovery lock. Снимается только marker завершённой эпохи после подтверждённых остановок и final block. После отказа критического шага нужна повторная явная `hold`, а не обход через resume. Отдельная safety table остаётся заблокированной до успешного штатного guard; pre-managed snapshot не создаёт canonical routing manifest.

Confirm получает `host.lock`, дожидается завершения сетевых операций и требует ID, будущий deadline, тот же boot, отсутствующий marker, активный timer и другой настоящий SSH tuple. Starttime именно socket-owning `sshd`/`sshd-session` должен быть строго больше `armed_uptime_ticks` и `last_mutation_ticks`. Runtime атомарно обновляет границу до разрешённого armed gate; `safetyMutationFinished(ctx)` обязательно вызывается после каждой опасной команды, включая её ошибку, пока удерживается `host.lock`. Эти записи сохраняют `pending=true`. Только `safetyOperationFinished(ctx)` в конце полной операции, после маршрутов и guard, ставит `pending=false` и обновляет ticks; право завершить marker отмечено `WarpSession.SafetyPending`. После crash/SIGKILL незавершённый marker запрещает confirm, даже когда host flock уже освобождён. Поэтому SSH, открытый до arm или до конца всей операции, не подходит. `check` проверяет lease без записи этой границы. Сначала атомарно сохраняется confirmed, потом останавливается timer: запоздавший expire подтверждённого ID становится no-op. Confirm из исходного SSH-сеанса отклоняется. Подключение через SSH multiplex с тем же TCP tuple не является новой проверкой. Удалённый агент, потерявший SSH ancestry или окружение, должен использовать отдельный обычный SSH-сеанс.

Если сохранённая политика имеет `configured=true` и `warp_enabled=true`, confirm дополнительно требует активную службу WARP, текущий статус `Connected` и сохранённый `egress.path=warp`. Метка `verified_at` должна быть не раньше `armed_at`, не в будущем и не старше 120 секунд. Проверяются только policy/status/egress под `host.lock`, без probes и изменений; внешние status-команды выполняются до получения короткого safety lock. Успешный ответ `connect` без фактически завершённого supervisor перехода не позволяет остановить таймер. При выключенном WARP либо первой pre-managed эпохе без политики эта дополнительная проверка не нужна; повреждённые сохранённые данные запрещают confirm.

## Истечение срока и аварийное удержание

При expire устаревший ID или confirmed без hold — no-op. Текущий armed/held ID переводится в hold независимо от wall clock: относительный systemd timer может сработать после перевода часов назад, а явный root expire имеет те же полномочия, что hold. Первым сохраняется `emergency_hold`, затем held JSON; только после этого начинаются внешние действия. Состояние повторно сверяется после получения rescue lock, чтобы старый expire не затронул новый ID.

Отдельные bounded попытки:

1. `systemctl stop --no-block awg_vps_warp.service`, ожидание остановки; при зависании `systemctl kill --kill-whom=all --signal=KILL` только этой unit и повторная проверка cgroup.
2. Применение `inet awg_vps_safety` из валидного snapshot, без `host.lock` и canonical state writes.
3. Ограниченный `warp-cli --accept-tos disconnect`.
4. Аналогичная остановка только `warp-svc.service` и повторная блокировка safety table.

Ошибка шага не отменяет остальные. Отсутствующий `warp-cli` фиксируется как успешный пропуск `not_installed`; отсутствующая warp-svc считается остановленной. Результаты содержат только фиксированные коды. Docker, AWG и `awg_vps_guard.service` не останавливаются; чужие маршруты/цепочки не очищаются. После подтверждённой остановки старого runtime, остановки warp-svc и повторного blocked guard recovery lock освобождается, затем запрашивается запуск основного runtime в held-режиме для диагностики. Успех запроса start отдельно фиксируется; он не утверждает готовность Unix API. Политика/галочка сохраняются.

Safety table имеет фиксированный comment и отдельный root marker владения. Неизвестная таблица с таким именем не заменяется. Она блокирует клиентский veth и выделенные Docker bridges, сохраняя только транспорт AWG и внутренний DNS/клиентский путь по проверенному snapshot. Правила не меняют host default route или SSH INPUT с физического интерфейса.

## Проверки и ограничения

Кроме отдельных команд runtime фиксирует границу после всей изменяющей операции API или supervisor, до освобождения `host.lock`. Это включает настройку маршрутов и guard после `warp-cli connect`: SSH, открытый до завершения этих шагов, не подтверждает итоговую доступность.

Этот модуль требует интеграции gate в runtime до любого включения/переподключения WARP и перед снятием блокировки. Блокировка после сохранения hold должна проверяться заново внутри последовательностей мутаций, чтобы уже начатый запрос не открыл путь после expiry. Snapshot не разрешает изменять произвольную новую Docker-топологию.

При отсутствии и safety snapshot, и canonical routing manifest команда hold всё равно пытается остановить WARP, но не может подтвердить клиентскую блокировку. Resume остаётся запрещённым; требуется восстановить проверенный snapshot вручную. Для свежей установки сначала выполняется arm с preflight, который сохраняет snapshot до опасных действий.

Локальные `gofmt`, Linux `go vet` и build проверяют код, но не подтверждают systemd/nft/SSH поведение. Обязательна отдельная контролируемая серверная приёмка: новый SSH-сеанс, истечение timer, зависший runtime, отказ отдельного шага, reboot до confirm, stale ID, конкурентный resume, сохранность SSH и отсутствие клиентского direct при hold. До этой приёмки включение WARP не считается безопасным.
