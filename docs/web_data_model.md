# Внутренние модели Web

Основание: `data_model.md`, `api.md`; описано до создания Go-структур.

| Модель | Поля и назначение |
| --- | --- |
| config | WebSocket, ControlSocket, SecretFile, StateFile — абсолютные пути; AllowedHost/AllowedOrigin — единственный origin SSH-туннеля; SessionTTL — максимум 12 часов |
| apiError | Code, Message, Status — безопасная ошибка HTTP/Control; без сырых команд и секретов |
| controlRequest | RequestID, Action, Payload — JSON-lines запрос из `data_model.md` |
| controlResponse | RequestID, OK, Data (`json.RawMessage`), Error — ответ, ID и структура проверяются |
| controlClient | Socket — Unix socket; Timeout — ограничение чтения и записи; реализует IControlClient |
| accessRequest | Secret — секрет только входящего запроса; не сохраняется и не логируется |
| authResponse | CSRFToken, ExpiresAt — ответ входа/проверки сессии; expires_at в UTC RFC3339 |
| sessionRecord | TokenHash, CSRFHash — SHA-256 токена и CSRF; CreatedAt, ExpiresAt — UTC; сырые токены не сохраняются |
| auditRecord | OccurredAt, Action, Success — ограниченный журнал безопасных имён действий; без payload |
| persistedState | Version, Sessions, Audit — единственный Web JSON state; до 64 сессий, до 1000 событий |
| sessionStore | Mutex, Path, SecretFile, SecretHash, BootKey, TTL, State, Attempts, AttemptWindow — синхронизация, пути, проверка ротации и ограничение частоты входов |
| application | Config, Store, Control — зависимости HTTP-приложения, явная сборка в main |
| operationRequest | Action, Payload, IdempotencyKey — HTTP контракт OperationRequest; ключ `[A-Za-z0-9_.:-]{16,128}`, строгая проверка разрешённых операций |
| policyUpdate | WarpEnabled, AllowDirectWithoutWarp (указатели для обнаружения отсутствующих bool), ExpectedRevision — `policy.set` |
| attachRequest | ContainerName, DNSContainerName, DockerNetwork — только имена, без произвольных путей/команд |
| logRequest | Source, Limit — allowlist источников и предел 1..200 |
| operationLookup | ID — 32 строчных hex-символа идентификатора операции |

Снимки и операции передаются как RawMessage согласно публичной модели. Web не создаёт собственных VPN peers, профилей или секретов WARP. IControlClient принимает context, action и JSON payload, возвращает data либо безопасную apiError.

Frontend обрабатывает дополнительное `Logs.available:false` как известное ограничение источника: выводит `reason` внутри журнала и помечает снимок недоступным, без общей ошибки страницы. Отсутствие строк при доступном источнике сохраняет отдельное сообщение «нет строк». Отсутствующее `available` поддерживает legacy WARP/supervisor; HTTP ошибки по-прежнему показываются как ошибки.

Frontend читает `Overview.awg` как `{running: bool, message: string, started_at?: string}`: `running=true` означает «Работает», `false` — «Работа не подтверждена» (inspection мог завершиться ошибкой). `Overview.warp` имеет `{installed: bool, service_active: bool, connected: bool, observed_at: string}`: `installed=false` — «Не установлен»; `installed=true` и `connected=true/false` — «Подключён»/«Отключён». Отсутствующий либо неверно типизированный статус показывает «Неизвестно»; работа службы и туннеля дополнительно выводится отдельными диагностическими проверками. Единого поля `status` у этих снимков нет.

Идентификаторы диагностик переводятся в русские названия: `awg.container`, `awg.interface`, `warp.service`, `warp.tunnel`, `routing.capability`, `routing.managed`, `routing.guard`, `egress.https`, `egress.dns`, `dependency.<binary>`. Неизвестный идентификатор остаётся видимым для диагностики.

Кнопка установки WARP изначально недоступна и разблокируется только после успешного чтения `policy.configured=true`. При загрузке, ошибке, неизвестном configured или выходе она заблокирована; счётчик запроса frontend `policyLoadID` не позволяет устаревшему ответу отменить более новое состояние. Для первой установки подпись объясняет последовательность: явно сохранить режим без WARP, установить WARP, затем включить его в политике.

При каждом запросе к сессии/входу проверяется защищённый файл access secret; его изменение очищает все сессии. Отсутствующий/небезопасный файл закрывает доступ. При каждом старте процесса ранее сохранённые сессии удаляются. Новые токены генерируются `crypto/rand`, CSRF выводится через HMAC с ключом процесса; на диске только их SHA-256. TTL фиксирован 12 часами, logout удаляет сессию до подтверждения. Сессии ограничены и очищаются при истечении TTL.

Файл state находится в собственном каталоге Web (0700), имеет 0600 и проверяемого владельца. Чтение не следует symlink, отклоняет hardlink и ограничено 2 MiB; проверяются владельцы и запрет чужой записи всех каталогов-предков (допускается root-owned sticky-каталог). Замена выполняется временным файлом в том же каталоге с fsync, rename и fsync каталога. При ошибке сохранения state изменение доступа не подтверждается. Каталог не разделяется с привилегированным runtime AWG.

Access secret: 43..256 символов base64url/hex, файл mode 0400 либо 0600, владелец root или Web UID; read-only bind mount установщика может задавать Web UID. API не выдаёт secret. Web socket mode 0600 в каталоге 0700, владелец Web UID. Production поддерживает только Linux Unix sockets. HTTP cookie Secure/HttpOnly/SameSite Strict с префиксом __Host-; браузер использует выделенный localhost origin через SSH.

Все API и assets имеют no-store. Web пишет в аудит только фиксированный тип действия и результат принятия запроса; окончательный результат сетевой операции хранит Control. Недоступный audit/state блокирует отправку мутации в Control.

Команда `healthcheck` проверяет собственный HTTP socket, затем Control `health` строгим JSON-lines клиентом от Web UID 10001; Control подтверждает также доступность Host. Ответ зависимости должен быть ровно `{"status":"ok"}`. На каждый обмен отводится до 3 секунд; секрет и HTTP-сессия не нужны. Публичный `/api/v1/health` остаётся минимальной проверкой процесса Web и не раскрывает состояние VPS.
