# Модель данных первого выпуска

Источник истины для транспортных Go-моделей. Публичная документация не содержит реквизитов тестового VPS. Внутренние модели каждого компонента уточняются в `web_data_model.md` и `control_data_model.md` до добавления соответствующих Go-структур.

## Unix JSON lines

Один запрос и один ответ на соединение, UTF-8 JSON с завершающим LF, максимум 1 MiB. Неизвестные поля верхнего уровня отклоняются. Все даты — UTC RFC3339. Секреты AWG и WARP не включаются в ответы.

| Модель | Поля |
| --- | --- |
| Request | `request_id: string` (случайный идентификатор); `action: string` (allowlist); `payload: object` (параметры действия, по умолчанию `{}`) |
| Response | `request_id: string` (идентификатор запроса); `ok: bool` (успех); `data: object/array/null` (результат); `error: Error/null` (безопасная ошибка) |
| Error | `code: string` (стабильный код); `message: string` (сообщение без секретов); `status: int` (аналог HTTP status) |
| Policy | `configured: bool` (оператор явно сохранил выбор; false означает unknown); `warp_enabled: bool` (намерение использовать WARP); `allow_direct_without_warp: bool` (разрешение fallback, default false); `revision: string` (SHA-256 сохранённой политики) |
| PolicyUpdate | `warp_enabled: bool`; `allow_direct_without_warp: bool`; `expected_revision: string` (обязательная ревизия) |
| AttachRequest | `container_name: string`; `dns_container_name: string` (может быть пустым); `docker_network: string` (явно выбранная обнаруженная сеть) |
| LogRequest | `source: string` (`awg`, `dns`, `warp`, `supervisor`, `bridge`); `limit: int` (1..200) |
| OperationRequest | `action: string`; `payload: object`; `idempotency_key: string` (16..128 символов `[A-Za-z0-9_.:-]`, повтор с другим содержимым — 409) |
| Operation | `id: string`; `action: string`; `status: string`; `created_at: string`; `updated_at: string`; `result: object/array/null`; `error: Error/null` |

## Снимки

Снимки допускают расширение полей; Go может переносить `data` как `json.RawMessage` без создания дополнительного источника истины. Поля ниже образуют общий контракт UI и host bridge.

- Overview: `observed_at`, `hostname`, `uptime_seconds`, `load_average` (массив), `memory` (`total_bytes`, `available_bytes`), `disk` (`total_bytes`, `free_bytes`), `attached` (bool), `installation` (описание привязки), `awg` (`running: bool`, `message`, необязательный `started_at`), `warp` (`installed: bool`, `service_active: bool`, `connected: bool`, `observed_at`), `policy`, `egress` (`path`: `warp|direct|blocked|unknown`, `verified_at`, `message`), `checks` (массив DiagnosticCheck). Успешный статус WARP-службы сам по себе не подтверждает выход клиентского трафика.
- Installation: `container_name`, `container_id`, `interface`, `config_path`, `dns_container_name`, `docker_network`, `capabilities` (массив строк), `supported` (bool), `reason` (сообщение). Не содержит ключей.
- Discovery: `observed_at`, `candidates` (массив Installation с доступными `networks`), `dependencies` (массив DiagnosticCheck).
- Peer: `public_key`, `name`, `allowed_ips` (массив строк), `endpoint`, `latest_handshake` (Unix seconds; 0 — не наблюдался), `rx_bytes`, `tx_bytes`. Read-only; собственная база пользователей отсутствует.
- DiagnosticCheck: `id`, `status` (`ok|warning|error|unknown`), `message`, `checked_at`. Проверки службы, туннеля, правил, HTTPS и DNS независимы. Неизвестное состояние не означает успешную проверку.
- Diagnostics: `observed_at`, `checks` (массив DiagnosticCheck).
- Logs: `source`, `observed_at`, `lines` (массив очищенных строк), `truncated` (bool); дополнительные поля `available` (bool) и `reason` (безопасная причина недоступности). Для AWG/DNS с Docker driver `none`: `available:false`, непустая `reason`, `lines:[]`, `truncated:false`; это успешный снимок известного ограничения. Прочитанные Docker logs имеют `available:true`. Legacy WARP/supervisor snapshots могут не содержать новые поля; UI считает недоступностью только явное `available:false`. Ошибки Docker, транспорта и привязки остаются Error, а не превращаются в пустой журнал.
- Configuration: `filename`, `revision`, `content` (только маскированный текст), `read_only` (всегда true в первом выпуске).

## Сессии Web

Access secret читается из отдельного файла и не выдаётся API. Сессия имеет случайный токен, CSRF-токен, время окончания. На диске сохраняются только их хеши/HMAC. Сессия живёт не более 12 часов; ротация access secret инвалидирует старые сессии. Истёкшие сессии удаляются. Audit ограничен по числу событий и не содержит request payload с секретами.

## Состояние Control и Host

Control хранит только журнал операций и ключи идемпотентности, без VPN-пользователей или клиентских профилей. Намерение мутации сохраняется до отправки host bridge. При перезапуске незавершённые операции получают явное состояние восстановления, без автоматического повторного запуска AWG restart.

Host хранит привязку к существующей установке, политику, manifest собственных ресурсов и последнюю проверку/результат. Состояние root-only и атомарно записывается. Отсутствующая/повреждённая галочка не разрешает direct. `warp_enabled=false` может возникнуть только из сохранённого явного выбора; отсутствие WARP-службы не меняет этот выбор.
