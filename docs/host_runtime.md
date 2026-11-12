# WARP runtime

`awg_control warp` — root-only служба Linux на стандартной библиотеке Go. Тот же бинарник устанавливается в `/opt/awg_vps_control/current/bin/awg_control`; конфигурация — `/etc/awg_vps_control/host.json` (root:root, 0600), состояние — `/var/lib/awg_vps_control/host` (root:root, 0700). Имена существующих JSON-файлов и сетевых ресурсов сохранены. Python/Bash fallback отсутствует. Модели определены в [warp_data_model.md](warp_data_model.md).

Конфигурация установщика (не содержит адресов или ключей VPS):

```json
{
  "schema_version": 1,
  "state_dir": "/var/lib/awg_vps_control/host",
  "control_uid": 10002,
  "adapter_uid": 10003,
  "socket_gid": 10002,
  "supervisor_interval_seconds": 15,
  "probe_interval_seconds": 60
}
```

Неизвестные поля отклоняются. `control_uid` сохраняется для совместимости и игнорируется при авторизации; `adapter_uid` по умолчанию 10003 и не может принимать другое значение. `socket_gid` фиксирован 10002. ENV `AWG_WARP_CONFIG` и `AWG_WARP_SOCKET` задают пути; флаги `--config`/`--socket` после режима имеют приоритет. Имена контейнера, сети, адреса, политики и manifest принадлежат root-only состоянию после `integration.attach`, а не установщику. `integration.attach` не меняет VPN и не активирует сетевой backend. До явного `policy.set` возвращается `configured:false`, а оба boolean — false без применения маршрутов. Оператор явно сохраняет `warp_enabled=false`, если желает существующий прямой выход. `revision` вычисляется по сохранённой политике.

Команды:

```text
/opt/awg_vps_control/current/bin/awg_control warp check-config
/opt/awg_vps_control/current/bin/awg_control warp serve
/opt/awg_vps_control/current/bin/awg_control warp guard
/opt/awg_vps_control/current/bin/awg_control warp request '{"request_id":"local_check","action":"health","payload":{}}'
```

По умолчанию сокет `/run/awg_vps_warp/warp.sock` имеет root:10002 и 0660, родительский каталог — root:10002 и 0750. Runtime принимает только UID 0 и 10003 через `SO_PEERCRED`; Control UID10002 не получает прямой доступ. Один JSON request/response на соединение; протокол описан в `api.md`. Общая блокировка — `<state_dir>/host.lock`. `health` проверяет живой API до блокировки и отвечает во время длительного setup.

Режим `serve` объединяет API и supervisor в одном процессе и одной systemd-службе; `guard` выполняется отдельным ранним oneshot. Остальная панель, Control и Docker-адаптер работают в Docker. Ранний guard использует только сохранённый root manifest и host nft/route rules: он не вызывает Docker inspect/nsenter и не зависит от Docker/WARP. Supervisor никогда не перезапускает AWG.

Root API разрешает только `health`, `integration.get`, `integration.attach`, `warp.overview`, `diagnostics`, `policy.get`, `policy.set`, `repair`, `warp.reconnect`, `warp.setup`, `logs`. `integration.get` возвращает `{installation: object|null, managed: boolean}`; attach принимает исходные имена ресурсов и самостоятельно закрепляет Docker IDs. Discovery/peers/native конфигурация/AWG logs/manual restart принадлежат Docker-адаптеру. Logs root API допускает только `warp` и `supervisor`. Полные Docker inspect/config/dump не передаются в Web.

`check-config` дополнительно проверяет совместимость существующего manifest, полной явной политики и закреплённой installation без Docker/network команд и без изменения этих файлов. Это preflight миграции до остановки прежних служб. Команды чтения внутри AWG выполняются через фиксированный container-side `timeout -s KILL 8`: остановка host Docker CLI сама по себе не прекращает Docker exec-процесс.

`request` обращается к работающему сокету и проверяет UID root сервера. Лимиты: JSON-lines 1 MiB, payload 4 KiB, 16 одновременно принятых соединений; чтение 30 секунд, мутация 90, WARP setup 180. Команды запускаются через argv без shell, с ограничением суммарного stdout/stderr и уничтожением process group по отмене/дедлайну. После ошибки операции остаётся короткий отдельный бюджет на blocked guard. Root state записывается атомарно с fsync и проверкой владельца/0600/обычного файла без symlink.
При **явной сетевой интеграции**, до первого изменения firewall, runtime создаёт fixed drop-ins `/etc/systemd/system/docker.service.d/awg_vps_guard.conf` и `/etc/systemd/system/warp-svc.service.d/awg_vps_guard.conf`: `Requires=awg_vps_guard.service` и `After=awg_vps_guard.service`. Затем выполняется только daemon-reload; Docker/AWG не перезапускаются. Установка UI этих drop-ins не создаёт. Чужой существующий файл не перезаписывается. Успешный guard — обязательное условие загрузки Docker/WARP: при его сбое они не запускаются, SSH остаётся доступным. Unit guard не должен зависеть от Docker/WARP, иначе возникнет цикл. При удалении UI активные зависимости и host runtime должны сохраняться до отдельного безопасного снятия интеграции.

Guard unit использует `Type=oneshot`, `RemainAfterExit=yes`; установщик запускает его (`enable --now`) ещё до интеграции. Без manifest это no-op. При настройке runtime проверяет, что guard уже active: иначе запуск warp-svc через APT зависел бы от guard, ожидающего занятую общей операцией блокировку. После ручной остановки guard его нужно снова запустить отдельно; preflight отклонит интеграцию до изменений.

No-op допустим только для новой установки без manifest и markers прежней интеграции. Повреждённый manifest или его исчезновение при наличии baseline/guard/integration markers завершает ранний guard с ошибкой; зависимости systemd не позволяют запустить Docker/WARP. Непроверенные поля manifest не используются для построения firewall. При существующем допустимом manifest отсутствующая, неполная либо `configured:false` политика закрывает клиентский выход через blocked guard; отсутствующие JSON-поля не дополняются разрешающими defaults.

Настройка WARP вызывается только `warp.setup`, после явного выбора политики. Используются [официальный APT-репозиторий](https://pkg.cloudflareclient.com/) и [официальные команды регистрации](https://developers.cloudflare.com/warp-client/get-started/linux/), проверенные 12 ноября 2026 года. Сначала создаются защитные правила и прямой административный маршрут: APT postinst может самостоятельно запустить демон. Существующая регистрация не удаляется и не заменяется. Даже при отсутствии пакета наличие `/var/lib/cloudflare-warp` запрещает автоматическую новую регистрацию после неудачного `registration show`. Установка пакета и включение WARP-политики — отдельные шаги; установка не включает fallback. Несовпадающие существующие APT source/key требуют ручного согласования. Публичные key/source принудительно получают 0644, в том числе при повторе после прежнего UMask0077; приватное состояние регистрации не меняет права.

Сетевой backend ограничен проверенной IPv4 Docker bridge-топологией. До записи он проверяет права, принадлежность контейнеров/сетей, адреса, конфликтующие таблицы и сторонние supervisor. Неподдерживаемая топология доступна для наблюдения и возвращает явную ошибку capability для изменения маршрутов. Приватные ключи, PSK, shell hooks и сырой вывод команд не возвращаются в Web.

## Сетевой backend

Для интеграции требуются установленные `ip`, `iptables` с backend `nf_tables`, `iptables-restore`, `ip6tables`, `ip6tables-restore`, `nft`, `nsenter`, `conntrack`, `curl`, `sysctl` и systemd. Python не требуется. Установщик UI их не ставит. Отсутствующий `conntrack` владелец устанавливает явно командой `apt-get install conntrack` перед настройкой WARP. Для APT setup также нужны `gpg` и `curl`.

Поддерживаются один IPv4 AWG-интерфейс, максимум две Docker bridge-сети AWG, один выбранный DNS-контейнер в основной сети и единственный прямой default route. Автоматический IPv6 link-local на AWG допускается; при интеграции собственные namespace-цепочки блокируют клиентский IPv6 через AWG, не удаляя адрес. Общие сети с посторонними контейнерами, маршрутизируемый IPv6 на AWG/IPv6 Docker-сеть, изменение container ID, занятые таблицы/приоритеты и старый активный supervisor блокируют сетевые записи. Без DNS-контейнера проверка DNS имеет статус unknown; клиенты могут использовать собственный внешний DNS через VPN.

Собственные ресурсы:

- veth `avps_host` ↔ `avps_peer` между хостом и существующим namespace AWG, link-local `169.254.217.0/30`;
- host tables 43001/43002, namespace table 43003; host rule priorities 40–46 и namespace 42–43;
- nftables `inet awg_vps_guard`, forward/input hook priority -10, независимый от порядка Docker iptables-цепочек;
- iptables-цепочки `AVPS_*`, принадлежащие только панели; случайно совпавшие существующие имена до подключения отклоняются.

Порядок и окончательность drop соответствуют [семантике nftables base chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains). Исключение транспорта использует direction и статус DNAT из [официального описания conntrack selectors](https://wiki.nftables.org/wiki-nftables/index.php/Matching_connection_tracking_stateful_metainformation); одного совпавшего UDP source port недостаточно.

Расшифрованный AWG-трафик направляется в выделенный veth. Исчезновение прежнего preserve-source не переводит его на исходный Docker-путь: даже после SNAT он поступает на тот же выделенный ingress. На исходных Docker bridges разрешается только проверенный conntrack DNAT внешнего AWG transport и предусмотренный DNS/ответный путь. INPUT от выделенного ingress закрыт; INPUT исходных Docker bridges допускает только ответ существующему локальному UDP proxy AWG. Docker embedded DNS в AWG/DNS namespaces блокируется, поскольку его upstream выполняется хостом в обход клиентского маршрута. DNS должен иметь самостоятельный upstream; несовместимость обнаруживается отдельной пробой.

Docker 28+ может блокировать доступ к неопубликованному адресу DNS уже в raw PREROUTING, до conntrack. Собственная `AVPS_RAW` разрешает там только UDP/TCP 53 из выделенного veth к явно выбранному DNS. Остальные Docker raw-правила сохраняются; nft guard и последующая фильтрация продолжают действовать. Порядок этого собственного hook включён в fingerprint восстановления.

Внешний IPv6 и SSH хоста глобально не отключаются. Данный backend обеспечивает IPv4 клиентский путь и блокирует клиентский IPv6; маршрутизируемая IPv6 client/network topology не принимается под управление. Server-initiated keepalive после истечения исходного conntrack может быть заблокирован до нового входящего AWG-пакета; полноценная независимая инициатива транспорта этим первым профилем не обещается.

Путь меняется за закрытым guard. При переходе удаляются только conntrack клиентской подсети, выделенного veth и выбранного DNS; SSH/чужие соединения не сбрасываются. Проверка WARP выполняется отдельно через его интерфейс, поэтому возврат с direct не зависит от текущего общего клиентского выхода. Затем проверяются HTTPS и UDP DNS из namespace с адреса AWG-интерфейса. DNS-пробу выполняет тот же Go-бинарник: `nsenter --target <PID> --net -- awg_control warp probe-dns --source <IPv4> --server <IPv4>`; сторонний интерпретатор не нужен. Это не заменяет реальный удалённый handshake.

Supervisor сравнивает отпечаток собственных правил и маршрутов, а внешние probes выполняет с ограничением частоты. Повторный repair не должен перезапускать AWG. `awg.restart` доступен только явной операцией Docker-адаптера; WARP runtime не принимает это действие. Если изменилось владение/топология, runtime сохраняет блокирующую защиту и требует ручной проверки.

Попытка start/restart/reconnect WARP выполняется с ограниченным временем и резервом на применение политики. Ошибка запуска демона не прерывает выбор разрешённого direct или блокирующего пути. Явная операция не считается восстановленной, если после применения не прошли HTTPS или выбранный DNS; результат проверки сохраняется для диагностики.

## Сбой и восстановление

Общей маркировки host OUTPUT нет: она перезаписывала метки самого WARP и нарушала его внутренние проверки связи. Собственные OUTPUT-цепочки сохраняются пустыми для совместимости владения. При включённом WARP обычный трафик хоста следует штатным маршрутам Cloudflare; SSH-адрес из safety-окна исключается штатным CLI, а внешний Docker AWG transport использует свой физический маршрут. При явном выключении WARP runtime также отключает туннель. Разрешение прямого клиентского выхода по-прежнему задаётся отдельно и обеспечивается guard, независимо от исключений Cloudflare.

До первого сетевого изменения сохраняются `integration_baseline.json`, manifest и marker незавершённой настройки. Это журнал восстановления, а не обещание атомарной транзакции всей сети. Ошибка после начала изменения возвращает `mutation_failed`; Control обязан обозначать возможное ручное восстановление. Runtime не восстанавливает весь чужой firewall из snapshot и не включает прямой выход без выбранной политики. После отказа сначала просматривают диагностику/журнал и устраняют конкретный конфликт; `repair` восстанавливает только собственные ресурсы. Полный uninstall сетевой интеграции не входит в удаление UI.

Первая настройка и переключение могут оборвать клиентские соединения. Сохранение peer-конфига, ключей и процесса AWG не означает сохранения TCP/NAT-сессий. Доказательство корректности на целевой топологии требует Linux-проверок: потеря WARP, порядок/удаление старого preserve-source, снятие разрешения direct, возврат в WARP, restart Docker и reboot. До этих проверок нельзя считать одну успешную Go-сборку подтверждением сетевой безопасности.

Сверка собственных policy rules сохраняет точное сравнение селекторов, таблицы и приоритета. Из observed-строки исключается только отметка ядра `[detached]`: она появляется при отсутствии интерфейса и исчезает при его создании, не меняя само правило ([iproute2](https://github.com/iproute2/iproute2/blob/main/ip/iprule.c)). Это позволяет WARP создавать и удалять свой интерфейс без ложного конфликта владения; любые изменения селекторов остаются конфликтом.

Ранний guard создаёт IPv4 probe-rule с приоритетом 40 до запуска `warp-svc`. Это сохраняет порядок при reboot: на проверенной версии WARP выбирает свободный приоритет перед первым действующим правилом. Если отложить probe-rule до основного runtime, WARP займёт 40 и строгая проверка владения заблокирует восстановление. Чужое правило на этом приоритете по-прежнему не перезаписывается.
