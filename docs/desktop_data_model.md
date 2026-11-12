# Desktop: модель данных и границы доступа

Первый срез этапа 8: Windows amd64, MyGo v0.9.0 и отдельный Go-модуль
`desktop` (Go 1.27.4). Серверные модули и Docker-архитектура не меняются.
SSH реализует `golang.org/x/crypto/ssh`; файлы профилей содержат только
параметры подключения. Общей базы VPN-клиентов нет.

## Модели до реализации

| Тип | Поля и назначение |
| --- | --- |
| `SSHProfile` | `ID`, `Name`, `Host`, `Port`, `User`, `AuthMode` (`password`/`key`), `KeyPath`. Только несекретные параметры, endpoint без shell-интерпретации. |
| `ProfileStore` | `Version=1`, `Profiles`. JSON в пользовательском каталоге приложения, ограничение размера и числа записей; атомарная запись. |
| `Credentials` | `Password`, `Passphrase`. Только память одной попытки; никогда JSON, журнал или аргументы процесса. |
| `HostKeyChallenge` | `Address`, `Algorithm`, `Fingerprint`, `Key`. Неизвестный ключ завершает попытку с типизированной ошибкой; подтверждение сохраняет точную строку known_hosts. Изменённый ключ отклоняется. |
| `Connection` | SSH/TCP transport, HTTP transport/server/listener, origin локальный/серверный, отмена контекста, mutex, состояние закрытия, done channel, ожидающий профиль; `saving bool` удерживает запрет следующей выдачи после передачи файла native UI. Владеет ресурсами одной сессии. |
| `PendingProfileDownload` | `OperationID`, `Filename`, `Data`, `ExpiresAt`. Одна выдача до 64 KiB в памяти, срок 10 минут, уничтожается при закрытии соединения, отказе/сохранении или замене. |
| `boundedBuffer` | Буфер и предел размера для stdout фиксированной SSH-команды; превышение возвращает ошибку без накопления лишних данных. |
| `Connection.panelCookie` | Единственный проверенный `*http.Cookie` серверной сессии. Только память до передачи ephemeral WebView; не JSON и не постоянное хранилище. |
| `DesktopApp` | Окно/встроенный WebView, текущие SSH-профили и поля редактирования, секреты попытки, key редактора секрета, generation подключения, cancel, connection, host-key challenge, сообщение/статус и pending download. Состояние UI принадлежит главному потоку; в JSON не сохраняется. |

Поля внутренних вспомогательных моделей разрешены только для описанных выше
состояний и ограничений. Все Go-типы, функции и поля имеют русские комментарии.

## Контракт transport-пакета

`internal/connection` предоставляет `SSHProfile`, `ProfileStore`, `Credentials`,
`HostKeyChallenge`, `Connection`, `PendingProfileDownload` и функции:

- `LoadProfiles(dir)` / `SaveProfiles(dir, profiles)` — только настройки.
- `Connect(ctx, dir, profile, credentials) (*Connection, error)` — проверка ключа,
  SSH, фиксированное чтение origin из `/etc/awg_vps_control/ui.env`, доступ к
  `/run/awg_vps_web/web.sock`, локальный listener на случайном порту.
- `TrustHostKey(dir, challenge) error` — явное подтверждение неизвестного ключа;
  существующий другой ключ не перезаписывается.
- `Connection.URL() string`, `Done() <-chan struct{}`, `Close() error`.
- `Connection.PendingDownload() (filename string, available bool)` и
  `TakeDownload() (*PendingProfileDownload, error)` — выдача один раз native UI.
- `Connection.FinishDownload()` — завершение владения переданным native UI
  профилем; снимает запрет следующей выдачи после save/cancel/error/TTL.

По уточнению пользователя desktop после SSH сразу авторизует панель. Фиксированная
SSH-команда читает `/etc/awg_vps_control/web/access_secret` с ограничением размера,
без shell source; содержимое используется только в памяти для штатного POST
`/api/v1/access` через защищённый SSH Unix channel. Cookie проверяется по имени,
размеру и Secure/HttpOnly/SameSiteStrict/Path; `TakePanelCookie()` передаёт его native
оболочке один раз до открытия страницы. Native `Session.Cookies.Set` задаёт cookie
только для случайного локального hostname в новой ephemeral session. Access secret
не передаётся странице, в аргументы, файл профилей или журнал. Отказ чтения/входа
останавливает подключение с понятной ошибкой, без ручной формы секрета.

Для обычного браузера штатная авторизация не меняется. После серверного 401 или
явного logout desktop закрывает соединение; новый SSH-вход создаёт новую сессию.
Первый срез не интерпретирует ssh_config, не поддерживает agent,
ProxyJump или PuTTY PPK; пароль/passphrase вводится на каждую попытку.

## Транспорт и доверие

`Connect` ограничивает TCP/SSH/bootstrap deadline; отмена закрывает исходный TCP.
Туннель открывает только фиксированный remote Unix socket, без произвольных
адресов/команд из UI панели. Listener слушает только `127.0.0.1`, UI использует
случайный `<random>.localhost:<port>` origin для Secure cookie.

Перед преобразованием Host/Origin proxy проверяет точный локальный Host и,
если Origin присутствует, его точное равенство локальному origin. Посторонние
запросы отвергаются. Только затем заменяет Host/Origin на значения из ui.env.
Redirect на чужой origin, абсолютный request target и upgrade не допускаются.
Удалённый транспорт не имеет обычного TCP dial: только SSH к фиксированному socket.
Заголовки пересылки, proxy credentials и внешние redirect не передаются.

Неизвестный SSH-ключ требует native подтверждения SHA256 fingerprint, изменённый
ключ даёт ошибку. Known-hosts принадлежит приложению и не правит глобальный файл.
Host-key challenge сам по себе не авторизует подключение. После подтверждения
пользователь повторяет подключение и вводит секрет заново.

Native UI не публикует Go bindings. Панель — отдельный `Untrusted` WebView с новой
ephemeral session; переходы разрешены только в пределах точного loopback origin.
Popups, внешние URL, file navigation, browser downloads и разрешения запрещены.
После disconnect/смены VPS listener, SSH, transport и WebView закрываются;
generation препятствует публикации результата старой попытки в новое окно.

## Разовая выдача профиля

Proxy перехватывает только успешный POST `/api/v1/peers/profile`: ID операции,
Content-Type, безопасное имя `awg_client_<12hex>.conf`, размер 1..65536 байт.
Полученный профиль хранится в памяти текущего `Connection`, не выводится в лог.
Тот же ограниченный ответ получает JS панели, как при обычной работе браузера;
его blob живёт в изолированной WebView session. Следующая выдача отклоняется до
обращения к VPS, пока предыдущий профиль ожидает сохранения, находится в native
диалоге или записывается на диск. `TakeDownload` атомарно передаёт буфер и ставит
`saving=true` под mutex соединения. Только `FinishDownload` после завершения
этого владения либо закрытие соединения снимают запрет. Срок ожидающего профиля
не освобождает владение уже начатой файловой операции.
Браузерная загрузка всегда блокируется. Native UI показывает кнопку сохранения;
диалог открывается только по нажатию пользователя. Файл записывается только по
явно выбранному пути; отмена и ошибка завершают выдачу и очищают буфер.
UI предупреждает, что повторное получение сервером не поддерживается.

## Состояние native UI

`DesktopApp` хранит `window *mygo.Window`, `directory string`, `profiles []SSHProfile`,
`profilesLoaded bool`, `draft SSHProfile`, `port string`, `secret string`, `secretEpoch/editorEpoch uint64`,
`generation uint64`, `connecting bool`, `cancel context.CancelFunc`,
`connection *Connection`, `webView *mygo.WebView`, `challenge *HostKeyChallenge`,
`message string`, `messageError bool`, `dialogBusy bool`, `pendingName string`,
`saveData *PendingProfileDownload`, `saveConnection *Connection`, `closed bool`, `ctx context.Context`,
`stop context.CancelFunc`. Все поля UI принадлежат главному потоку; mutex не нужен.
Фоновые результаты публикуются синхронным `mygo.RunOnMain` и отдельным redraw.
Если main loop уже закрыт, результат подключения закрывается в получившей его
goroutine. Устаревший generation никогда не заменяет действующее подключение.

Форма хранит только один временный secret: пароль SSH либо passphrase ключа.
После попытки, отмены, смены профиля и закрытия строка сбрасывается, а TextInput
получает новый Key, чтобы старый undo buffer не вернулся в новый редактор.
Подключение может быть разовым; отдельная кнопка сохраняет только SSHProfile.
Новый/изменённый профиль не перезаписывает существующий без явного сохранения.

При открытом Save dialog `saveData` остаётся во владении UI и очищается при TTL,
disconnect или закрытии приложения. После выбора пути и проверки generation
буфер передаётся короткой файловой операции с обязательным clear; ошибка или
отмена не возвращают его в очередь. Файл создаётся через временный файл в том
же каталоге, fsync и rename, только по выбранному пользователем абсолютному пути.
`saveConnection` и native callback сохраняют ссылку на исходный `Connection`: завершение старого
диалога или записи вызывает `FinishDownload` только у этого соединения.
При cancel/error/TTL во время диалога сначала очищается буфер, затем снимается
владение. После передачи буфера файловой операции владение завершается после
записи и очистки, включая путь ошибки; освобождение до записи запрещено.
Disconnect закрывает исходное соединение и очищает ещё не переданный записи
буфер. Операция записи по уже подтверждённому пользователем пути завершается
самостоятельно, не публикуя результат в другую сессию.

## Приёмка

Проверить сборку Windows, native окно, ошибки host key/auth, точный Host/Origin,
сессии/CSRF реального Web, закрытие ресурсов, лимит и очистку профиля. Отдельно
проверить SSH-вход и встроенную панель на личном VPS; приватные реквизиты и
исходные снимки остаются вне репозитория. Новые Go-тесты не создаются.
