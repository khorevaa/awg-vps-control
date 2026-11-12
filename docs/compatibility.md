# Совместимость первого выпуска

Цель: Linux amd64, Ubuntu 24.04, systemd, Docker/Compose v2 и существующий AmneziaWG в Docker. Go binaries собираются Go 1.26.9 без CGO; runtime проекта — Go и Bash, без Python. Docker и AWG не устанавливаются проектом.

Compose запускает Web (UID 10001), Control (UID 10002) и Adapter (UID 10003); Adapter использует образ Control в отдельном режиме. Все три контейнера имеют `network_mode: none`, read-only rootfs, `cap_drop: ALL` и no-new-privileges. Только Adapter получает существующий Docker Unix socket и его фактический GID; это доверенный доступ уровня root, даже при read-only bind mount. Web/Control Docker API не получают. Rootless Docker и userns-remap требуют отдельной проверки UID/GID и в первый профиль не входят.

На хосте только две проектные службы: WARP IPC+supervisor и ранний boot guard. Runtime-каталоги создаются systemd-tmpfiles. Отдельных systemd-служб Web/Control/Adapter/общего bridge нет. Существующие `/etc/awg_vps_control/host.json` и host state сохраняются; старый `control_uid` не предоставляет доступ к WARP socket, допустимый `adapter_uid` — 10003.

VPS hostname, uptime, load и memory читаются из явно примонтированных host files. Дисковая метрика измеряет раздел данных панели; она не подменяется размером контейнерного overlay. Контейнеры не получают host PID namespace, host networking, privileged или mount корня хоста.

Поддержка изменяющих сетевых операций включается только после проверки обнаруженной топологии. Имя контейнера не является версией протокола. Нужны доступные `awg` tools, интерфейс, родной конфиг и явно выбранная Docker-сеть. Неизвестные пути/параметры или непроверенная схема дают read-only диагностику.

WARP — официальный Linux client с полным туннелем, необязателен; установка запускается отдельно. Proxy mode и Mihomo не поддерживаются. Существующие keys/регистрация WARP не сбрасываются автоматически.

Клиентский IPv6 не должен обходить политику; непроверенный dual-stack блокирует изменение маршрутов либо защищается отдельными принадлежащими проекту правилами без изменения глобального IPv6/SSH.

Реквизиты тестовой установки находятся только в `.local/test_environment.md`. Никаких IP, провайдера или сведений доступа к этому стенду в GitHub/CI.
