#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Запустите скрипт от root.' >&2; exit 1; }
root=/opt/awg_vps_control
release=$(readlink -f "$root/current")
[[ $release == "$root/releases/"* && -d $release ]] || { echo 'Панель не установлена: сначала выполните install.sh из проверенного выпуска.' >&2; exit 1; }
compose() {
    docker compose --env-file /etc/awg_vps_control/ui.env --env-file "$release/runtime.env" -f "$release/compose.yaml" "$@"
}
request() {
    local payload=${2:-} body handler=adapter
    [[ -n $payload ]] || payload='{}'
    printf -v body '{"request_id":"cli_%s_%s","action":"%s","payload":%s}' "$(date +%s)" "$RANDOM" "$1" "$payload"
    case $1 in policy.get|policy.set|repair|warp.setup|warp.reconnect) handler=warp ;; esac
    "$release/bin/awg_control" "$handler" request "$body"
}
command=${1:-}
if [[ -z $command ]]; then if [[ -t 0 && -t 1 ]]; then command=menu; else command=status; fi; fi
case $command in
    menu) exec bash "$release/awg_vps_control.sh" menu ;;
    start-ui)
        systemd-tmpfiles --create /etc/tmpfiles.d/awg_vps_control.conf
        compose up -d --remove-orphans --wait --wait-timeout 90
        ;;
    stop-ui) compose stop ;;
    healthcheck)
        systemctl is-active --quiet awg_vps_warp.service
        "$release/bin/awg_control" warp request '{"request_id":"cli_health","action":"health","payload":{}}' >/dev/null
        compose exec -T adapter /usr/local/bin/awg_component adapter healthcheck
        compose exec -T control /usr/local/bin/awg_component healthcheck
        compose exec -T web /usr/local/bin/awg_component healthcheck
        ;;
    status) if [[ ${2:-} == --json ]]; then request overview; else "$release/bin/awg_control" manual status; fi ;;
    ui-status) compose ps ;;
    discover) request discover ;;
    doctor) if [[ ${2:-} == --json ]]; then request diagnostics; else "$release/bin/awg_control" manual doctor; fi ;;
    clients) if [[ ${2:-} == --json ]]; then request peers; else "$release/bin/awg_control" manual clients; fi ;;
    settings) if [[ ${2:-} == --json ]]; then request policy.get; else "$release/bin/awg_control" manual settings; fi ;;
    attach)
        [[ $# -eq 2 ]] || { echo 'Usage: awg-vps-control attach <json-payload>' >&2; exit 2; }
        request attach "$2"
        ;;
    policy)
        if [[ $# -eq 1 || ${2:-} == --json ]]; then request policy.get; else request policy.set "$2"; fi
        ;;
    repair) request repair ;;
    setup-warp) request warp.setup ;;
    reconnect-warp) request warp.reconnect ;;
    restart-awg)
        [[ ${2:-} == --confirm ]] || { echo 'Команда прервёт подключения AWG. Добавьте --confirm.' >&2; exit 2; }
        request awg.restart
        ;;
    logs) if [[ ${2:-} == --json ]]; then request logs '{"source":"supervisor","limit":100}'; else "$release/bin/awg_control" manual logs; fi ;;
    attach-guided) shift; "$release/bin/awg_control" manual attach "$@" ;;
    policy-guided) "$release/bin/awg_control" manual policy ;;
    start) "$0" start-ui ;;
    stop) compose stop ;;
    restart|restart-ui)
        compose restart
        deadline=$((SECONDS + 90))
        until "$0" healthcheck >/dev/null 2>&1; do
            [[ $SECONDS -lt $deadline ]] || { echo 'Панель не подтвердила готовность после перезапуска.' >&2; exit 1; }
            sleep 2
        done
        echo 'Контейнеры панели перезапущены; готовность подтверждена.'
        ;;
    ui-access) shift; "$release/bin/awg_control" install-tools ui-access "$@" ;;
    rotate-ui-access) "$release/bin/awg_control" install-tools rotate-secret ;;
    install-ui|update-ui)
        [[ $# -eq 2 ]] || { echo 'Usage: awg-vps-control update-ui <release-directory>' >&2; exit 2; }
        exec bash "$2/install.sh" "$2"
        ;;
    rollback-ui)
        exec 9>/run/awg_vps_install.lock
        flock -n 9 || { echo 'Другая операция выпуска уже выполняется.' >&2; exit 1; }
        previous=$(readlink -f "$root/previous")
        [[ $previous == "$root/releases/"* && -d $previous && $previous != "$release" ]] || { echo 'Предыдущий выпуск отсутствует.' >&2; exit 1; }
        [[ -f $previous/systemd/awg_vps_warp.service ]] || { echo 'Для старой архитектуры нужна отдельная миграция; автоматический откат недоступен.' >&2; exit 1; }
        (cd "$previous" && sha256sum --check --status manifest.sha256)
        recover_rollback() {
            result=$?
            trap - ERR
            ln -sfn "$release" "$root/current.next"
            mv -Tf "$root/current.next" "$root/current"
            cp -- "$release"/systemd/*.service /etc/systemd/system/
            install -m 0644 "$release/systemd/awg_vps_control.conf" /etc/tmpfiles.d/awg_vps_control.conf
            systemd-tmpfiles --create /etc/tmpfiles.d/awg_vps_control.conf
            systemctl daemon-reload
            systemctl restart awg_vps_warp.service || true
            "$release/scripts/awg_vps_control.sh" start-ui || true
            echo 'Откат не прошёл проверку; выбран исходный выпуск. Проверьте healthcheck.' >&2
            exit "$result"
        }
        trap recover_rollback ERR
        ln -sfn "$previous" "$root/current.next"
        mv -Tf "$root/current.next" "$root/current"
        cp -- "$previous"/systemd/*.service /etc/systemd/system/
        install -m 0644 "$previous/systemd/awg_vps_control.conf" /etc/tmpfiles.d/awg_vps_control.conf
        systemd-tmpfiles --create /etc/tmpfiles.d/awg_vps_control.conf
        systemctl daemon-reload
        systemctl restart awg_vps_warp.service
        "$previous/scripts/awg_vps_control.sh" start-ui
        "$previous/scripts/awg_vps_control.sh" healthcheck
        ln -sfn "$release" "$root/previous"
        trap - ERR
        ;;
    uninstall-ui) compose down; echo 'Контейнеры панели удалены. WARP, его защита, состояние и AWG сохранены.' ;;
    *) echo 'Commands: menu status discover doctor attach policy repair setup-warp reconnect-warp restart-awg ui-access rotate-ui-access install-ui update-ui rollback-ui uninstall-ui' >&2; exit 2 ;;
esac
