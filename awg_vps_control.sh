#!/usr/bin/env bash
set -euo pipefail
umask 077

# Менеджер запускает только именованные операции runtime из локального или установленного выпуска.
red='' green='' blue='' yellow='' plain=''
if [[ -t 1 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]]; then
    red=$'\033[0;31m' green=$'\033[0;32m' blue=$'\033[0;34m' yellow=$'\033[0;33m' plain=$'\033[0m'
fi

die() { printf '%sawg-vps-control: %s%s\n' "$red" "$*" "$plain" >&2; exit 1; }
usage_error() { printf 'Ошибка: %s\nКоманды: awg-vps-control help\n' "$*" >&2; exit 2; }
require_root() { [[ $EUID -eq 0 ]] || die 'Запустите эту команду через sudo или от root.'; }
no_arguments() { [[ $# -eq 0 ]] || usage_error 'У команды нет дополнительных аргументов.'; }

script_path=${BASH_SOURCE[0]}
for ((link_depth = 0; link_depth < 40; link_depth++)); do
    script_dir=$(CDPATH= cd -- "$(dirname -- "$script_path")" && pwd -P)
    script_path="$script_dir/$(basename -- "$script_path")"
    [[ -L $script_path ]] || break
    link_target=$(readlink -- "$script_path")
    if [[ $link_target == /* ]]; then script_path=$link_target; else script_path="$script_dir/$link_target"; fi
done
[[ ! -L $script_path ]] || die 'Слишком длинная цепочка ссылок на менеджер.'
runtime_root=$script_dir
if [[ ! -f $runtime_root/scripts/awg_vps_control.sh ]]; then runtime_root=/opt/awg_vps_control/current; fi
runtime_scripts="$runtime_root/scripts"
manager_version=development
if [[ -f $script_dir/version ]]; then manager_version=$(tr -d '\r\n' < "$script_dir/version"); fi
[[ $manager_version =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$ ]] || manager_version=unknown
case ${AWG_VPS_NONINTERACTIVE:-0} in 0|1) ;; *) die 'AWG_VPS_NONINTERACTIVE должен быть 0 или 1.' ;; esac
noninteractive=0
if [[ ${AWG_VPS_NONINTERACTIVE:-0} == 1 || ! -t 0 ]]; then noninteractive=1; fi

runtime_task() {
    require_root
    [[ -f $runtime_scripts/awg_vps_control.sh ]] || die 'Runtime не найден. Сначала выполните install-ui с каталогом собранного выпуска или опубликованным тегом.'
    bash "$runtime_scripts/awg_vps_control.sh" "$@"
}

prompt_value() {
    local variable=$1 label=$2 default_value=$3 required=$4 answer
    if [[ $noninteractive -eq 1 ]]; then answer=$default_value
    else
        read -r -p "$label${default_value:+ [$default_value]}: " answer || die 'Ввод прерван.'
        answer=${answer:-$default_value}
    fi
    [[ $required != required || -n $answer ]] || usage_error "$label: необходимо указать значение."
    printf -v "$variable" '%s' "$answer"
}

confirm() {
    local answer
    [[ $noninteractive -eq 0 ]] || usage_error 'Для этого диалога нужен терминал; используйте именованную команду с явными параметрами.'
    read -r -p "$1 [да/нет]: " answer || return 1
    [[ $answer == да || $answer == yes ]]
}

# Локальный bundle выбирается явно; remote-код всегда берётся из опубликованного release archive.
install_bundle() (
    require_root
    local action=$1 source=${2:-} temporary='' bundle
    [[ -n $source ]] || prompt_value source 'Каталог собранного выпуска или тег GitHub release' "${AWG_UI_VERSION:-latest}" required
    if [[ -d $source ]]; then bundle=$(CDPATH= cd -- "$source" && pwd -P)
    else
        [[ $source != */* && $source != .* ]] || die "Каталог выпуска не найден: $source"
        [[ -f $runtime_scripts/download_release.sh ]] || die 'Загрузчик отсутствует. Используйте полный checkout или локальный bundle.'
        temporary=$(mktemp -d "${TMPDIR:-/tmp}/awg_vps_release.XXXXXXXX")
        trap '[[ -z $temporary ]] || rm -rf -- "$temporary"' EXIT
        bash "$runtime_scripts/download_release.sh" "$source" "$temporary/download" >/dev/null
        bundle="$temporary/download/release"
    fi
    [[ -f $bundle/install.sh && ! -L $bundle/install.sh && -f $bundle/manifest.sha256 && -f $bundle/bin/awg_control && -f $bundle/bin/awg_web ]] || die 'Каталог не содержит полный release bundle. Сначала соберите выпуск scripts/build_release.sh или scripts/build_release.ps1.'
    printf '%s%s: установка проверенного выпуска из %s%s\n' "$blue" "$action" "$bundle" "$plain"
    bash "$bundle/install.sh" "$bundle"
)

install_ui() {
    [[ $# -le 1 ]] || usage_error 'install-ui [каталог-выпуска|тег|latest]'
    install_bundle install-ui "${1:-}"
}

update_ui() {
    [[ $# -le 1 ]] || usage_error 'update-ui [каталог-выпуска|тег|latest]'
    [[ -L /opt/awg_vps_control/current ]] || die 'Панель ещё не установлена; используйте install-ui.'
    install_bundle update-ui "${1:-}"
}

update_manager() {
    [[ $# -le 1 ]] || usage_error 'update-manager [тег|latest]'
    local tag=${1:-${AWG_UI_VERSION:-latest}}
    [[ ! -d $tag && $tag != */* ]] || usage_error 'update-manager принимает тег опубликованного выпуска; для локального bundle используйте update-ui.'
    printf '%sМенеджер обновляется вместе с совместимым runtime и UI: они входят в один проверяемый выпуск.%s\n' "$yellow" "$plain"
    install_bundle update-manager "$tag"
}

# Отдельная установка AWG доступна до установки панели и никогда не запускается её lifecycle-командами.
install_awg() {
    [[ -f $runtime_scripts/install_awg.sh ]] || die 'В этом выпуске нет установщика AWG; обновите полный bundle менеджера.'
    if [[ $# -gt 0 || $noninteractive -eq 1 ]]; then bash "$runtime_scripts/install_awg.sh" "$@"; return; fi
    require_root
    local port
    printf 'Будут установлены AWG 3.1 и AmneziaDNS в Docker по официальным скриптам Amnezia.\n'
    printf 'Существующая установка AWG не заменяется. WARP и установка Docker выполняются отдельно.\n'
    prompt_value port 'UDP-порт AWG' 55424 required
    [[ $port =~ ^[0-9]{1,5}$ && $((10#$port)) -ge 1024 && $((10#$port)) -le 65535 ]] || usage_error 'UDP-порт должен быть числом от 1024 до 65535.'
    confirm "Установить новый AWG и DNS с UDP-портом $port?" || return 0
    bash "$runtime_scripts/install_awg.sh" --port "$port" --confirm
}

attach_existing() {
    local container network dns
    if [[ $# -eq 1 && $1 == \{* ]]; then runtime_task attach "$1"; return; fi
    if [[ $# -gt 0 ]]; then
        [[ $# -ge 2 && $# -le 3 ]] || usage_error 'attach ИМЯ_КОНТЕЙНЕРА DOCKER_СЕТЬ [DNS_КОНТЕЙНЕР]'
        runtime_task attach-guided "$1" "$2" "${3:-}"
        return
    fi
    runtime_task discover
    printf '\nВыберите существующий AWG и его Docker-сеть из обнаруженных. DNS-контейнер должен находиться в этой сети.\n'
    printf 'Attach сохраняет привязку; конфигурация AWG, ключи и клиенты остаются на месте.\n'
    prompt_value container 'Имя контейнера AWG' "${AWG_CONTAINER:-}" required
    prompt_value network 'Общая Docker-сеть' "${AWG_DOCKER_NETWORK:-}" required
    prompt_value dns 'DNS-контейнер (пусто, если отдельного нет)' "${AWG_DNS_CONTAINER:-}" optional
    if [[ $noninteractive -eq 0 ]]; then confirm 'Подключить выбранную установку к панели?' || return 0; fi
    runtime_task attach-guided "$container" "$network" "$dns"
}

manage_policy() {
    [[ $# -le 1 ]] || usage_error 'policy [--json|JSON]'
    if [[ $# -eq 1 || $noninteractive -eq 1 ]]; then runtime_task policy "$@"; return; fi
    printf 'Сначала явно выберите режим выхода. Для первой установки WARP сохраните режим без WARP,\nзатем выполните setup-warp и снова откройте policy для включения WARP.\n'
    runtime_task policy-guided
}

show_ui_access() {
    [[ $# -le 1 ]] || usage_error 'ui-access [SSH_ПОЛЬЗОВАТЕЛЬ@VPS]'
    local ssh_target=${1:-${AWG_SSH_TARGET:-}}
    if [[ -n $ssh_target ]]; then runtime_task ui-access "$ssh_target"
    else runtime_task ui-access; fi
}

restart_awg() {
    if [[ $# -eq 1 && $1 == --confirm ]]; then runtime_task restart-awg --confirm; return; fi
    no_arguments "$@"
    [[ $noninteractive -eq 0 ]] || usage_error 'restart-awg прерывает VPN-соединения. Для явного согласия передайте --confirm.'
    confirm 'Перезапустить существующий AWG? Подключения всех его клиентов будут прерваны' || return 0
    runtime_task restart-awg --confirm
}

usage() {
    cat <<'EOF'
Использование: awg-vps-control <команда> [аргументы]
               sudo bash awg_vps_control.sh <команда> [аргументы]

Установка и выпуск:
  install-ui [каталог|тег|latest]  Установить панель из bundle или GitHub release
  update-ui [каталог|тег|latest]   Обновить установленную панель с проверкой readiness
  update-manager [тег|latest]     Обновить менеджер вместе с согласованным runtime/UI
  rollback-ui                    Вернуть предыдущий проверенный выпуск приложения
  uninstall-ui                   Удалить только три контейнера панели, сохранив WARP/AWG

Наблюдение и доступ:
  status [--json]                 Обзор VPS, AWG и WARP
  doctor [--json]                 Диагностика и причины ошибок
  clients [--json]                Штатный список клиентов Amnezia (только чтение)
  settings [--json]               Настройки без секретов
  logs [--json]                   Последние записи восстановления
  discover                       Найти существующие AWG/DNS-контейнеры и сети
  ui-status                      Состояние трёх контейнеров панели
  healthcheck                    Проверить цепочку Web → Control → Adapter → WARP
  ui-access [user@vps]            Показать URL, секрет и команду SSH-туннеля
  rotate-ui-access               Заменить секрет и отозвать сессии панели

Подключение и сеть:
  install-awg [--port N --confirm] Установить новый AWG/DNS из официальных скриптов Amnezia
  attach [ИМЯ СЕТЬ [DNS]]         Подключить существующий AWG; без аргументов — диалог
  attach '{...}'                 Передать точный JSON payload attach из API
  policy [--json|JSON]            Диалог режима выхода; --json читает, JSON сохраняет
  setup-warp                     Явно установить/настроить WARP после выбора политики
  reconnect-warp                 Переподключить WARP; соединения могут прерваться
  repair                         Восстановить свои маршруты/правила и WARP
  restart-awg [--confirm]         Отдельно подтвердить ручной перезапуск AWG
  start | stop | restart         Управлять только Web, Control и Adapter
  help | version | menu

Без команды открывается меню. Без терминала требуется именованная команда.
AWG_VPS_NONINTERACTIVE=1 запрещает диалоги; AWG_UI_VERSION задаёт release-тег.
Для attach без диалога: AWG_CONTAINER, AWG_DOCKER_NETWORK, AWG_DNS_CONTAINER.
Адрес SSH определяется автоматически; AWG_SSH_TARGET переопределяет его. NO_COLOR отключает цвет.
В noninteractive режиме policy без аргументов только читает текущую политику.
Команда изменения с явными параметрами считается намеренным действием;
для restart-awg в noninteractive режиме обязательно --confirm.

Теги загружаются только из khorevaa/awg-vps-control releases с SHA-256.
Если опубликованных выпусков нет, используйте каталог локальной сборки.
AWG устанавливается только отдельной install-awg. Обновление AWG и изменение клиентов — следующие этапы.
Aliases: install, update, rollback, uninstall, peers, access, rotate,
         start-ui, stop-ui, restart-ui, warp-setup, warp-reconnect.
EOF
}

dispatch() {
    local command_name=${1:-menu}
    [[ $# -eq 0 ]] || shift
    case $command_name in
        help|-h|--help) no_arguments "$@"; usage ;;
        version|-v|--version) no_arguments "$@"; printf 'awg-vps-control %s\n' "$manager_version" ;;
        menu) no_arguments "$@"; show_menu ;;
        install|install-ui) install_ui "$@" ;;
        update|update-ui) update_ui "$@" ;;
        update-manager) update_manager "$@" ;;
        install-awg) install_awg "$@" ;;
        status|doctor|settings|logs|clients|peers)
            [[ $# -eq 0 || ( $# -eq 1 && $1 == --json ) ]] || usage_error "$command_name [--json]"
            [[ $command_name != peers ]] || command_name=clients
            runtime_task "$command_name" "$@"
            ;;
        discover|ui-status|healthcheck) no_arguments "$@"; runtime_task "$command_name" ;;
        attach) attach_existing "$@" ;;
        policy) manage_policy "$@" ;;
        ui-access|access) show_ui_access "$@" ;;
        rotate-ui-access|rotate) no_arguments "$@"; runtime_task rotate-ui-access ;;
        restart-awg) restart_awg "$@" ;;
        setup-warp|warp-setup) no_arguments "$@"; runtime_task setup-warp ;;
        reconnect-warp|warp-reconnect) no_arguments "$@"; runtime_task reconnect-warp ;;
        repair) no_arguments "$@"; runtime_task repair ;;
        start|start-ui) no_arguments "$@"; runtime_task start-ui ;;
        stop|stop-ui) no_arguments "$@"; runtime_task stop-ui ;;
        restart|restart-ui) no_arguments "$@"; runtime_task restart-ui ;;
        rollback|rollback-ui) no_arguments "$@"; runtime_task rollback-ui ;;
        uninstall|uninstall-ui) no_arguments "$@"; runtime_task uninstall-ui ;;
        *) usage_error "Неизвестная команда: $command_name" ;;
    esac
}

show_menu() {
    [[ $noninteractive -eq 0 && -t 1 ]] || usage_error 'Для меню нужен терминал. Укажите команду, например ui-status или help.'
    local choice action confirmation result
    while true; do
        printf '\n%sAWG VPS Control %s%s\n' "$green" "$manager_version" "$plain"
        printf '%sУстановка и обслуживание · управление VPN — в веб-панели%s\n' "$blue" "$plain"
        printf '\n  1. Установить AWG в Docker\n  2. Установить / обновить панель\n  3. Доступ к панели\n  4. Перезапустить панель\n  0. Выход\n\nДругие сервисные команды: awg-vps-control help\n\n'
        read -r -p 'Выберите действие: ' choice || return 0
        confirmation=''
        case $choice in
            0) return 0 ;;
            1) action=install-awg ;;
            2)
                if [[ -L /opt/awg_vps_control/current ]]; then action=update-ui
                else action=install-ui; fi
                ;;
            3) action=ui-access ;;
            4) action=restart; confirmation='Перезапустить три контейнера панели?' ;;
            *) printf '%sНеизвестный пункт.%s\n' "$red" "$plain"; continue ;;
        esac
        if [[ -n $confirmation ]] && ! confirm "$confirmation"; then continue; fi
        # Отдельный Bash сохраняет set -e внутри действия и возвращает меню после ошибки.
        if bash "$script_path" "$action"; then
            printf '%sДействие завершено.%s\n' "$green" "$plain"
            case $action in
                install-ui|update-ui|rollback-ui)
                    if [[ -x /usr/local/bin/awg-vps-control ]]; then exec /usr/local/bin/awg-vps-control menu; fi
                    ;;
            esac
        else
            result=$?
            printf '%sДействие не завершено (код %s). Причина указана выше.%s\n' "$red" "$result" "$plain" >&2
        fi
        read -r -p 'Enter — вернуться в меню...' choice || return 0
    done
}

dispatch "$@"
