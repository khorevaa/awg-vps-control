#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Установка выполняется только по отдельной явной команде, до подключения панели.
unset BASH_ENV ENV CDPATH GLOBIGNORE
for environment_name in ${!DOCKER_@} ${!BUILDX_@} ${!BUILDKIT_@}; do unset "$environment_name"; done
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
readonly upstream_commit=ac175c8a8147cfe56f98c8372ec17ea2ba00bb02
readonly upstream_release=5.1.0.6
readonly upstream_repository=amnezia-vpn/amnezia-client
readonly state_root=/var/lib/awg_vps_control/awg_install
readonly awg_name=amnezia-awg2 dns_name=amnezia-dns
readonly awg_folder=/opt/amnezia/amnezia-awg2 dns_folder=/opt/amnezia/amnezia-dns
readonly network_name=amnezia-dns-net
readonly docker_socket=/var/run/docker.sock
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
port=55424
confirmed=0
state_started=0
completed=0
status=installing
step=preflight
exit_code=0
container_id= dns_container_id= network_id=
awg_image_id= dns_image_id= config_revision= rendered_manifest_sha256=
awg_base_image_id= awg_base_digest= dns_base_image_id= dns_base_digest=
operation_id= started_at= manager_version=unknown
readonly -a source_paths=(prepare_host.sh build_container.sh awg/Dockerfile awg/run_container.sh awg/configure_container.sh awg/start.sh dns/Dockerfile dns/run_container.sh dns/configure_container.sh)
declare -A source_hashes=()

# usage выводит только доступные безопасные параметры.
usage() {
    cat <<'EOF'
Использование: install_awg.sh [--port 55424] --confirm
Отдельная свежая установка AWG 3.1 и DNS из официальных скриптов Amnezia 5.1.0.6.
Нужны Ubuntu 24.04 amd64, root, Docker/Compose plugin >=2 и ip_forward=1.
Существующий AWG не заменяется. Docker, WARP и обновления ОС не устанавливаются.
Параметры: --port PORT (1024..65535), --confirm, --help.
EOF
}

# fail завершает шаг без вывода содержимого конфигурации или внешних команд.
fail() { printf 'Установка AWG: %s\n' "$*" >&2; exit 1; }

# parse_arguments отклоняет неоднозначные параметры до любых записей.
parse_arguments() {
    local have_port=0
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h) [[ $# -eq 1 ]] || fail '--help нельзя смешивать с другими параметрами.'; usage; exit 0 ;;
            --confirm) [[ $confirmed -eq 0 ]] || fail 'Повтор --confirm.'; confirmed=1; shift ;;
            --port)
                [[ $# -ge 2 && $have_port -eq 0 && $2 =~ ^[0-9]{1,5}$ ]] || fail 'Ожидается один --port с числом 1024..65535.'
                port=$((10#$2))
                [[ $port -ge 1024 && $port -le 65535 ]] || fail 'Порт должен быть в диапазоне 1024..65535.'
                have_port=1; shift 2
                ;;
            *) fail 'Неизвестный параметр. Используйте --help.' ;;
        esac
    done
    [[ $confirmed -eq 1 ]] || fail 'Для свежей установки добавьте --confirm. Изменения не выполнялись.'
}

# safe_path проверяет каждый существующий компонент, не переходя по ссылкам.
safe_path() {
    local path=$1 current= owner mode kind links
    [[ $path == /* && $path != *'/../'* && $path != */.. ]] || fail 'Небезопасный управляемый путь.'
    local -a components
    IFS=/ read -r -a components <<< "${path#/}"
    for component in "${components[@]}"; do
        current+="/$component"
        [[ ! -L $current ]] || fail 'Символическая ссылка в управляемом пути.'
        if [[ -e $current ]]; then
            read -r owner mode links < <(stat -c '%u %a %h' -- "$current")
            [[ $owner == 0 && $mode =~ ^[0-7]{3,4}$ ]] || fail 'Непроверенный владелец управляемого пути.'
            (( (8#$mode & 0022) == 0 )) || fail 'Управляемый путь доступен на запись посторонним.'
            if [[ ! -d $current ]]; then
                [[ $current == "$path" && -f $current && $links == 1 ]] || fail 'Небезопасный тип управляемого файла.'
            fi
        fi
    done
}

# docker_local всегда обращается к локальному rootful Docker и пустому config.
docker_local() {
    timeout -s TERM -k 5 60 /usr/bin/docker --host "unix://$docker_socket" --config "$docker_config" "$@"
}

# ipv4_number преобразует проверенный IPv4 в целое для сравнения подсетей.
ipv4_number() {
    local value=$1 a b c d
    [[ $value =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    IFS=. read -r a b c d <<< "$value"
    a=$((10#$a)); b=$((10#$b)); c=$((10#$c)); d=$((10#$d))
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
    printf '%s\n' "$(((a << 24) | (b << 16) | (c << 8) | d))"
}

# reject_subnet_overlap проверяет конфликты с двумя создаваемыми IPv4 подсетями.
reject_subnet_overlap() {
    local prefix=$1 address bits number mask low high wanted target
    [[ $prefix != *:* && $prefix != default ]] || return 0
    address=${prefix%/*}
    if [[ $prefix == */* ]]; then bits=${prefix##*/}; else bits=32; fi
    [[ $bits =~ ^[0-9]{1,2}$ ]] || fail 'Не удалось проверить существующую подсеть.'
    bits=$((10#$bits))
    (( bits >= 0 && bits <= 32 )) || fail 'Недопустимая маска существующей подсети.'
    number=$(ipv4_number "$address") || fail 'Не удалось проверить существующий IPv4 маршрут.'
    # Основной default route сохраняется и не считается пересечением частных подсетей.
    (( bits != 0 )) || return 0
    mask=$(((0xffffffff << (32 - bits)) & 0xffffffff))
    low=$((number & mask)); high=$((low | (0xffffffff ^ mask)))
    for wanted in 10.8.1.0 172.29.172.0; do
        target=$(ipv4_number "$wanted")
        (( high < target || low > target + 255 )) || fail 'Клиентская или DNS-подсеть пересекает существующий маршрут/Docker network.'
    done
}

# validate_manifest допускает ровно девять известных исходных файлов.
validate_manifest() {
    local hash name extra expected count=0
    [[ -f $script_dir/awg_upstream.sha256 && ! -L $script_dir/awg_upstream.sha256 ]] || fail 'Отсутствует штатный manifest upstream.'
    while read -r hash name extra; do
        [[ $hash =~ ^[0-9a-f]{64}$ && -z $extra ]] || fail 'Повреждён manifest upstream.'
        expected=0
        for path in "${source_paths[@]}"; do [[ $name != "$path" ]] || expected=1; done
        [[ $expected -eq 1 && -z ${source_hashes[$name]+present} ]] || fail 'Непредусмотренный или повторный исходный файл.'
        source_hashes[$name]=$hash
        count=$((count + 1))
    done < "$script_dir/awg_upstream.sha256"
    [[ $count -eq ${#source_paths[@]} ]] || fail 'Неполный manifest upstream.'
}

# capture_host_network запоминает только части сети, которые установка менять не вправе.
capture_host_network() {
    ip -4 route show table main default | sed -E 's/ expires [0-9]+sec//g' || return 1
    ip -6 route show table main default | sed -E 's/ expires [0-9]+sec//g' || return 1
    ip -4 rule show || return 1
    ip -6 rule show || return 1
    iptables -w 5 -S INPUT || return 1
    ip6tables -w 5 -S INPUT || return 1
    if [[ -n ${ssh_peer:-} ]]; then
        if [[ $ssh_peer == *:* ]]; then ip -6 route get "$ssh_peer" | awk 'NR == 1'; else ip -4 route get "$ssh_peer" | awk 'NR == 1'; fi
    fi
}

# preflight отказывает при существующей установке и не меняет сеть.
preflight() {
    [[ $EUID -eq 0 ]] || fail 'Запустите helper от root.'
    [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Поддерживается только Linux amd64.'
    [[ -r /etc/os-release ]] || fail 'Не удалось определить ОС.'
    grep -qx 'ID=ubuntu' /etc/os-release || fail 'Поддерживается Ubuntu 24.04.'
    grep -qx 'VERSION_ID="24.04"' /etc/os-release || fail 'Поддерживается Ubuntu 24.04.'
    for program in curl sha256sum flock timeout stat ip ss iptables ip6tables od awk sed grep sort sync install cmp df; do
        command -v "$program" >/dev/null || fail "Нужна уже установленная утилита: $program."
    done
    [[ -x /usr/bin/docker && -S $docker_socket && $(stat -Lc '%u' "$docker_socket") == 0 ]] || fail 'Нужен root-owned локальный Docker Unix socket.'
    [[ -c /dev/net/tun && -d /lib/modules ]] || fail 'Нужны /dev/net/tun и /lib/modules.'
    [[ $(cat /proc/sys/net/ipv4/ip_forward) == 1 ]] || fail 'IPv4 forwarding должен быть заранее включён администратором.'
    safe_path /run/awg_vps_install.lock
    exec 9>/run/awg_vps_install.lock
    flock -n 9 || fail 'Другая операция установки/выпуска уже выполняется.'
    for path in "$state_root" "$awg_folder" "$dns_folder" /opt/amnezia/amnezia-awg /opt/amnezia/awg \
        /etc/amnezia/amneziawg /etc/amnezia/awg /etc/amneziawg /etc/wireguard/awg0.conf; do
        safe_path "$path"
        [[ ! -e $path ]] || fail 'Найдены существующие данные AWG/DNS или попытка установки. Нужна ручная проверка; перезаписи нет.'
    done
    for path in /var/lib/awg_vps_control/host/installation.json /var/lib/awg_vps_control/host/routing_manifest.json; do
        [[ ! -e $path && ! -L $path ]] || fail 'Панель уже привязана к установке; fresh install запрещён.'
    done
    safe_path /var/lib/awg_vps_control
    safe_path /opt/amnezia
    safe_path /run/awg_vps_install_docker
    [[ ! -e /run/awg_vps_install_docker ]] || fail 'Временный Docker config уже существует; проверьте незавершённую попытку.'
    install -d -m 0700 /run/awg_vps_install_docker
    docker_config=/run/awg_vps_install_docker
    # Здесь создаётся только пустой локальный config, сетевых/Docker записей ещё нет.
    docker_local version --format '{{.Server.APIVersion}}' >/dev/null || fail 'Docker daemon недоступен.'
    local security inventory network subnet bridge_members prefix free_kib networks subnets routes docker_root containers id bindings container_port host_port compose_version images occupied_port host_links
    compose_version=$(docker_local compose version --short) || fail 'Нужен Docker Compose CLI plugin.'
    [[ $compose_version =~ ^v?([0-9]+)\.[0-9]+\.[0-9]+([+-][0-9A-Za-z._-]+)?$ ]] || fail 'Не удалось определить версию Docker Compose plugin.'
    (( 10#${BASH_REMATCH[1]} >= 2 )) || fail 'Нужен Docker Compose CLI plugin версии не ниже 2.'
    security=$(docker_local info --format '{{json .SecurityOptions}}')
    [[ $security != *rootless* && $security != *userns* ]] || fail 'Rootless Docker и userns-remap не поддерживаются.'
    inventory=$(docker_local container ls -a --format '{{.Names}} {{.Image}}')
    if grep -Eiq 'amnezia[-_]?awg|amneziawg|wireguard|(^|[[:space:]])amnezia-dns([[:space:]]|$)' <<< "$inventory"; then
        fail 'Найден существующий VPN/DNS-контейнер, включая остановленные. Установка прекращена.'
    fi
    images=$(docker_local image ls --format '{{.Repository}}') || fail 'Не удалось проверить существующие image tags.'
    while read -r name; do
        [[ $name != "$awg_name" && $name != "$dns_name" ]] || fail 'Штатный image tag уже занят; существующий образ не заменяется.'
    done <<< "$images"
    containers=$(docker_local container ls -aq --no-trunc) || fail 'Не удалось проверить все Docker port bindings.'
    while read -r id; do
        [[ -n $id ]] || continue
        [[ $id =~ ^[0-9a-f]{64}$ ]] || fail 'Некорректный container ID при проверке портов.'
        bindings=$(docker_local container inspect "$id" --format '{{range $name, $bindings := .HostConfig.PortBindings}}{{range $bindings}}{{printf "%s %s\n" $name .HostPort}}{{end}}{{end}}') || fail 'Не удалось проверить Docker port bindings.'
        while read -r container_port host_port; do
            [[ $container_port != */udp || $host_port != "$port" ]] || fail 'UDP-порт занят Docker publication, включая остановленный контейнер.'
        done <<< "$bindings"
    done <<< "$containers"
    networks=$(docker_local network ls --filter name='^amnezia-dns-net$' --format '{{.ID}}') || fail 'Не удалось проверить имя DNS network.'
    [[ -z $networks ]] || fail 'Штатная DNS-сеть уже существует.'
    ! ip link show dev amn0 >/dev/null 2>&1 || fail 'Bridge amn0 уже существует.'
    bridge_members=$(docker_local network inspect bridge --format '{{len .Containers}}')
    [[ $bridge_members == 0 ]] || fail 'Default Docker bridge занят посторонними контейнерами.'
    occupied_port=$(ss -H -lun "sport = :$port") || fail 'Не удалось проверить UDP sockets.'
    [[ -z $occupied_port ]] || fail 'Выбранный UDP-порт уже занят.'
    if command -v awg >/dev/null; then
        local interfaces
        interfaces=$(timeout -s KILL 8 awg show interfaces) || fail 'Не удалось проверить host AWG.'
        [[ -z $interfaces ]] || fail 'Обнаружен host AWG.'
    fi
    host_links=$(ip -d -o link show) || fail 'Не удалось проверить host interfaces.'
    if grep -Eq '(^|[[:space:]])(amneziawg|wireguard)([[:space:]]|$)' <<< "$host_links"; then fail 'Обнаружен существующий VPN-интерфейс хоста.'; fi
    networks=$(docker_local network ls --format '{{.ID}}') || fail 'Не удалось прочитать Docker networks.'
    while read -r network; do
        [[ $network =~ ^[0-9a-f]{12,64}$ ]] || fail 'Docker вернул некорректный network ID.'
        subnets=$(docker_local network inspect "$network" --format '{{range .IPAM.Config}}{{println .Subnet}}{{end}}') || fail 'Не удалось проверить Docker subnet.'
        while read -r subnet; do
            [[ -z $subnet ]] || reject_subnet_overlap "$subnet"
        done <<< "$subnets"
    done <<< "$networks"
    routes=$(ip -4 route show table all | awk '{ if ($1 ~ /^(local|broadcast|unicast|unreachable|blackhole|prohibit|throw)$/) print $2; else print $1 }') || fail 'Не удалось проверить host routes.'
    while read -r prefix; do
        [[ -z $prefix ]] || reject_subnet_overlap "$prefix"
    done <<< "$routes"
    docker_root=$(docker_local info --format '{{.DockerRootDir}}')
    [[ $docker_root == /* && -d $docker_root ]] || fail 'Не подтверждён каталог Docker data.'
    free_kib=$(df -Pk -- "$docker_root" | awk 'NR==2 {print $4}')
    [[ $free_kib =~ ^[0-9]+$ && $free_kib -ge 2097152 ]] || fail 'Для сборки требуется не менее 2 GiB свободного места в разделе Docker.'
    ssh_peer=
    if [[ -n ${SSH_CONNECTION:-} ]]; then
        read -r ssh_peer _ <<< "$SSH_CONNECTION"
        [[ $ssh_peer =~ ^[0-9a-fA-F:.]+$ ]] || fail 'Неподдерживаемый формат SSH peer.'
    fi
    host_network_before=$(capture_host_network) || fail 'Не удалось зафиксировать исходную host/SSH сеть.'
    validate_manifest
}

# save_state атомарно фиксирует только метаданные и хеши, без ключей.
save_state() {
    local path="$state_root/state.json" temporary="$state_root/state.next" item separator=
    safe_path "$path"
    safe_path "$temporary"
    {
        printf '{\n  "schema_version":1,"operation_id":"%s","status":"%s","step":"%s","exit_code":%s,\n' "$operation_id" "$status" "$step" "$exit_code"
        printf '  "started_at":"%s","updated_at":"%s","manager_version":"%s",\n' "$started_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$manager_version"
        printf '  "upstream_repository":"%s","upstream_release":"%s","upstream_commit":"%s",\n' "$upstream_repository" "$upstream_release" "$upstream_commit"
        printf '  "container_name":"%s","dns_container_name":"%s","interface":"awg0","listen_port":%s,\n' "$awg_name" "$dns_name" "$port"
        printf '  "client_subnet":"10.8.1.0/24","docker_network":"%s","docker_subnet":"172.29.172.0/24",\n' "$network_name"
        printf '  "container_id":"%s","dns_container_id":"%s","network_id":"%s",\n' "$container_id" "$dns_container_id" "$network_id"
        printf '  "awg_base_image_id":"%s","awg_base_digest":"%s","dns_base_image_id":"%s","dns_base_digest":"%s",\n' "$awg_base_image_id" "$awg_base_digest" "$dns_base_image_id" "$dns_base_digest"
        printf '  "awg_image_id":"%s","dns_image_id":"%s","config_revision":"%s","rendered_manifest_sha256":"%s",\n' "$awg_image_id" "$dns_image_id" "$config_revision" "$rendered_manifest_sha256"
        printf '  "sources":['
        for item in "${source_paths[@]}"; do
            printf '%s{"path":"%s","sha256":"%s"}' "$separator" "$item" "${source_hashes[$item]}"
            separator=,
        done
        printf ']\n}\n'
    } > "$temporary"
    chmod 0600 "$temporary"
    sync -f "$temporary"
    mv -Tf -- "$temporary" "$path"
    sync -f "$state_root"
}

# collect_partial_ids сохраняет наблюдаемые ID после ошибки внутри составного upstream шага.
collect_partial_ids() {
    local observed candidate image
    case $step in
        prepare_awg_host|prepare_dns_host|build_awg|build_dns|run_dns|configure_dns|run_awg|configure_awg|start_awg|verify_ready)
            if [[ -z $network_id ]]; then
                observed=$(timeout -s KILL 5 /usr/bin/docker --host "unix://$docker_socket" --config "$docker_config" network inspect "$network_name" --format '{{.Id}} {{.Driver}} {{len .IPAM.Config}} {{(index .IPAM.Config 0).Subnet}} {{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null) || observed=
                candidate=${observed%% *}
                if [[ $candidate =~ ^[0-9a-f]{64}$ && $observed == "$candidate bridge 1 172.29.172.0/24 amn0" ]]; then network_id=$candidate; fi
            fi
            ;;
    esac
    case $step in
        run_dns|configure_dns|run_awg|configure_awg|start_awg|verify_ready)
            if [[ -z $dns_container_id && -n $dns_image_id ]]; then
                observed=$(timeout -s KILL 5 /usr/bin/docker --host "unix://$docker_socket" --config "$docker_config" container inspect "$dns_name" --format '{{.Id}} {{.Image}}' 2>/dev/null) || observed=
                read -r candidate image <<< "$observed"
                if [[ $candidate =~ ^[0-9a-f]{64}$ && $image == "$dns_image_id" ]]; then dns_container_id=$candidate; fi
            fi
            ;;
    esac
    case $step in
        run_awg|configure_awg|start_awg|verify_ready)
            if [[ -z $container_id && -n $awg_image_id ]]; then
                observed=$(timeout -s KILL 5 /usr/bin/docker --host "unix://$docker_socket" --config "$docker_config" container inspect "$awg_name" --format '{{.Id}} {{.Image}}' 2>/dev/null) || observed=
                read -r candidate image <<< "$observed"
                if [[ $candidate =~ ^[0-9a-f]{64}$ && $image == "$awg_image_id" ]]; then container_id=$candidate; fi
            fi
            ;;
    esac
    return 0
}

# finish сохраняет неопределённый результат и не удаляет созданные VPN-ресурсы.
finish() {
    local result=$?
    trap - EXIT INT TERM
    if [[ $state_started -eq 1 && $completed -eq 0 ]]; then
        collect_partial_ids || true
        status=manual_recovery_required
        exit_code=$result
        [[ $exit_code -ne 0 ]] || exit_code=1
        save_state || printf 'Не удалось обновить журнал; требуется ручная проверка.\n' >&2
        printf 'Установка остановлена на шаге %s. Ресурсы сохранены; журнал: %s/state.json\n' "$step" "$state_root" >&2
        result=$exit_code
    fi
    # Каталог содержит только собственный пустой config; не трогаем Docker state.
    if [[ ${docker_config:-} == /run/awg_vps_install_docker && -d $docker_config && ! -L $docker_config ]]; then
        rmdir -- "$docker_config" 2>/dev/null || true
    fi
    exit "$result"
}

# begin_state сохраняет намерение прежде скачивания образов и создания сети.
begin_state() {
    install -d -m 0700 /var/lib/awg_vps_control
    mkdir -m 0700 -- "$state_root"
    install -d -m 0700 "$state_root/source/awg" "$state_root/source/dns" "$state_root/rendered/awg" "$state_root/rendered/dns" "$state_root/logs"
    operation_id=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    [[ $operation_id =~ ^[0-9a-f]{32}$ ]] || fail 'Не удалось создать ID операции.'
    started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    if [[ -f $script_dir/../version ]]; then
        manager_version=$(tr -d '\r\n' < "$script_dir/../version")
        [[ $manager_version =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$ ]] || manager_version=unknown
    fi
    state_started=1
    step=download_sources
    save_state
}

# download_sources получает только проверенные файлы закреплённого commit.
download_sources() {
    local path actual
    for path in "${source_paths[@]}"; do
        curl --disable --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error \
            --connect-timeout 15 --max-time 90 --max-filesize 1048576 --retry 2 \
            --output "$state_root/source/$path" \
            "https://raw.githubusercontent.com/$upstream_repository/$upstream_commit/client/server_scripts/$path" \
            2>/dev/null || fail 'Не удалось скачать официальный исходный файл; код не выполнялся.'
        actual=$(sha256sum -- "$state_root/source/$path")
        [[ ${actual%% *} == "${source_hashes[$path]}" ]] || fail 'SHA-256 upstream не совпадает; код не выполнялся.'
    done
    cp -- "$script_dir/awg_upstream.sha256" "$state_root/upstream.sha256"
}

# random_range выбирает штатный случайный параметр без стороннего генератора.
random_range() {
    local value
    read -r value < <(od -An -N4 -tu4 /dev/urandom)
    [[ $value =~ ^[0-9]+$ ]] || fail 'Недоступен источник случайности.'
    printf '%s' "$((value % ($2 - $1 + 1) + $1))"
}

# render заменяет только перечисленные placeholders, оставляя генерацию ключей контейнеру.
render() {
    local source=$1 destination=$2 name=$3 folder=$4 content token replacement
    content=$(cat -- "$source")
    local -A values=(
        [CONTAINER_NAME]="$name" [DOCKERFILE_FOLDER]="$folder" [AWG_SERVER_PORT]="$port"
        [AWG_SUBNET_IP]=10.8.1.0 [WIREGUARD_SUBNET_CIDR]=24 [SERVER_IP_ADDRESS]=''
        [JUNK_PACKET_COUNT]="$junk_count" [JUNK_PACKET_MIN_SIZE]=10 [JUNK_PACKET_MAX_SIZE]=50
        [INIT_PACKET_JUNK_SIZE]=12 [RESPONSE_PACKET_JUNK_SIZE]=12 [COOKIE_REPLY_PACKET_JUNK_SIZE]=12 [TRANSPORT_PACKET_JUNK_SIZE]=12
        [INIT_PACKET_MAGIC_HEADER]=1 [RESPONSE_PACKET_MAGIC_HEADER]=2 [UNDERLOAD_PACKET_MAGIC_HEADER]=3 [TRANSPORT_PACKET_MAGIC_HEADER]=4
        [CONTENT_PADDING_ADDITION]='' [REKEY_AFTER_TIME]="$rekey_after" [REKEY_TIMEOUT]="$rekey_timeout"
        [REJECT_AFTER_TIME]="$reject_after" [KEEPALIVE_TIMEOUT]="$keepalive_timeout" [MAX_HANDSHAKE_ATTEMPTS]="$max_handshakes"
        [RANDOM_TRAILERS]=on [DISABLE_COOKIES]=on [SPECIAL_JUNK_1]='' [SPECIAL_JUNK_2]='' [SPECIAL_JUNK_3]='' [SPECIAL_JUNK_4]='' [SPECIAL_JUNK_5]=''
    )
    for token in "${!values[@]}"; do
        replacement=${values[$token]}
        content=${content//\$$token/$replacement}
    done
    while read -r token; do
        case $token in '$WIREGUARD_SERVER_PRIVATE_KEY'|'$WIREGUARD_SERVER_PUBLIC_KEY'|'$WIREGUARD_PSK'|'$HEADER_PROTECTION_KEY'|'$CUR_USER'|'$HOME') ;;
            *) fail 'В шаблоне остался непредусмотренный placeholder.' ;;
        esac
    done < <(grep -oE '\$[A-Z][A-Z0-9_]*' <<< "$content" | sort -u)
    printf '%s\n' "$content" > "$destination"
}

# write_host_wrapper ограничивает sudo точными командами закреплённых upstream файлов.
write_host_wrapper() {
    cat > "$state_root/rendered/host_wrapper.sh" <<EOF
set -euo pipefail
umask 077
unset BASH_ENV ENV DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_TLS_VERIFY DOCKER_CERT_PATH
for environment_name in \${!DOCKER_@} \${!BUILDX_@} \${!BUILDKIT_@}; do unset "\$environment_name"; done
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH LC_ALL=C
sudo() {
    case "\$*" in
        'mkdir -p $awg_folder'|'mkdir -p $dns_folder'|'chown root $awg_folder'|'chown root $dns_folder') command "\$@" ;;
        'docker network ls'|'docker network create --driver bridge --subnet=172.29.172.0/24 --opt com.docker.network.bridge.name=amn0 amnezia-dns-net'|\
'docker build --no-cache --pull -t $awg_name $awg_folder'|'docker build --no-cache --pull -t $dns_name $dns_folder'|\
'docker run -d --log-driver none --restart always --privileged --cap-add=NET_ADMIN --cap-add=SYS_MODULE -p $port:$port/udp -v /lib/modules:/lib/modules --sysctl=net.ipv4.conf.all.src_valid_mark=1 --name $awg_name $awg_name'|\
'docker run -d --log-driver none --restart always --network amnezia-dns-net --ip=172.29.172.254 --name $dns_name $dns_name'|\
'docker network connect amnezia-dns-net $awg_name') shift; command /usr/bin/docker --host unix://$docker_socket --config $docker_config "\$@" ;;
        *) printf 'Непредусмотренная команда upstream.\n' >&2; return 1 ;;
    esac
}
EOF
}

# prepare_rendered создаёт публичные шаблоны; ключей на этом шаге ещё нет.
prepare_rendered() {
    junk_count=$(random_range 4 6)
    # Диапазоны передаются протоколу буквально: runtime выбирает интервалы сам.
    rekey_after=100-120
    rekey_timeout=3-7
    reject_after=150-180
    keepalive_timeout=5-15
    max_handshakes=15-20
    local kind name folder path
    for kind in awg dns; do
        if [[ $kind == awg ]]; then name=$awg_name; folder=$awg_folder; else name=$dns_name; folder=$dns_folder; fi
        for path in prepare_host.sh build_container.sh; do render "$state_root/source/$path" "$state_root/rendered/$kind/$path" "$name" "$folder"; done
        for path in run_container.sh configure_container.sh; do render "$state_root/source/$kind/$path" "$state_root/rendered/$kind/$path" "$name" "$folder"; done
    done
    render "$state_root/source/awg/start.sh" "$state_root/rendered/awg/start.sh" "$awg_name" "$awg_folder"
    write_host_wrapper
}

# execute_host исполняет проверенный локальный wrapper и конкретный подготовленный скрипт.
execute_host() {
    local script=$1 limit=$2
    (ulimit -f 262144; timeout -s TERM -k 15 "$limit" bash --noprofile --norc -c 'source "$1"; source "$2"' _ "$state_root/rendered/host_wrapper.sh" "$state_root/rendered/$script") \
        > "$state_root/logs/${step}.log" 2>&1 || fail 'Официальный шаг установки завершился ошибкой; автоматической очистки нет.'
}

# image_identity проверяет точный ID образа и официальный digest выбранной базы.
image_identity() {
    local image=$1 repository=$2 digest digests
    selected_image_id=$(docker_local image inspect "$image" --format '{{.Id}}')
    [[ $selected_image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'Docker не подтвердил image ID.'
    selected_digest=
    digests=$(docker_local image inspect "$image" --format '{{range .RepoDigests}}{{println .}}{{end}}') || fail 'Не удалось прочитать RepoDigests официального образа.'
    while read -r digest; do
        if [[ $digest == "$repository"@sha256:* && ${digest##*@sha256:} =~ ^[0-9a-f]{64}$ ]]; then selected_digest=$digest; break; fi
    done <<< "$digests"
    [[ -n $selected_digest ]] || fail 'Официальный образ не имеет проверенного RepoDigest.'
}

# pull_bases закрепляет реальные digest вместо изменяемого latest до сборки.
pull_bases() {
    step=pull_awg_base; save_state
    timeout -s TERM -k 15 600 /usr/bin/docker --host "unix://$docker_socket" --config "$docker_config" pull --platform linux/amd64 amneziavpn/amneziawg-go:latest > "$state_root/logs/pull_awg.log" 2>&1 || fail 'Не удалось загрузить официальную AWG base image.'
    image_identity amneziavpn/amneziawg-go:latest amneziavpn/amneziawg-go
    awg_base_image_id=$selected_image_id; awg_base_digest=$selected_digest; save_state
    step=pull_dns_base; save_state
    timeout -s TERM -k 15 600 /usr/bin/docker --host "unix://$docker_socket" --config "$docker_config" pull --platform linux/amd64 mvance/unbound:latest > "$state_root/logs/pull_dns.log" 2>&1 || fail 'Не удалось загрузить официальную DNS base image.'
    image_identity mvance/unbound:latest mvance/unbound
    dns_base_image_id=$selected_image_id; dns_base_digest=$selected_digest
    sed "1cFROM $awg_base_digest" "$state_root/source/awg/Dockerfile" > "$state_root/rendered/awg/Dockerfile"
    sed "1cFROM $dns_base_digest" "$state_root/source/dns/Dockerfile" > "$state_root/rendered/dns/Dockerfile"
    (cd "$state_root/rendered" && sha256sum host_wrapper.sh awg/prepare_host.sh awg/build_container.sh awg/run_container.sh awg/configure_container.sh awg/start.sh awg/Dockerfile dns/prepare_host.sh dns/build_container.sh dns/run_container.sh dns/configure_container.sh dns/Dockerfile) > "$state_root/rendered.sha256"
    rendered_manifest_sha256=$(sha256sum "$state_root/rendered.sha256"); rendered_manifest_sha256=${rendered_manifest_sha256%% *}
    save_state
}

# verify_network подтверждает именно новую штатную DNS-сеть перед каждым следующим шагом.
verify_network() {
    local actual
    actual=$(docker_local network inspect "$network_name" --format '{{.Id}} {{.Driver}} {{.EnableIPv6}} {{len .IPAM.Config}} {{(index .IPAM.Config 0).Subnet}} {{index .Options "com.docker.network.bridge.name"}}')
    [[ $actual == "$network_id bridge false 1 172.29.172.0/24 amn0" && $network_id =~ ^[0-9a-f]{64}$ ]] || fail 'DNS network не соответствует созданной топологии.'
}

# verify_container запрещает запись при смене ID, image или остановке контейнера.
verify_container() {
    local name=$1 id=$2 image=$3 actual
    actual=$(docker_local container inspect "$name" --format '{{.Id}} {{.Image}} {{.State.Running}}')
    [[ $id =~ ^[0-9a-f]{64}$ && $actual == "$id $image true" ]] || fail 'Новый контейнер изменён или остановлен; дальнейшая запись запрещена.'
}

# install_containers выполняет штатные шаги только для новых, закреплённых ресурсов.
install_containers() {
    step=prepare_awg_host; save_state
    execute_host awg/prepare_host.sh 60
    network_id=$(docker_local network inspect "$network_name" --format '{{.Id}}')
    [[ $network_id =~ ^[0-9a-f]{64}$ ]] || fail 'Docker не подтвердил созданную сеть.'
    save_state; verify_network
    step=prepare_dns_host; save_state
    # Сеть общая: повторный upstream prepare с grep -q ненадёжен под pipefail.
    verify_network
    safe_path "$dns_folder"
    [[ ! -e $dns_folder && ! -L $dns_folder ]] || fail 'Каталог DNS появился после preflight; перезаписи нет.'
    install -d -m 0700 -- "$dns_folder"
    verify_network
    install -m 0600 "$state_root/rendered/awg/Dockerfile" "$awg_folder/Dockerfile"
    install -m 0600 "$state_root/rendered/dns/Dockerfile" "$dns_folder/Dockerfile"
    step=build_awg; save_state; execute_host awg/build_container.sh 1800
    awg_image_id=$(docker_local image inspect "$awg_name" --format '{{.Id}}')
    [[ $awg_image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'Не подтверждён собранный AWG image.'
    save_state
    step=build_dns; save_state; execute_host dns/build_container.sh 1800
    dns_image_id=$(docker_local image inspect "$dns_name" --format '{{.Id}}')
    [[ $dns_image_id =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'Не подтверждён собранный DNS image.'
    save_state; verify_network
    step=run_dns; save_state; execute_host dns/run_container.sh 120
    dns_container_id=$(docker_local container inspect "$dns_name" --format '{{.Id}}')
    [[ $dns_container_id =~ ^[0-9a-f]{64}$ ]] || fail 'Не подтверждён созданный DNS container.'
    save_state; verify_container "$dns_name" "$dns_container_id" "$dns_image_id"
    step=configure_dns; save_state
    docker_local exec -i "$dns_container_id" sh -e < "$state_root/rendered/dns/configure_container.sh" >/dev/null 2>&1 || fail 'Не прошёл штатный шаг DNS configure.'
    step=run_awg; save_state; execute_host awg/run_container.sh 120
    container_id=$(docker_local container inspect "$awg_name" --format '{{.Id}}')
    [[ $container_id =~ ^[0-9a-f]{64}$ ]] || fail 'Не подтверждён созданный AWG container.'
    save_state; verify_container "$awg_name" "$container_id" "$awg_image_id"; verify_network
    local membership
    membership=$(docker_local container inspect "$container_id" --format '{{len .NetworkSettings.Networks}} {{(index .NetworkSettings.Networks "amnezia-dns-net").NetworkID}}')
    [[ $membership == "2 $network_id" ]] || fail 'AWG не получил штатную пару сетей.'
    membership=$(docker_local container inspect "$dns_container_id" --format '{{len .NetworkSettings.Networks}} {{(index .NetworkSettings.Networks "amnezia-dns-net").NetworkID}} {{(index .NetworkSettings.Networks "amnezia-dns-net").IPAddress}}')
    [[ $membership == "1 $network_id 172.29.172.254" ]] || fail 'DNS не получил штатную сеть/адрес.'
    step=configure_awg; save_state
    # Ключ HeaderProtectionKey появляется только внутри нового AWG, не в argv/host files.
    { printf 'umask 077\nset -e\nHEADER_PROTECTION_KEY=$(awg genkey)\n'; cat "$state_root/rendered/awg/configure_container.sh"; } | \
        docker_local exec -i "$container_id" timeout -s KILL 30 sh -e >/dev/null 2>&1 || fail 'Штатный AWG configure не завершён; повторять его автоматически нельзя.'
    verify_container "$awg_name" "$container_id" "$awg_image_id"
    config_revision=$(docker_local exec "$container_id" timeout -s KILL 8 sha256sum /opt/amnezia/awg/awg0.conf)
    config_revision=${config_revision%% *}
    [[ $config_revision =~ ^[0-9a-f]{64}$ ]] || fail 'Не подтверждён native AWG config.'
    save_state
    step=start_awg; save_state
    docker_local cp "$state_root/rendered/awg/start.sh" "$container_id:/opt/amnezia/start.sh" >/dev/null 2>&1 || fail 'Не удалось разместить штатный start.sh.'
    docker_local exec "$container_id" timeout -s KILL 8 chmod 0700 /opt/amnezia/start.sh >/dev/null 2>&1 || fail 'Не удалось установить права start.sh.'
    # Без -e: ожидаемый первый down в официальном скрипте может завершиться ненулевым кодом.
    docker_local exec -d "$container_id" /opt/amnezia/start.sh >/dev/null 2>&1 || fail 'Не удалось запустить штатный start.sh.'
}

# awg_rules_ready проверяет восемь штатных правил без изменения firewall контейнера.
awg_rules_ready() {
    docker_local exec -i "$container_id" timeout -s KILL 10 sh -e >/dev/null 2>&1 <<'EOF'
iptables -w 1 -C INPUT -i awg0 -j ACCEPT
iptables -w 1 -C FORWARD -i awg0 -j ACCEPT
iptables -w 1 -C OUTPUT -o awg0 -j ACCEPT
iptables -w 1 -C FORWARD -i awg0 -o eth0 -s 10.8.1.0/24 -j ACCEPT
iptables -w 1 -C FORWARD -i awg0 -o eth1 -s 10.8.1.0/24 -j ACCEPT
iptables -w 1 -C FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -w 1 -t nat -C POSTROUTING -s 10.8.1.0/24 -o eth0 -j MASQUERADE
iptables -w 1 -t nat -C POSTROUTING -s 10.8.1.0/24 -o eth1 -j MASQUERADE
EOF
}

# verify_ready проверяет интерфейс/порт/firewall/DNS и сохранность административного пути.
verify_ready() {
    step=verify_ready; save_state
    local deadline=$((SECONDS + 90)) interfaces listen_port awg_ready=0 dns_ready=0 host_network_after
    while (( SECONDS < deadline )); do
        verify_container "$awg_name" "$container_id" "$awg_image_id"
        interfaces=$(docker_local exec "$container_id" timeout -s KILL 8 awg show interfaces 2>/dev/null) || interfaces=
        listen_port=$(docker_local exec "$container_id" timeout -s KILL 8 awg show awg0 listen-port 2>/dev/null) || listen_port=
        if [[ $interfaces == awg0 && $listen_port == "$port" ]] && awg_rules_ready; then awg_ready=1; break; fi
        sleep 2
    done
    [[ $awg_ready -eq 1 ]] || fail 'AWG не подтвердил интерфейс, listen-port и все штатные forwarding/NAT rules.'
    docker_local exec "$container_id" timeout -s KILL 8 test -s /opt/amnezia/awg/awg0.conf >/dev/null 2>&1 || fail 'Отсутствует native AWG config.'
    docker_local exec "$container_id" timeout -s KILL 8 awg show awg0 peers >/dev/null 2>&1 || fail 'Не удалось прочитать native AWG peers.'
    verify_container "$dns_name" "$dns_container_id" "$dns_image_id"
    deadline=$((SECONDS + 60))
    while (( SECONDS < deadline )); do
        if docker_local exec "$container_id" timeout -s KILL 10 nslookup example.com 172.29.172.254 >/dev/null 2>&1; then dns_ready=1; break; fi
        sleep 2
    done
    [[ $dns_ready -eq 1 ]] || fail 'Штатный DNS не подтвердил разрешение внешнего имени.'
    host_network_after=$(capture_host_network) || fail 'Не удалось повторно проверить административную сеть.'
    [[ $host_network_after == "$host_network_before" ]] || fail 'Административная сеть изменилась; требуется ручная проверка SSH. Автоматического отката чужих правил нет.'
    verify_network
    step=complete
    status=succeeded
    save_state
    completed=1
    printf 'AWG 3.1 и DNS установлены: %s, UDP %s. WARP не включался.\n' "$awg_name" "$port"
    printf 'После установки панели: awg-vps-control attach %s %s %s\n' "$awg_name" "$network_name" "$dns_name"
    printf 'Происхождение и IDs: %s/state.json\n' "$state_root"
}

parse_arguments "$@"
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
preflight
printf 'Установка официального AmneziaVPN %s, AWG 3.1; commit %s; UDP %s.\n' "$upstream_release" "$upstream_commit" "$port"
begin_state
download_sources
prepare_rendered
pull_bases
install_containers
verify_ready
