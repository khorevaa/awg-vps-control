#!/usr/bin/env bash
set -euo pipefail
umask 077

# Загружается только опубликованный Linux amd64 bundle официального репозитория.
release_repository=khorevaa/awg-vps-control
release_archive=awg_vps_control_linux_amd64.tar.gz

release_error() { printf 'Загрузка выпуска: %s\n' "$*" >&2; exit 1; }

validate_release_tag() {
    [[ ${#1} -le 64 && $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+([._-][0-9A-Za-z][0-9A-Za-z._-]*)?$ ]] || release_error 'Нужен опубликованный версионный тег вида v0.1.0; ветки develop/main не поддерживаются.'
}

download_https() {
    local url=$1 output=$2 limit=$3
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error \
        --location --retry 2 --connect-timeout 15 --max-time 180 --max-filesize "$limit" \
        --output "$output" "$url"
}

resolve_release_tag() {
    local requested=$1 temporary=$2 response tag
    if [[ $requested != latest ]]; then validate_release_tag "$requested"; printf '%s\n' "$requested"; return; fi
    response="$temporary/release_metadata.json"
    download_https "https://api.github.com/repos/$release_repository/releases/latest" "$response" 1048576 || release_error 'Не удалось найти последний опубликованный GitHub release (его может ещё не быть). Используйте локально собранный bundle или конкретный опубликованный тег.'
    # GitHub REST отдаёт tag_name отдельным скалярным полем. Escaped/повторное поле отклоняется.
    tag=$(sed -nE 's/^[[:space:]]*"tag_name":[[:space:]]*"(v[0-9A-Za-z._-]+)"[[:space:]]*,?[[:space:]]*$/\1/p' "$response")
    validate_release_tag "$tag"
    printf '%s\n' "$tag"
}

verify_archive_checksum() {
    local archive=$1 checksum=$2 expected filename extra actual lines
    lines=$(awk 'END { print NR }' "$checksum")
    [[ $lines == 1 ]] || release_error 'SHA-256 файл должен содержать ровно одну запись.'
    read -r expected filename extra < "$checksum" || release_error 'Не удалось прочитать SHA-256.'
    filename=${filename#\*}
    [[ $expected =~ ^[0-9a-fA-F]{64}$ && $filename == "$release_archive" && -z $extra ]] || release_error 'Неверный формат SHA-256 или имя архива.'
    actual=$(sha256sum -- "$archive")
    [[ ${actual:0:64} == "${expected,,}" ]] || release_error 'SHA-256 архива не совпадает. Установщик не запускался.'
}

# Проверка выполняется ДО распаковки; принимаются только обычные файлы и каталоги release/.
verify_archive_members() {
    local archive=$1 directory=$2 member kind count=0
    local -A members=()
    LC_ALL=C tar --list --absolute-names --gzip --file "$archive" --quoting-style=escape > "$directory/archive_members.txt" || release_error 'Повреждённый tar archive.'
    while IFS= read -r member; do
        [[ $member =~ ^release(/[0-9A-Za-z_.-]+)*/?$ && $member != *'/../'* && $member != */.. && $member != *'/./'* && $member != */. ]] || release_error 'Архив содержит небезопасный путь.'
        member=${member%/}
        [[ -z ${members[$member]+present} ]] || release_error 'Архив содержит повторяющийся путь.'
        members[$member]=1
        count=$((count + 1))
        [[ $count -le 4096 ]] || release_error 'В архиве слишком много файлов.'
    done < "$directory/archive_members.txt"
    [[ $count -gt 0 && -n ${members[release/install.sh]+present} && -n ${members[release/manifest.sha256]+present} && -n ${members[release/bin/awg_control]+present} && -n ${members[release/bin/awg_web]+present} ]] || release_error 'Архив не содержит полный release bundle.'
    LC_ALL=C tar --list --absolute-names --verbose --gzip --file "$archive" --quoting-style=escape > "$directory/archive_details.txt" || release_error 'Не удалось проверить типы файлов архива.'
    while IFS= read -r member; do
        kind=${member:0:1}
        [[ $kind == - || $kind == d ]] || release_error 'Ссылки, устройства и специальные файлы в release archive запрещены.'
    done < "$directory/archive_details.txt"
}

download_release() {
    [[ $# -eq 2 ]] || release_error 'Использование: download_release.sh <v0.1.0|latest> <новый-каталог>'
    local requested=$1 directory=$2 tag url version command_name
    for command_name in curl tar sha256sum sed awk; do command -v "$command_name" >/dev/null || release_error "Не найдена обязательная команда: $command_name"; done
    [[ ! -e $directory && ! -L $directory ]] || release_error 'Для загрузки требуется новый, ещё не существующий каталог.'
    mkdir -m 0700 -- "$directory"
    directory=$(CDPATH= cd -- "$directory" && pwd -P)
    tag=$(resolve_release_tag "$requested" "$directory")
    printf 'Официальный выпуск: %s (%s)\n' "$tag" "$release_repository" >&2
    url="https://github.com/$release_repository/releases/download/$tag/$release_archive"
    download_https "$url.sha256" "$directory/$release_archive.sha256" 4096 || release_error 'У опубликованного выпуска нет доступного SHA-256. Установка остановлена.'
    download_https "$url" "$directory/$release_archive" 134217728 || release_error 'Не удалось скачать release archive. Используйте локальный bundle или повторите загрузку позже.'
    verify_archive_checksum "$directory/$release_archive" "$directory/$release_archive.sha256"
    verify_archive_members "$directory/$release_archive" "$directory"
    tar --extract --gzip --file "$directory/$release_archive" --directory "$directory" --no-same-owner --no-same-permissions
    [[ -f $directory/release/version ]] || release_error 'В выпуске отсутствует version.'
    version=$(tr -d '\r\n' < "$directory/release/version")
    [[ v$version == "$tag" ]] || release_error 'Версия bundle не совпадает с запрошенным тегом.'
    printf '%s/release\n' "$directory"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then download_release "$@"; fi
