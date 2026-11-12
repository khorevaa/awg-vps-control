//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// adapterPeerScript содержит только фиксированные файловые операции и не интерпретирует клиентские данные.
const adapterPeerScript = `
umask 077
mode=$1
iface=$2
op=$3
before_conf=$4
before_table=$5
after_conf=$6
after_table=$7
allow_active=$8
before_strip=$9
after_strip=${10}
native=/opt/amnezia/awg
cfg=$native/$iface.conf
table=$native/clientsTable
base=$native/.awg_vps_control
active=$base/active
safe_dir() {
    [ -d "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u "$1")" = 0 ] || exit 74
    permissions=$(stat -c %a "$1")
    [ $((0$permissions & 022)) = 0 ] || exit 74
}
safe_file() {
    [ -f "$1" ] && [ ! -L "$1" ] && [ "$(stat -c %u "$1")" = 0 ] && [ "$(stat -c %h "$1")" = 1 ] || exit 74
    permissions=$(stat -c %a "$1")
    [ $((0$permissions & 022)) = 0 ] || exit 74
}
hash_file() { safe_file "$1"; sha256sum "$1" | cut -d ' ' -f 1; }
table_hash() {
    if [ -e "$table" ] || [ -L "$table" ]; then hash_file "$table"; else printf absent; fi
}
check_current() {
    [ "$(hash_file "$cfg")" = "$1" ] && [ "$(table_hash)" = "$2" ] || exit 53
}
sync_files() { timeout -s KILL 5 sync; }
owned_active() {
    safe_dir "$active"
    safe_file "$active/owner"
    [ "$(cat "$active/owner")" = "$op" ] || exit 73
    safe_file "$active/phase"
}
remove_owned() {
    target=$1
    safe_dir "$target"
    safe_file "$target/owner"
    owner=$(cat "$target/owner")
    [ ${#owner} = 32 ] || exit 74
    case "$owner" in *[!a-f0-9]*) exit 74;; esac
    for file in "$target"/* "$target"/.[!.]* "$target"/..?*; do
        [ -e "$file" ] || [ -L "$file" ] || continue
        case "${file##*/}" in owner|phase|old.conf|old.clients|next.conf|next.clients|next.strip|restore.conf|restore.clients|install.conf|install.clients|old.strip) safe_file "$file";; *) exit 74;; esac
    done
    for file in "$target"/*; do [ ! -e "$file" ] || rm -- "$file"; done
    rmdir "$target"
}
for program in timeout sh stat sha256sum cut cat cp mv chmod mkdir rmdir rm sync awg awg-quick; do command -v "$program" >/dev/null || exit 74; done
for directory in /opt /opt/amnezia "$native"; do safe_dir "$directory"; done
safe_file "$cfg"
if [ -e "$table" ] || [ -L "$table" ]; then safe_file "$table"; fi
if [ -e "$native/wireguard_psk.key" ] || [ -L "$native/wireguard_psk.key" ]; then safe_file "$native/wireguard_psk.key"; fi
if [ -e "$base" ] || [ -L "$base" ]; then
    safe_dir "$base"
    safe_file "$base/format"
    [ "$(cat "$base/format")" = awg_vps_control_peers_v1 ] || exit 74
fi
if [ "$mode" = check ]; then
    if [ "$allow_active" != true ] && { [ -e "$active" ] || [ -L "$active" ]; }; then exit 73; fi
    exit 0
fi
if [ "$mode" = prepare ]; then
    check_current "$before_conf" "$before_table"
    if [ ! -e "$base" ]; then
        mkdir -m 700 "$base"
        printf '%s\n' awg_vps_control_peers_v1 > "$base/format"
        sync_files
    fi
    [ ! -e "$active" ] && [ ! -L "$active" ] || exit 73
    mkdir -m 700 "$active"
    printf '%s\n' "$op" > "$active/owner"
    printf '%s\n' prepared > "$active/phase"
    cp -- "$cfg" "$active/old.conf"
    chmod 600 "$active/old.conf"
    if [ "$before_table" != absent ]; then cp -- "$table" "$active/old.clients"; chmod 600 "$active/old.clients"; fi
    [ "$(hash_file "$active/old.conf")" = "$before_conf" ] || exit 53
    if [ "$before_table" != absent ]; then [ "$(hash_file "$active/old.clients")" = "$before_table" ] || exit 53; fi
    check_current "$before_conf" "$before_table"
    sync_files
    exit 0
fi
owned_active
if [ "$mode" = strip_next ] || [ "$mode" = strip_old ]; then
    [ "$(cat "$active/phase")" = prepared ] || exit 73
    source=next
    [ "$mode" != strip_old ] || source=old
    safe_file "$active/$source.conf"
    timeout -s KILL 8 awg-quick strip "$active/$source.conf" > "$active/$source.strip"
    safe_file "$active/$source.strip"
    [ -s "$active/$source.strip" ] || exit 74
    cat -- "$active/$source.strip"
    exit 0
fi
if [ "$mode" = abort ]; then
    [ "$(cat "$active/phase")" = prepared ] || exit 73
    remove_owned "$active"
    sync_files
    exit 0
fi
if [ "$mode" = apply ]; then
    [ "$(cat "$active/phase")" = prepared ] || exit 73
    check_current "$before_conf" "$before_table"
    [ "$(hash_file "$active/next.conf")" = "$after_conf" ] && [ "$(hash_file "$active/next.clients")" = "$after_table" ] || exit 74
    [ "$(hash_file "$active/old.conf")" = "$before_conf" ] || exit 74
    if [ "$before_table" != absent ]; then [ "$(hash_file "$active/old.clients")" = "$before_table" ] || exit 74; fi
    if [ "$before_conf" != "$after_conf" ]; then
        [ -s "$active/next.strip" ] && [ -s "$active/old.strip" ] || exit 74
        [ "$(hash_file "$active/next.strip")" = "$after_strip" ] && [ "$(hash_file "$active/old.strip")" = "$before_strip" ] || exit 74
    fi
    check_current "$before_conf" "$before_table"
    printf '%s\n' applying > "$active/phase"
    sync_files
    if [ "$before_conf" != "$after_conf" ]; then cp -- "$active/next.conf" "$active/install.conf"; chmod 600 "$active/install.conf"; mv -- "$active/install.conf" "$cfg"; fi
    cp -- "$active/next.clients" "$active/install.clients"
    chmod 600 "$active/install.clients"
    mv -- "$active/install.clients" "$table"
    sync_files
    if [ "$before_conf" != "$after_conf" ]; then timeout -s KILL 8 awg syncconf "$iface" "$active/next.strip"; fi
    check_current "$after_conf" "$after_table"
    printf '%s\n' applied > "$active/phase"
    sync_files
    exit 0
fi
if [ "$mode" = rollback ]; then
    phase=$(cat "$active/phase")
    case "$phase" in applying|applied|rolling_back) ;; *) exit 73;; esac
    current_conf=$(hash_file "$cfg")
    current_table=$(table_hash)
    { [ "$current_conf" = "$before_conf" ] || [ "$current_conf" = "$after_conf" ]; } || exit 53
    { [ "$current_table" = "$before_table" ] || [ "$current_table" = "$after_table" ]; } || exit 53
    [ "$(hash_file "$active/old.conf")" = "$before_conf" ] || exit 74
    if [ "$before_table" != absent ]; then [ "$(hash_file "$active/old.clients")" = "$before_table" ] || exit 74; fi
    printf '%s\n' rolling_back > "$active/phase"
    sync_files
    cp -- "$active/old.conf" "$active/restore.conf"
    chmod 600 "$active/restore.conf"
    mv -- "$active/restore.conf" "$cfg"
    if [ "$before_table" = absent ]; then
        if [ -e "$table" ]; then rm -- "$table"; fi
    else
        cp -- "$active/old.clients" "$active/restore.clients"
        chmod 600 "$active/restore.clients"
        mv -- "$active/restore.clients" "$table"
    fi
    sync_files
    if [ "$before_conf" != "$after_conf" ]; then
        [ -s "$active/old.strip" ] && [ "$(hash_file "$active/old.strip")" = "$before_strip" ] || exit 74
        timeout -s KILL 8 awg syncconf "$iface" "$active/old.strip"
    fi
    check_current "$before_conf" "$before_table"
    printf '%s\n' rolled_back > "$active/phase"
    sync_files
    exit 0
fi
if [ "$mode" = finish ] || [ "$mode" = rollback_finish ]; then
    if [ "$mode" = finish ]; then
        [ "$(cat "$active/phase")" = applied ] || exit 73
        check_current "$after_conf" "$after_table"
    else
        [ "$(cat "$active/phase")" = rolled_back ] || exit 73
        check_current "$before_conf" "$before_table"
    fi
    if [ -e "$base/last" ] || [ -L "$base/last" ]; then remove_owned "$base/last"; fi
    mv -- "$active" "$base/last"
    sync_files
    exit 0
fi
exit 74
`

// peerCommand ограничивает shell фиксированным протоколом и проверенными аргументами без секретов.
func (client *DockerClient) peerCommand(ctx context.Context, id, mode, iface, operationID, beforeConfig, beforeTable, afterConfig, afterTable string, allowActive bool, stripHashes ...string) ([]byte, int, *APIError) {
	if !dockerIDPattern.MatchString(id) || !awgInterfacePattern.MatchString(iface) {
		return nil, -1, failure(422, "invalid_payload", "Некорректная native операция.")
	}
	switch mode {
	case "check":
	case "prepare", "strip_next", "strip_old", "apply", "rollback", "finish", "rollback_finish", "abort":
		if !operationIDPattern.MatchString(operationID) || !revisionPattern.MatchString(beforeConfig) || beforeTable != "absent" && !revisionPattern.MatchString(beforeTable) || !revisionPattern.MatchString(afterConfig) || !revisionPattern.MatchString(afterTable) {
			return nil, -1, failure(422, "invalid_payload", "Некорректная native транзакция.")
		}
	default:
		return nil, -1, failure(422, "invalid_payload", "Native действие запрещено.")
	}
	beforeStrip, afterStrip := "", ""
	if len(stripHashes) == 2 {
		beforeStrip, afterStrip = stripHashes[0], stripHashes[1]
	} else if len(stripHashes) != 0 {
		return nil, -1, failure(422, "invalid_payload", "Некорректные strip hashes.")
	}
	if beforeConfig != afterConfig && (mode == "apply" || mode == "rollback") && (!revisionPattern.MatchString(beforeStrip) || !revisionPattern.MatchString(afterStrip)) {
		return nil, -1, failure(422, "invalid_payload", "Strip конфигурации не проверены.")
	}
	command := []string{"timeout", "-s", "KILL", "35", "sh", "-ceu", adapterPeerScript, "peer-transaction", mode, iface, operationID, beforeConfig, beforeTable, afterConfig, afterTable, strconv.FormatBool(allowActive), beforeStrip, afterStrip}
	return client.runExec(ctx, id, command, 40*time.Second)
}

// peerArchive отправляет два фиксированных обычных файла в собственный закрытый staging.
func (client *DockerClient) peerArchive(ctx context.Context, id string, files AdapterPeerFiles) *APIError {
	if !dockerIDPattern.MatchString(id) || len(files.Config) == 0 || len(files.Config) > adapterPeerFileLimit || len(files.Table) == 0 || len(files.Table) > adapterPeerFileLimit {
		return failure(422, "invalid_payload", "Недопустимый размер native файлов.")
	}
	var body bytes.Buffer
	writer := tar.NewWriter(&body)
	for _, name := range []string{"next.conf", "next.clients"} {
		content := files.Config
		if name == "next.clients" {
			content = files.Table
		}
		if writer.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(content)), Typeflag: tar.TypeReg, Uid: 0, Gid: 0}) != nil {
			return failure(500, "archive_failed", "Не удалось подготовить native staging.")
		}
		if _, err := writer.Write(content); err != nil {
			return failure(500, "archive_failed", "Не удалось подготовить native staging.")
		}
	}
	if writer.Close() != nil {
		return failure(500, "archive_failed", "Не удалось завершить native staging.")
	}
	defer clear(body.Bytes())
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://docker"+dockerAPIPrefix+"/containers/"+id+"/archive?path="+url.QueryEscape("/opt/amnezia/awg/.awg_vps_control/active")+"&noOverwriteDirNonDir=1&copyUIDGID=true", &body)
	if err != nil {
		return failure(500, "archive_failed", "Не удалось подготовить Docker archive.")
	}
	request.Header.Set("Content-Type", "application/x-tar")
	response, err := client.http.Do(request)
	if err != nil {
		return failure(503, "docker_unavailable", "Docker не подтвердил запись staging.")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return failure(502, "docker_rejected", "Docker отклонил запись staging.")
	}
	return nil
}
