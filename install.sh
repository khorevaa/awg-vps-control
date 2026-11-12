#!/usr/bin/env bash
set -euo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || { echo 'Linux amd64 is required.' >&2; exit 1; }
for command in docker systemctl systemd-tmpfiles sha256sum flock; do
    command -v "$command" >/dev/null || { printf 'Missing prerequisite: %s (not installed automatically)\n' "$command" >&2; exit 1; }
done
docker compose version >/dev/null
docker info >/dev/null
source_dir=$(cd -- "${1:-$(dirname -- "${BASH_SOURCE[0]}")}" && pwd -P)
[[ -f $source_dir/manifest.sha256 && -f $source_dir/bin/awg_web && -f $source_dir/bin/awg_control ]] || {
    echo 'Build a release with scripts/build_release.sh or scripts/build_release.ps1 first.' >&2
    exit 1
}
chmod 0755 "$source_dir/bin/awg_control"
"$source_dir/bin/awg_control" install-tools verify-release "$source_dir"
version=$(tr -d '\r\n' < "$source_dir/version")
revision=$(tr -d '\r\n' < "$source_dir/source_revision")
[[ $version =~ ^[0-9A-Za-z][0-9A-Za-z._-]{0,40}$ && $revision =~ ^[a-f0-9]{40}(-dirty)?$ ]] || { echo 'Invalid release identity.' >&2; exit 1; }
digest=$(sha256sum "$source_dir/manifest.sha256")
tag="$version-${digest:0:12}"
root=/opt/awg_vps_control
release="$root/releases/$tag"
exec 9>/run/awg_vps_install.lock
flock -n 9 || { echo 'Another lifecycle operation is running.' >&2; exit 1; }
for directory in "$root" /etc/awg_vps_control /var/lib/awg_vps_control; do
    [[ ! -L $directory ]] || { echo 'Unsafe installation path.' >&2; exit 1; }
    install -d -o root -g root -m 0700 "$directory"
done
install -d -m 0700 "$root/releases"
if [[ ! -d $release ]]; then
    install -d -m 0700 "$release"
    cp -R -- "$source_dir/." "$release/"
    chown -R root:root "$release"
fi
(cd "$release" && sha256sum --check --status manifest.sha256)
chmod 0755 "$release/bin/awg_web" "$release/bin/awg_control" "$release/scripts/awg_vps_control.sh" "$release/awg_vps_control.sh"
printf 'AWG_UI_IMAGE_TAG=%s\n' "$tag" > "$release/runtime.env"
"$release/bin/awg_control" install-tools init
"$release/bin/awg_control" warp check-config
for component in web control; do
    runtime_user=10001:10001
    [[ $component != control ]] || runtime_user=10002:10001
    docker build --network=none -f "$release/scripts/runtime_dockerfile" \
        --build-arg "COMPONENT=$component" --build-arg "RUNTIME_USER=$runtime_user" \
        --build-arg "VERSION=$version" --build-arg "REVISION=$revision" \
        -t "awg_vps_$component:$tag" "$release"
done
previous=''
if [[ -L $root/current ]]; then previous=$(readlink -f "$root/current");
elif [[ -e $root/current ]]; then echo 'Current release path must be a symlink.' >&2; exit 1; fi
if [[ -n $previous && $previous != "$root/releases/"* ]]; then echo 'Unsafe current release link.' >&2; exit 1; fi

rollback_install() {
    result=$?
    trap - ERR
    if [[ -n $previous ]]; then
        "$release/scripts/awg_vps_control.sh" stop-ui || true
        systemctl stop awg_vps_warp.service || true
        ln -sfn "$previous" "$root/current.next"
        mv -Tf "$root/current.next" "$root/current"
        cp -- "$previous"/systemd/*.service /etc/systemd/system/
        if [[ -f $previous/systemd/awg_vps_control.conf ]]; then
            install -m 0644 "$previous/systemd/awg_vps_control.conf" /etc/tmpfiles.d/awg_vps_control.conf
            systemd-tmpfiles --create /etc/tmpfiles.d/awg_vps_control.conf
        fi
        if [[ -f $previous/systemd/awg_vps_warp.service && -f $previous/awg_vps_control.sh ]]; then
            ln -sfn "$root/current/awg_vps_control.sh" /usr/local/bin/awg-vps-control
        else
            ln -sfn "$root/current/scripts/awg_vps_control.sh" /usr/local/bin/awg-vps-control
        fi
        systemctl daemon-reload
        restored=0
        if [[ -f $previous/systemd/awg_vps_warp.service ]]; then
            systemctl enable --now awg_vps_warp.service || true
            "$previous/scripts/awg_vps_control.sh" start-ui || true
        else
            systemctl disable awg_vps_warp.service || true
            systemctl enable awg_vps_host.service awg_vps_supervisor.service awg_vps_ui.service || true
            systemctl restart awg_vps_host.service awg_vps_supervisor.service awg_vps_ui.service || true
        fi
        for attempt in $(seq 1 30); do
            if "$previous/scripts/awg_vps_control.sh" healthcheck >/dev/null 2>&1; then restored=1; break; fi
            sleep 1
        done
        if [[ $restored -eq 1 ]]; then echo 'Panel update failed; previous release restored and health checked.' >&2
        else echo 'Panel update failed; previous files restored but service recovery requires manual attention.' >&2; fi
    else
        echo 'Panel installation incomplete. Inspect awg_vps_warp.service; AWG was not installed or restarted.' >&2
    fi
    exit "$result"
}
trap rollback_install ERR

# Миграция старого прототипа останавливает только наши процессы; guard и Docker не перезапускаются.
for unit in awg_vps_ui.service awg_vps_supervisor.service awg_vps_host.service; do
    if [[ -f /etc/systemd/system/$unit ]]; then systemctl disable --now "$unit"; fi
done
ln -sfn "$release" "$root/current.next"
mv -Tf "$root/current.next" "$root/current"
cp -- "$release"/systemd/*.service /etc/systemd/system/
install -m 0644 "$release/systemd/awg_vps_control.conf" /etc/tmpfiles.d/awg_vps_control.conf
systemd-tmpfiles --create /etc/tmpfiles.d/awg_vps_control.conf
ln -sfn "$root/current/awg_vps_control.sh" /usr/local/bin/awg-vps-control
systemctl daemon-reload
systemctl enable awg_vps_guard.service awg_vps_warp.service
systemctl start awg_vps_guard.service
systemctl restart awg_vps_warp.service
"$release/scripts/awg_vps_control.sh" start-ui
healthy=0
for attempt in $(seq 1 45); do
    if "$release/scripts/awg_vps_control.sh" healthcheck >/dev/null 2>&1; then healthy=1; break; fi
    sleep 1
done
[[ $healthy -eq 1 ]]
for unit in awg_vps_ui.service awg_vps_supervisor.service awg_vps_host.service; do rm -f -- "/etc/systemd/system/$unit"; done
systemctl daemon-reload
if [[ -n $previous && $previous != "$release" ]]; then ln -sfn "$previous" "$root/previous"; fi
trap - ERR
printf 'Panel installed: %s\nUse: sudo awg-vps-control ui-access <ssh-target>\n' "$tag"
