#!/usr/bin/env bash
set -euo pipefail
target=${1:?Usage: ui_tunnel.sh ssh-target [local-port]}
port=${2:-8787}
[[ $target != -* && $target != *[[:space:]]* && $port =~ ^[0-9]+$ && $port -ge 1024 && $port -le 65535 ]] || exit 2
exec ssh -N -o ExitOnForwardFailure=yes -L "localhost:$port:/run/awg_vps_web/web.sock" "$target"
