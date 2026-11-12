#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
version=$(tr -d '\r\n' < "$root/version")
output=${1:-"$root/.local/release"}
[[ ! -e $output ]] || { echo 'Output already exists; choose an empty directory.' >&2; exit 1; }
mkdir -p "$output/bin"
output=$(cd -- "$output" && pwd)
for component in web control; do
    (cd "$root/ui/$component" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -buildid= -X main.version=$version" -o "$output/bin/awg_$component" .)
done
tar -C "$root" -cf - scripts systemd compose.yaml install.sh awg_vps_control.sh license version | tar -C "$output" -xf -
revision=$(git -C "$root" rev-parse HEAD)
if [[ -n $(git -C "$root" status --porcelain) ]]; then revision="$revision-dirty"; fi
printf '%s\n' "$revision" > "$output/source_revision"
(cd "$output" && find . -type f ! -path '*/__pycache__/*' ! -name manifest.sha256 -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' sha256sum > manifest.sha256)
printf 'Release: %s\n' "$output"
