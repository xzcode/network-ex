#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.."&&pwd)"
cd "$root"
[[ "$(uname -s)" == Linux ]]||{ echo 'Linux host required for CGO SQLite server' >&2;exit 1; }
arch="$(go env GOHOSTARCH)"
[[ "$arch" == amd64 || "$arch" == arm64 ]]||{ echo 'Unsupported host architecture' >&2;exit 1; }
out="${1:-$root/artifacts}"
mkdir -p "$out";out="$(cd "$out"&&pwd)"
tmp="$(mktemp -d)";trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/network-ex"
dir="$tmp/network-ex"
# No private config or credentials copied.
go test ./...
CGO_ENABLED=1 go build -trimpath -o "$dir/network-ex-server" ./cmd/server
CGO_ENABLED=0 go build -trimpath -o "$dir/network-ex-agent" ./cmd/agent
version="$("$dir/network-ex-server" version)"
[[ "$version" =~ ^[A-Za-z0-9._-]+$ && "$("$dir/network-ex-agent" version)" == "$version" ]]
cp -a deploy/server "$dir/server-service"
cp -a deploy/linux "$dir/agent-service"
cp docs/M9_PACKAGING.md "$dir/README.md"
python3 scripts/dependency-inventory.py "$dir" "$version"
(cd "$dir";find . -type f ! -name SHA256SUMS -print0|sort -z|xargs -0 sha256sum > SHA256SUMS;sha256sum -c SHA256SUMS >/dev/null)
name="Network-EX-${version}-linux-${arch}-dev.tar.gz"
[[ ! -e "$out/$name" ]]||{ echo "Refusing overwrite $out/$name" >&2;exit 1; }
tar -C "$tmp" -czf "$out/$name" network-ex
(cd "$out";sha256sum "$name" > "$name.sha256";sha256sum -c "$name.sha256")
echo "Development package: $out/$name"
