#!/usr/bin/env bash
set -euo pipefail
# Only mutate an isolated namespace.
if [[ "${1:-}" != inside ]]; then exec unshare --net -- "$0" inside "${2:-$(pwd)/bin}"; fi
A="$2/network-ex-agent"
D=$(mktemp -d)
trap 'rm -rf "$D"' EXIT
umask 077
"$A" keygen -out "$D/a.wg" >/dev/null
PUB=$("$A" keygen -out "$D/b.wg")
printf '{"interface":"nex0","ip":"10.88.0.2","listen_port":51820,"wg_key_file":"%s/a.wg","peers":[{"ip":"10.88.0.3","public_key":"%s","direct":"192.0.2.3:51820"}]}\n' "$D" "$PUB" > "$D/config.json"
ip route add blackhole 10.88.0.0/24
if "$A" run -config "$D/config.json" > "$D/log" 2>&1; then cat "$D/log"; exit 1; fi
cat "$D/log"
grep -q "overlaps existing route" "$D/log"
if ip link show nex0 >/dev/null 2>&1; then echo "TUN leak";exit 1;fi
ip route show 10.88.0.0/24 | grep -q blackhole
echo "PASS: route overlap rejected before TUN creation and existing route preserved"
