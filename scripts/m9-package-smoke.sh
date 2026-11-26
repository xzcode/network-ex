#!/usr/bin/env bash
set -euo pipefail
[[ $# == 1 ]]||{ echo "Usage: $0 /path/to/linux-development.tar.gz" >&2;exit 1; }
archive="$(readlink -f "$1")"
# This is an explicit isolated package smoke test, not a systemd installation.
if [[ "${NEX_ISOLATED_SMOKE:-}" != 1 ]];then
 exec unshare --net env NEX_ISOLATED_SMOKE=1 "$0" "$archive"
fi
[[ "$(id -u)" == 0 ]]||{ echo "Root needed for isolated namespace/UID test" >&2;exit 1; }
d="$(mktemp -d)";pid=""
cleanup(){ if [[ -n "$pid" ]];then kill "$pid" 2>/dev/null||true;wait "$pid" 2>/dev/null||true;fi;rm -rf "$d";}
trap cleanup EXIT
trap 'echo "Smoke failed at line $LINENO" >&2; if [[ -f "$d/server.log" ]];then tail -10 "$d/server.log" >&2;fi' ERR
chmod 0755 "$d"
tar -xzf "$archive" -C "$d"
p="$d/network-ex"
(cd "$p";sha256sum -c SHA256SUMS >/dev/null)
test "$("$p/network-ex-server" version)" = "$("$p/network-ex-agent" version)"
echo "PASS: archive contents and binary versions"
install -d -m 0700 -o 65534 -g 65534 "$d/state"
as_service(){ setpriv --reuid 65534 --regid 65534 --clear-groups "$@"; }
as_service "$p/network-ex-server" issuer-keygen -out "$d/state/issuer.key" > "$d/issuer.pub"
# Test-only password and CA. Neither leaves this isolated temp directory.
(umask 077;printf '%s\n' 'network-ex-m9-local-fixture-password' > "$d/state/admin-password")
chown 65534:65534 "$d/state/admin-password"
as_service "$p/network-ex-server" admin-bootstrap -db "$d/state/network.db" -username test-admin -password-file "$d/state/admin-password"
rm "$d/state/admin-password"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 -keyout "$d/state/tls.key" -out "$d/state/tls.crt" >/dev/null 2>&1
chown 65534:65534 "$d/state/tls.key" "$d/state/tls.crt"
chmod 0600 "$d/state/tls.key"
ip link set lo up
setpriv --reuid 65534 --regid 65534 --clear-groups "$p/network-ex-server" -mode all -node fixture -db "$d/state/network.db" -issuer-key "$d/state/issuer.key" -listen 127.0.0.1:18443 -relay-url wss://127.0.0.1:18443/relay/v1 -tls-cert "$d/state/tls.crt" -tls-key "$d/state/tls.key" >"$d/server.log" 2>&1 & pid=$!
for i in {1..20};do
 if curl --noproxy '*' --fail --silent --cacert "$d/state/tls.crt" https://127.0.0.1:18443/healthz >"$d/health.json";then break;fi
 sleep .3
done
python3 - "$d/health.json" <<'PY'
import json,sys
assert json.load(open(sys.argv[1]))["status"]=="ok"
PY
test "$(awk '/^Uid:/{print $2}' /proc/"$pid"/status)" = 65534
echo "PASS: packaged TLS/SQLite server runs as unprivileged UID"
code="$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' --cacert "$d/state/tls.crt" https://127.0.0.1:18443/api/v1/networks)"
[[ "$code" == 401 ]]
echo "PASS: unauthenticated management API rejected"
kill "$pid";wait "$pid";pid=""
test -s "$d/state/network.db"
echo "PASS: orderly packaged-server shutdown and persisted SQLite"
echo "M9 Linux package smoke PASS"
