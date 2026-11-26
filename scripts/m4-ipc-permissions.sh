#!/usr/bin/env bash
set -euo pipefail
# Uses only a private temp dir; no network or real accounts are changed.
A="${1:-$(pwd)/bin/network-ex-agent}"
D="$(mktemp -d)"; p=""
cleanup(){ if [[ -n "$p" ]];then kill "$p" 2>/dev/null||true;wait "$p" 2>/dev/null||true;fi;rm -rf "$D"; }
trap cleanup EXIT
chmod 0711 "$D"
mkdir -m 0700 "$D/state";mkdir -m 0750 "$D/ipc";chown root:65534 "$D/ipc"
"$A" daemon -state-root "$D/state" -socket "$D/ipc/agent.sock" -socket-gid 65534 >"$D/daemon.log" 2>&1 & p=$!
for i in {1..20};do [[ -S "$D/ipc/agent.sock" ]]&&break;sleep .2;done
printf '%s\n' '{"action":"status"}' | "$A" ctl -socket "$D/ipc/agent.sock" | python3 -c 'import json,sys;assert json.load(sys.stdin)["ok"]'
# Binary path must be accessible by unprivileged users (copy into temp dir).
install -m 0755 "$A" "$D/agent"
printf '%s\n' '{"action":"status"}' | setpriv --reuid 65534 --regid 65534 --clear-groups "$D/agent" ctl -socket "$D/ipc/agent.sock" | python3 -c 'import json,sys;assert json.load(sys.stdin)["ok"]'
if printf '%s\n' '{"action":"status"}' | setpriv --reuid 65533 --regid 65533 --clear-groups "$D/agent" ctl -socket "$D/ipc/agent.sock" >/dev/null 2>&1;then echo 'FAIL: unauthorized local user connected';exit 1;fi
printf '%s\n' '{"action":"exec","command":"id"}' | "$A" ctl -socket "$D/ipc/agent.sock" >/dev/null 2>&1 && { echo 'FAIL: arbitrary IPC fields accepted';exit 1; } || true
printf '%s\n' '{"action":"exec"}' | "$A" ctl -socket "$D/ipc/agent.sock" | python3 -c 'import json,sys;assert not json.load(sys.stdin)["ok"]'
printf '%s\n' '{"action":"forget"}' | "$A" ctl -socket "$D/ipc/agent.sock" | python3 -c 'import json,sys;assert not json.load(sys.stdin)["ok"]'
echo "PASS: authorized group IPC, unauthorized UID denied, fixed action schema and explicit confirmation"
