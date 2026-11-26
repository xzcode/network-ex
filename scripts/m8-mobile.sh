#!/usr/bin/env bash
set -euo pipefail
# M8 shared mobile core: real Linux native fd fixture, not an Android emulator.
if [[ "${1:-}" != inside ]]; then exec unshare --net -- "$0" inside "${2:-$(pwd)/bin}" "${3:-all}" "${4:-relay}"; fi
BIN="$2"; MODE="${3:-all}"; A="$BIN/network-ex-agent"; S="$BIN/network-ex-server"
[[ "$MODE" == all || "$MODE" == split ]]
D="$(mktemp -d)"; export D
M="$BIN/mobile-fixture"
DIRECT_TEST="${4:-relay}"
declare -a pids=()
cleanup(){ for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; rm -rf "$D"; }
trap cleanup EXIT
umask 077
dump(){ for f in "$D"/*.log "$D"/{a,b}/managed.json "$D"/{a,b}/tunnel.json "$D/c-root/device/managed.json" "$D/c-root/device/tunnel.json"; do [[ ! -f "$f" ]] || { echo "--- $f"; tail -18 "$f"; }; done; }
ip link set lo up
ip link add nxbr type bridge; ip addr add 192.0.2.1/24 dev nxbr; ip link set nxbr up
for i in a b c; do
 unshare --net -- sleep 600 & p=$!; pids+=("$p"); printf -v "p$i" '%s' "$p"
 for j in {1..40}; do [[ "$(readlink /proc/$p/ns/net 2>/dev/null)" != "$(readlink /proc/self/ns/net)" ]] && break; sleep .1; done
 [[ "$(readlink /proc/$p/ns/net)" != "$(readlink /proc/self/ns/net)" ]]
 ip link add "h$i" type veth peer name "n$i";ip link set "h$i" master nxbr;ip link set "h$i" up;ip link set "n$i" netns "$p"
 nsenter -t "$p" -n ip link set lo up
 nsenter -t "$p" -n ip link set "n$i" up
done
nsenter -t "$pa" -n ip addr add 192.0.2.2/24 dev na
nsenter -t "$pb" -n ip addr add 192.0.2.3/24 dev nb
nsenter -t "$pc" -n ip addr add 192.0.2.4/24 dev nc
block_mobile_udp(){
 nsenter -t "$pc" -n iptables -I OUTPUT 1 -o nc -p udp -j DROP
 nsenter -t "$pc" -n iptables -I INPUT 1 -i nc -p udp -j DROP
}
unblock_mobile_udp(){
 nsenter -t "$pc" -n iptables -D OUTPUT -o nc -p udp -j DROP
 nsenter -t "$pc" -n iptables -D INPUT -i nc -p udp -j DROP
}
block_mobile_udp
mobile_flags=()
if [[ "$DIRECT_TEST" == direct ]];then mobile_flags=(-direct);elif [[ "$DIRECT_TEST" == flow ]];then mobile_flags=(-flow);fi
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=192.0.2.1 -addext subjectAltName=IP:192.0.2.1 -keyout "$D/tls.key" -out "$D/tls.crt" >/dev/null 2>&1
"$S" issuer-keygen -out "$D/issuer.key" > "$D/issuer.pub"
printf '%s\n' 'm3-test-strong-local-password' > "$D/password"
"$S" admin-bootstrap -db "$D/network.db" -username test-admin -password-file "$D/password"
if "$S" admin-bootstrap -db "$D/network.db" -username other-admin -password-file "$D/password" >/dev/null 2>&1; then echo "FAIL: bootstrap repeated";exit 1;fi
echo "PASS: one-time administrator bootstrap"
relayPort=18443
if [[ "$MODE" == split ]]; then
 relayPort=18444
 "$S" -mode relay -listen 192.0.2.1:18444 -stun-listen 192.0.2.1:3478 -node test-node -issuer-public "$D/issuer.pub" -tls-cert "$D/tls.crt" -tls-key "$D/tls.key" >"$D/relay.log" 2>&1 & pids+=("$!")
fi
start_management(){
 local mode=all; local flags=(-stun-listen 192.0.2.1:3478)
 if [[ "$MODE" == split ]]; then mode=management;flags=();fi
 "$S" -mode "$mode" -listen 192.0.2.1:18443 -node test-node -db "$D/network.db" -issuer-key "$D/issuer.key" -relay-url "wss://192.0.2.1:$relayPort/relay/v1" -stun-url stun:192.0.2.1:3478 -tls-cert "$D/tls.crt" -tls-key "$D/tls.key" "${flags[@]}" >"$D/management.log" 2>&1 & manager=$!;pids+=("$manager")
 sleep 1;kill -0 "$manager"
}
start_management
cat >"$D/api.py" <<'PY'
import os,sys,json,ssl,urllib.request,urllib.error,pathlib,time,concurrent.futures
d=pathlib.Path(os.environ["D"]);base="https://192.0.2.1:18443";ctx=ssl.create_default_context(cafile=str(d/"tls.crt"))
def api(path,method="GET",body=None,token=None,expect=200):
 h={}
 if token:h["Authorization"]="Bearer "+token
 if body is not None:h["Content-Type"]="application/json"
 r=urllib.request.Request(base+path,method=method,data=None if body is None else json.dumps(body).encode(),headers=h)
 try:
  with urllib.request.urlopen(r,context=ctx,timeout=8) as res:
   assert res.status==expect,(path,res.status,expect);b=res.read()
 except urllib.error.HTTPError as e:
  assert e.code==expect,(path,e.code,expect,e.read());return {}
 return json.loads(b)
def login(name,password):return api("/api/v1/auth/login","POST",dict(login=name,password=password))["token"]
def getadmin():return login("test-admin",(d/"password").read_text().strip())
cmd=sys.argv[1]
if cmd=="setup":
 assert api("/healthz")["status"]=="ok"
 with urllib.request.urlopen(base,context=ctx) as r:assert b"Network EX" in r.read() and "script-src 'self'" in r.headers["Content-Security-Policy"]
 api("/api/v1/networks",expect=401)
 t=getadmin()
 u=api("/api/v1/users","POST",dict(login="member1",password="m3-member-strong-password"),t,201)
 member=login("member1","m3-member-strong-password")
 n=api("/api/v1/networks","POST",dict(name="M3 Test",cidr="10.88.0.0/24",policy="allow_members"),t,201)
 nid=n["id"];(d/"network").write_text(nid)
 assert not api("/api/v1/networks",token=member)
 api("/api/v1/networks/"+nid+"/devices",token=member,expect=404)
 api("/api/v1/users",token=member,expect=403)
 api("/api/v1/networks","POST",dict(name="overlap",cidr="10.88.0.0/25",policy="deny_members"),member,409)
 for i in "abc":
  inv=api("/api/v1/networks/"+nid+"/invites","POST",dict(ttl_seconds=3600),t,201)
  (d/(i+".invite")).write_text(inv["invite"]+"\n")
 print("PASS: HTTPS UI, login, network, owner isolation and CIDR overlap protection")
elif cmd=="mobile-revoke":
 t=getadmin();nid=(d/"network").read_text();ds=json.loads((d/"devices.json").read_text())
 result=api("/api/v1/networks/"+nid+"/devices/"+ds["c"]["id"]+"/revoke","POST",{},t)
 assert result["status"]=="revoked"
elif cmd=="approve":
 t=getadmin();nid=(d/"network").read_text()
 ds=api("/api/v1/networks/"+nid+"/devices",token=t);assert len(ds)==3 and all(x["status"]=="pending" for x in ds)
 # Concurrent approvals exercise the transactional IP allocator.
 def approve(x):return api("/api/v1/networks/"+nid+"/devices/"+x["id"]+"/approve","POST",{},t)
 with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:ds=list(ex.map(approve,ds))
 assert len({x["ip"] for x in ds})==3 and all(x["status"]=="approved" for x in ds)
 (d/"devices.json").write_text(json.dumps({x["name"]:x for x in ds}))
 print("PASS: three concurrent approvals produced distinct virtual IPs")
elif cmd in ("deny","allow","revoke","persist"):
 t=getadmin();nid=(d/"network").read_text();ds=json.loads((d/"devices.json").read_text())
 if cmd in ("deny","allow"):
  r=api("/api/v1/networks/"+nid+"/rules","PUT",dict(a=ds["a"]["id"],b=ds["b"]["id"],allow=cmd=="allow"),t)
  assert r["allow"]==(cmd=="allow")
 elif cmd=="revoke":
  x=api("/api/v1/networks/"+nid+"/devices/"+ds["c"]["id"]+"/revoke","POST",{},t);assert x["status"]=="revoked"
 else:
  new=api("/api/v1/networks/"+nid+"/devices",token=t)
  assert {x["name"]:x["ip"] for x in new}=={name:x["ip"] for name,x in ds.items()}
  assert next(x for x in new if x["name"]=="c")["status"]=="revoked"
  assert api("/api/v1/audit",token=t)
  print("PASS: SQLite state and revocation persisted after restart")
PY
python3 "$D/api.py" setup
for i in a b; do
 var="p$i"; nsenter -t "${!var}" -n "$A" managed-enroll -server https://192.0.2.1:18443 -ca "$D/tls.crt" -invite-file "$D/$i.invite" -name "$i" -state-dir "$D/$i"
done
mkdir -m 700 "$D/c-root"
if [[ "$DIRECT_TEST" == flow ]];then
 mkdir -m 700 "$D/c-enroll"
 nsenter -t "$pc" -n "$M" enroll -server https://192.0.2.1:18443 -ca "$D/tls.crt" -invite-file "$D/c.invite" -name c -root "$D/c-enroll" -restore-root "$D/c-root"
else
 nsenter -t "$pc" -n "$M" enroll -server https://192.0.2.1:18443 -ca "$D/tls.crt" -invite-file "$D/c.invite" -name c -root "$D/c-root"
fi
if nsenter -t "$pa" -n "$A" managed-enroll -server https://192.0.2.1:18443 -ca "$D/tls.crt" -invite-file "$D/a.invite" -name reused -state-dir "$D/reused" >"$D/reused.log" 2>&1; then echo "FAIL: invite reused";exit 1;fi
echo "PASS: consumed invite rejected"
for i in a b; do
 var="p$i";nsenter -t "${!var}" -n "$A" managed-run -state-dir "$D/$i" -ice-interfaces "n$i" >"$D/$i.log" 2>&1 & p=$!;pids+=("$p");printf -v "agent$i" '%s' "$p"
done
nsenter -t "$pc" -n "$M" run -root "$D/c-root" "${mobile_flags[@]}" -deny-protect >"$D/deny.log" 2>&1 & deny=$!;pids+=("$deny")
sleep 3
if nsenter -t "$pc" -n ip link show nxmobile0 >/dev/null 2>&1;then echo "FAIL: rejected socket protection established a VPN";exit 1;fi
kill "$deny";wait "$deny"
grep -Eq 'protected=[1-9][0-9]* opened=0' "$D/deny.log"
echo "PASS: rejected platform socket protection blocks network setup"
nsenter -t "$pc" -n "$M" run -root "$D/c-root" "${mobile_flags[@]}" >"$D/c.log" 2>&1 & agentc=$!;pids+=("$agentc")
state(){ local statepath="$D/$1/managed.json"; [[ "$1" != c ]]||statepath="$D/c-root/device/managed.json";python3 - "$statepath" <<'PY'
import json,sys
try:print(json.load(open(sys.argv[1]))["state"])
except (OSError,ValueError):print("unavailable")
PY
}
for j in {1..15}; do [[ "$(state a)" == pending && "$(state b)" == pending && "$(state c)" == pending ]] && break;sleep 1;done
[[ "$(state a)" == pending && "$(state b)" == pending && "$(state c)" == pending ]] || { dump;exit 1; }
if nsenter -t "$pa" -n ip link show nex0 >/dev/null 2>&1;then echo "FAIL: pending device has TUN";exit 1;fi
if nsenter -t "$pc" -n ip link show nxmobile0 >/dev/null 2>&1;then echo "FAIL: mobile pending TUN";exit 1;fi
echo "PASS: pending desktop and native VPN devices cannot establish TUN"
python3 "$D/api.py" approve
getip(){ python3 - "$D/devices.json" "$1" <<'PY'
import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]]["ip"])
PY
}
ipa="$(getip a)";ipb="$(getip b)";ipc="$(getip c)"
echo "Assigned: a=$ipa b=$ipb c=$ipc"
waitping(){ local p="$1" ip="$2" tries="$3";for ((j=0;j<tries;j++));do if nsenter -t "$p" -n ping -c1 -W1 "$ip" >/dev/null 2>&1;then return 0;fi;sleep 1;done;echo "FAIL: unreachable $ip";dump;return 1;}
waitping "$pa" "$ipb" 35
waitping "$pa" "$ipc" 25
pathmode(){ local status="$D/$1/tunnel.json";[[ "$1" != c ]]||status="$D/c-root/device/tunnel.json";python3 - "$status" "$2" <<'PY'
import json,sys
try:print(next(p["mode"] for p in json.load(open(sys.argv[1]))["peers"] if p["ip"]==sys.argv[2]))
except (OSError,ValueError,StopIteration,TypeError):print("unavailable")
PY
}
for j in {1..30};do [[ "$(pathmode a "$ipb")" == ice-selected && "$(pathmode a "$ipc")" == relay-fallback ]]&&break;sleep 1;done
[[ "$(pathmode a "$ipb")" == ice-selected && "$(pathmode a "$ipc")" == relay-fallback ]] || { dump;exit 1; }
echo "PASS: managed auto-configuration; A-B ICE direct and A-C mobile relay"
nsenter -t "$pc" -n ip -4 -j addr show nxmobile0 | python3 -c 'import json,sys;assert any(a["local"]==sys.argv[1] and a["prefixlen"]==32 for a in json.load(sys.stdin)[0]["addr_info"])' "$ipc"
nsenter -t "$pc" -n ip -4 route show dev nxmobile0
[[ -z "$(nsenter -t "$pc" -n ip -4 route show default dev nxmobile0)" ]]
echo "PASS: detached native fd uses overlay host routes, not default route"

cat >"$D/echo.py" <<'PY'
import socket,sys,threading
ip=sys.argv[1]
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,19001))
 while True:
  b,a=s.recvfrom(4096);s.sendto(b,a)
threading.Thread(target=udp,daemon=True).start()
s=socket.socket();s.bind((ip,19002));s.listen()
while True:
 c,_=s.accept()
 with c:
  b=c.recv(4096);c.sendall(b)
PY
nsenter -t "$pb" -n python3 "$D/echo.py" "$ipb" & pids+=("$!")
nsenter -t "$pc" -n python3 "$D/echo.py" "$ipc" & pids+=("$!")
sleep 1
nsenter -t "$pa" -n python3 - "$ipb" "$ipc" <<'PY'
import socket,sys
for ip in sys.argv[1:]:
 for typ,port in [(socket.SOCK_STREAM,19002),(socket.SOCK_DGRAM,19001)]:
  with socket.socket(socket.AF_INET,typ) as s:
   s.settimeout(8);s.connect((ip,port));msg=b"NETWORK_EX_M3_PAYLOAD"+b"x"*1000;s.sendall(msg);v=s.recv(4096)
   while typ==socket.SOCK_STREAM and len(v)<len(msg):v+=s.recv(4096)
   assert v==msg
 print("PASS: managed TCP/UDP echo",ip)
PY
# Restart native session: descriptor closed, routes removed, advisory lock reusable.
kill "$agentc";wait "$agentc"
grep -Eq 'protected=[1-9][0-9]* opened=[1-9][0-9]*' "$D/c.log"
if nsenter -t "$pc" -n ip link show nxmobile0 >/dev/null 2>&1;then echo "FAIL: native VPN leaked on stop";exit 1;fi
nsenter -t "$pc" -n "$M" run -root "$D/c-root" "${mobile_flags[@]}" >"$D/c.log" 2>&1 & agentc=$!;pids+=("$agentc")
waitping "$pa" "$ipc" 35
echo "PASS: native session stop closes fd and restart restores connectivity"
if [[ "$DIRECT_TEST" == direct ]];then
 unblock_mobile_udp
 for j in {1..70};do [[ "$(pathmode a "$ipc")" == ice-selected && "$(pathmode c "$ipa")" == ice-selected ]]&&break;sleep 1;done
 [[ "$(pathmode a "$ipc")" == ice-selected && "$(pathmode c "$ipa")" == ice-selected ]]||{ dump;exit 1; }
 waitping "$pa" "$ipc" 20
 nsenter -t "$pa" -n python3 - "$ipc" <<'PY2'
import socket,sys
for typ,port in [(socket.SOCK_STREAM,19002),(socket.SOCK_DGRAM,19001)]:
 with socket.socket(socket.AF_INET,typ) as s:
  s.settimeout(8);s.connect((sys.argv[1],port));s.sendall(b"protected-direct");assert s.recv(1024)==b"protected-direct"
PY2
 echo "PASS: protected native ICE selected at both ends, real TCP/UDP"
 block_mobile_udp
 for j in {1..25};do [[ "$(pathmode a "$ipc")" == relay-fallback && "$(pathmode c "$ipa")" == relay-fallback ]]&&break;sleep 1;done
 [[ "$(pathmode a "$ipc")" == relay-fallback && "$(pathmode c "$ipa")" == relay-fallback ]]||{ dump;exit 1; }
 waitping "$pa" "$ipc" 20
 echo "PASS: protected native ICE failure returns to WSS relay"
fi
python3 "$D/api.py" mobile-revoke
for j in {1..20};do if ! kill -0 "$agentc" 2>/dev/null;then break;fi;sleep 1;done
if kill -0 "$agentc" 2>/dev/null;then dump;echo "FAIL: revoked mobile still running";exit 1;fi
wait "$agentc"||true
if nsenter -t "$pc" -n ip link show nxmobile0 >/dev/null 2>&1;then echo "FAIL: revoked mobile interface leaked";exit 1;fi
waitping "$pa" "$ipb" 25
echo "PASS: management revocation removes native VPN without affecting other peers"
echo "M8 mobile shared core integration PASS ($DIRECT_TEST)"
