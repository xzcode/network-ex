#!/usr/bin/env bash
set -euo pipefail
# M7b real Ethernet TAP/ARP over encrypted direct and relay paths
if [[ "${1:-}" != inside ]]; then exec unshare --net -- "$0" inside "${2:-$(pwd)/bin}" "${3:-all}"; fi
BIN="$2"; MODE="${3:-all}"; A="$BIN/network-ex-agent"; S="$BIN/network-ex-server"
[[ "$MODE" == all || "$MODE" == split ]]
D="$(mktemp -d)"; export D
declare -a pids=()
cleanup(){ for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; rm -rf "$D"; }
trap cleanup EXIT
umask 077
dump(){ for f in "$D"/*.log "$D"/{a,b,c}/managed.json "$D"/{a,b,c}/tunnel.json; do [[ ! -f "$f" ]] || { echo "--- $f"; tail -18 "$f"; }; done; }
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
nsenter -t "$pc" -n iptables -I OUTPUT 1 -o nc -p udp -j DROP
nsenter -t "$pc" -n iptables -I INPUT 1 -i nc -p udp -j DROP
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
elif cmd=="ethernet":
 t=getadmin();nid=(d/"network").read_text();root="/api/v1/networks/"+nid
 api(root+"/ethernet","PUT",dict(enabled=True),t)
 assert api(root+"/ethernet",token=t)["enabled"]
 print("PASS: administrator enabled Ethernet mode")
elif cmd in ("acl","restore-acl","mode-off","check-conflicts"):
 t=getadmin();nid=(d/"network").read_text();root="/api/v1/networks/"+nid
 ds=json.loads((d/"devices.json").read_text());a,b,c=[ds[x]["id"] for x in "abc"]
 if cmd=="acl":
  api(root+"/traffic","PUT",dict(a=a,b=b,policy=dict(services=[dict(protocol="udp",port=19021)])),t)
 elif cmd=="restore-acl":
  api(root+"/traffic","PUT",dict(a=a,b=b,policy=None),t)
 elif cmd=="mode-off":
  api(root+"/ethernet","PUT",dict(enabled=False),t)
  assert not api(root+"/ethernet",token=t)["enabled"]
 else:
  api(root+"/devices/"+b+"/advanced","PUT",dict(subnets=["192.168.77.0/24"],dns_label=""),t,409)
  api(root+"/exit","PUT",dict(client=a,gateway=b,targets=["93.184.216.34"]),t,409)
  print("PASS: incompatible subnet and exit grants rejected in Ethernet mode")
elif cmd in ("discovery","clear-discovery"):
 t=getadmin();nid=(d/"network").read_text();root="/api/v1/networks/"+nid
 if cmd=="discovery":
  api(root+"/discovery","PUT",dict(rules=[dict(destination="10.88.0.254",port=19021)]),t,400)
  api(root+"/discovery","PUT",dict(rules=[dict(destination="224.0.0.251",port=5353)]),t,400)
  api(root+"/discovery","PUT",dict(rules=[dict(destination="10.88.0.255",port=19021),dict(destination="239.88.0.7",port=19022),dict(destination="255.255.255.255",port=19023)]),t)
  assert len(api(root+"/discovery",token=t)["rules"])==3
  print("PASS: discovery policy; unicast and link-local multicast rejected")
 else:
  api(root+"/discovery","PUT",dict(rules=[]),t)
  assert api(root+"/discovery",token=t)["rules"]==[]
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
python3 "$D/api.py" discovery
python3 "$D/api.py" ethernet
for i in a b c; do
 var="p$i"; nsenter -t "${!var}" -n "$A" managed-enroll -server https://192.0.2.1:18443 -ca "$D/tls.crt" -invite-file "$D/$i.invite" -name "$i" -state-dir "$D/$i"
done
if nsenter -t "$pa" -n "$A" managed-enroll -server https://192.0.2.1:18443 -ca "$D/tls.crt" -invite-file "$D/a.invite" -name reused -state-dir "$D/reused" >"$D/reused.log" 2>&1; then echo "FAIL: invite reused";exit 1;fi
echo "PASS: consumed invite rejected"
for i in a b c; do
 var="p$i";flags=(-layer2);[[ "$i" == b ]]&&flags=();nsenter -t "${!var}" -n "$A" managed-run -state-dir "$D/$i" -ice-interfaces "n$i" -game-discovery "${flags[@]}" >"$D/$i.log" 2>&1 & p=$!;pids+=("$p");printf -v "agent$i" '%s' "$p"
done
state(){ python3 - "$D/$1/managed.json" <<'PY'
import json,sys
try:print(json.load(open(sys.argv[1]))["state"])
except (OSError,ValueError):print("unavailable")
PY
}
for j in {1..15}; do [[ "$(state a)" == pending && "$(state b)" == pending && "$(state c)" == pending ]] && break;sleep 1;done
[[ "$(state a)" == pending && "$(state b)" == pending && "$(state c)" == pending ]] || { dump;exit 1; }
if nsenter -t "$pa" -n ip link show nex0 >/dev/null 2>&1;then echo "FAIL: pending device has TUN";exit 1;fi
echo "PASS: pending devices cannot establish TUN"
python3 "$D/api.py" approve
for j in {1..20};do if ! kill -0 "$agentb" 2>/dev/null;then break;fi;sleep .5;done
if kill -0 "$agentb" 2>/dev/null;then echo "FAIL: non-opted Ethernet device not stopped";exit 1;fi
wait "$agentb" || true
grep -q 'HTTP 426' "$D/b.log"
if nsenter -t "$pb" -n ip link show nex0 >/dev/null 2>&1;then echo "FAIL: non-opted Ethernet device has interface";exit 1;fi
echo "PASS: Ethernet mode requires explicit local opt-in"
nsenter -t "$pb" -n "$A" managed-run -state-dir "$D/b" -ice-interfaces nb -game-discovery -layer2 >"$D/b.log" 2>&1 & agentb=$!;pids+=("$agentb")
getip(){ python3 - "$D/devices.json" "$1" <<'PY'
import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]]["ip"])
PY
}
ipa="$(getip a)";ipb="$(getip b)";ipc="$(getip c)"
echo "Assigned: a=$ipa b=$ipb c=$ipc"
waitping(){ local p="$1" ip="$2" tries="$3";for ((j=0;j<tries;j++));do if nsenter -t "$p" -n ping -c1 -W1 "$ip" >/dev/null 2>&1;then return 0;fi;sleep 1;done;echo "FAIL: unreachable $ip";dump;return 1;}
waitping "$pa" "$ipb" 35
waitping "$pa" "$ipc" 25
pathmode(){ python3 - "$D/$1/tunnel.json" "$2" <<'PY'
import json,sys
try:print(next(p["mode"] for p in json.load(open(sys.argv[1]))["peers"] if p["ip"]==sys.argv[2]))
except (OSError,ValueError,StopIteration,TypeError):print("unavailable")
PY
}
for j in {1..30};do [[ "$(pathmode a "$ipb")" == ice-selected && "$(pathmode a "$ipc")" == relay-fallback ]]&&break;sleep 1;done
[[ "$(pathmode a "$ipb")" == ice-selected && "$(pathmode a "$ipc")" == relay-fallback ]] || { dump;exit 1; }
echo "PASS: managed auto-configuration; A-B ICE direct and A-C relay"
# Verify real kernel Ethernet type, network mask and deterministic MAC mapping.
for i in a b c;do
 var="p$i";ip="$(getip "$i")"
 nsenter -t "${!var}" -n ip -j link show nex0 | python3 -c 'import json,sys;x=json.load(sys.stdin)[0];expected="02:4e:"+":".join(f"{int(n):02x}" for n in sys.argv[1].split("."));assert x["link_type"]=="ether" and x["address"]==expected and x["mtu"]==1200,x' "$ip"
 nsenter -t "${!var}" -n ip -4 -j addr show nex0 | python3 -c 'import json,sys;assert any(a["local"]==sys.argv[1] and a["prefixlen"]==24 for a in json.load(sys.stdin)[0]["addr_info"])' "$ip"
done
waitping "$pa" "$ipb" 20
waitping "$pa" "$ipc" 20
nsenter -t "$pa" -n ip -j neigh show dev nex0 | python3 -c 'import json,sys;n=json.load(sys.stdin);assert all(any(x["dst"]==ip and x.get("lladdr")=="02:4e:"+":".join(f"{int(v):02x}" for v in ip.split(".")) for x in n) for ip in sys.argv[1:]),n' "$ipb" "$ipc"
echo "PASS: actual Linux TAP Ethernet, /24, deterministic MAC and kernel ARP neighbor entries"

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

cat >"$D/game.py" <<'PY2'
import socket,sys,threading
ip=sys.argv[1]
def serve(port,group=None):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b"nex0\0")
 s.bind(("",port))
 if group:
  s.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(group)+socket.inet_aton(ip))
 while True:
  data,addr=s.recvfrom(2048)
  s.sendto(b"ROOM:"+data+b":"+ip.encode(),addr)
for port,group in ((19021,None),(19022,"239.88.0.7"),(19023,None),(19024,None)):
 threading.Thread(target=serve,args=(port,group),daemon=True).start()
threading.Event().wait()
PY2
cat >"$D/findroom.py" <<'PY2'
import socket,sys,time
ip,dst,port=sys.argv[1],sys.argv[2],int(sys.argv[3])
expected=set(sys.argv[4:])
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b"nex0\0")
s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
s.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_IF,socket.inet_aton(ip))
s.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,1)
s.bind((ip,0))
nonce=b"DISCOVER-ROOM"
s.sendto(nonce,(dst,port))
seen=set();end=time.monotonic()+3
while time.monotonic()<end:
 s.settimeout(max(.05,end-time.monotonic()))
 try: data,addr=s.recvfrom(2048)
 except socket.timeout:break
 if data.startswith(b"ROOM:"+nonce+b":"):
  identity=data.split(b":")[-1].decode();assert addr[0]==identity,(addr,identity)
  seen.add(identity)
assert seen==expected,(dst,port,seen,expected)
print("PASS: room discovery",dst,port,"responders",sorted(seen))
PY2
game_pids=()
start_games(){
 for pid in "${game_pids[@]}";do kill "$pid" 2>/dev/null||true;wait "$pid" 2>/dev/null||true;done
 game_pids=()
 for i in b c;do
  var="p$i";ip="$(getip "$i")"
  nsenter -t "${!var}" -n python3 "$D/game.py" "$ip" >"$D/game-$i.log" 2>&1 & pid=$!;pids+=("$pid");game_pids+=("$pid")
 done
 sleep 1
 for pid in "${game_pids[@]}";do kill -0 "$pid";done
}
start_games
room(){ nsenter -t "$pa" -n python3 "$D/findroom.py" "$ipa" "$@"; }
room 10.88.0.255 19021 "$ipb" "$ipc" || { dump; cat "$D"/game-*.log;exit 1; }
room 239.88.0.7 19022 "$ipb" "$ipc" || { dump;cat "$D"/game-*.log;exit 1; }
room 255.255.255.255 19023 "$ipb" "$ipc" || { dump;cat "$D"/game-*.log;exit 1; }
room 10.88.0.255 19024
echo "PASS: unknown UDP discovery port blocked"
waitping "$pa" "$ipb" 20
waitping "$pa" "$ipc" 20
sleep 2
python3 - "$D" <<'PY2'
import json,pathlib,sys
d=pathlib.Path(sys.argv[1])
for x in "abc":
 v=json.loads((d/(x+"/tunnel.json")).read_text());s=v["ethernet"]
 assert all(isinstance(s[k],int) and s[k]>=0 for k in ("sent","received","arp","group","dropped")) and v["mac"],v
 print("PASS: live Ethernet counters (per tunnel generation)",x,v["mac"],s)
PY2
python3 "$D/api.py" check-conflicts
python3 "$D/api.py" acl
sleep 7
waitping "$pa" "$ipc" 20
# Policy refresh recreates TAP; applications bound by ifindex must rebind.
start_games
# Confirm an existing permitted broadcast still discovers both peers, while
# the restricted peer does not receive another centrally approved group.
room 10.88.0.255 19021 "$ipb" "$ipc"
room 239.88.0.7 19022 "$ipc"
if nsenter -t "$pa" -n ping -c2 -W1 "$ipb" >/dev/null 2>&1;then echo "FAIL: Ethernet unicast ACL bypass";exit 1;fi
waitping "$pa" "$ipc" 15
echo "PASS: Ethernet broadcast and unicast obey device-pair service ACL"
python3 "$D/api.py" restore-acl
sleep 7
waitping "$pa" "$ipb" 25
waitping "$pa" "$ipc" 20
start_games
room 239.88.0.7 19022 "$ipb" "$ipc"
sleep 2

python3 "$D/api.py" clear-discovery
for j in {1..20};do
 if [[ -z "$(nsenter -t "$pa" -n ip -4 route show exact 239.88.0.7/32)" ]];then break;fi;sleep 1
done
[[ -z "$(nsenter -t "$pa" -n ip -4 route show exact 239.88.0.7/32)" ]]
waitping "$pa" "$ipb" 20
waitping "$pa" "$ipc" 20
# Connected subnet and its kernel broadcast route must survive discovery policy withdrawal.
echo "PASS: discovery withdrawal preserves Ethernet unicast and ARP"
kill "$agenta";wait "$agenta"
if nsenter -t "$pa" -n ip link show nex0 >/dev/null 2>&1;then echo "FAIL: TAP remains after stop";exit 1;fi
[[ -z "$(nsenter -t "$pa" -n ip -4 route show exact 10.88.0.0/24)" ]]
echo "PASS: TAP and connected route removed on graceful stop"
python3 "$D/api.py" mode-off
for j in {1..25};do if ! kill -0 "$agentb" 2>/dev/null&&! kill -0 "$agentc" 2>/dev/null;then break;fi;sleep .5;done
if kill -0 "$agentb" 2>/dev/null||kill -0 "$agentc" 2>/dev/null;then echo "FAIL: mismatched mode did not stop agents";exit 1;fi
wait "$agentb"||true;wait "$agentc"||true
for p in "$pb" "$pc";do if nsenter -t "$p" -n ip link show nex0 >/dev/null 2>&1;then echo "FAIL: TAP persists after network mode change";exit 1;fi;done
for i in a b c;do
 var="p$i";nsenter -t "${!var}" -n "$A" managed-run -state-dir "$D/$i" -ice-interfaces "n$i" >"$D/$i.log" 2>&1 & pids+=("$!")
done
waitping "$pa" "$ipb" 35
waitping "$pa" "$ipc" 35
nsenter -t "$pa" -n ip -j link show nex0 | python3 -c 'import json,sys;assert json.load(sys.stdin)[0]["link_type"]=="none"'
nsenter -t "$pa" -n ip -4 -j addr show nex0 | python3 -c 'import json,sys;assert any(a["prefixlen"]==32 for a in json.load(sys.stdin)[0]["addr_info"])'
echo "PASS: mode change stops TAP and same device identities reconnect using original Layer-3 TUN"

echo "M7b Ethernet integration PASS"
