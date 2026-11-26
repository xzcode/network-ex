#!/usr/bin/env bash
set -euo pipefail
# M6 subnet, traffic ACL, private DNS and route revocation integration.
if [[ "${1:-}" != inside ]]; then exec unshare --net -- "$0" inside "${2:-$(pwd)/bin}" "${3:-all}"; fi
BIN="$2"; MODE="${3:-all}"; A="$BIN/network-ex-agent"; S="$BIN/network-ex-server"
[[ "$MODE" == all ]]
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
# A real LAN host without Agent, behind B; two subnets, only one approved.
unshare --net -- sleep 600 & pd=$!;pids+=("$pd")
for j in {1..40};do [[ "$(readlink /proc/$pd/ns/net)" != "$(readlink /proc/self/ns/net)" ]]&&break;sleep .1;done
ip link add lanb type veth peer name land
ip link set lanb netns "$pb";ip link set land netns "$pd"
nsenter -t "$pb" -n ip link set lanb up
nsenter -t "$pd" -n ip link set land up
nsenter -t "$pd" -n ip link set lo up
nsenter -t "$pb" -n ip addr add 192.168.77.1/24 dev lanb
nsenter -t "$pb" -n ip addr add 192.168.78.1/24 dev lanb
nsenter -t "$pd" -n ip addr add 192.168.77.2/24 dev land
nsenter -t "$pd" -n ip addr add 192.168.78.2/24 dev land
nsenter -t "$pd" -n ip route add 10.88.0.0/24 via 192.168.77.1
nsenter -t "$pb" -n sysctl -qw net.ipv4.ip_forward=1
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
elif cmd in ("advanced","remove"):
 t=getadmin();nid=(d/"network").read_text();ds=json.loads((d/"devices.json").read_text())
 aid,bid,cid=[ds[x]["id"] for x in "abc"]
 root="/api/v1/networks/"+nid
 if cmd=="advanced":
  # Explicitly test overlapping overlay, nonprivate export and duplicate labels.
  api(root+"/devices/"+bid+"/advanced","PUT",dict(subnets=["10.88.0.0/24"],dns_label="gateway"),t,409)
  api(root+"/devices/"+bid+"/advanced","PUT",dict(subnets=["0.0.0.0/0"],dns_label="gateway"),t,400)
  api(root+"/devices/"+bid+"/advanced","PUT",dict(subnets=["192.168.77.0/24"],dns_label="gateway"),t)
  api(root+"/devices/"+aid+"/advanced","PUT",dict(subnets=[],dns_label="gateway"),t,409)
  api(root+"/devices/"+aid+"/advanced","PUT",dict(subnets=[],dns_label="client"),t)
  api("/api/v1/networks","POST",dict(name="overlap",cidr="192.168.77.0/24",policy="deny_members"),t,409)
  api(root+"/traffic","PUT",dict(a=aid,b=bid,policy=dict(services=[dict(protocol="tcp",port=19002),dict(protocol="udp",port=19001)])),t)
  print("PASS: admin route/alias/service policy; conflict and default-route rejection")
 else:
  api(root+"/devices/"+bid+"/advanced","PUT",dict(subnets=[],dns_label=""),t)
  print("PASS: administrator removed subnet and DNS alias")
 view=api(root+"/advanced",token=t)
 assert isinstance(view["devices"],list) and isinstance(view["rules"],list)
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
for i in a b c; do
 var="p$i"; nsenter -t "${!var}" -n "$A" managed-enroll -server https://192.0.2.1:18443 -ca "$D/tls.crt" -invite-file "$D/$i.invite" -name "$i" -state-dir "$D/$i"
done
if nsenter -t "$pa" -n "$A" managed-enroll -server https://192.0.2.1:18443 -ca "$D/tls.crt" -invite-file "$D/a.invite" -name reused -state-dir "$D/reused" >"$D/reused.log" 2>&1; then echo "FAIL: invite reused";exit 1;fi
echo "PASS: consumed invite rejected"
for i in a b c; do
 var="p$i";nsenter -t "${!var}" -n "$A" managed-run -state-dir "$D/$i" -ice-interfaces "n$i" -dns-listen 127.0.0.1:15353 >"$D/$i.log" 2>&1 & p=$!;pids+=("$p");printf -v "agent$i" '%s' "$p"
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
python3 "$D/api.py" advanced
for j in {1..20};do [[ "$(state b)" == config-error ]]&&break;sleep 1;done
[[ "$(state b)" == config-error ]]||{ dump;exit 1; }
if nsenter -t "$pb" -n ip link show nex0 >/dev/null 2>&1;then echo "FAIL: gateway without local opt-in";exit 1;fi
echo "PASS: centrally approved subnet does not enable gateway without local opt-in"
kill "$agentb";wait "$agentb"
nsenter -t "$pb" -n "$A" managed-run -state-dir "$D/b" -ice-interfaces nb -allow-subnets 192.168.77.0/24 -dns-listen 127.0.0.1:15353 >"$D/b.log" 2>&1 & agentb=$!;pids+=("$agentb")
# Echo servers on actual LAN host (approved and unapproved address).
cat >"$D/lan.py" <<'PY2'
import socket,threading
def tcp(ip,port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((ip,port));s.listen()
 while True:
  c,_=s.accept()
  with c:
   c.sendall(c.recv(4096))
def udp(ip,port):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,port))
 while True:
  b,a=s.recvfrom(4096);s.sendto(b,a)
for ip in ["192.168.77.2","192.168.78.2"]:
 for port in [19002,19003]:threading.Thread(target=tcp,args=(ip,port),daemon=True).start()
 threading.Thread(target=udp,args=(ip,19001),daemon=True).start()
threading.Event().wait()
PY2
nsenter -t "$pd" -n python3 "$D/lan.py" & pids+=("$!")
cat >"$D/test_lan.py" <<'PY2'
import socket,sys
mode=sys.argv[1];ip=sys.argv[2]
ports=[(socket.SOCK_STREAM,19002),(socket.SOCK_DGRAM,19001)] if mode=="allow" else [(socket.SOCK_STREAM,19003)]
if mode=="unapproved":ports=[(socket.SOCK_STREAM,19002)]
for typ,port in ports:
 with socket.socket(socket.AF_INET,typ) as s:
  s.settimeout(2);msg=b"NETWORK_EX_M6_LAN"
  try:s.connect((ip,port));s.sendall(msg);out=s.recv(4096)
  except OSError:
   if mode=="allow":raise
  else:
   assert mode=="allow" and out==msg,("unexpected communication",mode,ip,port,out)
PY2
ok=false
for j in {1..30};do
 if nsenter -t "$pa" -n python3 "$D/test_lan.py" allow 192.168.77.2 >/dev/null 2>&1;then ok=true;break;fi
 sleep 1
done
[[ "$ok" == true ]]||{ dump;exit 1; }
echo "PASS: TCP and UDP to real LAN host without Agent through approved gateway"
# Prove blocked service exists and can be reached directly from B.
nsenter -t "$pb" -n python3 - <<'PY2'
import socket
with socket.create_connection(("192.168.77.2",19003),2) as s:s.sendall(b"test");assert s.recv(4)==b"test"
PY2
nsenter -t "$pa" -n python3 "$D/test_lan.py" deny 192.168.77.2
echo "PASS: existing TCP service on disallowed port is unreachable through tunnel"
nsenter -t "$pa" -n ip route add 192.168.78.0/24 dev nex0
nsenter -t "$pa" -n python3 "$D/test_lan.py" unapproved 192.168.78.2
nsenter -t "$pa" -n ip route del 192.168.78.0/24 dev nex0
echo "PASS: manually adding a route cannot reach unapproved LAN subnet"
cat >"$D/dns.py" <<'PY2'
import socket,struct,sys
name=sys.argv[1];expect=int(sys.argv[2]);ip=sys.argv[3] if len(sys.argv)>3 else None
q=struct.pack("!HHHHHH",0x1234,0x0100,1,0,0,0)+b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\x00"+struct.pack("!HH",1,1)
for t in [socket.SOCK_DGRAM,socket.SOCK_STREAM]:
 with socket.socket(socket.AF_INET,t) as s:
  s.settimeout(2);s.connect(("127.0.0.1",15353))
  if t==socket.SOCK_STREAM:
   s.sendall(struct.pack("!H",len(q))+q);h=s.recv(2);n=struct.unpack("!H",h)[0];v=b""
   while len(v)<n:v+=s.recv(n-len(v))
  else:s.send(q);v=s.recv(4096)
  rid,flags,qd,an,_,_=struct.unpack("!HHHHHH",v[:12]);assert rid==0x1234 and flags&0x8000 and flags&15==expect,(name,flags)
  if ip:assert an==1 and socket.inet_ntoa(v[-4:])==ip,(name,v)
  else:assert an==0
PY2
nsenter -t "$pa" -n python3 "$D/dns.py" gateway.network-ex.internal 0 "$ipb"
nsenter -t "$pa" -n python3 "$D/dns.py" unknown.network-ex.internal 3
nsenter -t "$pa" -n python3 "$D/dns.py" example.com 5
echo "PASS: TCP/UDP private DNS alias and refusal of external DNS"
python3 "$D/api.py" remove
for j in {1..25};do [[ -z "$(nsenter -t "$pa" -n ip -4 route show exact 192.168.77.0/24)" ]]&&break;sleep 1;done
[[ -z "$(nsenter -t "$pa" -n ip -4 route show exact 192.168.77.0/24)" ]]
# Wait for latest DNS snapshot to apply, then verify removed alias.
for j in {1..15};do if nsenter -t "$pa" -n python3 "$D/dns.py" gateway.network-ex.internal 3 >/dev/null 2>&1;then break;fi;sleep 1;done
nsenter -t "$pa" -n python3 "$D/dns.py" gateway.network-ex.internal 3
echo "PASS: subnet route and DNS alias removed after policy revocation"
echo "M6 advanced networking integration PASS"
