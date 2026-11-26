#!/usr/bin/env bash
set -euo pipefail
# Every interface, firewall rule and route is created in isolated netns.
if [[ "${1:-}" != inside ]]; then exec unshare --net -- "$0" inside "${2:-$(pwd)/bin}"; fi
BIN="$2"; A="$BIN/network-ex-agent"; S="$BIN/network-ex-server"
D="$(mktemp -d)"
declare -a pids=()
cleanup(){ for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; rm -rf "$D"; }
trap cleanup EXIT
umask 077
dump(){ for i in a b c relay; do echo "--- $i log"; tail -30 "$D/$i.log" 2>/dev/null || true; [[ "$i" == relay ]] || cat "$D/$i.status" 2>/dev/null || true; done; }
ip link set lo up
ip link add nxbr type bridge
ip addr add 192.0.2.1/24 dev nxbr
ip link set nxbr up
for i in a b c ra rb; do
 unshare --net -- sleep 300 & p=$!; pids+=("$p"); printf -v "p$i" '%s' "$p"
 for j in {1..40}; do [[ "$(readlink /proc/$p/ns/net 2>/dev/null)" != "$(readlink /proc/self/ns/net)" ]] && break; sleep .1; done
 [[ "$(readlink /proc/$p/ns/net)" != "$(readlink /proc/self/ns/net)" ]]
 nsenter -t "$p" -n ip link set lo up
done
for i in ra rb c; do
 var="p$i"; p="${!var}"
 ip link add "h$i" type veth peer name "w$i"
 ip link set "h$i" master nxbr; ip link set "h$i" up
 ip link set "w$i" netns "$p"
 nsenter -t "$p" -n ip link set "w$i" up
done
nsenter -t "$pra" -n ip addr add 192.0.2.10/24 dev wra
nsenter -t "$prb" -n ip addr add 192.0.2.11/24 dev wrb
nsenter -t "$pc" -n ip addr add 192.0.2.4/24 dev wc
for i in a b; do
 n="p$i"; p="${!n}"; r="pr$i"; router="${!r}"; segment=10; [[ "$i" == b ]] && segment=20
 ip link add "l$i" type veth peer name "n$i"
 ip link set "l$i" netns "$router"; ip link set "n$i" netns "$p"
 nsenter -t "$router" -n ip link set "l$i" up
 nsenter -t "$router" -n ip addr add "172.20.$segment.1/24" dev "l$i"
 nsenter -t "$p" -n ip link set "n$i" up
 nsenter -t "$p" -n ip addr add "172.20.$segment.2/24" dev "n$i"
 nsenter -t "$p" -n ip route add default via "172.20.$segment.1"
 nsenter -t "$router" -n sysctl -w net.ipv4.ip_forward=1 >/dev/null
 nsenter -t "$router" -n iptables -P FORWARD DROP
 nsenter -t "$router" -n iptables -A FORWARD -i "l$i" -o "wr$i" -j ACCEPT
 nsenter -t "$router" -n iptables -A FORWARD -i "wr$i" -o "l$i" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
 nsenter -t "$router" -n iptables -t nat -A POSTROUTING -o "wr$i" -j MASQUERADE
done
# C may still transmit overlay UDP through nex0, but its underlay UDP is blocked.
nsenter -t "$pc" -n iptables -I OUTPUT 1 -o wc -p udp -j DROP
nsenter -t "$pc" -n iptables -I INPUT 1 -i wc -p udp -j DROP
for i in a b c; do "$A" keygen -out "$D/$i.wg" > "$D/$i.pub"; "$A" keygen -kind identity -out "$D/$i.id" > "$D/$i.idpub"; done
"$S" issuer-keygen -out "$D/issuer.key" > "$D/issuer.pub"
for i in b c; do "$S" lease -issuer-key "$D/issuer.key" -node test-relay -network nx-test -flow "a$i" -a "$(cat "$D/a.idpub")" -b "$(cat "$D/$i.idpub")" -ttl 5m -out "$D/a$i.token"; done
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=192.0.2.1 -addext subjectAltName=IP:192.0.2.1 -keyout "$D/tls.key" -out "$D/tls.crt" >/dev/null 2>&1
python3 - "$D" <<'PY'
import json,pathlib,sys
d=pathlib.Path(sys.argv[1])
def peer(n,flow,iface):
    return dict(ip="10.88.0."+str("abc".index(n)+2),public_key=(d/(n+".pub")).read_text().strip(),relay_url="wss://192.0.2.1:18443/relay/v1",relay_token_file=str(d/(flow+".token")),relay_ca=str(d/"tls.crt"),ice=True,stun_url="stun:192.0.2.1:3478",ice_interfaces=[iface])
for n,peers in {"a":[peer("b","ab","na"),peer("c","ac","na")],"b":[peer("a","ab","nb")],"c":[peer("a","ac","wc")]}.items():
    (d/(n+".json")).write_text(json.dumps(dict(interface="nex0",ip="10.88.0."+str("abc".index(n)+2),listen_port=51820,wg_key_file=str(d/(n+".wg")),identity_key_file=str(d/(n+".id")),status_file=str(d/(n+".status")),peers=peers)))
PY
"$S" -mode relay -listen 192.0.2.1:18443 -stun-listen 192.0.2.1:3478 -node test-relay -issuer-public "$D/issuer.pub" -tls-cert "$D/tls.crt" -tls-key "$D/tls.key" >"$D/relay.log" 2>&1 & pids+=("$!")
sleep 1
# Independent STUN wire-format check through each NAT gateway.
for i in a b; do n="p$i"; p="${!n}"; want=192.0.2.10; [[ "$i" == b ]] && want=192.0.2.11
 nsenter -t "$p" -n python3 - "$want" <<'PY'
import os,socket,struct,sys
cookie=0x2112A442; tx=os.urandom(12)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(3);s.sendto(struct.pack("!HHI12s",1,0,cookie,tx),("192.0.2.1",3478))
b,_=s.recvfrom(512);typ,size,magic,rid=struct.unpack("!HHI12s",b[:20]);assert typ==0x101 and magic==cookie and rid==tx and size==len(b)-20
off=20
while off<len(b):
    t,n=struct.unpack("!HH",b[off:off+4]);v=b[off+4:off+4+n]
    if t==0x20:
        assert n==8 and v[1]==1
        port=struct.unpack("!H",v[2:4])[0]^(cookie>>16); ip=socket.inet_ntoa(struct.pack("!I",struct.unpack("!I",v[4:8])[0]^cookie));assert ip==sys.argv[1] and port>0
        print("PASS: STUN mapped NAT address",ip);break
    off+=4+((n+3)//4)*4
else: raise AssertionError("XOR-MAPPED-ADDRESS absent")
PY
done
for i in a b c; do
 "$A" check -config "$D/$i.json"
 var="p$i"; nsenter -t "${!var}" -n "$A" run -config "$D/$i.json" >"$D/$i.log" 2>&1 & p=$!; pids+=("$p"); printf -v "agent$i" '%s' "$p"
done
mode(){ python3 - "$D/$1.status" "$2" <<'PY'
import json,sys
try:
 p=next(x for x in json.load(open(sys.argv[1]))["peers"] if x["ip"]==sys.argv[2]);print(p["mode"])
except (OSError,StopIteration,ValueError): print("unavailable")
PY
}
waitmode(){ local node="$1" ip="$2" want="$3" seconds="$4"
 for ((j=0;j<seconds;j++)); do [[ "$(mode "$node" "$ip")" == "$want" ]] && return 0; sleep 1; done
 echo "FAIL: expected $node->$ip $want, got $(mode "$node" "$ip")";dump;return 1
}
waitmode a 10.88.0.3 ice-selected 65
waitmode b 10.88.0.2 ice-selected 15
waitmode a 10.88.0.4 relay-fallback 15
echo "PASS: independent NATs ICE nominated; UDP-blocked C uses relay"
cat >"$D/echo.py" <<'PY'
import socket,sys,threading
ip=sys.argv[1]
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((ip,19001))
 while True:
  b,a=s.recvfrom(4096);s.sendto(b,a)
threading.Thread(target=udp,daemon=True).start()
def worker(c):
 with c:
  while True:
   data=c.recv(4096)
   if not data: return
   c.sendall(data)
s=socket.socket();s.bind((ip,19002));s.listen()
while True:
 c,_=s.accept();threading.Thread(target=worker,args=(c,),daemon=True).start()
PY
for i in b c; do var="p$i"; ip=10.88.0.3; [[ "$i" == c ]] && ip=10.88.0.4; nsenter -t "${!var}" -n python3 "$D/echo.py" "$ip" & pids+=("$!"); done
sleep 1
check_data(){ nsenter -t "$pa" -n python3 - "$@" <<'PY'
import socket,sys
for ip in sys.argv[1:]:
 for typ,port in [(socket.SOCK_STREAM,19002),(socket.SOCK_DGRAM,19001)]:
  with socket.socket(socket.AF_INET,typ) as s:
   s.settimeout(8);s.connect((ip,port));msg=b"NETWORK_EX_M2_TEST"+b"x"*1182;s.sendall(msg);v=s.recv(4096)
   while typ==socket.SOCK_STREAM and len(v)<len(msg): v+=s.recv(4096)
   assert v==msg
 print("PASS: TCP and UDP echo",ip)
PY
}
check_data 10.88.0.3 10.88.0.4
sleep 2
python3 - "$D/a.status" "$D/b.status" <<'PY'
import json,sys
for f,ip in [(sys.argv[1],"10.88.0.3"),(sys.argv[2],"10.88.0.2")]:
 p=next(x for x in json.load(open(f))["peers"] if x["ip"]==ip)
 ice=p["ice"];assert p["mode"]=="ice-selected" and ice["direct_tx_bytes"]>0 and ice["direct_rx_bytes"]>0 and int(p["handshake_unix"])>0
 assert ice["local_type"] in ("srflx","prflx") or ice["remote_type"] in ("srflx","prflx"),ice
 print("PASS: actual ICE/WireGuard traffic",ip,ice)
p=next(x for x in json.load(open(sys.argv[1]))["peers"] if x["ip"]=="10.88.0.4")
assert p["mode"]=="relay-fallback" and p["relay_connected"] and int(p["rx_bytes"])>0
PY
# Force loss of the nominated ICE path without affecting WSS or overlay UDP.
start=$(date +%s)
nsenter -t "$pb" -n iptables -I OUTPUT 1 -o nb -p udp -j DROP
nsenter -t "$pb" -n iptables -I INPUT 1 -i nb -p udp -j DROP
waitmode a 10.88.0.3 relay-fallback 25
waitmode b 10.88.0.2 relay-fallback 25
check_data 10.88.0.3 10.88.0.4
echo "PASS: direct loss -> relay application recovery in $(($(date +%s)-start)) seconds (polling + echo)"
start=$(date +%s)
nsenter -t "$pb" -n iptables -D OUTPUT -o nb -p udp -j DROP
nsenter -t "$pb" -n iptables -D INPUT -i nb -p udp -j DROP
waitmode a 10.88.0.3 ice-selected 70
waitmode b 10.88.0.2 ice-selected 15
check_data 10.88.0.3 10.88.0.4
echo "PASS: UDP restored -> ICE renegotiation and application recovery in $(($(date +%s)-start)) seconds"
kill "$agenta"; wait "$agenta"
if nsenter -t "$pa" -n ip link show nex0 >/dev/null 2>&1; then echo "FAIL: TUN not removed";exit 1;fi
test -z "$(nsenter -t "$pa" -n ip -4 route show exact 10.88.0.3/32)"
echo "PASS: cleanup after dynamic paths"
echo "M2 isolated NAT integration PASS"
