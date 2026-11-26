#!/usr/bin/env bash
set -euo pipefail
# Run only in isolated network namespaces. No host routes/listeners.
if [[ "${1:-}" != inside ]]; then exec unshare --net -- "$0" inside "${2:-$(pwd)/bin}"; fi
BIN="$2"
A="$BIN/network-ex-agent"
S="$BIN/network-ex-server"
D="$(mktemp -d)"
declare -a pids=()
cleanup(){ for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done; rm -rf "$D"; }
trap cleanup EXIT
umask 077
ip link set lo up
ip link add nxbr type bridge
ip addr add 192.0.2.1/24 dev nxbr
ip link set nxbr up
for i in a b c; do
 unshare --net -- sleep 300 & p=$!; pids+=("$p"); printf -v "p$i" '%s' "$p"
 for attempt in {1..40}; do [[ "$(readlink /proc/$p/ns/net 2>/dev/null)" != "$(readlink /proc/self/ns/net)" ]] && break; sleep .1; done
 [[ "$(readlink /proc/$p/ns/net)" != "$(readlink /proc/self/ns/net)" ]]
 ip link add "h$i" type veth peer name "n$i"
 ip link set "h$i" master nxbr; ip link set "h$i" up
 ip link set "n$i" netns "$p"
 nsenter -t "$p" -n ip link set lo up
 nsenter -t "$p" -n ip link set "n$i" up
done
nsenter -t "$pa" -n ip addr add 192.0.2.2/24 dev na
nsenter -t "$pb" -n ip addr add 192.0.2.3/24 dev nb
nsenter -t "$pc" -n ip addr add 192.0.2.4/24 dev nc
for i in a b c; do "$A" keygen -out "$D/$i.wg" > "$D/$i.pub"; "$A" keygen -kind identity -out "$D/$i.id" > "$D/$i.idpub"; done
"$S" issuer-keygen -out "$D/issuer.key" > "$D/issuer.pub"
"$S" lease -issuer-key "$D/issuer.key" -node test-relay -network nx-test -flow ac -a "$(cat "$D/a.idpub")" -b "$(cat "$D/c.idpub")" -ttl 5m -out "$D/ac.token"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=192.0.2.1 -addext subjectAltName=IP:192.0.2.1 -keyout "$D/tls.key" -out "$D/tls.crt" >/dev/null 2>&1
python3 - "$D" <<'PY'
import json, pathlib, sys
d=pathlib.Path(sys.argv[1])
def peer(n, mode):
    p={"ip": "10.88.0."+str("abc".index(n)+2), "public_key": (d/(n+".pub")).read_text().strip()}
    if mode=="direct": p["direct"]="192.0.2."+str("abc".index(n)+2)+":51820"
    else: p.update(relay_url="wss://192.0.2.1:18443/relay/v1", relay_token_file=str(d/"ac.token"),relay_ca=str(d/"tls.crt"))
    return p
for n,peers in {"a":[peer("b","direct"),peer("c","relay")],"b":[peer("a","direct")],"c":[peer("a","relay")]}.items():
    (d/(n+".json")).write_text(json.dumps(dict(interface="nex0",ip="10.88.0."+str("abc".index(n)+2),listen_port=51820,wg_key_file=str(d/(n+".wg")),identity_key_file=str(d/(n+".id")),status_file=str(d/(n+".status")),peers=peers)))
PY
"$S" -mode relay -listen 192.0.2.1:18443 -node test-relay -issuer-public "$D/issuer.pub" -tls-cert "$D/tls.crt" -tls-key "$D/tls.key" >"$D/relay.log" 2>&1 & pids+=("$!")
for i in a b c; do
 "$A" check -config "$D/$i.json"
 var="p$i"; nsenter -t "${!var}" -n "$A" run -config "$D/$i.json" >"$D/$i.log" 2>&1 & p=$!; pids+=("$p"); printf -v "agent$i" '%s' "$p"
done
dump(){ for i in a b c relay; do echo "--- $i log"; tail -20 "$D/$i.log" || true; done; }
for i in {1..25}; do
 if nsenter -t "$pa" -n ping -c1 -W1 10.88.0.3 >/dev/null 2>&1 && nsenter -t "$pa" -n ping -c1 -W1 10.88.0.4 >/dev/null 2>&1; then break; fi
 if [[ $i == 25 ]]; then dump; exit 1; fi
 sleep 1
done
echo "PASS: A -> B direct ICMP and A -> C relay ICMP simultaneously"
cat > "$D/echo.py" <<'PY'
import socket, sys, threading
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
        data=c.recv(4096);c.sendall(data)
PY
for i in b c; do var="p$i"; ip=10.88.0.3; [[ "$i" == c ]] && ip=10.88.0.4; nsenter -t "${!var}" -n python3 "$D/echo.py" "$ip" & pids+=("$!"); done
sleep 1
cat > "$D/capture.py" <<'PY'
import socket, select, time
socks=[]
for name in ["ha","hb","hc"]:
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));s.bind((name,0));socks.append(s)
n=0
until=time.monotonic()+5
while time.monotonic()<until:
    for s in select.select(socks,[],[],.2)[0]:
        data=s.recv(65535);n+=1
        if b"NETWORK_EX_M1_PAYLOAD_TEST_8a2d" in data: raise SystemExit("FAIL: cleartext marker seen on underlay")
assert n>0
print("PASS: underlay capture",n,"frames; application marker absent")
PY
python3 "$D/capture.py" >"$D/capture.log" & cap=$!; pids+=("$cap")
sleep .4
nsenter -t "$pa" -n python3 - <<'PY'
import socket
marker=b"NETWORK_EX_M1_PAYLOAD_TEST_8a2d"
for ip,mode in [("10.88.0.3","direct"),("10.88.0.4","relay")]:
    for t,port in [(socket.SOCK_STREAM,19002),(socket.SOCK_DGRAM,19001)]:
        with socket.socket(socket.AF_INET,t) as s:
            s.settimeout(4);s.connect((ip,port));s.sendall(marker);assert s.recv(4096)==marker
    print("PASS:",mode,"TCP and UDP echo")
PY
wait "$cap"; cat "$D/capture.log"
sleep 1
"$A" status -file "$D/a.status"
python3 - "$D/a.status" <<'PY'
import json,sys
p=json.load(open(sys.argv[1]))["peers"]
assert len(p)==2 and all(int(x["handshake_unix"])>0 and int(x["rx_bytes"])>0 and int(x["tx_bytes"])>0 for x in p)
assert p[0]["mode"]=="direct-configured" and p[1]["mode"]=="relay-configured" and p[1]["relay_connected"]
print("PASS: real WireGuard handshakes and traffic counters on both paths")
PY
kill "$agenta"; wait "$agenta"
if nsenter -t "$pa" -n ip link show nex0 >/dev/null 2>&1; then echo "FAIL: TUN not removed"; exit 1; fi
test -z "$(nsenter -t "$pa" -n ip -4 route show exact 10.88.0.3/32)"
echo "PASS: graceful stop removed TUN and overlay route"
echo "M1 isolated Linux network integration PASS"
