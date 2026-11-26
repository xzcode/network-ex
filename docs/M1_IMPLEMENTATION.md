# M1 Linux 数据面开发与验收（2026-11-26）

## 已实现
Go 1.23 工程及锁定依赖、Agent CLI（version/keygen/check/run/status）、真实 Linux TUN、/32 地址和路由、WireGuard 用户态引擎、每 peer 可选 direct UDP 或 TLS WSS 中继、静态配置、后台中继重连、退出清理及真实握手/收发计数。中继由独立 server 进程提供，支持离线签发短期租约、Ed25519 身份挑战证明、节点与网络/设备对 scope、队列及连接/速率限制、租约到期关闭。WireGuard 数据包原样转发，WSS 外层 TLS，不改变 WG 加密。当前无管理 API、自动 NAT 穿透、自动路径切换、租约自动续期或动态节点注册。

## 构建（Linux）
```sh
go mod download
go test ./...
mkdir -p bin
go build -o bin/network-ex-agent ./cmd/agent
go build -o bin/network-ex-server ./cmd/server
sudo bash scripts/m1-netns.sh outside "$(pwd)/bin"
```
Go 1.23.12 实测。需要 root/CAP_NET_ADMIN、/dev/net/tun、iproute2、unshare/nsenter、Python3、openssl、ping；测试仅创建临时独立网络命名空间、临时证书和密钥。禁止在生产网直接运行未经规划的静态路由配置。脚本不需要公网入站端口。
当前 Go 依赖版本是 M1 实验基线而非生产安全审计结果；后续升级与漏洞审查必做。

## CLI 示例（参数均为示意）
```sh
network-ex-agent keygen -out a.wg
network-ex-agent keygen -kind identity -out a.id
network-ex-server issuer-keygen -out issuer.key > issuer.pub
network-ex-server lease -issuer-key issuer.key -node relay1 -network net1 -flow ab -a '<device-a-public-hex>' -b '<device-b-public-hex>' -ttl 10m -out ab.token
network-ex-server -mode relay -listen 127.0.0.1:8443 -node relay1 -issuer-public issuer.pub -tls-cert cert.pem -tls-key tls.key
network-ex-agent check -config a.json
network-ex-agent run -config a.json
network-ex-agent status -file a.status
```
静态租约必须由两端共享，签名者公钥由 Relay 预置；端侧配置各自的 identity 私钥，私钥文件及 token 文件必须 0600。TLS 默认验证证书；私有 CA 可用 relay_ca。不要将真实密钥/租约上传仓库。
静态 Agent JSON schema：
```json
{
  "interface": "nex0",
  "ip": "10.88.0.2",
  "listen_port": 51820,
  "wg_key_file": "a.wg",
  "identity_key_file": "a.id",
  "status_file": "a.status",
  "peers": [
    {"ip": "10.88.0.3", "public_key": "<64-hex-WG-public-key>", "direct": "192.0.2.3:51820"},
    {"ip": "10.88.0.4", "public_key": "<64-hex-WG-public-key>", "relay_url": "wss://relay.example.com/relay/v1", "relay_token_file": "ac.token", "relay_ca": "ca.pem"}
  ]
}
```
只支持私有 IPv4 overlay、静态 peer 和固定物理 UDP endpoint；每 peer 恰好一个 path。接口名、地址、密钥、路由应在使用前检查。check 是静态校验而非连通性检测。status 中 configured 表示配置模式，不等于在线，握手时间与流量来自 WG。自动切换 M2。

## 真实验收
环境：首尔 Linux OpenCloudOS 9.6，Go 1.23.12 amd64，三个互相隔离的 Linux netns，通过隔离 bridge 192.0.2.0/24 作为 underlay。独立中继进程 192.0.2.1:18443。未开放宿主机公网监听。A=10.88.0.2，B=10.88.0.3，C=10.88.0.4。
- 两个 CLI 构建成功，版本 0.1.0-dev-m1。
- A -> B direct ICMP，A -> C relay ICMP 同时通过。
- 两种路径 TCP echo 与 UDP echo 实测成功。
- AF_PACKET underlay 抓包 56 帧，测试 marker 未出现（仅验证本次数据，不是完整密码学审计）。
- A 两条路径均有真实 WG 握手时间及非零收发计数：B rx=1148/tx=1172，C rx=1204/tx=1148 bytes；C relay_connected=true。
- SIGTERM 后 A 的 TUN 与 overlay /32 路由被清理。
- TestSignedLeaseScope（过期/错误签名/过长 TTL 拒绝）和 TestRelayIdentityAndFlow（TLS WSS 真实转发、不同 network scope 隔离、错误身份签名拒绝）均通过。
- 自动 NAT/ICE、跨真实公网 NAT、动态切换、实际高负载、MTU 边界与 endpoint roaming、恶意 WG peer、跨平台、完整路由冲突与长期重连压测：NOT RUN/待实现。M1 核心闭环通过，严格 M1 退出条件尚有这些补测项；不得当作生产版本。

## 已知限制与安全边界
M1 静态逻辑 endpoint 使用虚拟 IP:1 对应实际传输路径，直接接收只接受已配置物理 endpoint；尚未支持漫游和双栈。WSS 目前用单条二进制消息承载一个密文包，连接绑定签名 lease，未实现 PROTOCOL 中独立 flow_id 二进制帧（M2/M3 协议冻结前统一）。短租约到期后 fail closed，CLI 需重新配置有效 token；不宣称无限在线。路由集成只拒绝已存在的精确 /32 route，完整重叠路由/多网络策略在后续补齐。管理/all mode 明确返回未实现而不是空服务。WSS/TCP 阻塞和吞吐需测；QUIC 延后。固定静态配置受本地管理员信任，不能公开提供开放中继。M2 前补强上述安全与传输边界。
