# M2：STUN、ICE 穿透及动态路径（2026-11-26）

## 实现与配置

Linux 开发版 0.2.0-dev-m2。沿用 M1 的 WireGuard、TUN、WSS relay、Ed25519 设备证明与离线签名租约。Pion ICE v2.3.38、Pion STUN v0.6.1。新增：

- 内置 IPv4 UDP STUN Binding 服务（可选监听）。通过 RFC5389/8489 格式的 XOR-MAPPED-ADDRESS 返回实际观测的 NAT 地址；512-byte 请求上限、全局请求限速；仅 Binding，不提供 TURN 或任意地址代理。公网防滥用与部署安全审查仍待完成。
- TLS WSS /signal/v1：与中继使用同一个签名 lease + 随机 challenge + Ed25519 proof；网络、节点、设备对、flow、期限绑定；每一连接世代仅交换一组 ICE credentials/candidates，按身份确定 controlling/controlled，任一方离开会关闭并重新协商该世代。限制候选数量/消息大小/并发；无公共任意目标信令。
- 每 peer 独立 Pion ICE Agent，UDP4 host/srflx 候选；直接使用选中的 ICE Conn 发送与接收 WireGuard 密文，并保留已认证 WSS relay 作为 fallback。静态路径仍兼容 M1。直连候选通过 ICE 认证检查与短稳定期后选中，直连失败/断开/信令世代结束时清除选中状态、回退并指数重试。虚拟 IP 和 WireGuard peer identity 不改变。没有自行修改密码学。
- 状态文件增加 ice-selected / relay-fallback / unavailable、ICE 状态、候选类型、直连密文收发计数、尝试次数。状态代表选路，应用可达性仍需结合真实握手、收发与主动连通性测试。
- Linux 在创建 TUN 前检查接口是否已存在及 IPv4 非默认路由重叠；配置时再次检查。冲突不覆盖原有路由，正常退出清理 TUN。

构建（Go 1.23.12 实测）：

```sh
go test ./...
mkdir -p bin
go build -o bin/network-ex-agent ./cmd/agent
go build -o bin/network-ex-server ./cmd/server
sudo bash scripts/m1-netns.sh outside "$(pwd)/bin"
sudo bash scripts/m2-route-conflict.sh outside "$(pwd)/bin"
sudo bash scripts/m2-nat.sh outside "$(pwd)/bin"
```

测试依赖：Linux TUN、iproute2、iptables/netfilter、unshare/nsenter、sysctl、openssl、python3、ping、root/CAP_NET_ADMIN。脚本仅在独立网络命名空间创建接口、NAT、路由、防火墙和临时证书，不开放宿主机公网端口。

Server 使用 M1 的 issuer-keygen/lease 命令和 TLS 参数（见 M1_IMPLEMENTATION.md），新增：
```sh
network-ex-server -mode relay -listen 127.0.0.1:8443 -stun-listen 127.0.0.1:3478 -node relay1 -issuer-public issuer.pub -tls-cert cert.pem -tls-key tls.key
```
真实部署须配置正确可达地址、证书、防火墙；不要将测试证书或租约写入仓库。

在 M1 Agent peer 配置的 relay_url、relay_token_file、relay_ca 基础上增加：
```json
{
  "ip": "10.88.0.3",
  "public_key": "<64-hex-WG-public-key>",
  "relay_url": "wss://relay.example.com/relay/v1",
  "relay_token_file": "ab.token",
  "relay_ca": "ca.pem",
  "ice": true,
  "stun_url": "stun:relay.example.com:3478",
  "ice_interfaces": ["eth0"]
}
```
ice_interfaces 为可选白名单；stun_url 可省略（仅 host 候选）。两端需启用 ice、共享匹配租约、各有独立设备及 WG 私钥。signal 路径由 relay_url 同 origin 推导；仍为静态租约，没有在线注册或自动续期。租约到期关闭中继及信令世代，ICE 回退/重试不能延长授权。

## 实测证据

环境：首尔 Linux OpenCloudOS 9.6，三个 Agent + 两台独立 Linux NAT 路由器 + 一个中继/STUN 节点，全部运行于隔离 netns。A=10.88.0.2，B=10.88.0.3，C=10.88.0.4。A/B 分别位于 172.20.10.0/24、172.20.20.0/24；NAT WAN 192.0.2.10/11；C 的 underlay UDP 双向封锁，WSS 可用。没有实际公网 CGNAT 验收。

- STUN 独立 wire-format 请求通过两台 NAT，正确返回 192.0.2.10 和 192.0.2.11。
- A/B 双向 ICE 选中 srflx ↔ srflx；A 的 direct_tx/rx 为 3040/2848 bytes，B 为 2848/3040 bytes，真实 WG 握手非零。C 使用 relay-fallback。
- A-B 与 A-C 同时真实 TCP/UDP 1200-byte 回显。
- 阻断 B 底层 UDP，保持 TLS WSS：直连自动回退，TCP/UDP 应用恢复约 5 秒（轮询加回显）。解除封锁后自动重新协商 ICE 并恢复 TCP/UDP，约 21 秒（首次实测）。非长期性能 SLA。
- 动态路径运行后停止 Agent，TUN 与 overlay route 清理通过。
- M1 回归：静态 direct/relay TCP/UDP、抓包测试 marker 未出现（58 frames）、中继重启恢复、未经授权 WG key 拒绝及退出清理通过。
- Go tests：签名租约、Relay identity/flow、SignalScopeAndIdentity 均通过；信令跨网络隔离、未授权身份拒绝、配对世代失效通过。
- 路由冲突：预置 blackhole 10.88.0.0/24，Agent 拒绝，原路由保留，无 TUN 泄漏；最终实现提前到 TUN 创建前。

## 限制及下一阶段

严格 M2 验收并非全部结束：IPv6、真实跨互联网 CGNAT/对称 NAT/双重 NAT、实际 Wi-Fi/网线切换、持续 TCP 会话不中断、完整 MTU 边界/高负载/长期运行和安全审计均 NOT RUN。重探测是 ICE timeout/世代重建机制，而非完整 OS 网络变更监听；当前实现只有 IPv4 UDP，WSS 作为兜底。不承诺零丢包、零中断或 100% 直连。

信令当前使用离线 lease 的单节点临时协议，M3 将改成管理服务签发/续期、设备注册和拓扑快照；不将其视为最终控制面协议。信令候选白名单、速率限制和可信授权 peer 假设仍需生产安全复核（尤其恶意成员探测其他地址）。QUIC 暂不启用，依赖版本待安全升级审计。M3 首先完成 SQLite、管理员、网络与 IPAM、设备审批/撤销、租约续期、WSS 信令接入；然后 Web 管理与三种部署模式。