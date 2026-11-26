# M6 高级网络功能（2026-11-26）

版本 0.6.0-dev-m6。Linux 子网路由、LAN 共享、私有 DNS、细粒度设备对流量策略及多网络独立配置已通过隔离网络实测。互联网出口节点、GUI 多网络统一管理、原生跨平台子网路由及完整高可用仍未完成。

## M5 补强
- SQLite v1/v2 到 v3 的迁移读取和执行位于同一立即写事务；双独立数据库连接并发打开真实 v1 数据库测试通过。只验证单主机本地 SQLite，不宣称分布式或多机 HA。
- 中继及信令在设备 Ed25519 持有证明通过后再请求中心授权；过期离线设备对占用的中继容量预留可回收（180s 安全窗口）。
- 新增节点连接数/聚合字节 token bucket 限额、回收和动态修改的单元测试。不是公网吞吐压测。

## M6 实现
### 子网共享
管理员通过 Web 或 PUT /api/v1/networks/{id}/devices/{device}/advanced 设置 {subnets:["192.168.77.0/24"],dns_label:"home-server"}。仅批准的设备可设置；子网只允许管理员审批，必须是规范 RFC1918 IPv4 /16–/32，每网关最多8个。禁止与任何已存在的虚拟网段或其他已审批子网重叠。普通网络所有者可管理未配置子网的设备别名。新增虚拟网络亦检查已审批子网冲突。
网关本机管理员必须明确允许相同子网，启动 managed-run 或 daemon 时传入 -allow-subnets 192.168.77.0/24。Linux 须预先由管理员启用 IPv4 forwarding，并且批准网段实际属于已连接网卡；程序不自动开启全局转发、改防火墙或配置 NAT。未匹配本地授权则停止隧道并显示 config-error。远端 Agent 将已批准的网段加入该 peer 的 WireGuard AllowedIPs 和系统路由，检查已有非默认路由、地址范围及管理/中继/STUN underlay 地址冲突；ICE 不将远端导入网段作为连接候选。LAN 设备须配置正确返回路径（可在 LAN 网关添加 overlay 网段静态路由）。TUN 删除时撤销本程序创建的路由。无默认路由/互联网出口劫持。
子网路由仅 Linux 实现；macOS/Windows 收到子网配置时明确拒绝，不是假支持。实际网关由可信管理员管理，无法防止网关 OS 自身恶意篡改转发。

### 流量访问控制
PUT /api/v1/networks/{id}/traffic：
```json
{"a":"device-a","b":"device-b","policy":{"services":[{"protocol":"tcp","port":443},{"protocol":"udp","port":53},{"protocol":"icmp"}]}}
```
设备对基础 ACL 仍须允许。policy:null 移除端口限制；services:[] 拒绝所有新连接；列表指定双向允许发起的服务及其返回流量。支持 TCP、UDP、ICMP Echo；不是方向单独、用户级或应用识别规则。
解密后的 TUN 包在 ingress/egress 均检查本地/远端地址所有权、允许前缀及服务，WireGuard AllowedIPs 同时绑定 peer 源地址；即使底层 OS IP forwarding 已开启，也不能将正常 Agent 当成跨 overlay 网络的路由器。拒绝 IPv4 options、分片、非 IPv4；受限策略对 TCP SYN / UDP / ICMP Echo 建立有界状态，拒绝无状态的伪返回流量，最多8192条流。连接跟踪是初版简化状态机，非完整操作系统防火墙；策略变更重建 tunnel，现存连接可能中断。启用高级配置后，未宣告 M6 capability 的旧 Agent 收到426；能力标志不等同防篡改证明。接收端仍必须是可信运行的 M6 Agent。

### DNS
管理员或相应权限的网络所有者为设备配置唯一小写 DNS label。已授权的 peer 以 label.network-ex.internal 解析到虚拟 IPv4。客户端可选 -dns-listen 127.0.0.1:15353，TCP 和 UDP 同时绑定 IPv4 loopback，只解析本配置当前授权记录；外部查询 REFUSED、未知私有别名 NXDOMAIN、授权失效 SERVFAIL。TTL 最长5秒且不超过剩余授权。默认不启动、不修改系统 DNS，不代理外部 DNS。需在系统 resolver 或应用端自行指定；各独立网络配置应使用不同端口，尚未统一 split-DNS 配置。

### 多网络
同一物理机器可运行多个 managed-run（或分别配置独立 daemon）实例：不同 state-dir、identity/WG key、interface、listen-port、可选 DNS 端口。要求网段不重叠；同一管理实例全局检查 overlay/子网冲突，客户端也检查实际路由冲突。暂无单 GUI/单 daemon 多配置统一编排、VRF 或重叠地址虚拟化。
Web 管理新增高级设备与服务规则表单；桌面 topology 显示 peer DNS、子网，搜索纳入两字段。Vue 生产构建、Web JS 语法通过；未在原生 Tauri 实机验证。

## 实测
首尔 Linux OpenCloudOS，所有测试为临时 network namespaces，不修改宿主机真实网络或防火墙：
- scripts/m6-advanced.sh 完整退出0：三设备基础 P2P/relay TCP/UDP；拒绝重叠网段、0/0 与重复别名；无本地 opt-in 不启动网关；批准后从 overlay 客户端经过 Linux 网关访问实际未安装 Agent 的 LAN 主机，TCP/UDP 回显；真实存在的未授权 TCP 服务不可达；手动加路由不能访问未批准的第二 LAN 子网；TCP/UDP DNS 查询、外部域名拒绝、撤销子网与 DNS 后清理均通过。
- scripts/m6-multinetwork.sh 完整退出0：两独立 managed network 同时运行于一个物理 namespace、不同 TUN 与 UDP 端口，双网均通；开启网关 IP forwarding 后跨网络访问仍失败，正常网络继续可用。
- go test ./... 通过：数据包地址范围/端口/返回流量/分片等负向测试，SQLite 双连接迁移，M5 限额单元测试。
- Linux amd64 server/Agent 构建及 Windows amd64、Darwin amd64/arm64、Linux arm64 Agent 交叉构建通过；Vue/Vite 构建成功。

复现（从项目根目录，准备 Linux root 权限及 iproute2、iptables、unshare、Python3、openssl）：
```sh
go test ./...
mkdir -p bin
go build -o bin/network-ex-server ./cmd/server
CGO_ENABLED=0 go build -o bin/network-ex-agent ./cmd/agent
sudo bash scripts/m6-advanced.sh outside "$(pwd)/bin"
sudo bash scripts/m6-multinetwork.sh outside "$(pwd)/bin"
```

## 尚未完成
M6 出口节点（默认路由、underlay 排除、kill-switch、DNS/IPv6 泄漏验证）、统一多网络 GUI 与系统 DNS 集成、Windows/macOS 子网运行支持、方向独立高级 ACL、真实公网长时间与容量验证。M5 管理服务多机共享数据库/高可用尚未实现，M4 原生 Tauri 打包与安装/实机验收也未完成。无公网部署，无 release。
