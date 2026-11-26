# M3 管理服务、自动注册与访问控制（2026-11-26）

## 实现
版本 0.3.0-dev-m3，Linux IPv4 开发版。SQLite schema v1 自动创建，WAL、外键、唯一约束及事务分配。mattn/go-sqlite3 内置 SQLite C 实现，不要求运行时另装数据库；Go 构建当前需 CGO 和 C 编译器。管理员通过本地 CLI 单次初始化，密码 Argon2id；成员账号、短期管理会话（token 哈希存储、1h）、网络所有者与管理员访问范围。没有公开注册。
- 网络使用明确的 allow_members 或 deny_members 策略，默认 UI 选择 deny_members；不允许重复/重叠私有 IPv4 /24–/28 网段。一次性邀请最多 24h，只保存哈希；设备使用本地生成的 Ed25519 identity 和 WireGuard key，签名提交公钥、名称与邀请。审批后分配唯一虚拟 IP，撤销后地址暂不复用；每网络最多 64 个已分配身份（包括已撤销），128 个登记记录。
- 每设备签名快照请求带随机 nonce、时间戳与防重放记录。管理端每 3s 轮询返回当前授权 peer、/32 IP、公钥、签名中继租约；待审批或撤销设备不能获取其他 peer。明确允许/拒绝的双向设备对规则优先于网络默认策略。当前为设备对级访问控制，不是端口/协议级 ACL。
- 租约与网络 revision、pair、节点、两分钟 epoch 关联，下一 epoch 边界后 30s 到期；相同 pair/revision/epoch 两端获得相同 token。管理 Agent 按快照自动创建 TUN、ICE/WSS 路径；拓扑或租约变化时重建 tunnel，存在短暂中断，不承诺无感续期。成功快照有效期约 20s，失联到期关闭 tunnel；明确撤销则停止。管理 Agent 当前每状态目录只加入一个网络。私钥与本地状态使用权限受限目录和文件。
- all 模式中继与信令在鉴权及约 1s 周期校验当前 DB 策略、成员状态、revision；独立 relay 模式只验证签名、scope 与租约有效期，当前没有跨节点即时撤销通知，旧租约可能持续到期（最长约 150s）。正常 Agent 收到新配置会移除路由与 peer；不能声称对恶意独立客户端立即撤销全部连接。
- 内置 Web 静态界面：登录、网络列表/创建、生成邀请、设备审批/撤销、设备对策略、成员账号创建、审计记录。原生 HTML/CSS/JS 直接 embed 到服务端；无 Node.js 运行时；Bearer token 仅保存在页面内存，CSP 防外部脚本。M3 未做完整浏览器交互与视觉验收，后续完善 UI。
- 三个运行模式：all、management、relay。management-only 广告独立 relay URL；relay-only 只需 issuer 公钥、TLS 和节点 ID，无 SQLite、无需业务库凭据。节点自动注册/多节点调度属 M5。

## 构建
Linux Go 1.23.12 + GCC（本次实测）；`CGO_ENABLED=1`。
```sh
go test ./...
mkdir -p bin
go build -o bin/network-ex-server ./cmd/server
go build -o bin/network-ex-agent ./cmd/agent
```
生产前需依赖安全审查、签名发行、平台验证。此版没有公开部署或 release。

## 单机部署示例（替换成真实受控地址/证书）
```sh
umask 077
mkdir -p data
network-ex-server issuer-keygen -out data/issuer.key > data/issuer.pub
# 通过安全方式将管理员初始密码写入 data/admin-password（0600），不少于12字节
network-ex-server admin-bootstrap -db data/network.db -username admin -password-file data/admin-password
# 初始化后妥善删除或移出初始密码文件；私钥不要上传
network-ex-server -mode all -listen 127.0.0.1:8443 -node relay1 \
  -db data/network.db -issuer-key data/issuer.key \
  -relay-url wss://network.example.com/relay/v1 \
  -stun-url stun:network.example.com:3478 -stun-listen 127.0.0.1:3478 \
  -tls-cert cert.pem -tls-key tls.key
```
示例监听 loopback；真实远端访问必须按实际反代或监听地址设置 TCP/UDP 端口，证书须匹配公开地址。禁止关闭 TLS 校验。登录管理 Web，创建网络与设备邀请码（用一次失效）。

## 独立部署
管理服务器使用 `-mode management`、同样的 db/issuer-key、node、TLS 参数，relay-url 指向独立中继，stun-url 指向其 STUN；不传 -stun-listen。
中继服务器：
```sh
network-ex-server -mode relay -listen 127.0.0.1:8443 \
  -node relay1 -issuer-public issuer.pub -stun-listen 127.0.0.1:3478 \
  -tls-cert cert.pem -tls-key tls.key
```
节点 ID 与管理端发行的 lease 必须一致；中继只分发 issuer.pub，不分发 issuer.key。当前仅支持静态指定一个中继地址。备份须包含 SQLite 一致性备份与 issuer 私钥（分开保护）；SQLite WAL 不能只盲拷主数据库。

## 客户端
将 Web 一次性邀请码保存在权限 0600 的文件中。首次：
```sh
network-ex-agent managed-enroll -server https://network.example.com \
  -invite-file invite.txt -name my-linux -state-dir ./device
# 私有 CA 可额外指定 -ca ca.pem
# 管理员审批后：
sudo network-ex-agent managed-run -state-dir ./device -interface nex0
```
状态文件 device/managed.json（管理授权状态）与 device/tunnel.json（实际路径/握手/流量）；`network-ex-agent status -file ./device/managed.json`。需 Linux TUN 与适当权限。管理/中继不同私有 CA 可 -relay-ca；可选 -ice-interfaces。正常退出清理，异常退出可能留下 run.lock，确认旧进程停止且路由/接口已清理后方可移除。注册失败保留密钥目录，若邀请已消费但响应丢失目前需要管理员重新邀请/清理；不要重复覆盖身份目录。

## API
POST /api/v1/auth/login、logout；GET /api/v1/me；GET/POST /api/v1/users；GET/POST /api/v1/networks；POST /api/v1/networks/{id}/invites；GET /api/v1/networks/{id}/devices；POST .../devices/{device}/approve|revoke；PUT .../policy；GET/PUT .../rules；GET /api/v1/audit；POST /api/v1/devices/enroll、snapshot（设备签名）。实际 JSON 结构见 internal/control/protocol.go 与 server.go；本阶段临时 API，不宣称已冻结 OpenAPI。

## 实测
首尔 Linux OpenCloudOS 9.6；隔离 network namespaces，三台 Agent，第三台底层 UDP 封锁，TLS 私有测试证书。两次运行均退出 0（all 与 split），无公网部署。
- 两个程序构建、版本 0.3.0-dev-m3，Go tests 全部通过；TestManagedAuthorizationLifecycle 验证默认拒绝、显式规则、同 pair lease、签名身份与重放保护、策略变更及撤销导致旧 lease 失效。
- all/split 均通过 HTTPS UI 资源与 CSP、初始化管理员不可重复、成员登录、所有者隔离、网段重叠拦截、一次性邀请不能重复消费。
- 三台 Agent managed-enroll、待审批不建 TUN、三项并发审批 IP 唯一、自动配置无需手填 peer；A-B ICE direct，A-C WSS relay；两条路径 TCP/UDP 真实回显。
- A-B deny 后路由删除且不可达、A-C 仍互通；允许后 A-B 恢复；撤销 C 后其 TUN 删除且其他设备移除 C 路由。
- 两次管理服务停机均约 18s 后过期授权关闭 TUN；重启 SQLite 数据、地址、撤销记录持久化，授权设备通信恢复；正常停止清理。
复现：
```sh
sudo bash scripts/m3-managed.sh outside "$(pwd)/bin" all
sudo bash scripts/m3-managed.sh outside "$(pwd)/bin" split
```
需 root、iproute2、iptables、unshare/nsenter、python3、openssl、ping、TUN。临时网络命名空间、证书、数据库和密钥由脚本清理。
## 待完成
严格生产验收未结束：完整多租户组织模型、多网络、细粒度端口 ACL、在线免中断密钥/lease 热更新、管理高可用、分布式即时撤销、节点自动注册、容量/长期稳定性、真实公网 NAT、跨平台签名/权限、浏览器实操、依赖与安全审查、正式部署包与许可证。未把 M0 的全部未来 API/schema 宣称实现。后续 M4 桌面 UI 与平台适配需先拆分共享 protocol 类型，避免 Agent 不必要地引入 SQLite/CGO。
