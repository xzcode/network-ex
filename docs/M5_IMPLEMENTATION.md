# M5 多中继节点与调度（2026-11-26）

版本 0.5.0-dev-m5。单中心管理服务、多个独立中继节点的核心实现已通过隔离 Linux 网络实测；不是多管理实例高可用集群。

## 实现
- SQLite schema v2：relay_nodes、node_nonces、node_probes、pair_relays。v1 自动事务迁移。管理员创建节点（地区、WSS 地址、可选 STUN 地址、全网络或指定网络、优先级与限额）；一次性邀请码有效 1h，仅存哈希。独立节点 Ed25519 身份与签名 nonce/timestamp 请求，注册、心跳、授权查询；节点不需要业务库或签发私钥。
- 节点每 3 秒心跳，12 秒无心跳视为离线。上报当前连接数、累计收发字节及丢包数（进程重启归零，不是持久化计费数据）。管理员支持 active/draining/revoked 和限额更新。
- 管理服务向已批准设备分发符合网络范围的在线 active 节点目录。M5 Agent 并行进行 TLS 校验 HTTPS /healthz 探测，整体超时 2 秒，签名上报测量；探测反映 HTTP 可达性与请求耗时，不是完整 UDP/ICE RTT。每个设备对由中心事务选定共同节点，综合两端测量、优先级、容量/已分配设备对和连续失败；稳定分配及迟滞，避免频繁换节点。探测数据有效约20秒；连续失败或节点离线/维护触发重选。每个 peer 使用独立 relay/STUN URL；无可用节点且无静态 fallback 时不分配 peer。
- 节点接入后按管理端下发的连接上限（2–256）及节点聚合数据限速（65536–1073741824 B/s）执行；本地 token bucket，超额包丢弃。连接上限用于新连接准入，已有连接不强制逐个关闭。计数包含中继应用载荷而非全部链路开销，不应视为计费精确值；信令仍使用原有独立上限。
- 注册节点在连接与定期授权检查时向管理端验证签名 lease 的节点、成员、设备对规则、revision 与当前分配；短缓存约1秒，查询超时/失联 fail closed。draining 节点不再分配，现有设备轮询后迁移，不保证零中断；revoked 节点不可重新启用。原有静态 relay 模式仍兼容旧部署，但不具备注册节点在线重新授权能力。
- Web 管理新增节点列表、注册邀请、状态、心跳、连接/流量计数、维护/恢复/撤销及配额编辑；前端 JS 语法已验证，未做浏览器交互验收。Agent 状态公开 peer relay_node，不泄露租约。
- 多节点注册启用后需要 M5 Agent；旧客户端不能正确处理每 peer 动态分配，管理端对有可用注册节点的旧请求返回 426。无注册节点的静态模式保留。

## 部署
中心管理实例使用 TLS，-mode management，可不传 -relay-url（仅注册节点）；若设置静态 fallback，优先使用符合条件的注册节点。all 模式仍须指定自身 -relay-url。
管理后台以管理员创建节点，填写实际对外可访问 WSS 和 STUN 地址，生成邀请码。将 issuer 公钥（不是私钥）、可信管理 CA 与一次性邀请码传给中继。邀请码文件权限 0600。

```sh
umask 077
network-ex-server node-keygen -out relay.key > relay.pub
network-ex-server -mode relay -node relay-1 -listen 0.0.0.0:8443 \
  -stun-listen 0.0.0.0:3478 -issuer-public issuer.pub \
  -tls-cert relay.crt -tls-key relay-tls.key \
  -management-url https://control.example.com \
  -management-ca control-ca.pem -node-key relay.key \
  -node-invite-file relay.invite
```
节点 ID 必须与管理员创建的 ID 相同；TLS 证书须匹配对外域名。注册成功后可移除邀请码文件及启动参数，后续使用同一身份密钥心跳接入。公网证书可信时可省略管理 CA 参数。切勿复制 issuer 私钥到 relay。

## 实测
首尔 Linux 隔离 network namespaces；一个中心管理服务（SQLite），两个独立 relay/STUN 进程，三个 Agent。C 的底层 UDP 封锁；A-B ICE 直连，A-C 通过 relay。
- go test ./...、Go server/CGO-free Agent 构建通过；Web JavaScript 语法检查通过。
- 管理端 HTTPS、登录及成员隔离、设备邀请/审批、地址唯一；两台中继注册上线，真实 TCP 与 UDP 回显，收发字节计数非零。
- 停止 r1 后 A/C 双端改为 r2 且 ping 恢复：9 秒；重启 r1 使用原身份，r2 进入维护后 A/C 改为 r1 且 ping 恢复：5 秒。计数心跳继续更新。完整脚本 exit 0。
```sh
sudo bash scripts/m5-multirelay.sh outside /absolute/path/to/bin-m5
```
脚本仅使用临时命名空间、证书、数据库与进程；无需生产环境。切换时长是单次隔离测试结果，不是服务等级承诺。限额与授权实现已编译，未做专门高负载限流/恶意节点/压测验证；旧阶段静态回归全套本轮未重跑。真实公网多地域、长时间高并发、管理服务多实例共享数据库/高可用、配额持久化计费、节点跨区域调度指标与独立安全审计仍待完成。M4 原生 GUI/安装包验收门槛仍保留。无公网部署、无 release。
