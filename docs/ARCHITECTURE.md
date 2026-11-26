# 架构 M0

## 分层
- 控制面：HTTPS API、设备注册、IPAM、ACL、签发短期中继授权、拓扑配置快照、WSS 信令；可独立扩容。
- 数据面：Agent TUN -> WireGuard 加密 -> peer 传输适配 -> 直连 UDP 或中继 -> 远端 WireGuard -> TUN。Server 不转发用户明文，Relay 仅转发密文。
- 发现面：STUN/ICE 候选交换，节点注册与健康监测。每个 peer 有独立 path manager，而非整网固定路径。
- UI：Tauri 2 + Vue 3 + TS；管理 Web 静态文件可 embed 于 Go Server。Agent 与 UI 通过受 OS ACL 保护的本地 IPC 通信。

## 部署形态
一个 Go server 二进制：all（管理+信令+relay+STUN）、management、relay。按模式启停组件，共享配置结构。Agent 为独立二进制。单机 SQLite、内存 session/events，集群可切换 PostgreSQL、Redis/NATS 或等效实现；不要求部署中间件才能启动。Relay 不直接访问业务库，使用独立节点身份与短期授权。

## 传输关键决策
候选：wireguard-go 用户态引擎的 conn.Bind/Endpoint 适配，维护逻辑 peer endpoint 到实际路径的映射；同一 peer 的密文可以送往 UDP 或经认证 Relay。WireGuard 自身握手、重放保护和密钥协商不改。接收端不得信任转发帧声明的 peer 身份；WireGuard 验证后才接受数据。须验证 endpoint roaming、cookie endpoint 绑定、接收缓冲区、BatchSize、Close、双栈、MTU、并发切换、ICE 与实际数据 socket 的一致性。备选：本地逐 peer UDP proxy + WireGuard 标准 endpoint，比较端口、MTU、漫游及隔离成本；不同时维护两套生产路径。M1 技术门通过后冻结选择。
参考：https://github.com/WireGuard/wireguard-go/blob/master/conn/conn.go
ICE: https://www.rfc-editor.org/rfc/rfc8445.html
STUN: https://www.rfc-editor.org/rfc/rfc8489.html
TURN: https://www.rfc-editor.org/rfc/rfc8656.html
不默认依赖外置 coturn；若原生 Pion STUN 组件不满足，则明确 optional profile；TURN 兼容以后再决定。

## 代码边界
cmd/server、cmd/agent；internal/control/{auth,ipam,policy,signal,store}，internal/dataplane/{tunnel,path,relay}，internal/platform/{tun,route,service,ipc}，internal/node/{registry,stun}，pkg/protocol。依赖方向：入口 -> 业务模块 -> 接口/协议；平台与存储实现注入，control 不依赖 UI，relay 不读取业务数据。
接口：Store（事务/唯一约束）、SessionRegistry（设备到实例、租约）、EventBus（事件+重同步）、PeerTransport（Send/Receive/Close）、PathManager（候选/状态）、PolicyCompiler（默认拒绝）、NodeRegistry（注册/健康/调度）。

## 容错
持久状态 revision 单调，事件可能重复/乱序；客户端按 revision 忽略旧消息、发现 gap 重拉快照。控制面断开时仅在授权有效且未超过离线期限内使用现有 peer；超过期限 fail closed。Relay 故障重连其他获授权节点，无法保证 TCP 会话必不丢失。节点 drain、健康、容量上报；管理集群重连可换实例。M0 不承诺性能或 HA 已实现。
