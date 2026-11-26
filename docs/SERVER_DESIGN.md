# 服务端

## 模块
HTTP API、管理员初始化、身份与授权、组织/网络/设备、IPAM、配置快照、信令、Relay registry、授权签发、审计、指标、静态管理 Web。Go net/http 或轻量路由优先，框架按 M3 实现选择。请求必须携带认证身份、明确 tenant/network scope，RBAC 拒绝优先；服务不接受任意目的地址转发。

## 生命周期
首次启动用本地 CLI 创建管理员或输出短期仅本机可用 bootstrap；完成后关闭 bootstrap。默认关闭公开注册。设备注册生成独立身份公钥与各网络 WireGuard 公钥；服务端只保存公钥及撤销状态。邀请为高熵短期一次性秘密、仅保存哈希。设备证明持有身份私钥后获取短期会话令牌。网络成员变更在同一事务更新 revision 并写 outbox，异步发送通知；掉线后重新获取快照。
IPAM 在网络 scope 中事务分配，冲突重试并保持唯一；禁用成员时先撤销 ACL/租约，地址隔离期后才能复用。不得将同一设备的地址视为身份。

## 扩容
管理 API 无状态（认证密钥、数据、revocation 共享）；信令 WSS 实例维护本地 socket，分布式注册 device/session -> instance，事件总线转发；session lease/fencing 避免旧连接覆盖新状态；断开则 revision 全量恢复。数据库使用迁移及事务约束，HA PostgreSQL 单写入者优先。分布式锁仅用于 leader job；不得依赖 Redis 持久化 ACL。
Relay mode 通过一次性节点 enrollment 取得独立身份，心跳报告节点地区、协议、版本、出口容量、连接、队列、错误；过期标记 offline，节点可 drain。签发 node/network/src/dst/expiry 限定授权，不发业务库凭据。
单机不需要 Redis/NATS。横向扩展优先增加 Relay、再拆信令、再控制面 HA；避免过早分片。

## API 拟定
见 PROTOCOL。健康 /healthz 只表示进程存活；/readyz 检查必要依赖；/metrics 默认内网/认证。管理操作记录 actor、target、action、result、revision、timestamp、request_id（不记录 token）。速率限制按账号、设备、IP、节点；所有日志默认无 payload。
