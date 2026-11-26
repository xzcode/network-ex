# ADR 与未决事项

| ADR | 选择 | 状态 |
|---|---|---|
| 001 | 自主客户端/服务端/信令，复用 WireGuard 与 ICE，不复制商业产品 | 采用 |
| 002 | Go server 单 binary 三模式；Agent 独立；管理 Web embed | 采用 |
| 003 | 模块化单体 + 独立 relay；SQLite 默认；集群接口预留 | 采用 |
| 004 | L3 IPv4 先行，L2/游戏广播后续 | 采用 |
| 005 | 每 peer 混合路径；直连优先，WSS relay 兜底；QUIC 可选 | 采用，QUIC 待测 |
| 006 | wireguard-go Bind 自定义适配优先，本地 UDP proxy 备选 | M1 实验门 |
| 007 | ICE/Pion 与 STUN 数据 socket 一致；TURN 不作为必选外部服务 | M2 实验门 |
| 008 | 管理控制面受信任，端到端 WG；设备/节点租约与 ACL，离线期限 | 采用，具体 token 实现 M3 |
| 009 | Tauri 2/Vue 3/TS；后台 Go；平台特权适配 | 采用，macOS/Windows 分发验证 M4 |
| 010 | 软件许可证、商标、官方域名、计费政策 | 待所有者确认，不阻塞 M1 私有开发 |

依赖来源：WireGuard wireguard-go（上游 MIT，锁定版本后复核）、Pion ICE（MIT，锁定后复核）、Pion STUN（待锁定复核）、QUIC 库和 SQLite driver 待选。引用标准 RFC8445/8489/8656；第三方 license 以实际发布版本为准。不要默认使用外部 TURN 或强制官方账号。无代码依赖版本在 M0 被安装，禁止宣称兼容已通过。
