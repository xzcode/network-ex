# 状态与交接（2026-11-26）

M0 已完成。M1.1–M1.6 核心闭环实测完成，M2.1–M2.6 核心实现落地：内置 STUN、基于签名租约的 TLS 信令、Pion ICE 数据 socket、每 peer 独立直连选路、WSS fallback、失败后重协商与真实状态。
M2 隔离 NAT 实验：A/B 位于独立 NAT 后，srflx/srflx 直连，C 的 UDP 封锁时仍走中继；TCP/UDP 同时互通；主动阻断 UDP 后约 5s 恢复中继、恢复 UDP 后约 21s 重新穿透（首次测试），清理通过。M1 静态路径回归通过，信令安全测试、路由冲突前置保护通过。详见 [M2 实现与验收](M2_IMPLEMENTATION.md)。
严格生产退出门未清零：实际公网/CGNAT/对称 NAT、IPv6、OS 网络变更监听、长连接无感切换、完整 MTU 与长期负载、安全审计、跨平台尚未验收。没有公网部署、没有 Release。M2 开发版仅 Linux/IPv4。
下一批 M3.1–M3.8：SQLite schema、管理员与账号、网络/IPAM、设备注册审批/撤销、信令快照、授权租约/续期与 ACL、内置管理 Web、all/management/relay 部署模式；兼容现有隔离网络验收。项目与依赖许可证仍待最终复核。