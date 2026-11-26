# 状态与交接（2026-11-26）

M0 完成。M1/M2 Linux IPv4 数据面核心完成：WireGuard、STUN、ICE/WSS 中继、隔离 NAT 实测与回退。详见 M1/M2_IMPLEMENTATION。
M3.1–M3.8 管理服务核心已实现：SQLite、管理员/成员、网络/IPAM、一次性邀请、设备审批/撤销、设备签名快照/防重放、双向设备对 ACL、租约自动续期、内置 Web、all/management/relay。
版本 0.3.0-dev-m3。Go tests、all 与 split 三设备隔离网络完整脚本均通过（实际 TCP/UDP、P2P+relay、审批/ACL/撤销、管理停机约18s fail closed、SQLite重启持久化/恢复）。详见 M3_IMPLEMENTATION.md。
未完成的生产验收：管理 Agent 变更配置/租约时重建 tunnel；独立 relay 仍按签名 lease 到期撤销，无分布式即时撤销；多网络/端口 ACL/真实公网、IPv6、长期性能、安全评审、跨平台及浏览器交互尚未验收。无公网部署、无 release。
下一阶段 M4：提取共享 protocol 以消除 Agent SQLite/CGO 耦合，安全 IPC、后台服务生命周期、Tauri/Vue 桌面 UI 与主题/i18n、Windows/macOS/Linux 虚拟网卡与路由适配、各平台真实安装验收；再 M5 多中继扩展。项目许可证及依赖安全需复核。
