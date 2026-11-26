# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面、M3 管理服务、M4 Linux daemon/IPC 核心实测通过。M4 原生 Tauri、安装及 Windows/macOS 实机验收保留。
M5 多中继注册、调度、故障转移/维护迁移实测通过，单中心 SQLite；跨主机数据库 HA 未实现。
M6 Linux 私有子网、服务 ACL、DNS、单 daemon 多 profile、选择性 IPv4 出口与指定目标防回落实测通过。完整全流量出口、系统 resolver、IPv6 与跨平台子网/出口未完成。
M7 0.7.0：受控 UDP 广播/多播发现实测通过。M7b 0.7.1-dev-m7：独立 Linux TAP、真实虚拟 MAC/ARP、受控 IPv4 Ethernet frame，经 WireGuard P2P/relay 传输；管理员与本地 opt-in、服务 ACL、MAC/ARP/IP 所有权校验、限速防环路、Web 网络模式和桌面计数。首次完整二层隔离测试通过，增强 ACL 实测通过，Go tests/五目标 Agent build/Vue build/JS syntax 通过。最终扩展脚本尚未确认完整退出；切回三层验收保留。详见 M7B_IMPLEMENTATION.md。
剩余：策略/租约更新可能重建网卡，游戏绑定需重开；Windows/macOS TAP、实际游戏兼容、公网与生产审计。无公网部署、无 Release。M8 移动端可独立推进；M4/M5/M6 门槛仍保留。
