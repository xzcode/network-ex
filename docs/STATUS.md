# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面、M3 管理服务、M4 Linux daemon/IPC 核心实测通过。M4 原生 Tauri、安装及 Windows/macOS 实机验收保留。
M5 多中继注册、调度、故障转移/维护迁移实测通过，单中心 SQLite；跨主机数据库 HA 未实现。
M6 0.6.0/0.6.1：Linux 私有子网、服务 ACL、DNS、单 daemon 多 profile、选择性 IPv4 出口与指定目标防回落实测通过。完整全流量出口、系统 resolver、IPv6 与跨平台子网/出口仍未完成，见 M6_IMPLEMENTATION.md、M6B_IMPLEMENTATION.md。
M7 0.7.0-dev-m7：Linux IPv4 UDP 游戏发现核心，管理端地址/端口白名单、设备签名 opt-in、WireGuard 加密逐 peer 封装、直连和中继、ACL、限速与防环路、管理 Web 和桌面真实计数。三 Agent 隔离集成脚本实测三类广播/组播房间发现、未知端口阻断、撤销清路由、基础 TCP/UDP；Go tests、Linux server/Agent、四额外目标 Agent、Vue build 与 JS syntax 通过。详见 M7_IMPLEMENTATION.md。
M7 待完成：真正的二层 TAP/Ethernet、虚拟 MAC/ARP、Windows/macOS 发现运行适配、真实游戏客户端兼容性与跨公网验收。无公网部署、无 release。
下一批：优先完成二层模式与游戏兼容验收，或推进移动端；保留 M4/M5/M6 安全及发布门槛，不标记为全部完成。
