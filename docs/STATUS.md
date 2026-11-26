# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面、M3 管理服务、M4 Linux daemon/IPC 核心实测通过。M4 原生 Tauri、安装及 Windows/macOS 实机验收保留。
M5 0.5.0-dev-m5 多中继注册、双端调度、自动故障转移/维护迁移核心实测通过；管理端仍单中心 SQLite，无多机高可用。M6 补强 SQLite 原子迁移、先验设备身份再授权、过期容量回收、节点限额单测。
M6 0.6.0-dev-m6：Linux 私有子网共享、双重授权、WireGuard AllowedIPs 与 TUN 双向流量边界、设备对 TCP/UDP/ICMP 服务 ACL、可选本机 TCP/UDP DNS、CLI 多独立网络实例、Web 高级配置与桌面 peer 路由/DNS 展示。两个隔离集成脚本、Go tests、五种 Agent 架构构建与 Vue build 通过。详见 M6_IMPLEMENTATION.md。
M6 待补齐：互联网出口节点、统一多网络 UI、系统 DNS 与跨平台子网适配；出口必须经过 underlay 路由保护/kill-switch/DNS IPv6 泄漏验证。M5 多管理实例/跨主机数据库 HA、原生桌面及生产安全、公网真实环境验证依旧待完成。无 release、无公网部署。
下一批：先补齐 M6 安全出口与网络配置编排，再 M7 广播/二层与游戏联机。高可用与原生安装任务不能标记完成。
