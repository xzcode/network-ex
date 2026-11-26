# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面、M3 管理服务、M4 Linux daemon/IPC 核心实测通过。M4 原生 Tauri、安装及 Windows/macOS 实机验收保留。
M5 多中继注册、调度、故障转移/维护迁移实测通过，单中心 SQLite；跨主机数据库 HA 未实现。
M6 0.6.0-dev-m6：Linux 私有子网、服务 ACL、DNS、独立多网络实测通过（M6_IMPLEMENTATION.md）。
M6 补充 0.6.1-dev-m6：单 daemon 1–8 个 profile、桌面网络列表与切换、独立持久化/恢复、统一 DNS hub 与 profile-qualified 名称、dnsmasq/macOS 可选 split-DNS 配置工具；Linux 选择性出口授权、双本地 opt-in、/32 目标路由、nftables 指定目标防回落。多 profile 与选择性出口两个隔离集成脚本实测退出0；Go tests、五目标 Agent 构建、Vue build、Web JS 和 DNS 脚本语法/配置输出通过。详见 M6B_IMPLEMENTATION.md。
剩余：完整全流量出口及 IPv6/DNS 泄漏保护、OS resolver 实机接入、Windows/macOS 子网/出口、M4 原生桌面安装与 M5 HA、真实公网和安全审计。选择性出口不是全局 VPN，终止异常可保留 nft 规则，需明确本地恢复操作。无公网部署、无 release。
下一批：补齐完整出口方案的路由与安全边界，或并行推进 M7 游戏联机（广播发现/二层）。保持已实现功能的实际验收边界。
