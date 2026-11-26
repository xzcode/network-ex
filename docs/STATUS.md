# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面、M3 管理服务、M4 Linux daemon/IPC 核心实测通过。M4 原生 Tauri、安装及 Windows/macOS 实机验收保留。
M5 多中继注册、调度、故障转移/维护迁移实测通过，单中心 SQLite；跨主机数据库 HA 未实现。
M6 Linux 私有子网、服务 ACL、DNS、单 daemon 多 profile、选择性 IPv4 出口与指定目标防回落实测通过。全流量出口、系统 resolver、IPv6 与跨平台子网/出口未完成。
M7/M7b 受控 UDP 广播/多播及 Linux TAP/IPv4/ARP 二层核心实测通过。策略/租约变化可能重建接口；真实游戏及跨平台 TAP 未验收。
M8/M8b 0.8.1-dev-m8：共享 Go mobile API、Android VPNService 原生界面、前台服务、保护 socket、默认中继与可选实验性 P2P。Tokyo 独立 SDK/NDK/JDK/Gradle 环境已完成；Go tests 与 Linux native-fd direct 集成脚本退出0，双端 ICE 直连/TCP UDP/UDP阻断回退/撤销通过。实际 ARM64/x64 AAR、Java/Gradle Debug APK 构建、v2签名、ELF及ZIP 16KiB静态对齐通过。产物在 /app/agent/network-ex-m8b-20261126/artifacts，见 M8B_IMPLEMENTATION.md。Android linkname 兼容 flag 待生产依赖复核。
Android 真机安装、VPN权限/前台、移动网络切换、实际 16KiB/P2P 尚未验收；iOS 仍设计阶段。无公网部署、无 Release。下一批优先 Android 实机、iOS packet-flow extension、M9生产发布门槛。M4/M5/M6/M7 未完事项保留。
