# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面、M3 管理服务、M4 Linux daemon/IPC 核心实测通过。M4 原生 Tauri、安装及 Windows/macOS 实机验收保留。
M5 多中继注册、调度、故障转移/维护迁移实测通过，单中心 SQLite；跨主机数据库 HA 未实现。
M6 Linux 私有子网、服务 ACL、DNS、单 daemon 多 profile、选择性 IPv4 出口与指定目标防回落实测通过。全流量出口、系统 resolver、IPv6 与跨平台子网/出口未完成。
M7/M7b 0.7.0/0.7.1：受控 UDP 广播/多播及独立 Linux TAP/IPv4/ARP 二层核心、ACL、二层退出并切回三层实测通过。策略/租约变化可能重建接口；真实游戏和跨平台 TAP 未验收，见 M7B_IMPLEMENTATION.md。
M8 0.8.0-dev-m8：共享 mobile Go API、外部 VPN fd、socket 保护、授权租约、Android 原生 Java VPNService/前台服务/双语 UI 源码、构建脚本。初始 Android arm64/amd64 Go package 编译、更新依赖后 Go 全量测试及 Linux 最终构建、Java binding 生成、XML/脚本检查通过。Linux 原生 fd fixture 实际三设备 TCP/UDP、未授权及保护拒绝、停止清理、重连、撤销通过；这不是 Android 真机。M8 初版仅 peer /32 + WSS relay，不支持 ICE、子网、出口、TAP、IPv6 隧道。iOS 仅设计文档。详见 M8_IMPLEMENTATION.md。
阻塞：当前首尔构建机无 Android SDK/NDK、JDK/Gradle 且磁盘紧张；AAR/APK 与 Java/Gradle 编译、真机权限和前台/网络切换、iOS Xcode extension/签名均未完成。下一批优先实际 Android 构建及验收，之后移动端 P2P/iOS；M4/M5/M6/M7 生产门槛仍保留。无公网部署、无 Release。
