# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面、M3 管理服务、M4 Linux daemon/IPC 核心实测通过。M4 原生 Tauri、安装及 Windows/macOS 实机验收保留。
M5 多中继注册、调度、故障转移/维护迁移实测通过，单中心 SQLite；跨主机数据库 HA 未实现。
M6 Linux 私有子网、服务 ACL、DNS、多 profile、选择性 IPv4 出口实测通过。全流量出口、系统 resolver、IPv6 与跨平台子网/出口待完成。
M7/M7b 受控 UDP 广播/多播及 Linux TAP/IPv4/ARP 二层核心实测通过。接口重建、真实游戏及跨平台 TAP 未验收。
M8/M8b Android VPNService、默认中继与实验性 P2P，Linux fd 实网、Android Debug APK 构建签名/16KiB静态检查通过；真机待验收。
M8c 0.8.2-dev-m8：iOS SwiftUI/Packet Tunnel、Go packet-flow queue、Keychain bundle、XcodeGen/构建脚本源码。Go tests、iOS arm64 Go package、Objective-C binding、配置解析、Linux flow 实网 TCP/UDP、注册身份恢复、停止重连撤销通过；修复 mapped IPv4 路由检查。Android 0.8.2 Debug APK 回归构建签名对齐通过。详见 M8C_IMPLEMENTATION.md。
无 macOS/Xcode/Apple 签名环境，iOS native compile/XCFramework/IPA/真机待完成。Android 真机、M4/M5/M6/M7 生产门槛保留。无公网部署、无 Release。下一批 M9 开发版构建及发布准备、依赖/安全/许可证及原生验收。

M9a：实际 GitHub 官方 Runner 工作流已触发（桌面 Windows/macOS Intel Agent sidecar 编译通过，首次 npm 安装失败；98 条 HTTP 镜像锁地址已切官方 HTTPS，重试 run 45791414659，iOS 改 Intel Xcode runner 以避 ARM 排队）。Linux 0.8.2 开发 tar.gz、22组件 Go SBOM/依赖 notices、非 root 服务端独立验收通过，部署脚本不启动公网服务。govulncheck 发现40项 reachable findings，开始独立 Go/依赖升级候选；生产安全、项目许可证、原生安装和签名门槛仍开放。详见 M9_IMPLEMENTATION.md、M9_PACKAGING.md。当前未发布 Release。以 Actions 实际结果为准，不把 queued/in_progress 当成功。
