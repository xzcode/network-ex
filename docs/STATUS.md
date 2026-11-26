# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面核心与 M3 管理服务核心已实测通过（详见各阶段文档）。
M4 版本 0.4.0-dev-m4：共享 protocol 解耦 Agent/SQLite，daemon/ctl 安全 IPC、后台自动恢复、Vue/Tauri 桌面源码、状态/设备/拓扑/监控/诊断、系统托盘源码、中英及主题、Linux/macOS/Windows 路由和服务候选实现、安装脚本/sidecar 构建脚本。Linux amd64/arm64、Windows amd64、macOS Intel/arm64 Agent 跨编译成功；Vue 生产构建成功；Linux IPC 组权限及三设备完整 daemon integration 实测通过。首次验收暴露 Pion ICE 并发 Close 崩溃，已修复并重新通过。见 M4_IMPLEMENTATION.md。
M4 尚未严格结束：首尔无 Rust/GUI 依赖，Tauri 原生壳、GUI 实际交互、系统服务真实安装、Windows 标准用户授权与 Wintun、macOS utun/签名、跨平台安装包未验收。无 release，无公网部署。M3 续期可能短暂断连、独立 relay 到期撤销、单网络限制等仍保留。
下一批：补齐 M4 原生验证和安装门槛；M5 多中继节点注册、心跳、目录、双端调度、配额、drain、故障转移、分布式控制面；生产安全、实际公网、许可证与依赖审查仍需完成。
