# 状态与交接（2026-11-26）

M0 已提交。M1.1–M1.6 核心代码已落地：Go 工程、Linux TUN / 路由、WireGuard、静态每 peer UDP/WSS path、签名租约与设备证明、CLI/后台重连/状态/清理。
实际 Go 1.23.12 编译成功，两个 relay 安全测试通过，三节点隔离 netns 同时直连/中继的 ICMP、TCP、UDP、底层抓包与路由清理实测通过；第二轮 1200-byte TCP/UDP、中继重启恢复、未经授权的 WG 密钥拒绝均通过。见 [M1 实现及验收证据](M1_IMPLEMENTATION.md)。
M1 核心闭环通过；严格退出门尚未完全清零：完整 MTU 边界扫描、更多恶意 peer 场景、endpoint roaming、完整路由冲突、长时间重连尚未验证/补强。非生产版本，未部署公网、未发布 release、未验证 Windows/macOS。当前没有 NAT 自动打洞、自动切换和管理服务。
下一批：补齐 M1 安全与传输边界；随后推进 M2.1–M2.6：STUN/ICE 同 socket 传输、信令、动态 path 状态机、回退、重探测、真实 NAT 验收。参见 ROADMAP、DECISIONS、M1_IMPLEMENTATION。
决策：WSS 先行、QUIC 可选；静态原型不增加外置中间件。依赖/项目许可证待最终复核。
