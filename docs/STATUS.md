# 状态与交接（2026-11-26）

M0：设计文档和目录骨架完成，未实现运行代码。没有实际编译、网络测试、部署、Release。阶段验收仅为文档基线，不表示产品可用。
M1 下一批：确认 Go 工具链和依赖版本，创建最小 Agent/server、Linux TUN/route，静态 peer WG 双向 TCP/UDP；随后验证 Bind adapter 与经过认证的 WSS relay。真实证据满足 ROADMAP 后才能进入 M2。
阻塞/未决：WireGuard Bind 语义和 ICE socket 适配未验证；QUIC MTU/数据报未验证；Windows/macOS 签名和平台权限待验证；项目许可证待所有者确认。当前不部署或开放公网端口。
