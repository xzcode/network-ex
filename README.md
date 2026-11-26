# Network EX

自主开发的跨平台虚拟局域网工具：端到端加密、P2P 直连优先、中继兜底、完全自托管。

当前状态：M2 Linux 数据面开发版；真实隔离 NAT 环境已验证自动 ICE 穿透、P2P/WSS 中继混合组网及双向切换。管理服务、桌面界面、生产安全和公网验证未完成。详见 [M2 实现与验收](docs/M2_IMPLEMENTATION.md)、[M1 实现](docs/M1_IMPLEMENTATION.md)、[阶段状态](docs/STATUS.md)。

## 构建
Go 1.23；Linux 运行时。见 M2 文档及 scripts/m1-netns.sh、scripts/m2-nat.sh。
```sh
go test ./...
go build ./cmd/agent
go build ./cmd/server
```

## 开发入口
- [产品需求](docs/PRD.md)
- [架构](docs/ARCHITECTURE.md)
- [服务端](docs/SERVER_DESIGN.md) / [客户端](docs/CLIENT_DESIGN.md)
- [协议](docs/PROTOCOL.md) / [P2P](docs/P2P_DESIGN.md) / [中继](docs/RELAY_DESIGN.md)
- [安全](docs/SECURITY.md) / [数据模型](docs/DATABASE.md)
- [界面](docs/UI_DESIGN.md) / [部署](docs/DEPLOYMENT.md)
- [路线与验收](docs/ROADMAP.md) / [技术决策](docs/DECISIONS.md)
- [开发协作](AGENTS.md)

Windows、macOS、Linux 优先，Android/iOS 后续。单一服务端程序计划支持 all / management / relay 三种模式；目前 relay 模式包含 WSS 中继、认证信令及可选 STUN。桌面 UI 与后台 Agent 分离。所有功能以实测记录为准。
