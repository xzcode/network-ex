# Network EX

自主开发的跨平台虚拟局域网工具：端到端加密、P2P 直连优先、中继兜底、完全自托管。

当前状态：M1 Linux 数据面开发版；静态 peer 的 WireGuard 直连及认证 TLS WSS 中继真实互通已通过隔离网络测试。未实现自动 NAT 穿透、动态切换、管理服务或桌面界面；不是生产版本。详见 [实现与验收](docs/M1_IMPLEMENTATION.md) 和 [阶段状态](docs/STATUS.md)。

## 构建
Go 1.23；Linux 运行时。见 M1 文档及 scripts/m1-netns.sh。
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

Windows、macOS、Linux 优先，Android/iOS 后续。单一服务端程序计划支持 all / management / relay 三种模式；目前仅 relay 已实现。桌面 UI 与后台 Agent 分离。所有功能以实测记录为准。
