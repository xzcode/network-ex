# Network EX

自主开发的跨平台虚拟局域网工具：端到端加密、P2P 直连优先、中继兜底、完全自托管。

当前状态：0.6.1-dev-m6。Linux 混合组网、多中继、私有子网、服务 ACL、单 daemon 多网络及 DNS hub、选择性 IPv4 出口实测通过；完整全流量出口、管理 HA、原生桌面安装及生产验收待完成。详见 [M6 补充实现与验收](docs/M6B_IMPLEMENTATION.md)、[阶段状态](docs/STATUS.md)。

## 构建
Go 1.23；服务端需 CGO/C 编译器，Agent 支持 CGO_ENABLED=0。桌面 Vue/Tauri 工程位于 apps/desktop，详见 M4 文档。
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

Windows、macOS、Linux 优先，Android/iOS 后续。单一服务端程序支持 all / management / relay 三种模式，单机内置 SQLite 与 Web 管理。桌面 UI 与后台 Agent 分离。所有功能以实测记录为准。
