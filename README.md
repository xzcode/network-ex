# Network EX

自主开发的跨平台虚拟局域网工具：端到端加密、P2P 直连优先、中继兜底、完全自托管。

当前状态：0.8.2-dev-m8。Linux 组网及移动端共享数据面实测通过，Android Debug APK 已构建并通过签名及16KiB静态检查；iOS 原生源码、Go package 与 Objective-C 绑定已完成，Xcode 编译/签名/真机未验收。详见 [M8c 实现与验收](docs/M8C_IMPLEMENTATION.md)、[iOS 构建](apps/ios/README.md)、[阶段状态](docs/STATUS.md)。

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
