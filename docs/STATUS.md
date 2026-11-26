# 状态与交接（2026-11-26）

M0 完成；M1/M2 Linux IPv4 数据面、M3 管理服务、M4 Linux daemon/IPC 核心实测通过。M4 Agent 五种架构交叉构建和 Vue 前端构建通过，原生 Tauri 与系统安装、Windows/macOS 实机运行未验收，见 M4_IMPLEMENTATION.md。
M5 0.5.0-dev-m5：SQLite v2、注册节点身份/一次性邀请、签名心跳与授权、节点目录、按设备对统一调度、双端 HTTPS 探测、限额与计数、维护/恢复/撤销、Web 管理，代码已实现。两个独立注册 relay、三个真实 Agent 隔离网络测试通过；故障迁移9秒、主动维护迁移5秒（单次实测），TCP/UDP 真实回显与流量计数通过。Go tests/build 及 JS syntax 通过。见 M5_IMPLEMENTATION.md。
严格 M5 未全部结束：管理端仍单中心 SQLite，分布式管理集群/共享数据库与高可用、专门限流压测、浏览器实操和公网跨地区验证未验收；M4 原生桌面安装包未完成。无 release，无公网部署。
下一批：补齐 M5 多管理实例与容量/安全验证，随后 M6 高级网络能力（子网路由、出口节点、DNS、多网络等）。项目许可证、依赖及生产安全复核保留。
