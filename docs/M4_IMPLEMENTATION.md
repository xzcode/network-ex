# M4 桌面与后台 Agent（2026-11-26）

版本 0.4.0-dev-m4。M4 核心代码完成，Linux 后台网络真实验收通过；桌面原生壳与 Windows/macOS 运行验收未完成。

## 交付
- 抽取 pkg/protocol 管理协议类型，Agent 与 SQLite/CGO 解耦；控制端保留 SQLite。Agent 可使用 CGO_ENABLED=0 构建。
- daemon / ctl：后台进程独立于 UI，固定 JSON 请求 status、diagnostics、enroll、connect、disconnect、forget。输入经 stdin，不将邀请码放入命令行。IPC 无任意命令或文件读写接口，限制请求大小。Linux/macOS 使用 Unix socket，父目录必须受信任且不可被组/其他人写入，socket 0660；Windows 使用本机 named pipe，默认仅 SYSTEM 与提升权限的管理员，客户端验证 pipe owner。系统授权组拥有控制本机组网配置的权限。服务 state root 由管理员预先创建且权限受限。
- 后台保存 desired 连接状态，服务重启后自动恢复；主动断开保存 false；forget 需断开并明确确认，仅清除本机身份，服务端撤销是独立操作。所有管理/隧道状态由真实 Agent 提供，公开状态不包含密钥、租约或 CA 文件路径。M3 保留每状态目录单一网络的限制。
- Vue 3 / Vite / TypeScript 桌面前端，Tauri 2 Rust shell 源码。概览/注册与审批、连接管理、设备名称/IP/路径/握手/计数、可搜索筛选排序的设备列表、拓扑、真实流量差值曲线、诊断、设置；中英文及跟随系统、浅/灰/深色。原生壳使用固定 sidecar ctl 命令经 stdin 传递 JSON；没有任意 shell API。系统托盘和关闭窗口隐藏逻辑已写入 Rust 源码。前端无伪造在线或流量数据。选中路径不保证应用可达。
- Linux TUN 与 systemd 模板；macOS utun 路由表检查、ifconfig/route 与 launchd 安装脚本；Windows Wintun、ActiveStore /32 路由、权限文件 DACL 检查、named pipe、Windows Service SCM 及安装脚本。平台特权配置留在 Agent，不在普通 UI 内执行。
- 修复真实压力/失联测试发现的 Pion ICE v2 并发 Close 导致 close of closed channel 崩溃：使用 sync.Once 串行化关闭与收集完成通知，避免旧连接关闭回调清除下一世代状态；macOS ICE 排除 utun 接口。
- 桌面图标为项目原创几何网络图案；SVG 源和 Tauri 生成的 PNG/ICO/ICNS 一并保存。

## 构建
Go 1.23.12 实测；服务端仍使用 CGO/GCC 构建 SQLite。
```sh
go test ./...
mkdir -p bin
CGO_ENABLED=0 go build -o bin/network-ex-agent ./cmd/agent
go build -o bin/network-ex-server ./cmd/server
```
Linux amd64、Linux arm64、Windows amd64、Darwin arm64 与 amd64 的 Agent 均交叉构建成功；这不等同原生 OS 安装、驱动、路由、SCM、LaunchDaemon 验收。

桌面前端：
```sh
cd apps/desktop
npm ci
npm run build
```
原生构建前需安装对应系统 Tauri 2 prerequisites（Rust、系统 WebView/GTK 等）、Go 与 Node。项目根目录运行：
```sh
node scripts/build-desktop-sidecar.mjs
cd apps/desktop
npm run tauri -- build
```
sidecar 支持显式 Rust target triple；打包后应位于 GUI 可执行文件同目录。开发调试可用绝对路径环境变量 NETWORK_EX_AGENT_BIN（仅 debug）。依赖前端 package-lock 已锁定；Rust 尚未完成原生构建，Cargo.lock 待生成并复核。Tauri sidecar 参考 https://v2.tauri.app/develop/sidecar/ 。当前首尔无 Cargo/Rust/必要 GUI 依赖，因此只完成 Vue/Vite 生产构建及图标生成，原生壳未编译、未发布安装包。

## 安装 Agent（候选脚本，尚未实际部署系统服务）
Linux: `sudo bash deploy/linux/install-agent.sh /path/to/network-ex-agent`；管理员明确授权本地用户：`sudo usermod -aG network-ex USERNAME`，重新登录。systemd 创建 state/runtime 目录，组成员可进行 IPC 控制；卸载保留设备密钥与状态。不要授权不可信成员。
macOS: `sudo bash deploy/macos/install-agent.sh /path/to/network-ex-agent`；root LaunchDaemon + admin 组 IPC；需要签名/系统权限与真实 utun 路由验收。非 App Store Network Extension 方案。
Windows: 管理员运行 `deploy/windows/install-agent.ps1 -Agent <exe> -Wintun <official-signed-dll>`，必须提供匹配架构、来自可信官方渠道的 Wintun DLL；安装脚本验证 Authenticode 状态并创建受限 DACL，开发版 pipe 仅提升权限管理员可访问，因此标准用户桌面操作暂未解决。SCM、Wintun DLL 签名、DACL、路由、清理待原生验证。卸载保留状态并要求人工复核。
上述安装脚本不自动运行，不应在生产环境未经审查直接执行。macOS 和 Windows 安装升级、权限/签名策略需后续完成；Linux systemd 文件尚未在真实系统启动服务，实测的是等价 daemon 进程。

CLI 示例（已准备服务目录和 socket）：
```sh
printf '%s\n' '{"action":"status"}' | network-ex-agent ctl
printf '%s\n' '{"action":"connect"}' | network-ex-agent ctl
printf '%s\n' '{"action":"disconnect"}' | network-ex-agent ctl
```
客户端注册通过 IPC enroll，字段 server/name/invite/ca_pem。诊断返回本地状态；停止桌面 UI 不停止后台。

## 实测记录
环境：首尔 OpenCloudOS 9.6 Linux，Go 1.23.12，Node 24 / npm 11，隔离 network namespaces。
- go test ./... 通过，Agent CGO_ENABLED=0，依赖图不包含 mattn/go-sqlite3；上述五种目标架构编译成功（修复 ICE Close 后重新跨编译）。
- npm install / npm run build 成功，Vite 6.3.5 生成生产前端；Tauri icon 生成成功。
- scripts/m4-ipc-permissions.sh：授权组的非 root UID 可访问 socket；非授权 UID 被拒；禁止任意 IPC 命令/额外字段；forget 需明确确认。
- scripts/m4-daemon.sh：三个真实 daemon 通过 IPC 注册和连接；待审批无 TUN；并发审批 IP 唯一；A-B ICE P2P、A-C UDP 封锁使用 WSS relay；两条路径真实 TCP/UDP 回显；设备对 deny/allow 路由变化；撤销移除 TUN 与其他 peer route；管理失联约18s 过期断开、恢复 SQLite 状态并重新互通；真实状态和 peer metadata 通过 IPC 获取且不暴露 CA 文件路径或密钥；后台重启自动恢复；IPC disconnect/forget 清理。首次运行在 ICE Close 并发崩溃处失败，修复后重复完整 all 模式测试退出码0。
- 本轮没有实际公网部署，没有原生 Tauri shell、Windows/macOS 实机验收，没有实际安装、签名或 release。
```sh
sudo bash scripts/m4-ipc-permissions.sh "$(pwd)/bin/network-ex-agent"
sudo bash scripts/m4-daemon.sh outside "$(pwd)/bin" all
```
所有实际网络测试均在临时命名空间运行，清理测试设备、路由、密钥、数据库及临时进程。

## 后续门槛
M4 原生桌面壳需编译/交互验收、系统托盘及窗口行为验收、Windows 普通用户授权组、安全安装器与 Wintun 驱动分发、macOS 签名与权限、Linux systemd 真实安装、GUI 平台打包。当前多网络加入、账号式客户端授权、细粒度 ACL、真实公网 NAT、IPv6、长时间运行、生产级安全与许可证复核仍是未完成项。M5 可并行推进中继注册、区域与多节点选择，但不能将 M4 跨平台发布门槛标记完成。
