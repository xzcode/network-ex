# 客户端与 Agent

## 进程
Agent 后台服务独立于 UI；CLI 与 UI 调同一本地 IPC（Unix domain socket 0600/受控组，Windows named pipe DACL），校验调用者和权限；不得以未认证 localhost HTTP 作为管理员入口。安装驱动/系统路由需要显式管理员授权；UI 普通权限。Agent 状态：stopped、starting、auth_required、connecting、connected、degraded、stopping、error。

## 平台适配
Linux TUN + netlink/系统路由，systemd；Windows Wintun/WireGuard 兼容驱动及 Windows Service（签名与安装待验）；macOS utun 或 Network Extension（根据签名、权限、沙盒及分发实测选型），launchd；移动端后续 Android VpnService、iOS Network Extension。驱动/特权接口遵循上游许可证与平台规则。不要在 UI 进程持有长期私钥或系统管理员权限。

## 设备状态
本地持久化 server origin、设备 ID、独立身份私钥、每网络 WireGuard 私钥、配置 revision、授权到期；系统安全存储优先，Linux 以最小权限文件；无明文日志。信令断线指数退避含随机抖动、上限 60s（初始建议）；本地 route 变化/网卡切换触发 ICE restart；后台保活策略节能，UI 显示测量时点。
只为授权 peer 的 virtual /32 路由，网络前缀按服务端配置；多网络重叠在初版拒绝，不覆盖本机现有路由。默认不接管 DNS/默认路由；关闭后精确撤销自己安装的 route、TUN、防火墙；崩溃后可恢复。地址访问受入站/出站 ACL，OS 原有防火墙仍有效。子网路由以后需防路由泄漏和环路。

## IPC v1 提议
GetStatus、ListNetworks、Join/Leave、Connect/Disconnect、ListPeers、SubscribeEvents、RunDiagnostics、UpdateSettings（严格 schema；不提供任意命令执行）。
状态包括 peer_id、network_id、ip、path_mode、last_handshake、rtt_ms（未知为 null）、rx_bytes/tx_bytes、reason、sample_at；不得把信令在线误报为数据可达。
