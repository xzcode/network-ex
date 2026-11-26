# P2P 与路径切换

## 路径模型
每个 (network_id, peer_id) 独立维护 generation、候选、active path、健康、RTT、最近认证握手。候选：同 LAN host、IPv6 global、STUN srflx，TURN relay candidate 为后续可选；自研 Relay 是独立的密文传输路径，不等同标准 TURN。使用 ICE RFC8445/Pion 实现候选与连通性检查，信令仅传授权 peer 数据；候选可访问范围防滥用（禁止任意第三方探测、link-local/多播等默认过滤，LAN 私址按策略允许）。
同一个真正承载数据的 UDP socket/ICE connection 进行检查；不可探测 A socket 后在随机 B socket 假定相同公网映射。不要通过虚假 endpoint 或 ping 成功声称已完成 WG 握手。

## 状态机
idle -> relay_connecting -> relay_ready -> direct_probing -> direct_verified -> direct_active；可并行直连与中继，直连成功可先于 relay_ready。direct_active 丢失时 -> relay_ready 或 degraded；网络变化、ICE 重启、配置变化增加 generation。只有真实双向 WG 数据通畅才标为 active；旧 generation 消息忽略。
M2 初始策略：启动后并行 relay 与 ICE；优先直连，经连续认证健康检查（初始 3 次）再切换；故障快速回退已准备 Relay；退避重探测，防震荡，路径变更保持虚拟 IP 与 WireGuard peer key 不变。持续密文/数据面验证及应用层连接测试，不能保证 TCP 一定无感。
初始阈值待实测：探测 5s、直连确认 3 次、空闲探测 15–30s、失败退避 1–60s；休眠/移动端另测。IPv4/IPv6、对称 NAT/CGNAT、UDP 封锁、双 NAT、Wi-Fi/网线切换、同 LAN、重启均纳入 M2 矩阵。
## MTU/并发
初始 TUN MTU 1280，按路径实测调整，确保 IPv4/IPv6 包尺寸与 QUIC datagram 上限一致；如 QUIC 不适配，先用 WSS，不做不安全自定义分片。并发发送、队列上限、关闭阻塞、Endpoint roaming/cookie 语义是 M1 门槛。每 peer 延迟、路径切换次数、失败原因、真实直连率可观测。
