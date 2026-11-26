# Protocol v1（拟定，未冻结实现）

## 通用
API HTTPS /api/v1；JSON UTF-8，ID UUID，UTC RFC3339，IP/CIDR 标准文本，revision 为网络内单调整数（JSON 字符串避免 JS 精度损失）。请求 request_id、幂等键用于写操作；错误 {code,message,request_id,retryable}，HTTP 400/401/403/404/409/429/503 等按语义。TLS 校验证书、主机名，禁止默认跳过验证；服务地址变更重新授权。major 不兼容则拒绝；minor 能力协商，不认识的可选字段忽略，未知必需能力拒绝。

## REST
POST /bootstrap（仅本机且初次，或 CLI）
POST /auth/login, /auth/refresh, /auth/logout；POST /devices/enroll（邀请+公钥+签名挑战），POST /devices/{id}/approve|revoke；GET /devices；POST /networks；GET /networks；POST /networks/{id}/invites；POST /networks/{id}/members；DELETE /networks/{id}/members/{member}; GET /networks/{id}/snapshot；PUT /networks/{id}/policy（If-Match revision）；POST /relay/enroll；POST /relay/heartbeat；POST /relay/leases；GET /relay/nodes。
登录/管理与设备会话 token 分开 scope；短期 token（建议 15min），刷新 token rotation，撤销与重放检测。具体签名标准库/JOSE 方案在 M3 冻结。
快照含 network_id/revision/expires_at、self assigned address、authorized peers(id, WG public key, allowed IPs)、policy、relay directory、server time。每网络每设备独立 WG key；不向无权设备分发 peer 候选。

## Signal WSS /api/v1/signal
鉴权在握手，不在 URL query。消息 envelope: {v,type,msg_id,network_id,session_id,revision,body}；客户端发送 type=hello、heartbeat、candidate、ice_offer、ice_answer、ice_restart；服务端发送 hello_ack、config_changed、peer_presence、candidate、ice_offer、ice_answer、relay_directory_changed、error。候选消息携带目标 peer 与 ICE generation/ufrag，服务端检查同网/ACL/当前会话，过期 generation 丢弃，限制大小及频率。不得向非授权网络广播。配置通知为 hint；客户端 revision gap/full reconnect 拉快照。ACK 仅表示信令接受，不表示数据可达。
建议 heartbeat 20s、90s presence timeout、64KiB JSON 帧上限，均可配置/测试后调整。WSS 有界队列，慢客户端断开并重新同步。

## 数据路径
用户 IP 包由 WireGuard 加密；不自定义明文加密。Relay 帧 v1 草案：4-byte big-endian body length（WSS 每消息一帧也检查长度），1-byte version、1-byte type、16-byte flow_id、payload；DATA payload 仅原始 WG datagram，flow_id 绑定经验证的双向租约与连接，不允许发送任意目的 IP。控制帧独立 schema；初始最大 64KiB 且 DATA 受协商 MTU/实际 datagram 上限约束。QUIC datagram 路径必须验证 negotiated max datagram；不支持则 WSS。禁止未验证 token 前收发数据、禁止跨网络 flow ID、禁止隐式广播。
M1 static test config 的 peer 映射/Relay lease 可离线生成；不得公网无认证 relay。M2 明确 ICE candidate 编码及数据 socket 适配；M3 冻结 OpenAPI、schema、测试向量和兼容矩阵。
