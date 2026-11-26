# 部署规范

## 单机默认
Linux amd64/arm64；server 一个二进制，配置文件和 SQLite 数据目录；可选 Docker 同一镜像，通过 mode 参数启动。管理后台 embed 静态文件。无外部 DB/Redis/NATS 强制依赖。目标 1–2 vCPU / 1–2GB 起步是规划值，带宽按中继使用实测，不是 SLA。
拟定 CLI（尚未实现）：
- network-ex-server --mode=all --config=/etc/network-ex/config.yaml
- network-ex-server --mode=management --config=...
- network-ex-server --mode=relay --config=...
- network-ex-server admin bootstrap（本机）
- network-ex-server relay enroll（读取受限文件/stdin）
Agent CLI 独立。Docker Compose 示例待 M3 用实际参数生成。

## 端口规划
443/tcp HTTPS API/Web/WSS，relay 单机可同端口以路径分流；独立节点使用独立域名/端口；3478/udp STUN；443/udp QUIC 可选且需实现后开放。80/tcp 仅证书 ACME HTTP 验证/跳转按需开放。默认本机开发监听 loopback，生产公网必须 TLS；metrics 与内管端口只在内部/认证访问。Agent peer UDP 动态端口，无需用户必须配置路由器。
管理节点可使用系统反代（WSS 升级与超时配置）；Relay QUIC 需 UDP 直接或支持 UDP 的负载均衡；STUN 不能通过 HTTP 反代。配置支持 bind/advertise 区分。不得默认在公网开放 debug/admin bootstrap。
## 配置模型（示意，未实现）
mode, http.listen, http.public_url, tls.cert_file/key_file, storage.driver/path/dsn_file, relay.enabled/region/public_url/limits, stun.listen/advertise, auth.issuer/key_file, security.lease_ttl, observability.metrics_listen, log.level。秘密走权限文件或秘密管理器，不写示例真实值。
## 分布式
S1 all + SQLite；S2 management + 多地区 relay（每台自动注册、认证、心跳、drain）；S3 多 control 实例、PostgreSQL、共享 session/events、LB，relay 继续独立；S4 按区域容灾（先实测）。同一组织可自建私有节点，官方节点仅可选。
升级：备份 SQLite/PG 与必要密钥，发布校验和、兼容检查、迁移、readiness、回滚（若 schema 不可逆需恢复快照）。中继 drain 后滚动重启；记录可用性。systemd 低权限用户、只写必要目录，限制 capabilities；容器非 root、最低权限。Agent 的网络权限单独设置。初次部署不开放真实公网服务，先隔离测试。
