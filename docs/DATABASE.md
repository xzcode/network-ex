# 数据模型（逻辑 schema）

SQLite 默认 WAL（本地磁盘，不在网络共享文件系统），启用 FK、busy timeout、迁移备份；PostgreSQL 使用同等事务语义和唯一约束。所有时间 UTC。schema migration 严格顺序、升级前快照、不可逆迁移说明。租户 scope 为逻辑隔离不是只靠前端过滤。

| 表 | 核心字段/约束 |
|---|---|
| tenants | id PK,name,status,created_at |
| users | id PK, normalized_login UNIQUE,password_hash,status |
| tenant_users | tenant_id,user_id,role, UNIQUE pair |
| networks | id PK,tenant_id,name,ipv4_cidr,revision,policy_version,status |
| devices | id PK,tenant_id,owner_user_id,identity_pubkey UNIQUE,name,status,last_seen,revoked_at |
| members | network_id,device_id,tenant_id,wg_pubkey,virtual_ip,status, UNIQUE(network_id,device_id), UNIQUE(network_id,virtual_ip), UNIQUE(network_id,wg_pubkey) |
| invites | id,tenant_id,network_id,secret_hash UNIQUE,expires_at,used_at,max_uses,issuer |
| allocations | network_id,ip,member_id,release_after, UNIQUE(network_id,ip) |
| policies | network_id,revision,policy_json,updated_by,created_at, UNIQUE pair |
| relay_nodes | id,owner_tenant_id(nullable official),scope,identity_pubkey,region,public_endpoints,capacity,status,last_heartbeat |
| relay_leases | id,node_id,network_id,src_device,dst_device,expires_at,revoked_at,limits |
| sessions | id,device_id,refresh_hash,expires_at,revoked_at,generation |
| outbox | id,tenant_id,network_id,revision,type,created_at,published_at |
| audit_events | id,tenant_id,actor_id,action,target_id,result,request_id,created_at |
| usage_buckets | tenant_id,network_id,node_id,device_id,bucket_at,ingress_bytes,egress_bytes, UNIQUE dimensions |

Composite FK/transaction validation ensures members/devices/networks share tenant and relay scope permits flow; nullable official node requires explicit scope. IP pool example 10.88.0.0/24, configurable; reject overlapping routes on client, no globally unique IP assumption. Reserve network/broadcast/server-designated addresses. IPAM allocate + revision + outbox in single transaction; enforce no duplicate active allocations even under concurrency. Revocation and cooldown before reuse.
Online session maps, candidate ICE data and instantaneous node stats ephemeral TTL in memory initially; cluster implementation shared session registry. No plaintext tunnel packet storage. Retention: audit default 90 days configurable, usage aggregates configurable, candidate data transient; secrets hashed or encrypted where recovery necessary; backup/restore includes schema version and signing keys protected separately.
