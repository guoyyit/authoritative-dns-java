# 本地权威域名解析服务（Authoritative DNS, Java / Spring Boot）

在可配置的监听地址与无特权端口上同时提供 UDP / TCP 标准 DNS 权威服务，支持区域数据
热更新、持久化与崩溃恢复、鉴权区域传输（AXFR）以及完整审计。

## 构建与测试

```bash
mvn package        # 编译 + 51 个自动化测试
```

测试覆盖：报文解析/压缩域名/未知类型、并发更新快照一致性、UDP 截断与 TCP 重试、
AXFR 鉴权与传输快照隔离、重启恢复与损坏拒绝启动、管理接口越权拒绝、
未知类型（TYPEnnn）经提交/持久化/重启/查询/传输全链路的类型代码保持。

## 运行

```bash
java -jar target/authoritative-dns-java-1.0-SNAPSHOT.jar \
  --dns.listen-address=127.0.0.1 \
  --dns.udp-port=15353 --dns.tcp-port=15353 \
  --dns.data-dir=data --server.port=18080
# 密钥可用环境变量覆盖：DNS_UPDATE_KEY / DNS_TRANSFER_KEY
```

首次启动在数据目录提交一份确定性的种子区 `example.local.`；之后启动从
`zone.dat` 恢复。文件校验和不匹配（损坏 / 写入中途崩溃）将拒绝启动。

## 配置项（application.properties）

| 键 | 默认值 | 说明 |
| --- | --- | --- |
| dns.listen-address | 127.0.0.1 | 监听地址 |
| dns.udp-port / dns.tcp-port | 15353 | UDP/TCP 端口（无特权，可本地复现） |
| dns.udp-max-payload | 512 | UDP 响应上限，超出则截断并置 TC 位 |
| dns.data-dir / dns.zone-file / dns.audit-file | data / zone.dat / audit.log | 持久化与审计 |
| dns.update-key / dns.transfer-key | 见配置 | 更新 / AXFR 共享密钥 |

## 管理接口（HTTP）

```bash
# 新建区域（需要 X-Update-Key）
curl -X POST "http://127.0.0.1:18080/zones?origin=example.local." -H "X-Update-Key: $DNS_UPDATE_KEY"
# 增删记录（先持久化，后原子发布）
curl -X POST http://127.0.0.1:18080/zones/records -H "X-Update-Key: $DNS_UPDATE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"add":[{"name":"www.example.local.","type":"A","ttl":60,"rdata":"127.0.0.2"}],"remove":[]}'
# 查看当前区域
curl http://127.0.0.1:18080/zones
```

## 协议语义

- 支持 A、AAAA、CNAME、NS、SOA、MX、TXT；未知类型以原始 RDATA 透传，不会导致整条响应失败。
- 权威应答置 AA；CNAME 自动追踪；存在委托点（NS）时返回非权威 referral（NS + glue）。
- 域名不存在：NXDOMAIN，权威区放 SOA（TTL 取 SOA minimum，RFC 2308）。
- 域名存在但类型不存在：NOERROR，ANSWER 为空，权威区放同一 SOA。
- UDP 响应超过 `udp-max-payload` 时仅保留头与问题、置 TC；客户端经 TCP 重试得到完整响应。
- TCP 使用两字节长度前缀组帧（RFC 1035 §4.2.2），单连接可承载多个顺序查询。
- AXFR 仅经 TCP，密钥以 additional 区中名为 `key.` 的 TXT 记录携带；授权响应以 SOA 开头
  与结尾并取自单一不可变快照；未授权返回 REFUSED 并写入审计。

## 未知记录类型（RFC 3597）

未内置支持的类型在各环节一律按 RFC 3597 表示，类型代码自始至终保持不变：

- **表示规则**：文本形式（管理接口 `type` 字段、`zone.dat` 区域文件）为 `TYPEnnn`，
  其中 `nnn` 为十进制类型代码；线上报文中就是 16 位类型字段本身。RDATA 使用通用形式
  `\# <长度> <十六进制字节...>`，按原始字节透传，不做任何解释。
- **边界行为**：合法代码为 0–65535（16 位），单数字（`TYPE9`）、多数字（`TYPE99`）
  与接近最大值（`TYPE65535`）均支持；大小写不敏感（`type99` 亦可）。`TYPE`（缺数字）、
  `TYPE-1`、`TYPE12x`、`TYPE65536`、裸数字 `99` 等非法表示在管理接口被明确拒绝
  （HTTP 400 + 错误说明），不会静默截断或映射成其他类型；被拒绝的更新不会改动
  内存区域与磁盘文件。
- **一致性保证**：提交时的类型代码与内存、持久化文件、UDP/TCP 查询应答及 AXFR
  传输中的代码完全一致；含未知类型记录的区域重启后完整恢复（名称、类型、TTL、
  类、RDATA 逐项一致），已有区域文件无需迁移。
- **验证方法**：`DnsRecordTypeTest`（解析边界与拒绝）、`PersistenceRecoveryTest`
  （存取往返逐项一致）、`UnknownTypeEndToEndTest`（提交→落盘→重启→UDP/TCP→AXFR
  全链路）。本地手动复现：

```bash
# 提交一条 TYPE99 记录（RDATA 为 3 字节 de ad be）
curl -X POST http://127.0.0.1:18080/zones/records -H "X-Update-Key: $DNS_UPDATE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"add":[{"name":"u99.example.local.","type":"TYPE99","ttl":300,"rdata":"\\# 3 de ad be"}],"remove":[]}'
grep TYPE99 data/zone.dat        # 落盘为完整 TYPE99
# 重启服务后查询，应答类型仍为 99；AXFR 同样保持
dig @127.0.0.1 -p 15353 u99.example.local. TYPE99
dig @127.0.0.1 -p 15353 example.local. AXFR +tcp   # 需携带密钥，见上文
```

## 并发与持久化保证

- 区域以不可变快照（`Zone`）保存，更新构造全新快照、写入临时文件 fsync 后原子改名，
  再用 `AtomicReference` 原子发布；在途查询/传输只见完整旧版或完整新版。
- 持久化文件含 SHA-256 校验和；已提交变更崩溃后不丢，未提交变更不生效，损坏即拒。
- `audit.log` 记录每次 UPDATE/AXFR 的 ALLOWED/DENIED、操作者与细节，越权可追溯。
