# authoritative-dns-java

一个本地权威域名解析服务（Java 17 / Spring Boot）。在可配置的监听地址与端口上接收标准
DNS 查询报文，依据可维护的区域数据返回权威应答，并保证在并发更新、传输边界与异常中断下
行为确定且可复现。

## 构建与运行

```bash
mvn package                 # 构建并运行全部测试
java -jar target/authoritative-dns-java-1.0-SNAPSHOT.jar
```

首次启动时若数据目录中没有区域文件，会自动提交一个可复现的演示区域
`example.local.`（含 A/AAAA/CNAME/NS/SOA/MX/TXT 记录与一个委托子域 `sub.example.local.`）。

## 配置（`src/main/resources/application.properties`）

| 键 | 默认 | 说明 |
|---|---|---|
| `dns.listen-address` | `127.0.0.1` | UDP/TCP 监听地址 |
| `dns.udp-port` / `dns.tcp-port` | `15353` | 监听端口（非特权端口，可本地复现） |
| `dns.udp-max-payload` | `512` | UDP 响应上限，超过即截断并置 TC |
| `dns.data-dir` | `data` | 区域数据与审计日志目录 |
| `dns.update-key` | 环境变量 `DNS_UPDATE_KEY` | 区域更新密钥 |
| `dns.transfer-key` | 环境变量 `DNS_TRANSFER_KEY` | 区域传输密钥 |
| `server.port` | `18080` | HTTP 管理接口 |

## 功能要点

1. **协议解析与组帧**：A、AAAA、CNAME、NS、SOA、MX、TXT；正确处理压缩域名（含 RDATA
   内的压缩指针展开与防循环）、多条记录与未知记录类型（未知类型按 RFC 3597 原样保留，
   不会导致整条响应失败）。
2. **权威应答语义**：命中返回 AA=1 应答（含 CNAME 链追踪）；不存在的域名返回
   NXDOMAIN；存在但类型不存在返回 NOERROR 且 ANSWER 为空；两种否定应答都在 AUTHORITY
   区携带 SOA（TTL 取 SOA minimum，RFC 2308）。子域委托返回 AA=0 的 referral（NS +
   glue）。
3. **并发读写与热更新**：区域是不可变快照，更新整体构建新快照后原子切换
   （`AtomicReference`），进行中的查询只能看到完整的旧版本或新版本。
4. **UDP 与 TCP**：TCP 使用两字节长度前缀组帧，单连接可承载多条查询；UDP 响应超过
   上限时截断并设置 TC 标志，客户端可通过 TCP 重试取得完整响应。
5. **持久化与恢复**：区域变更先写入临时文件、fsync、再原子 rename——崩溃后要么看到
   旧的已提交版本、要么看到新版本，绝不会是半成品；文件带 SHA-256 校验和，损坏的数据
   会被识别并拒绝启动。未提交的变更（如鉴权失败、构建失败）不会生效。
6. **区域传输鉴权**：AXFR 仅走 TCP，密钥以 `key.` 为名的 TXT 记录放在查询的
   ADDITIONAL 区；授权请求返回首尾各一条 SOA 的完整自洽区域（取自单一快照，传输期间
   的更新不会混入），未授权请求返回 REFUSED。
7. **审计**：区域更新与区域传输的每一次允许/拒绝都追加写入 `data/audit.log`
   （时间戳、动作、操作者、结果、详情），越权操作被拒绝且可追溯。
8. **自动化测试**：39 个测试覆盖协议解析、并发更新、传输截断、重启恢复与越权拒绝。

## 管理 API

```bash
# 创建区域（覆盖现有区域）
curl -X POST 'http://127.0.0.1:18080/zones?origin=example.com.' \
     -H 'X-Update-Key: change-me-update-key'

# 应用记录增删（原子、先持久化后发布）
curl -X POST http://127.0.0.1:18080/zones/records \
     -H 'Content-Type: application/json' \
     -H 'X-Update-Key: change-me-update-key' \
     -d '{"add":[{"name":"www.example.com.","type":"A","ttl":300,"rdata":"192.0.2.1"}],
          "remove":[]}'

# 查看当前区域
curl http://127.0.0.1:18080/zones
```

密钥错误返回 `403`，并记入审计日志。

## 快速验证

```bash
# 需要 dig；或参考测试中的原始报文构造
dig @127.0.0.1 -p 15353 www.example.local A
dig @127.0.0.1 -p 15353 nope.example.local A      # NXDOMAIN + SOA
dig @127.0.0.1 -p 15353 txt.example.local AAAA    # NOERROR 空应答 + SOA
```

## 测试

```bash
mvn test
```

- `DnsMessageCodecTest`：编解码往返、压缩指针（含 RDATA 内指针）、未知类型、畸形报文。
- `QueryHandlerTest`：权威应答、NXDOMAIN、NODATA、CNAME 链、委托与 glue。
- `ZoneConcurrencyTest`：400 个版本并发切换，查询永不看到混合视图。
- `TransportTruncationTest`：真实 UDP/TCP 端口上的截断 TC、TCP 重试、双查询组帧。
- `PersistenceRecoveryTest`：持久化往返、损坏拒绝、崩溃原子性、重启恢复。
- `ZoneTransferAuthTest`：AXFR 授权/拒绝、传输期间更新不混合、审计。
- `AuthorizationAuditTest`：越权更新拒绝、磁盘与内存均不被污染、审计可追溯。
