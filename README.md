# 威胁事件关联检测服务（本地内存版）

一个可本地运行的威胁事件关联检测服务：用本地内存数据模拟多来源安全日志的接入与判定，
保证在**乱序到达、重复投递、规则变更、进程重启、并发摄入**等情形下告警结论一致、可复现、可解释。

- 技术栈：Java 21、Spring Boot 3.4.x、JUnit 5；除 Spring Web 外无外部中间件，无需数据库。
- 所有状态保存在进程内存中，规则/来源在启动时自动注册，启动即可用。

## 1. 快速开始

```bash
# 构建 + 全量单测（37 个用例）
mvn test

# 启动 Web 服务（默认 8080；若端口被占用可用 --server.port 指定）
mvn spring-boot:run
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8088"

# 启动并运行内置场景演示（乱序/重复/迟到/非法 + 重放复现对比），不启动 Web
mvn spring-boot:run -Dspring-boot.run.profiles=demo \
  -Dspring-boot.run.arguments="--spring.main.web-environment=false"
```

启动时自动注册 3 个来源（`edr` / `firewall` / `syslog`）和初始规则
`R-BRUTE-FORCE` v1（60 秒窗口内同一主机出现 3 次 `login_failure` 即告警）。

## 2. 归一化约定（多来源 -> 统一模型）

每种来源由一个 `SourceDescriptor` 描述，声明归一化字段在原始 payload 中的**候选键**
（按顺序取第一个非空，支持点路径取嵌套字段，如 `host.id`）：

| 归一化字段 | edr 候选键 | firewall 候选键 | syslog 候选键 |
| --- | --- | --- | --- |
| 实体 entityId | `hostId`,`host` | `host.id`,`srcIp` | `host_id`,`hostname` |
| 事件类型 eventType | `eventType`,`type` | `event.type`,`type` | `event_code_desc`,`msg_type` |
| 事件时间 | `timestamp`,`ts`（epoch 毫秒） | `event.time`,`@timestamp`（ISO-8601） | `epoch`（epoch 秒）,`time` |
| 严重级别 | `severity`,`sev` | `event.severity` | `level`（不做枚举校验） |

- **时间戳**：数字绝对值 < 1e12 视为 epoch **秒**（自动 ×1000），否则视为 epoch **毫秒**；
  纯数字字符串同上；其余字符串按 ISO-8601（如 `2026-09-22T10:00:00Z`）解析。
  超过当前时间 60 秒（时钟偏差容忍 `FUTURE_SLACK_MILLIS`）视为未来时间拒绝。
- **严重级别**：统一转小写；不在来源允许枚举内时归一化为 `unknown`，**不作为拒绝条件**。
- **事件指纹 eventId**：`SHA-1(source|entity|type|eventTime|规范化payload)`，
  payload 按键排序规范化，因此同一物理事件（即使没有投递 ID）重复投递指纹不变。
- **绝不静默丢弃**：非法记录返回结论 `REJECTED` 与可区分原因，并计入守恒统计：

| rejectReason | 触发条件 |
| --- | --- |
| `UNKNOWN_SOURCE` | 来源未在注册表登记 |
| `EMPTY_PAYLOAD` | payload 为空 |
| `MISSING_ENTITY` | 实体候选键全部缺失/空白 |
| `MISSING_EVENT_TYPE` | 类型候选键全部缺失且无固定类型 |
| `INVALID_TIMESTAMP` | 时间字段缺失、空串、非数字非 ISO、非正数 |
| `FUTURE_TIMESTAMP` | 事件时间超过当前时间 + 60 秒 |

## 3. 关联规则语义

规则 `CorrelationRule(ruleId, version, eventTypes, entityScope, windowMillis, threshold, lateToleranceMillis)`：

1. **适用条件**：事件类型属于 `eventTypes`，且实体在 `entityScope` 内（空表示全部实体）。
2. **固定窗口**：按事件发生时间对齐，`windowStart = floor(eventTime / windowMillis) * windowMillis`，
   窗口左闭右开。窗口边界两侧的事件分属不同窗口，各计各的。
3. **阈值**：窗口内**去重事件数**首次 `>= threshold` 时产生且仅产生一次告警。
4. **乱序与迟到**：维护 `watermark = 已见最大 eventTime`：
   - `watermark - eventTime <= lateToleranceMillis`：容忍内，正常计入（乱序到达同样有效），判定稳定；
   - `watermark - eventTime > lateToleranceMillis`：明确标记结论 `TOO_LATE`，**不参与计数、不丢弃**；
   - 边界取等号：恰好等于容忍仍接受，超过 1ms 才标记。
5. **窗口内容去重**：窗口内按 eventId 去重。投递侧重试导致 deliveryId 变化但事件内容相同
   （窗口边界抖动/重发）时，不会重复计数。
6. **窗口驱逐**：窗口结束时间 `<= watermark - lateToleranceMillis` 后，其中任何未来事件都必然
   被判 TOO_LATE，窗口状态安全回收（纯内存实现控制内存占用，不影响结论）。

### 规则版本化与可复现性

- `ruleId` 相同、`version` 严格递增才允许部署；回灌旧版本会被拒绝。
- 窗口状态按 `ruleId#version + 实体`隔离；在线部署新版本只影响**新到达**的事件，不回写历史。
- **重放**：`replay(events, fixedRules)` 使用全新隔离引擎、隔离去重器，不写在线告警与计数。
  同一批事件（同顺序）+ 同一规则版本，重放结论（含告警 ID）逐字节可复现；换版本重放可对比规则变更影响。

## 4. 幂等与告警标识

- **投递层幂等键**：优先 `deliveryId`（记为 `dlv:<id>`）；缺失时使用事件指纹（记为 `evt:<eventId>`）。
  进程重启后可用历史键集合快照重建 `DeliveryDeduplicator`（模拟持久层恢复）。
- **确定性告警 ID**：`alert-<ruleId>-v<version>-<entityId>-w<windowStart>`。
  同一（规则版本, 实体, 窗口）永远对应同一告警 ID，跨进程/重启/重复投递都不会产生第二条告警。

## 5. 告警生命周期

合法迁移（非法/重复迁移返回 409 并带 `from`/`to`；告警不存在返回 404）：

```
OPEN ──► ACKNOWLEDGED ──► RESOLVED（终态，不可迁出）
 │            │
 ├─► SUPPRESSED ◄─┘     SUPPRESSED ──► OPEN / ACKNOWLEDGED / RESOLVED
```

- 同状态重复迁移（如 OPEN→OPEN）单独拒绝，原因文案与非法跳跃可区分。

## 6. 并发摄入与守恒统计

- 同一实体的“窗口判定 + 建告警”在 **64 段实体分段锁**内串行完成；不同实体互不阻塞。
- 计数器全部为原子计数；告警创建前再按确定性 ID 查存一次（幂等兜底）。
- 每条投递都有且仅有一种结论，守恒关系恒成立：

```
total = rejected + duplicate + tooLate + acceptedNoAlert + acceptedAlert
持久告警总数 = acceptedAlert
```

结论枚举：`REJECTED / DUPLICATE / TOO_LATE / ACCEPTED_NO_ALERT / ACCEPTED_ALERT`。

## 7. REST 接口（本地验证）

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/events` | 单条摄入，返回结构化结论 |
| `POST /api/events/batch` | 批量摄入（顺序处理，逐条返回） |
| `GET /api/alerts` | 列出全部告警及生命周期状态 |
| `POST /api/alerts/{id}/transition?to=&note=` | 告警状态迁移 |
| `GET /api/stats` | 守恒统计 + 拒绝原因分布 |
| `GET /api/debug/windows` | 窗口状态快照（计数/事件指纹/watermark/是否已告警） |

示例：

```bash
curl -X POST http://localhost:8080/api/events -H 'Content-Type: application/json' -d '{
  "sourceId":"edr","deliveryId":"evt-001",
  "payload":{"hostId":"host-1","eventType":"login_failure",
             "timestamp":1790000001000,"severity":"low"}}'
# {"outcome":"ACCEPTED_NO_ALERT",...,"detail":"事件计入窗口 [...,...)，当前去重计数 1/3，未越阈 ..."}
```

## 8. 兼容范围与边界

- 支持来源：已注册的键值型 JSON 负载（含一层/多层嵌套 Map）；未注册来源一律拒绝。
- 支持时间格式：epoch 秒/毫秒（数字或数字字符串）、ISO-8601 字符串；不支持自定义日期格式（如 `yyyy/MM/dd HH:mm:ss`）。
- 语义范围：固定窗口、单实体维度阈值关联；不含滑动窗口/会话窗口、跨实体关联、规则 DSL 热加载（当前以代码/配置部署版本化规则）。
- 持久化：纯内存模拟。重启后状态不自动保留；但投递键可通过快照注入模拟恢复，且告警 ID 确定性派生，可据此做持久化扩展。
- 摄入结论是**按到达顺序**确定的（watermark 定义如此）；重放时保持相同输入顺序即可复现。

## 9. 测试场景与日志

`mvn test`（37 个用例）覆盖：

- `NormalizationTest`：三种来源、秒/毫秒/ISO 时间戳、6 种拒绝原因逐一区分、不静默丢弃。
- `OutOfOrderAndLateEventTest`：乱序容忍内稳定计数、恰好等于容忍边界接受、超容忍 TOO_LATE 不计数且不漏报、窗口边界不串窗、独立运行结论一致。
- `DeduplicationTest`：相同 deliveryId、无 deliveryId 内容指纹、重试导致的 ID 抖动、整批重投、重启后键集合恢复、跨进程告警 ID 一致。
- `RuleReplayTest`：同版本重放逐结论复现、v1/v2 版本隔离结论不同、在线更新不回写历史、重放不污染在线态、版本号必须递增。
- `AlertLifecycleTest`：合法迁移链、抑制/恢复、非法跳跃、重复迁移、终态保护（from/to 可区分）。
- `ConcurrentIngestTest`：同实体 100 事件/50 线程计数精确且告警恰好一条、10 实体并发守恒、同一投递 64 线程并发只生效一次、并发混入非法/迟到事件仍守恒。

测试日志（SLF4J）逐条打印**事件内容、判定前后窗口快照（计数/事件指纹/watermark）、判定依据**
以及守恒统计，便于失败定位。查看某次测试日志：

```bash
mvn test -Dtest=OutOfOrderAndLateEventTest
# surefire 原始输出：target/surefire-reports/*Output.txt
```

## 10. 模块结构

```
model/          统一模型、规则、窗口快照、告警、结论/拒绝原因枚举
normalization/  来源注册表、来源描述、归一化器（校验 + 时间解析 + 指纹）
dedup/          投递幂等去重器（可注入恢复键集合）
detection/      窗口状态（watermark/去重/驱逐）、关联引擎（版本化）
alert/          告警生命周期服务与非法迁移异常
store/          内存态：规则版本史、告警、原子守恒计数、实体分段锁
service/        编排门面：归一化→去重→加锁→判定→告警→计数；隔离重放
web/            REST 接口与结构化错误
config/ demo/   默认来源/规则引导；demo profile 场景演示
```
