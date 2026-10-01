# 威胁事件关联检测服务（本地内存版）

一个可本地运行的威胁事件关联检测服务：用本地内存数据模拟多来源安全日志的接入与判定，
保证在**乱序到达、重复投递、规则变更、进程重启、并发摄入**等情形下告警结论一致、可复现、可解释。

- 技术栈：Java 21、Spring Boot 3.4.x、JUnit 5；除 Spring Web 外无外部中间件，无需数据库。
- 所有运行状态保存在进程内存中，并在优雅停机时原子写入**本地状态快照文件**（仅本地文件，
  不引入任何外部数据库/中间件）；滚动重启后用同一份状态恢复，未结束的关联窗口接着算。
- 规则/来源在启动时自动注册；首次启动即可用，重启后按快照恢复（默认引导幂等，不重复注册）。

## 1. 快速开始

```bash
# 构建 + 全量单测（49 个用例）
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
  投递键集合随停机快照持久化、重启自动恢复，重复投递不二次计数。
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

## 7. 重启续跑（本地快照，无外部依赖）

服务支持在会做**滚动重启**的环境里“停掉再用同一份本地状态启动，接着算”。状态只写本地文件
（默认 `./data/engine-state.json` + 同名 `.sha256` 校验和），不引入外部数据库或中间件。

### 7.1 恢复覆盖哪些状态

停机快照（`StateMemento`，格式版本 `formatVersion=1`）覆盖、重启后逐项延续：

| 状态面 | 内容 | 重启后效果 |
| --- | --- | --- |
| 来源描述符 | 3 个（或自定义）来源的候选键配置 | 归一化行为不变 |
| 规则**全部历史版本** | 每个 `ruleId` 的 v1/v2/… | 各版本窗口槽位都重建，在线最新版本不回退 |
| 未结束的窗口 | `watermark`（迟到判断基准）、每窗去重事件指纹、计数、`alerted` 已告警标记 | 未结束窗口接着算；迟到/去重判定基准延续；同一窗口不重复告警 |
| 投递去重键 | 全部 `dlv:` / `evt:` 幂等键 | 历史投递重放仍判 `DUPLICATE`，计数不膨胀 |
| 告警及处置状态 | 告警 ID、版本、触发窗口/计数、`OPEN/ACKNOWLEDGED/SUPPRESSED/RESOLVED`、备注、时间 | 已产生告警不丢失，处置状态与生命周期约束原样保留 |
| 守恒统计 + 拒绝分布 | 6 个原子计数与 rejectReason 分布 | 重启后累计数延续，不从 0 开始 |

**等价性保证**：重启点之前/之后按同一顺序投同一批事件，最终逐条结论（`REJECTED / DUPLICATE /
TOO_LATE / ACCEPTED_NO_ALERT / ACCEPTED_ALERT`、告警 ID、统计）与“同一进程从头到尾没重启过”
**完全一致**——不多告警、不漏告警，重复、迟到、拒绝判定不因重启改变。`RestartResumeTest` 用
“基线全程 vs 重启续跑”逐条断言这一点。

### 7.2 哪些状态会被回收（恢复耗时可控）

- **窗口内容随运行自动驱逐**：窗口结束时间 `<= watermark - lateToleranceMillis` 后，其中任何
  未来事件都必判 `TOO_LATE`，该窗口被回收（见 3.6）。**被驱逐窗口不写入快照、重启后不复活**，
  因此快照体积与恢复耗时只与**存活窗口**有关，不随历史窗口数无限增长。
- **投递去重键保留**：为保证“历史投递在重启后重放仍判 `DUPLICATE`”这一结论严格不变，
  去重键不做自动删除（键仅为短字符串，数量取决于历史**唯一投递数**，而非窗口/事件总量）。
  这是为保证结论等价而保留的部分；如需限定唯一投递保留期，应在上游投递侧重试窗口之外
  不再重放，而不是在引擎侧悄悄删键（删键会把 `DUPLICATE` 变成 `TOO_LATE`，改变结论）。
- 回收与不回收对后续判定**完全无影响**：`StateReclamationBoundaryTest` 对比“不重启自然回收 /
  回收后重启 / 全新对照”三条路线对同一批后续事件（含迟到、重复、存活窗新事件、容忍边界事件）
  的结论，完全一致。

### 7.3 恢复与对外摄入的边界

启动时恢复在 Web 容器开始接客**之前**完成（`SmartInitializingSingleton`）。运行期由
`RecoveryGate` 守护：

- 恢复期间到达的写请求（`/api/events`、告警迁移）**阻塞等待恢复结束**，不会被当成空实例
  先算一遍，也不会在恢复后被重复计算；恢复成功后在恢复出的同一份状态上**恰好执行一次**。
- 等待超时（默认 10s，`detection.recovery.await-timeout-millis`）返回 **503 SERVICE_UNAVAILABLE**。
- 恢复期间 + 恢复之后对**同一实体**的并发摄入，仍由 64 段实体分段锁串行化，计数与告警守恒
  （`ConcurrentRecoveryIngestTest` 用 16 线程在恢复中并发验证）。
- 读接口（`/api/stats`、`/api/recovery`、`/api/alerts`、`/api/debug/windows`）始终可用，
  恢复阶段也能从 `/api/recovery` 看到当前阶段。

### 7.4 状态缺失或损坏时的表现

| 启动时状态文件 | 默认策略（`fail-on-corrupt=true`） | 显式 `--detection.state.fail-on-corrupt=false` |
| --- | --- | --- |
| 不存在 | `ACTIVE_FRESH`：合法的全新空实例，正常服务 | 同左 |
| 存在但 JSON 损坏/为空/版本不支持 | `FAILED`：保守停服，写请求一律 **503**，不落盘覆盖 | 重置为全新实例，阶段仍为 `ACTIVE_FRESH` 但带 **`corruptionReset=true`** 标记 |
| JSON 正常但 SHA-256 不匹配（截断/静默损坏） | 同上，`FAILED` | 同上，带 `corruptionReset` 标记 |
| 快照语义不合法（如窗口缺对应规则版本槽位） | `FAILED` | 同上 |

关键原则：**绝不悄悄按全新实例继续对外服务**。默认损坏即停服，要求人工修复/移走文件后再启动；
只有显式配置才允许“损坏后重置”，且该事实在 `/api/recovery`、`/api/stats` 的 `recovery` 段和
启动日志中可见、可与正常首启区分。`FAILED` 阶段禁止写快照，避免用空/半状态覆盖历史文件。

### 7.5 规则版本切换后重启

各版本窗口与告警按 `ruleId#version` 严格隔离。恢复时规则按版本号升序逐条部署，旧版本（含已被
新版本取代者）的窗口槽位也会重建；重启后在线判定仍只用最新版本、不回写历史，旧版本窗口计数与
“是否已告警”不会被新版本读到或改动（`RuleVersionSwitchRestartTest`）。

### 7.6 本地如何复现验证

```bash
mvn test                       # 全量 49 个用例（含 recovery 包 12 个新增用例）

# 端到端：首启 -> 投事件 -> 优雅停机(SIGTERM 自动快照) -> 用同一文件重启 -> 继续投
java -jar target/*.jar --server.port=8088 --detection.state.path=./data/engine-state.json
curl -X POST http://localhost:8088/api/events -H 'Content-Type: application/json' -d '{...}'
curl http://localhost:8088/api/recovery        # ACTIVE_FRESH / ACTIVE_RESTORED / FAILED
curl -X POST http://localhost:8088/api/state/checkpoint   # 也可手动立即落盘（非 ACTIVE 返回 409）
# kill -TERM <pid> 触发优雅停机快照；再次用同一命令启动即看到 ACTIVE_RESTORED 与恢复摘要
```

相关配置（`application.properties` 或命令行覆盖）：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `detection.state.path` | `./data/engine-state.json` | 本地快照文件路径（另写 `.sha256`） |
| `detection.state.fail-on-corrupt` | `true` | 损坏时保守停服；`false` 为损坏后重置并标记 |
| `detection.recovery.await-timeout-millis` | `10000` | 恢复期间写请求最长阻塞等待 |
| `server.shutdown` | `graceful` | 优雅停机，保证 SIGTERM 时先完成在途请求再写快照 |

落盘为“临时文件 + fsync 风格写出 + 原子 rename + 独立校验和”：正常停机读到的必然是成对一致的
完整快照；写盘过程中崩溃会留下新旧不成对文件，下次启动表现为可识别的 `CORRUPT` 而非半份内容。

## 8. REST 接口（本地验证）

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/events` | 单条摄入，返回结构化结论 |
| `POST /api/events/batch` | 批量摄入（顺序处理，逐条返回） |
| `GET /api/alerts` | 列出全部告警及生命周期状态 |
| `POST /api/alerts/{id}/transition?to=&note=` | 告警状态迁移 |
| `GET /api/stats` | 守恒统计 + 拒绝原因分布 + 当前恢复状态（recovery 段） |
| `GET /api/recovery` | 恢复阶段/是否延续/是否损坏重置/状态文件/说明 |
| `POST /api/state/checkpoint` | 立即原子落盘当前状态（非 ACTIVE 阶段返回 409） |
| `GET /api/debug/windows` | 窗口状态快照（计数/事件指纹/watermark/是否已告警） |

恢复未完成或恢复失败时，写接口（`/api/events`、告警迁移）返回 **503** 并带 `recoveryPhase`，
与“空实例正常接收”明确区分。

示例：

```bash
curl -X POST http://localhost:8080/api/events -H 'Content-Type: application/json' -d '{
  "sourceId":"edr","deliveryId":"evt-001",
  "payload":{"hostId":"host-1","eventType":"login_failure",
             "timestamp":1790000001000,"severity":"low"}}'
# {"outcome":"ACCEPTED_NO_ALERT",...,"detail":"事件计入窗口 [...,...)，当前去重计数 1/3，未越阈 ..."}
```

## 9. 兼容范围与边界

- 支持来源：已注册的键值型 JSON 负载（含一层/多层嵌套 Map）；未注册来源一律拒绝。
- 支持时间格式：epoch 秒/毫秒（数字或数字字符串）、ISO-8601 字符串；不支持自定义日期格式（如 `yyyy/MM/dd HH:mm:ss`）。
- 语义范围：固定窗口、单实体维度阈值关联；不含滑动窗口/会话窗口、跨实体关联、规则 DSL 热加载（当前以代码/配置部署版本化规则）。
- 持久化：内存态 + 本地快照文件（见第 7 节）。优雅停机自动落盘、启动自动恢复；
  损坏默认保守停服，不引入外部数据库/中间件。
- 摄入结论是**按到达顺序**确定的（watermark 定义如此）；重放时保持相同输入顺序即可复现。

## 10. 测试场景与日志

`mvn test`（49 个用例）覆盖：

- `NormalizationTest`：三种来源、秒/毫秒/ISO 时间戳、6 种拒绝原因逐一区分、不静默丢弃。
- `OutOfOrderAndLateEventTest`：乱序容忍内稳定计数、恰好等于容忍边界接受、超容忍 TOO_LATE 不计数且不漏报、窗口边界不串窗、独立运行结论一致。
- `DeduplicationTest`：相同 deliveryId、无 deliveryId 内容指纹、重试导致的 ID 抖动、整批重投、重启后键集合恢复、跨进程告警 ID 一致。
- `RuleReplayTest`：同版本重放逐结论复现、v1/v2 版本隔离结论不同、在线更新不回写历史、重放不污染在线态、版本号必须递增。
- `AlertLifecycleTest`：合法迁移链、抑制/恢复、非法跳跃、重复迁移、终态保护（from/to 可区分）。
- `ConcurrentIngestTest`：同实体 100 事件/50 线程计数精确且告警恰好一条、10 实体并发守恒、同一投递 64 线程并发只生效一次、并发混入非法/迟到事件仍守恒。
- `recovery/RestartResumeTest`（新增）：正常停机重启后未结束窗口接着算（计数/去重指纹/watermark 延续），续跑逐条结论与“全程未重启”基线完全一致；告警处置状态（SUPPRESSED→ACKNOWLEDGED）跨重启保留；多次重启幂等。
- `recovery/ConcurrentRecoveryIngestTest`（新增）：恢复期间 16 线程并发摄入全部阻塞、恢复后恰好执行一次（恢复的 2 计数 + 16 新事件精确守恒、告警恰好一条）；恢复后 32 线程并发守恒；FAILED/超时写请求得到可区分拒绝。
- `recovery/StateCorruptionRecoveryTest`（新增）：无文件合法首启（ACTIVE_FRESH）；损坏 JSON / 校验和篡改默认 FAILED 且写请求 503、不落盘、不偷偷空启动；`fail-on-corrupt=false` 重置但带 `corruptionReset` 标记。
- `recovery/StateReclamationBoundaryTest`（新增）：被驱逐窗口不进快照/不复活、快照只含存活窗口；回收 vs 不回收 vs 回收后重启对迟到/重复/边界/新事件结论完全一致；20 个历史窗口后快照存活窗口有界、恢复耗时不随历史增长。
- `recovery/RuleVersionSwitchRestartTest`（新增）：v1 运行→升级 v2→停机→重启，两版本窗口计数/已告警标记与告警按版本各自恢复且不串，重启后新事件只按 v2 判定、不回写 v1，不多/漏告警。

测试日志（SLF4J）逐条打印**事件内容、判定前后窗口快照（计数/事件指纹/watermark）、判定依据**
以及守恒统计；重启相关用例额外打印**恢复状态摘要（恢复来源/规则版本/窗口/去重键/告警数）、
重启前后窗口计数对比、`[结论对比] 基线=… 重启=…`、`[恢复期间并发结果]`、`[RECOVERY]`** 等，
可直接看出重启前后窗口计数变化与判定依据。查看某次测试日志：

```bash
mvn test -Dtest=RestartResumeTest
mvn test -Dtest='com.github.lisama569.threatdetectionenginejava.tests.recovery.*'
# surefire 原始输出：target/surefire-reports/*Output.txt
```

## 11. 模块结构

```
model/          统一模型、规则、窗口快照、告警、结论/拒绝原因枚举
normalization/  来源注册表、来源描述、归一化器（校验 + 时间解析 + 指纹）
dedup/          投递幂等去重器（可注入恢复键集合）
detection/      窗口状态（watermark/去重/驱逐/备忘录导出导入）、关联引擎（版本化）
alert/          告警生命周期服务与非法迁移异常
store/          内存态：规则版本史、告警、原子守恒计数、实体分段锁；状态导出/恢复
persistence/    本地快照：StateMemento 及各组件备忘录、JSON+SHA-256 编解码、原子文件库
recovery/       恢复闸门(阶段/阻塞放行/保守停服)、恢复与落盘编排、生命周期钩子、配置
service/        编排门面：归一化→去重→(恢复闸门)→加锁→判定→告警→计数；隔离重放；快照捕获
web/            REST 接口与结构化错误（含 503 恢复不可用、/api/recovery、手动 checkpoint）
config/ demo/   默认来源/规则引导（恢复后幂等）；demo profile 场景演示
```
