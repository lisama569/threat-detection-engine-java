# 威胁事件关联检测服务（本地内存 + 重启续跑版）

一个可本地运行的威胁事件关联检测服务：用本地内存数据模拟多来源安全日志的接入与判定，
保证在**乱序到达、重复投递、规则变更、进程重启、滚动重启恢复、并发摄入**等情形下
告警结论一致、可复现、可解释。

- 技术栈：Java 21、Spring Boot 3.4.x、Jackson、JUnit 5；除 Spring Web 外无外部中间件，
  **无需数据库/消息队列**，重启状态只写本地磁盘文件。
- 规则/来源在启动时自动注册；优雅停机时把运行状态原子落盘，下次启动自动恢复，未结束的
  关联窗口、告警处置状态接着跑。

## 1. 快速开始

```bash
# 构建 + 全量单测（42 个用例）
mvn test

# 启动 Web 服务（默认 8080；若端口被占用可用 --server.port 指定；本地状态默认写 ./data/state）
mvn spring-boot:run
mvn spring-boot:run -Dspring-boot.run.arguments="--server.port=8088"
# 优雅停机（Ctrl+C / kill <pid> / 滚动重启 SIGTERM）会落盘；再次启动自动 RESTORED 续跑

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
  进程重启后从本地状态文件恢复历史键集合，重复投递仍然只生效一次。
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

## 7. 重启续跑（本地状态持久化与恢复）

只用本地磁盘（默认目录 `./data/state/state.json`，属性 `engine.state-dir` 可改），不引入任何
外部数据库或中间件。优雅停机（Spring `@PreDestroy`，如滚动重启的 SIGTERM）时把内存态原子落盘，
下次启动 `@PostConstruct` 阶段（Web 端口对外服务之前）完成恢复。

### 7.1 落盘与原子性

- 文件外层是一个**信封**：`formatVersion` + `generation`（状态代数，每次保存 +1）+ `checksum`
  （对 payload 规范化 JSON 的 SHA-256）+ payload。
- 原子写：先写 `state.json.tmp`（权限 `600`），同目录 `ATOMIC_MOVE` 覆盖 `state.json`。
  滚动重启时要么读到完整的上一代、要么读不到，绝不会读到半截文件。
- 任何 JSON 损坏、必填字段缺失、枚举非法或**校验和不匹配（含被篡改）**都判为损坏。

### 7.2 哪些状态会被恢复（续跑覆盖范围）

| 状态 | 是否恢复 | 说明 |
| --- | --- | --- |
| 规则全部历史版本 | 是 | 引擎按 `ruleId#version` 隔离；恢复后在线判定仍只看最高版本 |
| 固定窗口计数 | 是 | 每个（规则版本, 实体）仍存活窗口的去重事件数、是否已告警 |
| 窗口内去重指纹 | 是 | 只存 eventId 集合（判定只依赖指纹，不依赖事件明细） |
| watermark（迟到基准） | 是 | 即使某实体所有窗口都已回收，watermark 仍单独保留，迟到判定不回退 |
| 投递去重键集合 | 是 | 历史 `dlv:`/`evt:` 键，重启后重投仍判 DUPLICATE |
| 告警 + 当前处置状态 | 是 | OPEN/ACKNOWLEDGED/SUPPRESSED/RESOLVED、备注、各时间戳全部延续 |
| 守恒统计 + 拒绝原因分布 | 是 | 重启后累计值与“从头到尾没重启过”完全一致 |

用同一份本地状态重启后继续投后续事件，最终结论（每条事件的结论、告警 ID 集合、守恒统计）
与“这个进程从头到尾没重启、按同样顺序投同一批事件”**逐结论一致**：不多告警、不漏告警，
重复/迟到/拒绝判定不改变。

### 7.3 哪些状态会被安全回收（恢复耗时可控）

停机落盘前以参考时间 `ref = max(当前时钟, 各实体 watermark)` 对每个（规则版本, 实体）执行回收：
仅保留满足 `windowEnd > ref - lateTolerance` 的固定窗口，其余窗口丢弃。

- 被回收窗口里**今后可能到达的任何事件**都必然落在容忍之外（要么窗口早已关闭、要么判 TOO_LATE），
  因此回收与不回收对后续事件的判定结论完全相同（有边界单测逐结论对照）。
- **不回收**的部分：watermark（迟到基准）、投递去重键、全部告警（含历史）、规则版本。
  这些任一丢失都会改变判定（例如去重键丢失会让历史重投从 DUPLICATE 变成计数/告警）。
- 恢复数据量只与“仍可能影响判定的近容忍窗口 + 实体数 + 去重键 + 告警量”相关，
  不会随全部历史窗口无限增长。

### 7.4 恢复边界与并发

- 恢复期间服务处于 `RECOVERING`：一切**写入**（摄入/批量/告警迁移/部署规则）返回
  **503 `RECOVERY_IN_PROGRESS`**，请求既不会被当成空实例处理，也不会在恢复后被重复补算；
  读接口（stats/alerts/windows）仍可用。
- 恢复完成切到 `ACTIVE` 后才放行；恢复期间到达的请求需要客户端重试，恢复后的同实体并发摄入
  仍由实体分段锁保证计数与告警守恒。
- 状态结论可区分并暴露在 `GET /api/stats` 与 `GET /api/recovery`：
  - `FRESH`：未发现状态文件（首次启动），正常全新启动；
  - `RESTORED`：成功恢复（附恢复的规则/告警/窗口态/去重键数量、保留窗口数、代数）；
  - `DISABLED`：`engine.state.enabled=false`，退化为旧的纯内存行为；
  - `CORRUPT`：状态损坏。默认 `engine.state.allow-fresh-on-corrupt=false`，实例进入
    **`FAILED`**：拒绝一切写入（503 `RECOVERY_FAILED`），**绝不静默按空实例继续对外服务**，
    且不会覆盖损坏文件、保持读接口可查，便于在统计与日志中看到失败原因；置
    `engine.state.fail-fast-on-corrupt=true` 可改为直接终止启动（交编排层/容器处理重启）；
    `allow-fresh-on-corrupt=true` 时才会清空损坏状态、全新启动，但恢复结论仍
    如实标记为 `CORRUPT`，统计与日志可见。

### 7.5 配置项

| 属性 | 默认值 | 说明 |
| --- | --- | --- |
| `engine.state-dir` | `data/state` | 本地状态目录 |
| `engine.state.enabled` | `true` | 关闭后不读不写，等同改造前纯内存行为 |
| `engine.state.allow-fresh-on-corrupt` | `false` | 状态损坏时是否允许清空并全新启动（默认拒绝） |
| `engine.state.fail-fast-on-corrupt` | `false` | 损坏时是否直接终止启动；默认不终止，留在 `FAILED` 在线拒绝写入、读接口与恢复结论仍可见 |

> 注意：续跑依赖**优雅停机**落盘（SIGTERM/容器 preStop）。进程被 `kill -9` 等硬杀时，
> 最近一代未落盘的事件不在状态文件中——这与“未处理”等价，上游重投即可，且因幂等键与
> 确定性告警 ID 不会造成重复计数或重复告警。

## 8. REST 接口（本地验证）

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/events` | 单条摄入，返回结构化结论；恢复中返回 503，恢复失败返回 503 |
| `POST /api/events/batch` | 批量摄入（顺序处理，逐条返回） |
| `GET /api/alerts` | 列出全部告警及生命周期状态 |
| `POST /api/alerts/{id}/transition?to=&note=` | 告警状态迁移 |
| `GET /api/stats` | 守恒统计 + 拒绝原因分布 + `recovery` 恢复结论 |
| `GET /api/recovery` | 恢复阶段/状态/代数/恢复计数/详情（FRESH/RESTORED/CORRUPT…） |
| `GET /api/debug/windows` | 窗口状态快照（计数/事件指纹/watermark/是否已告警） |

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
- 持久化：本地文件重启续跑（见第 7 节），无外部依赖；设 `engine.state.enabled=false` 可退化为纯内存。
  续跑依赖优雅停机落盘；硬杀进程时最近未落盘的事件按“未处理”对待，重投依靠幂等键不重复计数/告警。
- 摄入结论是**按到达顺序**确定的（watermark 定义如此）；重放时保持相同输入顺序即可复现。

## 10. 测试场景与日志

`mvn test`（42 个用例）覆盖：

- `NormalizationTest`：三种来源、秒/毫秒/ISO 时间戳、6 种拒绝原因逐一区分、不静默丢弃。
- `OutOfOrderAndLateEventTest`：乱序容忍内稳定计数、恰好等于容忍边界接受、超容忍 TOO_LATE 不计数且不漏报、窗口边界不串窗、独立运行结论一致。
- `DeduplicationTest`：相同 deliveryId、无 deliveryId 内容指纹、重试导致的 ID 抖动、整批重投、重启后键集合恢复、跨进程告警 ID 一致。
- `RuleReplayTest`：同版本重放逐结论复现、v1/v2 版本隔离结论不同、在线更新不回写历史、重放不污染在线态、版本号必须递增。
- `AlertLifecycleTest`：合法迁移链、抑制/恢复、非法跳跃、重复迁移、终态保护（from/to 可区分）。
- `ConcurrentIngestTest`：同实体 100 事件/50 线程计数精确且告警恰好一条、10 实体并发守恒、同一投递 64 线程并发只生效一次、并发混入非法/迟到事件仍守恒。
- `RestartRecoveryTest`（新增，重启续跑 5 个场景）：
  - **正常重启续跑**：重启后窗口计数/去重指纹/watermark/告警处置状态延续，12 条事件逐条结论、
    告警 ID、守恒统计与“从头到尾没重启”的对照组完全一致（不多/不漏告警）；
  - **恢复期间并发摄入**：RECOVERING 阶段 16 线程并发全部 503 拒绝、不污染计数；恢复后 30 事件
    /30 线程同实体并发告警恰好一条、统计守恒；
  - **状态缺失/损坏**：无文件=`FRESH` 放行；篡改校验和后默认 `FAILED` 拒绝写入且不覆盖现场，
    `allow-fresh-on-corrupt=true` 才清空并全新启动（结论仍标记 `CORRUPT`，可区分）；
  - **回收后的边界事件**：恰好等于容忍接受、超 1ms 判 TOO_LATE、旧窗重投不复活、迟到不新建窗口，
    与同样执行回收的连续运行逐结论一致；
  - **规则版本切换后重启**：v1/v2 窗口与告警按版本恢复互不串，重启后事件只按在线 v2 判，
    v1 计数不被污染、不产生 v1 告警。

测试日志（SLF4J）逐条打印**事件内容、判定前后窗口快照（计数/事件指纹/watermark）、判定依据**、
**重启恢复报告（RESTORED/FRESH/CORRUPT、恢复了多少窗口/告警/去重键、回收了多少窗口、状态代数）**
以及守恒统计，可直接看出重启前后窗口计数变化与判定依据。查看某次测试日志：

```bash
mvn test -Dtest=RestartRecoveryTest
# 控制台或 surefire 原始输出：target/surefire-reports/*Output.txt
```

### 10.1 本地手动复现“滚动重启接着跑”

```bash
# 终端 A：启动（状态默认写 ./data/state/state.json）
mvn spring-boot:run

# 终端 B：投 2 条（计数 2/3，未告警）
for i in 1 2; do
  curl -s -X POST http://localhost:8080/api/events -H 'Content-Type: application/json' -d "{
    \"sourceId\":\"edr\",\"deliveryId\":\"r-$i\",
    \"payload\":{\"hostId\":\"host-r\",\"eventType\":\"login_failure\",
                 \"timestamp\":$((1790000000000+i*1000)),\"severity\":\"low\"}}"; echo;
done
curl -s http://localhost:8080/api/debug/windows | head -c 400; echo

# 终端 A：Ctrl+C 优雅停机 -> 观察日志 [RECOVERY] 状态已落盘代数=1 ...
# 再次启动 -> 观察日志 [RECOVERY] status=RESTORED, ... retainedWindows=...
mvn spring-boot:run

# 终端 B：确认恢复结论 + 第 3 条越阈（应产生且只产生一条告警）
curl -s http://localhost:8080/api/recovery; echo
curl -s -X POST http://localhost:8080/api/events -H 'Content-Type: application/json' -d '{
  "sourceId":"edr","deliveryId":"r-3",
  "payload":{"hostId":"host-r","eventType":"login_failure",
             "timestamp":1790000003000,"severity":"low"}}'; echo

# 损坏状态演示：篡改文件后重启，默认进入 FAILED，摄入返回 503 RECOVERY_FAILED，
# /api/stats 里 recovery.status=CORRUPT；加 --engine.state.allow-fresh-on-corrupt=true 可清空重启
```

## 11. 模块结构

```
model/          统一模型、规则、窗口快照、告警、结论/拒绝原因枚举
normalization/  来源注册表、来源描述、归一化器（校验 + 时间解析 + 指纹）
dedup/          投递幂等去重器（可注入恢复键集合）
detection/      窗口状态（watermark/去重/驱逐/安全回收/恢复导出）、关联引擎（多版本隔离）
alert/          告警生命周期服务与非法迁移异常
store/          内存态：规则版本史、告警、原子守恒计数、实体分段锁、状态恢复/导出
persistence/    重启续跑：JSON+SHA-256 信封编解码、本地原子文件、恢复协调器（RECOVERING/ACTIVE/FAILED）
service/        编排门面：归一化→去重→加锁→判定→告警→计数；恢复门禁；隔离重放
web/            REST 接口与结构化错误（含 503 RECOVERY_IN_PROGRESS / RECOVERY_FAILED）
config/ demo/   默认来源/规则引导（恢复后不覆盖已恢复规则）；demo profile 场景演示
```
