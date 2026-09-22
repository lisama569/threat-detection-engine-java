# 威胁事件关联检测服务（本地可运行）

一个基于 Spring Boot 3 / Java 21 的**本地内存**威胁事件关联检测服务，用内存数据模拟多来源安全日志的接入、归一化、窗口关联判定、告警生命周期与重启恢复。目标是在**乱序到达、重复投递、规则变更、进程重启、并发摄入**等情形下给出**一致且可解释**的告警结论。

## 1. 构建与本地运行

```bash
# 运行全部测试（51 个用例，含 20 次并发重复压测）
mvn test

# 打包并以文件日志模式启动（重启后自动重放恢复）
mvn package -DskipTests
java -jar target/threat-detection-engine-java-1.0-SNAPSHOT.jar \
  --threat.engine.journal-path=/tmp/threat-demo/events.jsonl \
  --server.port=8089
```

配置项（`src/main/resources/application.properties`）：

| 配置 | 默认 | 说明 |
| --- | --- | --- |
| `threat.engine.journal-path` | 空 | 已接受事件的本地只追加日志（JSON Lines）。为空时纯内存运行，不落盘、不可跨进程恢复 |
| `threat.engine.replay-on-start` | `true` | 启动时是否按日志顺序重放，恢复窗口计数与告警 |

## 2. REST 接口

| 方法与路径 | 说明 |
| --- | --- |
| `POST /api/events` | 接入单条原始事件，返回归一化结论与每条匹配规则的判定 |
| `POST /api/events/batch` | 并发批量接入，返回守恒统计报告 |
| `GET /api/rules` / `POST /api/rules` | 查询当前规则 / 登记新版本（版本必须严格递增） |
| `GET /api/rules/{ruleId}/versions/{version}` | 取回历史版本规则 |
| `GET /api/alerts` | 列出全部告警 |
| `POST /api/alerts/{alertId}/transition` | 告警状态迁移，body：`{"status":"ACKNOWLEDGED"}`（alertId 含 `#`，HTTP 调用需 URL 编码） |
| `GET /api/state/watermark` | 当前 watermark |
| `GET /api/state/window?ruleId=&version=&entityId=&windowStartMs=` | 查询窗口计数状态（判定依据可解释） |

原始事件示例：

```json
{
  "source": "auth-sys",
  "eventId": "e-1",
  "fields": { "username": "alice", "action": "auth_fail", "ts": "2026-09-22T14:02:21.000Z" }
}
```

## 3. 归一化约定

- **统一模型 `SecurityEvent`**：`eventId / source / entityId / type / eventTimeMs / ingestTimeMs`。
- **全局事件 ID**：`source + "#" + 原始eventId`。不同来源即使原始 ID 相同也不会互相去重；同一来源重复 ID 才判重。
- **默认注册来源**（`DefaultDataInitializer`，可通过 `SourceRegistry` 扩展）：
  - `auth-sys`：实体字段 `username`，类型词 `auth_fail / auth_ok / priv_esc`，时间字段 `ts`（ISO-8601）。
  - `edp-agent`：实体字段 `host`，类型词 `fail_login / escalation / malware`，时间字段 `occurredAt`（epoch millis）。
  - `web-gateway`：实体字段 `srcIp`，类型词 `web_attack / blocked`，时间取顶层 `timestamp`。
- **时间戳**：支持 ISO-8601 字符串、epoch 数字/纯数字字符串；秒级 epoch（绝对值 < 10^12）自动 ×1000 换算为毫秒。
- **不静默丢弃**：归一化失败返回 `REJECTED` 与可区分的 `rejectReason`：
  `PAYLOAD_EMPTY`、`SOURCE_NOT_REGISTERED`、`MISSING_EVENT_ID`、`INVALID_TIMESTAMP`、
  `TIMESTAMP_OUT_OF_RANGE`（早于 1970 或晚于 2100）、`MISSING_ENTITY_ID`、`MISSING_EVENT_TYPE`（缺字段或类型词无法映射）。
  校验顺序固定，拒绝原因互不重叠。

## 4. 关联规则语义

规则 `CorrelationRule` 为**按版本不可变**对象：

```
ruleId, version, eventTypes[], threshold, windowSizeMs, allowedLatenessMs
```

默认规则：`brute-force-login v1`——同一实体在 **10 秒**窗口内出现 **3 次**`FAILED_LOGIN/FIREWALL_BLOCK` 即告警，迟到容忍 **5 秒**；另有 `malware-or-escalation v1`（阈值 1）。

- **窗口**：按 `windowSizeMs` 对齐的滚动窗口，`windowStart = floor(eventTime / windowSize) * windowSize`（左闭右开）。边界只由事件时间决定，与到达顺序无关，窗口抖动不影响归属。
- **watermark**：按 `(规则版本, 实体)` 维护已观测最大事件时间，`watermark = maxEventTime - allowedLatenessMs`，单调不减。
- **乱序**：事件在窗口内按 `(eventTime, eventId)` 有序聚合，窗口状态是**事件集合**而非到达序列的函数；乱序输入与顺序输入结论一致。
- **迟到分级**（以事件**到达引擎时刻**为准）：
  - 到达时间 `<= windowEnd + allowedLatenessMs`：容忍内。事件时间不落后于 watermark 为 `ACCEPTED`，落后于 watermark 为 `LATE_WITHIN_TOLERANCE`，两者都正常计数；
  - 到达时间 `> windowEnd + allowedLatenessMs`：明确标记 `LATE_BEYOND_TOLERANCE`，**不计数、不告警**，返回带窗口截止时刻的说明。
  - 边界采用左闭：恰好等于 `windowEnd + allowedLatenessMs` 仍在容忍内。
- **告警恰好一次**：窗口计数首次达到阈值时登记告警。`alertId = ruleId#v{version}#{entityId}#{windowStart}` 为确定性派生（无随机量），登记接口幂等，因此重复投递、窗口抖动、重放、重启都不会产生第二个告警。
- **规则版本与重放**：新版本号必须**严格大于**当前版本，历史版本永久保留。事件按其处理时的规则版本评估；规则更新**不回溯改写**历史结论。用“同一批事件 + 同一规则版本”重放（含全新引擎实例、乱序重放）得到完全相同的计数、贡献事件集合与 `alertId`。
- **重启恢复**：已接受事件以 JSON Lines 同步追加到本地日志，条目同时持久化**引擎接收时刻**；启动时按序确定性重放（接收时刻沿用持久化值，迟到判定与首次一致），恢复窗口计数与告警。重放只恢复状态，不宣称“新产生告警”。

## 5. 告警生命周期

合法迁移：`OPEN → ACKNOWLEDGED`、`OPEN → RESOLVED`、`ACKNOWLEDGED → RESOLVED`。
非法/无效迁移被拒绝并给出可区分原因：`ALERT_NOT_FOUND`、`ALREADY_IN_TARGET_STATUS`、`ILLEGAL_TRANSITION`（含回退、从 `RESOLVED` 再迁移）。

> 兼容范围说明：当前版本为本地单机内存态，**事件日志可跨重启恢复计数与告警本身**；但 `ACKNOWLEDGED/RESOLVED` 等生命周期操作状态仅保存在内存，不随日志持久化，重启后告警恢复为 `OPEN`。如需保留处置状态，可在此基础上增加告警快照落盘。

## 6. 并发与守恒统计

- 摄入链：归一化 → 按全局 eventId 幂等去重 → 追加日志 → 窗口检测。
- 采用 64 段分段锁（按 eventId 哈希）+ 窗口对象内置锁：同一实体串行、不同实体并行；计数与阈值判定在窗口临界区内完成，并发下不丢不重。
- 重复投递命中已处理缓存，返回 `DUPLICATE` 并附带**首次结论快照**，不重新计数。
- 批量报告 `BatchReport` 满足守恒式：
  `accepted + duplicate + lateWithinTolerance + lateBeyondTolerance + rejected == total`，
  且 `alertsRaised` 为本次摄入新产生告警数。

## 7. 可解释性

- 每次评估在日志中打印事件、规则版本、实体、窗口区间、计数/阈值、watermark、是否产生告警及判定依据（例如 `counted once per eventId; threshold check on aligned window`）。
- `GET /api/state/window` 返回贡献事件 ID 列表、阈值、是否达阈/已告警，便于复盘。
- 测试日志同样打印事件、窗口状态与判定依据（见 `target/surefire-reports` 或控制台输出）。

## 8. 测试覆盖

`src/test/.../tests`：

| 测试类 | 覆盖场景 |
| --- | --- |
| `NormalizationTest` | 多来源格式、epoch 秒/毫秒、字段缺失、非法/越界时间戳、未注册来源（拒绝原因可区分） |
| `OutOfOrderAndLatenessTest` | 乱序稳定、容忍内迟到补阈、超容忍明确标记且不计数、边界左闭、窗口边界隔离 |
| `DuplicateDeliveryTest` | 重复投递不重算、不重复告警、跨来源同 ID 不判重、非法记录重复投递 |
| `RuleVersionReplayTest` | 版本单调、历史版本保留、同版本重放可复现、规则更新不重写历史 |
| `RestartJournalReplayTest` | 落盘日志 + 全新实例模拟重启，计数/告警恢复，重启后重复仍幂等 |
| `AlertLifecycleTest` | 合法迁移链、各类非法迁移可区分原因、并发幂等登记 |
| `ConcurrentIngestionTest` | 同实体 300 事件 12 线程 ×20 轮计数精确、混杂重复投递、批量报告守恒 |
