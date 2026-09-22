package com.github.lisama569.threatdetectionenginejava.detection;

import com.github.lisama569.threatdetectionenginejava.alert.AlertIds;
import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleManager;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.IngestStatus;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowState;
import com.github.lisama569.threatdetectionenginejava.rule.RuleRegistry;
import com.github.lisama569.threatdetectionenginejava.window.WindowMath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 基于版本化规则的时间窗关联检测引擎。
 * <p>
 * 语义约定（全部为确定性纯逻辑，与到达顺序、并发调度、重启无关）：
 * <ul>
 *   <li>窗口为按窗口长度对齐的滚动窗口，windowStart 只由 eventTime 决定；</li>
 *   <li>watermark = 已观测最大事件时间 - 规则容忍时间，对同一实体单调不减；</li>
 *   <li>事件到达时间 &gt; 窗口结束 + 容忍时间 即 LATE_BEYOND_TOLERANCE，明确标记且不计数；</li>
 *   <li>容忍范围内的迟到事件正常计数，事件时间早于当前 watermark 时额外标记为 LATE_WITHIN_TOLERANCE；</li>
 *   <li>窗口内计数首次达到阈值即登记一次告警，alertId 为确定性派生；重复事件/重复调用幂等；</li>
 *   <li>计数按 (eventTime, eventId) 排序后聚合，乱序输入得到与顺序输入相同的窗口状态。</li>
 * </ul>
 */
@Component
public class CorrelationEngine {

    private static final Logger log = LoggerFactory.getLogger(CorrelationEngine.class);

    private final RuleRegistry ruleRegistry;
    private final AlertLifecycleManager alertManager;

    /** 窗口键 -> 可变窗口聚合状态 */
    private final Map<WindowKey, MutableWindow> windows = new ConcurrentHashMap<>();
    /** 每个 (规则版本, 实体) 已观测到的最大事件时间，用于 watermark */
    private final Map<EntityKey, AtomicLong> maxEventTime = new ConcurrentHashMap<>();

    public CorrelationEngine(RuleRegistry ruleRegistry, AlertLifecycleManager alertManager) {
        this.ruleRegistry = ruleRegistry;
        this.alertManager = alertManager;
    }

    /**
     * 以当前时刻为到达时间评估一条事件对所有匹配的当前版本规则的影响。
     */
    public List<IngestResult> evaluate(SecurityEvent event, long nowMs) {
        return evaluate(event, nowMs, false);
    }

    /**
     * 评估一条事件对所有匹配的当前版本规则的影响。
     *
     * @param restoring true 表示正在重放恢复：窗口计数与告警状态照常恢复，
     *                  但结论不宣称“新产生告警”，保证重启不产生第二个可观测告警
     */
    public List<IngestResult> evaluate(SecurityEvent event, long nowMs, boolean restoring) {
        List<IngestResult> results = new ArrayList<>();
        for (CorrelationRule rule : ruleRegistry.currentRules()) {
            if (rule.eventTypes().contains(event.type())) {
                results.add(evaluateInternal(event, nowMs, rule, false, restoring));
            }
        }
        return results;
    }

    /**
     * 按指定规则版本评估（重放时使用，保证规则更新后结论可复现）。
     */
    public IngestResult evaluateWith(SecurityEvent event, long arrivalTimeMs,
                                    String ruleId, int ruleVersion) {
        return evaluateWith(event, arrivalTimeMs, ruleId, ruleVersion, false);
    }

    /**
     * 按指定规则版本评估。
     *
     * @param restoring true 表示重放恢复，抑制结论中的新告警宣称
     */
    public IngestResult evaluateWith(SecurityEvent event, long arrivalTimeMs,
                                    String ruleId, int ruleVersion, boolean restoring) {
        CorrelationRule rule = ruleRegistry.getVersion(ruleId, ruleVersion)
                .orElseThrow(() -> new IllegalArgumentException(
                        "rule version not found: " + ruleId + "#v" + ruleVersion));
        if (!rule.eventTypes().contains(event.type())) {
            return IngestResults.skipped(event, rule, null, null, null,
                    "event type not subscribed by rule (rule update replay)");
        }
        return evaluateInternal(event, arrivalTimeMs, rule, true, restoring);
    }

    private IngestResult evaluateInternal(SecurityEvent event, long arrivalTimeMs,
                                          CorrelationRule rule, boolean pinnedVersion,
                                          boolean restoring) {
        long windowStart = WindowMath.windowStart(event.eventTimeMs(), rule.windowSizeMs());
        long windowEnd = WindowMath.windowEnd(windowStart, rule.windowSizeMs());
        WindowKey key = new WindowKey(rule.ruleId(), rule.version(), event.entityId(), windowStart);
        EntityKey entityKey = new EntityKey(rule.ruleId(), rule.version(), event.entityId());

        MutableWindow window = windows.computeIfAbsent(key,
                k -> new MutableWindow(rule, event.entityId(), windowStart, windowEnd));

        // 对同一窗口串行化，保证并发下计数精确、告警恰好一次
        synchronized (window) {
            // 先推进 watermark 再判断迟到，语义固定
            long observedMax = maxEventTime
                    .computeIfAbsent(entityKey, k -> new AtomicLong(Long.MIN_VALUE))
                    .accumulateAndGet(event.eventTimeMs(), Math::max);
            long watermark = observedMax - rule.allowedLatenessMs();

            if (WindowMath.isBeyondTolerance(windowEnd, arrivalTimeMs, rule.allowedLatenessMs())) {
                log.info("event late beyond tolerance: eventId={} rule={}#v{} entity={} "
                                + "window=[{},{}) arrival={} deadline={}",
                        event.eventId(), rule.ruleId(), rule.version(), event.entityId(),
                        windowStart, windowEnd, arrivalTimeMs,
                        windowEnd + rule.allowedLatenessMs());
                window.lastUpdatedMs = Math.max(window.lastUpdatedMs, arrivalTimeMs);
                return IngestResults.build(
                        event.eventId(), IngestStatus.LATE_BEYOND_TOLERANCE, null,
                        "event arrived after window close + allowed lateness "
                                + rule.allowedLatenessMs() + "ms",
                        rule, windowStart, window.count, window.thresholdReached, null);
            }

            boolean isLate = event.eventTimeMs() + rule.allowedLatenessMs() < observedMax
                    || event.eventTimeMs() < watermark;
            boolean added = window.add(event);
            if (!added) {
                log.info("duplicate event suppressed in window: eventId={} windowKey={}",
                        event.eventId(), key);
            }

            String alertId = null;
            if (window.thresholdReached && !window.alertRaised) {
                Alert alert = window.toAlert();
                AlertLifecycleManager.RegisterOutcome outcome = alertManager.registerIfAbsent(alert);
                window.alertRaised = true; // 登记为幂等操作，alertId 确定性，不会产生第二个告警
                // 仅在真实摄入（非重放恢复）且本次确实新建时才宣称产生新告警
                if (outcome.created() && !restoring) {
                    alertId = outcome.alert().alertId();
                }
            }
            window.lastUpdatedMs = Math.max(window.lastUpdatedMs, arrivalTimeMs);

            IngestStatus status;
            if (isLate) {
                status = IngestStatus.LATE_WITHIN_TOLERANCE;
            } else {
                status = IngestStatus.ACCEPTED;
            }

            log.info("event evaluated: eventId={} status={} rule={}#v{} entity={} "
                            + "window=[{},{}) count={}/{} watermark={} alertRaised={} alertId={} "
                            + "basis='{}'",
                    event.eventId(), status, rule.ruleId(), rule.version(), event.entityId(),
                    windowStart, windowEnd, window.count, rule.threshold(), watermark,
                    window.alertRaised, alertId,
                    added ? "counted once per eventId; threshold check on aligned window"
                          : "eventId already present in window, not counted twice");

            return IngestResults.build(
                    event.eventId(), status, null,
                    added ? "counted in aligned window" : "duplicate event within window, idempotent",
                    rule, windowStart, window.count, window.thresholdReached, alertId);
        }
    }

    public Optional<WindowState> windowState(String ruleId, int version,
                                             String entityId, long windowStartMs) {
        WindowKey key = new WindowKey(ruleId, version, entityId, windowStartMs);
        MutableWindow window = windows.get(key);
        if (window == null) {
            return Optional.empty();
        }
        synchronized (window) {
            return Optional.of(window.snapshot());
        }
    }

    /**
     * 当前全局 watermark（取所有实体中的最小值），仅供可观测查询。
     */
    public long currentWatermarkMs() {
        long min = Long.MAX_VALUE;
        for (Map.Entry<EntityKey, AtomicLong> e : maxEventTime.entrySet()) {
            CorrelationRule rule = ruleRegistry.getVersion(e.getKey().ruleId(), e.getKey().version())
                    .orElse(null);
            long lateness = rule == null ? 0 : rule.allowedLatenessMs();
            min = Math.min(min, e.getValue().get() - lateness);
        }
        return min == Long.MAX_VALUE ? Long.MIN_VALUE : min;
    }

    /* ---------------- 内部类型 ---------------- */

    record WindowKey(String ruleId, int version, String entityId, long windowStart) {
    }

    record EntityKey(String ruleId, int version, String entityId) {
    }

    /**
     * 可变窗口聚合：事件保存在有序结构中，使窗口状态是事件集合（而非到达序列）的函数。
     */
    private static final class MutableWindow {
        final CorrelationRule rule;
        final String entityId;
        final long start;
        final long end;
        final java.util.SortedSet<SecurityEvent> events =
                new java.util.TreeSet<>(Comparator
                        .comparingLong(SecurityEvent::eventTimeMs)
                        .thenComparing(SecurityEvent::eventId));
        int count;
        boolean thresholdReached;
        boolean alertRaised;
        long lastUpdatedMs;

        MutableWindow(CorrelationRule rule, String entityId, long start, long end) {
            this.rule = rule;
            this.entityId = entityId;
            this.start = start;
            this.end = end;
        }

        boolean add(SecurityEvent event) {
            boolean added = events.add(event);
            if (added) {
                count = events.size();
                if (!thresholdReached && count >= rule.threshold()) {
                    thresholdReached = true;
                }
            }
            return added;
        }

        Alert toAlert() {
            SecurityEvent first = events.first();
            SecurityEvent last = events.last();
            return new Alert(
                    AlertIds.derive(rule.ruleId(), rule.version(), entityId, start),
                    rule.ruleId(), rule.version(), entityId, start, end,
                    count, first.eventTimeMs(), last.eventTimeMs(),
                    System.currentTimeMillis(), AlertStatus.OPEN);
        }

        WindowState snapshot() {
            return new WindowState(
                    rule.ruleId(), rule.version(), entityId, start, end,
                    count, rule.threshold(), thresholdReached,
                    false, alertRaised,
                    events.stream().map(SecurityEvent::eventId).toList(),
                    lastUpdatedMs);
        }
    }
}
