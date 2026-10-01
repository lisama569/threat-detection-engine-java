package com.github.lisama569.threatdetectionenginejava.service;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.detection.Evaluation;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowSnapshot;
import com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalization.NormalizationException;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.persistence.StateMemento;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryGate;
import com.github.lisama569.threatdetectionenginejava.store.IngestStats;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.Lock;

/**
 * 服务编排门面：归一化 -> 投递去重 -> 实体加锁 -> 窗口判定 -> 告警生命周期 -> 守恒计数。
 *
 * 幂等/一致性要点：
 * <ul>
 *   <li>投递层：deliveryId（缺失时用事件内容指纹）去重，重启后可用历史键集恢复；</li>
 *   <li>窗口层：窗口内按 eventId 内容去重，计数不会因重复投递膨胀；</li>
 *   <li>告警 ID 由 ruleId/version/entity/windowStart 确定性派生，同一窗口即使跨进程也不重复告警；</li>
 *   <li>同一实体的“判定+建告警”在实体分段锁内完成，计数与告警不重复不丢失；</li>
 *   <li>{@link #replay} 使用隔离引擎，不触碰在线状态与计数，保证可复现。</li>
 * </ul>
 */
public class DetectionService {

    private static final Logger log = LoggerFactory.getLogger(DetectionService.class);

    private final InMemoryStore store;
    private final SourceRegistry registry;
    private final CorrelationEngine engine;
    private final EventNormalizer normalizer;
    private final AlertLifecycleService lifecycle;
    private final Clock clock;
    /** 恢复边界闸门；为 null（隔离重放/历史单测）时不做恢复阶段限制，等价于始终可写。 */
    private final RecoveryGate gate;
    /** 恢复期间写请求最长阻塞等待；由装配层设置，默认 10s。 */
    private long awaitTimeoutMillis = 10_000L;

    public DetectionService(InMemoryStore store, SourceRegistry registry, CorrelationEngine engine,
                            EventNormalizer normalizer, AlertLifecycleService lifecycle, Clock clock) {
        this(store, registry, engine, normalizer, lifecycle, clock, null);
    }

    public DetectionService(InMemoryStore store, SourceRegistry registry, CorrelationEngine engine,
                            EventNormalizer normalizer, AlertLifecycleService lifecycle, Clock clock,
                            RecoveryGate gate) {
        this.store = store;
        this.registry = registry;
        this.engine = engine;
        this.normalizer = normalizer;
        this.lifecycle = lifecycle;
        this.clock = clock;
        this.gate = gate;
    }

    public void setAwaitTimeoutMillis(long awaitTimeoutMillis) {
        this.awaitTimeoutMillis = awaitTimeoutMillis;
    }

    public InMemoryStore getStore() { return store; }
    public SourceRegistry getRegistry() { return registry; }
    public CorrelationEngine getEngine() { return engine; }

    public void registerSource(SourceDescriptor descriptor) {
        registry.register(descriptor);
    }

    /** 部署规则：同时写入在线引擎与历史版本存储。 */
    public void deployRule(CorrelationRule rule) {
        engine.deployRule(rule);
        store.saveRule(rule);
    }

    /** 摄入单条原始事件（线程安全、幂等）。恢复期间阻塞等待恢复结束，恢复失败则拒绝。 */
    public IngestResult ingest(RawEvent raw) {
        awaitWritable();
        return doIngest(raw, engine, store, true);
    }

    /** 批量摄入：逐条处理并加锁，保持顺序可解释。 */
    public List<IngestResult> ingestBatch(List<RawEvent> raws) {
        awaitWritable();
        List<IngestResult> results = new ArrayList<>();
        for (RawEvent raw : raws) {
            results.add(ingest(raw));
        }
        return results;
    }

    /** 恢复边界：恢复没完成不能把请求当空实例处理；恢复失败显式拒绝（由上层映射 503）。 */
    private void awaitWritable() {
        if (gate != null) {
            gate.awaitWritable(awaitTimeoutMillis);
        }
    }

    /**
     * 用指定（固定）规则版本集合重放一批事件：隔离引擎、隔离去重、不写告警与计数，
     * 因此同一批事件 + 同一规则版本（同顺序）结论可复现，且不污染在线态。
     */
    public List<IngestResult> replay(List<RawEvent> raws, List<CorrelationRule> fixedRules) {
        CorrelationEngine replayEngine = new CorrelationEngine();
        for (CorrelationRule rule : fixedRules) {
            replayEngine.deployRule(rule);
        }
        InMemoryStore replayStore = new InMemoryStore();
        List<IngestResult> results = new ArrayList<>();
        for (RawEvent raw : raws) {
            results.add(doIngest(raw, replayEngine, replayStore, false));
        }
        return results;
    }

    private IngestResult doIngest(RawEvent raw, CorrelationEngine targetEngine,
                                  InMemoryStore targetStore, boolean persist) {
        SecurityEvent event;
        try {
            event = normalizer.normalize(raw);
        } catch (NormalizationException e) {
            if (persist) {
                store.increment(IngestOutcome.REJECTED);
                store.incrementRejected(e.getReason());
            } else {
                targetStore.increment(IngestOutcome.REJECTED);
            }
            log.warn("[REJECTED] source={}, reason={}, detail={}",
                    raw == null ? null : raw.sourceId(), e.getReason(), e.getMessage());
            return IngestResult.rejected(e.getReason(), e.getMessage());
        }

        String deliveryId = raw.deliveryId();
        String dedupKey = (deliveryId == null || deliveryId.isBlank())
                ? "evt:" + event.eventId()
                : "dlv:" + deliveryId;

        if (!targetStore.deduplicator().markIfFirst(dedupKey)) {
            if (persist) {
                store.increment(IngestOutcome.DUPLICATE);
            } else {
                targetStore.increment(IngestOutcome.DUPLICATE);
            }
            String detail = "重复投递被幂等忽略: dedupKey=" + dedupKey + ", eventId=" + event.eventId();
            log.info("[DUPLICATE] {}", detail);
            return IngestResult.of(IngestOutcome.DUPLICATE, event.eventId(), detail);
        }

        Lock lock = targetStore.entityLock(event.entityId());
        lock.lock();
        try {
            List<Evaluation> evaluations = targetEngine.evaluate(event);
            return resolveOutcome(event, evaluations, targetEngine, targetStore, persist);
        } finally {
            lock.unlock();
        }
    }

    private IngestResult resolveOutcome(SecurityEvent event, List<Evaluation> evaluations,
                                        CorrelationEngine targetEngine, InMemoryStore targetStore,
                                        boolean persist) {
        if (evaluations.isEmpty()) {
            IngestOutcome outcome = IngestOutcome.ACCEPTED_NO_ALERT;
            if (persist) {
                store.increment(outcome);
            } else {
                targetStore.increment(outcome);
            }
            String detail = "事件已归一化接收，但无适用规则: eventId=" + event.eventId()
                    + ", type=" + event.eventType();
            log.debug("[ACCEPTED_NO_ALERT] {}", detail);
            return IngestResult.of(outcome, event.eventId(), detail);
        }

        // 迟到：所有适用规则一致基于 eventTime 判定；任一字段明确说明即可，全部评估均记录在日志。
        boolean anyTooLate = evaluations.stream().anyMatch(Evaluation::tooLate);
        boolean allTooLate = evaluations.stream().allMatch(Evaluation::tooLate);
        boolean contentDuplicate = evaluations.stream().anyMatch(Evaluation::contentDuplicate);
        Evaluation crossing = evaluations.stream()
                .filter(Evaluation::crossedThreshold)
                .findFirst()
                .orElse(null);

        if (anyTooLate) {
            Evaluation lateEval = evaluations.stream().filter(Evaluation::tooLate).findFirst().get();
            if (persist) {
                store.increment(IngestOutcome.TOO_LATE);
            } else {
                targetStore.increment(IngestOutcome.TOO_LATE);
            }
            log.info("[TOO_LATE] event={}, detail={}", event, lateEval.reason());
            return IngestResult.of(IngestOutcome.TOO_LATE, event.eventId(), lateEval.reason());
        }

        if (crossing != null) {
            WindowSnapshot snap = crossing.after();
            String alertId = alertId(snap.ruleId(), snap.ruleVersion(), snap.entityId(),
                    snap.windowStart());
            if (persist && store.findAlert(alertId).isEmpty()) {
                Alert alert = lifecycle.open(alertId, snap.ruleId(), snap.ruleVersion(),
                        snap.entityId(), event.eventTime(), snap.count());
                store.saveAlert(alert);
            }
            if (persist) {
                store.increment(IngestOutcome.ACCEPTED_ALERT);
            } else {
                targetStore.increment(IngestOutcome.ACCEPTED_ALERT);
            }
            String detail = crossing.reason() + " | window=" + crossing.after();
            log.info("[ACCEPTED_ALERT] event={}, alertId={}, before={}, after={}",
                    event, alertId, crossing.before(), crossing.after());
            return IngestResult.alert(event.eventId(), alertId, detail);
        }

        IngestOutcome outcome = contentDuplicate
                ? IngestOutcome.DUPLICATE
                : IngestOutcome.ACCEPTED_NO_ALERT;
        if (persist) {
            store.increment(outcome);
        } else {
            targetStore.increment(outcome);
        }
        Evaluation first = evaluations.get(0);
        log.info("[{}] event={}, before={}, after={}, reason={}",
                outcome, event, first.before(), first.after(), first.reason());
        return IngestResult.of(outcome, event.eventId(),
                contentDuplicate ? first.reason()
                        : first.reason() + " | 适用规则数=" + evaluations.size());
    }

    /** 确定性告警 ID：同一（规则版本, 实体, 窗口）永远对应同一告警。 */
    static String alertId(String ruleId, int ruleVersion, String entityId, long windowStart) {
        return "alert-" + ruleId + "-v" + ruleVersion + "-" + entityId + "-w" + windowStart;
    }

    public Alert transitionAlert(String alertId, AlertStatus to, String note) {
        awaitWritable();
        Alert alert = store.findAlert(alertId)
                .orElseThrow(() -> new IllegalArgumentException("告警不存在: " + alertId));
        synchronized (alert) {
            return lifecycle.transition(alert, to, note);
        }
    }

    public List<Alert> listAlerts() {
        return store.listAlerts();
    }

    public List<WindowSnapshot> debugWindows() {
        return engine.debugWindows();
    }

    public IngestStats stats() {
        return store.stats();
    }

    public Map<String, Long> rejectionBreakdown() {
        return store.rejectionBreakdown();
    }

    /** 恢复状态视图（无闸门的隔离实例返回 null）。 */
    public com.github.lisama569.threatdetectionenginejava.recovery.RecoveryStatus recoveryStatus() {
        return gate == null ? null : gate.status();
    }

    /**
     * 在停机/快照时刻捕获一致状态备忘录。调用方（checkpoint 编排）须已确认实例处于 ACTIVE，
     * 且此处对全部实体分段锁加锁，保证捕获窗口/去重/告警/统计的瞬间没有摄入写在中途。
     */
    public StateMemento captureState(
            com.github.lisama569.threatdetectionenginejava.recovery.StateSnapshotService snapshots) {
        List<Lock> locks = new ArrayList<>();
        try {
            for (int i = 0; i < store.lockStripeCount(); i++) {
                Lock l = store.entityLockByStripe(i);
                l.lock();
                locks.add(l);
            }
            return snapshots.capture(store, engine, registry);
        } finally {
            for (Lock l : locks) {
                l.unlock();
            }
        }
    }
}
