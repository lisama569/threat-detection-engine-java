package com.github.lisama569.threatdetectionenginejava.service;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.detection.Evaluation;
import com.github.lisama569.threatdetectionenginejava.detection.WindowState;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowSnapshot;
import com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalization.NormalizationException;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryFailedException;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryInProgressException;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryPhase;
import com.github.lisama569.threatdetectionenginejava.store.IngestStats;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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

    /**
     * 恢复边界：直接 new 出来（单测/隔离重放）默认 {@link RecoveryPhase#ACTIVE}；
     * Spring 装配、走重启续跑时由 StateRecoveryCoordinator 在构造后置为 RECOVERING。
     */
    private volatile RecoveryPhase phase = RecoveryPhase.ACTIVE;

    public DetectionService(InMemoryStore store, SourceRegistry registry, CorrelationEngine engine,
                            EventNormalizer normalizer, AlertLifecycleService lifecycle, Clock clock) {
        this.store = store;
        this.registry = registry;
        this.engine = engine;
        this.normalizer = normalizer;
        this.lifecycle = lifecycle;
        this.clock = clock;
    }

    public RecoveryPhase getPhase() {
        return phase;
    }

    /** 标记进入“恢复中”：此后一切写入请求被拒绝，直到 {@link #markActive()}。 */
    public void markRecovering() {
        this.phase = RecoveryPhase.RECOVERING;
        log.info("服务进入 RECOVERING：恢复完成前拒绝一切摄入/状态迁移请求");
    }

    /** 恢复成功或确认无状态全新启动后放行。 */
    public void markActive() {
        this.phase = RecoveryPhase.ACTIVE;
        log.info("服务进入 ACTIVE：恢复完成，开始正常对外服务");
    }

    /** 状态损坏且未允许丢弃：永久拒绝写入，只能由运维介入，绝不静默按空实例服务。 */
    public void markFailed() {
        this.phase = RecoveryPhase.FAILED;
        log.error("服务进入 FAILED：本地状态恢复失败，拒绝一切写入请求");
    }

    /** 写入路径统一门禁：恢复中 503、恢复失败拒绝。读路径（stats/alerts/windows）不受限。 */
    private void ensureWritable() {
        if (phase == RecoveryPhase.RECOVERING) {
            throw new RecoveryInProgressException(
                    "本地状态正在恢复中，请稍后重试；该请求未被计入，恢复后也不会被重复处理");
        }
        if (phase == RecoveryPhase.FAILED) {
            throw new RecoveryFailedException(
                    "本地状态恢复失败，实例已拒绝服务；请修复状态文件或显式允许丢弃后重启");
        }
    }

    public InMemoryStore getStore() { return store; }
    public SourceRegistry getRegistry() { return registry; }
    public CorrelationEngine getEngine() { return engine; }

    public void registerSource(SourceDescriptor descriptor) {
        registry.register(descriptor);
    }

    /** 部署规则：同时写入在线引擎与历史版本存储。 */
    public void deployRule(CorrelationRule rule) {
        ensureWritable();
        engine.deployRule(rule);
        store.saveRule(rule);
    }

    /** 摄入单条原始事件（线程安全、幂等）。 */
    public IngestResult ingest(RawEvent raw) {
        ensureWritable();
        return doIngest(raw, engine, store, true);
    }

    /** 批量摄入：逐条处理并加锁，保持顺序可解释。 */
    public List<IngestResult> ingestBatch(List<RawEvent> raws) {
        ensureWritable();
        List<IngestResult> results = new ArrayList<>();
        for (RawEvent raw : raws) {
            results.add(ingest(raw));
        }
        return results;
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
        ensureWritable();
        Alert alert = store.findAlert(alertId)
                .orElseThrow(() -> new IllegalArgumentException("告警不存在: " + alertId));
        synchronized (alert) {
            return lifecycle.transition(alert, to, note);
        }
    }

    // ---- 重启恢复（内部使用：仅 StateRecoveryCoordinator 在 RECOVERING 阶段调用） ----

    /** 恢复全部规则版本（引擎按版本隔离 + 历史版本存储），不走在线部署校验。 */
    public void restoreRules(List<CorrelationRule> rules) {
        for (CorrelationRule rule : rules) {
            engine.restoreRule(rule);
            store.restoreRule(rule);
        }
    }

    /** 恢复告警（含处置状态）。 */
    public void restoreAlerts(List<Alert> alerts) {
        for (Alert alert : alerts) {
            store.restoreAlert(alert);
        }
    }

    /** 恢复投递去重键。 */
    public void restoreDedupKeys(Set<String> keys) {
        store.restoreDedupKeys(keys);
    }

    /** 恢复守恒计数与拒绝原因分布。 */
    public void restoreStats(IngestStats snapshot, Map<RejectReason, Long> rejectionBreakdown) {
        store.restoreStats(snapshot);
        store.restoreRejectionBreakdown(rejectionBreakdown);
    }

    /**
     * 恢复某个规则版本下所有实体的窗口态（计数/去重指纹/watermark 全部延续）。
     * 调用前应已通过 {@link #restoreRules} 恢复对应规则版本。
     */
    public void restoreWindowStates(String ruleId, int version, List<WindowState> states) {
        engine.restoreStates(ruleId, version, states);
    }

    /** 全部历史规则版本（快照用）。 */
    public List<CorrelationRule> allRules() {
        return store.allRules();
    }

    /** 全部告警（快照用）。 */
    public List<Alert> allAlerts() {
        return store.listAlerts();
    }

    /** 投递去重键快照。 */
    public Set<String> dedupKeySnapshot() {
        return new HashSet<>(store.deduplicator().snapshotKeys());
    }

    /**
     * 以参考时间（停机墙钟上界）安全回收全部历史版本里不可能再影响判定的固定窗口。
     * 真正的回收判定以各实体自己的事件时间 watermark 为准（参考时间只作上界），
     * 所以停机前空闲一段再回收，仍可能收到迟到容忍内事件的窗口不会被带走；
     * 回收与不回收对后续事件判定结论一致，不影响统计与告警。
     *
     * @return 被回收的窗口数
     */
    public int compactHistory(long referenceTime) {
        return engine.compact(referenceTime);
    }

    /** 遍历所有（规则版本, 实体）窗口态（快照用）。 */
    public List<WindowState> allWindowStates() {
        List<WindowState> all = new ArrayList<>();
        for (CorrelationRule rule : store.allRules()) {
            engine.statesOfVersion(rule.ruleId(), rule.version())
                    .ifPresent(byEntity -> all.addAll(byEntity.values()));
        }
        return all;
    }

    /** 测试辅助：查询某规则版本某实体的窗口态。 */
    public java.util.Optional<WindowState> findWindowStateForTest(String ruleId, int version,
                                                                  String entityId) {
        return engine.findState(ruleId, version, entityId);
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
}
