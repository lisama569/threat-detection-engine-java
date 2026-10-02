package com.github.lisama569.threatdetectionenginejava.persistence;

import com.github.lisama569.threatdetectionenginejava.detection.WindowState;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.store.IngestStats;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.time.Clock;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * 重启续跑协调器：启动时从 {@link LocalStateStore} 恢复到 {@link DetectionService}，
 * 优雅停机时把当前内存态快照（含安全回收）原子落盘。
 *
 * <p>恢复边界：{@link #initialize()} 完成前服务处于 {@link RecoveryPhase#RECOVERING}，
 * 摄入/迁移请求被拒绝（HTTP 503），不会被当成空实例处理、也不会在恢复后被重复计算；
 * 状态损坏且 {@code allowFreshOnCorrupt=false} 时进入 {@link RecoveryPhase#FAILED}。</p>
 *
 * <p>状态缺失（首次启动）与状态损坏是两种可区分结论：前者 FRESH 放行，后者默认不放行。</p>
 */
public class StateRecoveryCoordinator {

    private static final Logger log = LoggerFactory.getLogger(StateRecoveryCoordinator.class);

    private final DetectionService service;
    private final LocalStateStore stateStore;
    private final StateCodec codec;
    private final Clock clock;
    private final boolean allowFreshOnCorrupt;

    private volatile RecoveryPhase phase = RecoveryPhase.RECOVERING;
    private volatile RecoveryReport report;
    private volatile long generation = 0L;
    private volatile boolean initialized = false;
    private volatile boolean enabled = true;
    /** 损坏时是否直接让启动失败（默认 false：留在 FAILED 在线拒绝写入，保证统计/恢复结论可见）。 */
    private volatile boolean failFastOnCorrupt = false;

    public StateRecoveryCoordinator(DetectionService service, LocalStateStore stateStore,
                                    StateCodec codec, Clock clock, boolean allowFreshOnCorrupt) {
        this.service = service;
        this.stateStore = stateStore;
        this.codec = codec;
        this.clock = clock;
        this.allowFreshOnCorrupt = allowFreshOnCorrupt;
        // 一旦装配了协调器，默认把门关起来：在 initialize() 显式放行前不接受写入
        service.markRecovering();
    }

    /** 是否启用本地重启续跑（engine.state.enabled）。禁用时跳过读写，等价于原纯内存行为。 */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** 损坏时是否直接终止启动（engine.state.fail-fast-on-corrupt，默认 false）。 */
    public void setFailFastOnCorrupt(boolean failFastOnCorrupt) {
        this.failFastOnCorrupt = failFastOnCorrupt;
    }

    /**
     * 启动恢复：幂等，只有第一次调用真正执行。
     * 建议放在 Spring bean 的 @PostConstruct（Web 端口对外服务之前完成）。
     */
    @PostConstruct
    public synchronized RecoveryReport initialize() {
        if (initialized) {
            return report;
        }
        initialized = true;
        String stateFile = stateStore.getStateFile().toString();

        if (!enabled) {
            service.markActive();
            phase = RecoveryPhase.ACTIVE;
            report = RecoveryReport.disabled("engine.state.enabled=false，本地重启续跑已禁用，按纯内存实例启动");
            log.warn("[RECOVERY] status=DISABLED, detail={}", report.detail());
            return report;
        }

        if (!stateStore.exists()) {
            // 状态缺失 = 首次启动：可区分于“损坏”，明确记录为 FRESH 后放行
            service.markActive();
            phase = RecoveryPhase.ACTIVE;
            report = RecoveryReport.fresh("未发现本地状态文件 " + stateFile + "，按全新实例启动");
            log.warn("[RECOVERY] status=FRESH, detail={}", report.detail());
            return report;
        }

        String json;
        StateCodec.Envelope envelope;
        try {
            json = stateStore.read();
            envelope = codec.decode(json);
        } catch (CorruptStateException e) {
            return handleCorrupt(stateFile, e);
        } catch (RuntimeException e) {
            return handleCorrupt(stateFile,
                    new CorruptStateException(stateFile, "读取/解析状态失败: " + e.getMessage(), e));
        }

        try {
            apply(envelope.state());
        } catch (CorruptStateException e) {
            return handleCorrupt(stateFile, e);
        } catch (RuntimeException e) {
            return handleCorrupt(stateFile,
                    new CorruptStateException(stateFile, "恢复状态失败: " + e.getMessage(), e));
        }

        generation = envelope.generation();
        int retained = countWindows(envelope.state());
        service.markActive();
        phase = RecoveryPhase.ACTIVE;
        report = new RecoveryReport(RecoveryPhase.ACTIVE, "RESTORED",
                "已从 " + stateFile + " 恢复（代数=" + generation + "）",
                envelope.state().alerts().size(),
                countWindowStates(envelope.state()),
                envelope.state().dedupKeys().size(),
                envelope.state().rules().size(),
                retained, generation);
        log.warn("[RECOVERY] status=RESTORED, file={}, generation={}, rules={}, alerts={}, "
                        + "windowStates={}, retainedWindows={}, dedupKeys={}, stats={}",
                stateFile, generation, report.restoredRules(), report.restoredAlerts(),
                report.restoredWindowStates(), retained, report.restoredDedupKeys(),
                envelope.state().stats());
        return report;
    }

    private RecoveryReport handleCorrupt(String stateFile, CorruptStateException cause) {
        log.error("[RECOVERY] status=CORRUPT, file={}, detail={}", stateFile, cause.getMessage());
        if (allowFreshOnCorrupt) {
            stateStore.clear();
            service.markActive();
            phase = RecoveryPhase.ACTIVE;
            report = new RecoveryReport(RecoveryPhase.ACTIVE, "CORRUPT",
                    "本地状态损坏但配置允许丢弃，已清空并全新启动: " + cause.getMessage(),
                    0, 0, 0, 0, 0, 0L);
            log.error("[RECOVERY] allowFreshOnCorrupt=true，已清空损坏状态，按全新实例启动");
            return report;
        }
        service.markFailed();
        phase = RecoveryPhase.FAILED;
        report = new RecoveryReport(RecoveryPhase.FAILED, "CORRUPT",
                "本地状态损坏，拒绝静默全新启动: " + cause.getMessage(),
                0, 0, 0, 0, 0, 0L);
        if (failFastOnCorrupt) {
            // 显式要求快速失败：阻止进程继续启动（由编排层/容器处理重启）
            throw new RecoveryFailedException(report.detail(), cause);
        }
        // 默认：进程保持运行但停在 FAILED，写入一律 503，读接口与恢复结论仍可观测，不吞日志
        log.error("[RECOVERY] 实例保持 FAILED 在线拒绝写入；读接口仍可查看恢复结论与统计");
        return report;
    }

    private void apply(StateCodec.StateSnapshot s) {
        // 1) 规则（全部历史版本先恢复，窗口恢复需要按版本规则校验/隔离）
        List<CorrelationRule> rules = new ArrayList<>();
        for (StateCodec.RuleData r : s.rules()) {
            rules.add(new CorrelationRule(r.ruleId(), r.version(), r.eventTypes(),
                    r.entityScope(), r.windowMillis(), r.threshold(), r.lateToleranceMillis()));
        }
        service.restoreRules(rules);

        // 2) 告警（含处置状态、备注、时间）
        List<Alert> alerts = new ArrayList<>();
        for (StateCodec.AlertData a : s.alerts()) {
            AlertStatus status;
            try {
                status = AlertStatus.valueOf(a.status());
            } catch (IllegalArgumentException e) {
                throw new CorruptStateException(stateStore.getStateFile().toString(),
                        "告警状态非法: " + a.status() + ", alertId=" + a.alertId());
            }
            Alert alert = new Alert(a.alertId(), a.ruleId(), a.ruleVersion(), a.entityId(),
                    a.createdAt(), a.triggerEventTime(), a.triggerCount(), status,
                    a.statusUpdatedAt(), a.resolutionNote());
            alerts.add(alert);
        }
        service.restoreAlerts(alerts);

        // 3) 投递去重键
        service.restoreDedupKeys(Set.copyOf(s.dedupKeys()));

        // 4) 各规则版本的窗口态（版本隔离恢复）
        int stateCount = 0;
        for (StateCodec.RuleVersionWindows rv : s.windows()) {
            List<WindowState> states = new ArrayList<>();
            for (StateCodec.EntityWindows ew : rv.entities()) {
                List<WindowState.PersistedWindow> pws = new ArrayList<>();
                for (StateCodec.WindowData w : ew.windows()) {
                    pws.add(new WindowState.PersistedWindow(w.windowStart(), w.eventIds(), w.alerted()));
                }
                if (ew.watermark() < 0) {
                    throw new CorruptStateException(stateStore.getStateFile().toString(),
                            "watermark 非法: " + ew.watermark());
                }
                states.add(WindowState.restore(rv.ruleId(), rv.version(), ew.entityId(),
                        ew.windowMillis(), ew.watermark(), pws));
                stateCount++;
            }
            service.restoreWindowStates(rv.ruleId(), rv.version(), states);
        }

        // 5) 守恒计数 + 拒绝原因分布
        StateCodec.StatsData st = s.stats();
        IngestStats restoredStats = new IngestStats(st.total(), st.rejected(), st.duplicate(),
                st.tooLate(), st.acceptedNoAlert(), st.acceptedAlert());
        Map<RejectReason, Long> breakdown = new EnumMap<>(RejectReason.class);
        for (Map.Entry<String, Long> e : s.rejectionBreakdown().entrySet()) {
            try {
                breakdown.put(RejectReason.valueOf(e.getKey()), e.getValue());
            } catch (IllegalArgumentException ex) {
                throw new CorruptStateException(stateStore.getStateFile().toString(),
                        "拒绝原因枚举非法: " + e.getKey());
            }
        }
        service.restoreStats(restoredStats, breakdown);
        log.info("[RECOVERY] 恢复明细: {} 条实体窗口态，{} 个仍存活固定窗口", stateCount, countWindows(s));
    }

    /**
     * 把当前内存态（已回收历史部分）原子落盘。
     * 参考时间取 max(当前时钟, 各实体 watermark) 作为“墙钟上界”传入；真正的回收由
     * WindowState 按各实体自身的事件时间 watermark 收敛（min(参考时间, watermark)），
     * 因此时钟回拨不会多收窗口，停机前空闲（墙钟领先 watermark）也不会误收仍在迟到
     * 容忍内的窗口。
     */
    public synchronized void snapshot() {
        if (!enabled) {
            log.debug("[RECOVERY] 持久化已禁用，跳过落盘");
            return;
        }
        if (phase == RecoveryPhase.FAILED) {
            log.warn("[RECOVERY] 当前为 FAILED，跳过落盘以免覆盖损坏状态");
            return;
        }
        long referenceTime = Math.max(clock.millis(), maxWatermark());
        int reclaimed = service.compactHistory(referenceTime);

        List<StateCodec.RuleData> ruleData = new ArrayList<>();
        for (CorrelationRule r : service.allRules()) {
            ruleData.add(new StateCodec.RuleData(r.ruleId(), r.version(), r.eventTypes(),
                    r.entityScope(), r.windowMillis(), r.threshold(), r.lateToleranceMillis()));
        }
        List<StateCodec.AlertData> alertData = new ArrayList<>();
        for (Alert a : service.allAlerts()) {
            alertData.add(new StateCodec.AlertData(a.getAlertId(), a.getRuleId(),
                    a.getRuleVersion(), a.getEntityId(), a.getCreatedAt(), a.getTriggerEventTime(),
                    a.getTriggerCount(), a.getStatus().name(), a.getStatusUpdatedAt(),
                    a.getResolutionNote()));
        }

        // 按 ruleId#version 聚合窗口态
        Map<String, StateCodec.RuleVersionWindows> byVersion = new TreeMap<>();
        int retainedWindows = 0;
        for (WindowState ws : service.allWindowStates()) {
            String key = ws.getRuleId() + "#v" + ws.getRuleVersion();
            StateCodec.RuleVersionWindows rv =
                    byVersion.computeIfAbsent(key, k -> new StateCodec.RuleVersionWindows(
                            ws.getRuleId(), ws.getRuleVersion(), new ArrayList<>()));
            List<WindowState.PersistedWindow> pws = ws.exportWindows();
            retainedWindows += pws.size();
            long wm = ws.rawWatermark() == Long.MIN_VALUE ? 0L : ws.rawWatermark();
            rv.entities().add(new StateCodec.EntityWindows(ws.getEntityId(),
                    ws.getWindowMillis(), wm,
                    pws.stream().map(p -> new StateCodec.WindowData(p.windowStart(), p.eventIds(), p.alerted()))
                            .toList()));
        }

        IngestStats stats = service.stats();
        Map<String, Long> breakdown = new TreeMap<>(service.rejectionBreakdown());
        StateCodec.StateSnapshot snapshotState = new StateCodec.StateSnapshot(
                ruleData, alertData, List.copyOf(service.dedupKeySnapshot()),
                List.copyOf(byVersion.values()),
                new StateCodec.StatsData(stats.total(), stats.rejected(), stats.duplicate(),
                        stats.tooLate(), stats.acceptedNoAlert(), stats.acceptedAlert()),
                breakdown);

        long nextGeneration = generation + 1;
        String json = codec.encode(snapshotState, nextGeneration);
        stateStore.writeAtomic(json);
        generation = nextGeneration;
        log.warn("[RECOVERY] 状态已落盘代数={}, 本次回收固定窗口={}, 保留窗口={}, 告警={}, 去重键={}",
                generation, reclaimed, retainedWindows, alertData.size(),
                snapshotState.dedupKeys().size());
    }

    private long maxWatermark() {
        long max = 0L;
        for (WindowState ws : service.allWindowStates()) {
            if (ws.rawWatermark() != Long.MIN_VALUE && ws.rawWatermark() > max) {
                max = ws.rawWatermark();
            }
        }
        return max;
    }

    /** 优雅停机钩子：只在正常 ACTIVE 阶段落盘，恢复失败绝不覆盖现场。 */
    @PreDestroy
    public void shutdown() {
        if (phase == RecoveryPhase.ACTIVE) {
            try {
                snapshot();
            } catch (RuntimeException e) {
                log.error("[RECOVERY] 停机落盘失败: {}", e.getMessage(), e);
            }
        } else {
            log.warn("[RECOVERY] phase={}，停机不落盘", phase);
        }
    }

    public RecoveryPhase phase() {
        return phase;
    }

    public RecoveryReport report() {
        return report;
    }

    public long generation() {
        return generation;
    }

    private static int countWindowStates(StateCodec.StateSnapshot s) {
        int n = 0;
        for (StateCodec.RuleVersionWindows rv : s.windows()) {
            n += rv.entities().size();
        }
        return n;
    }

    private static int countWindows(StateCodec.StateSnapshot s) {
        int n = 0;
        for (StateCodec.RuleVersionWindows rv : s.windows()) {
            for (StateCodec.EntityWindows ew : rv.entities()) {
                n += ew.windows().size();
            }
        }
        return n;
    }
}
