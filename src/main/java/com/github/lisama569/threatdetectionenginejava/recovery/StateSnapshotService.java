package com.github.lisama569.threatdetectionenginejava.recovery;

import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.persistence.AlertMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.RuleMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.SourceMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.StateMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.StatsMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.WindowMemento;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 在线内存态 &lt;-&gt; 持久化备忘录 的双向映射（捕获快照 / 应用快照恢复）。
 *
 * <p>捕获的状态面：来源描述符、全部历史规则版本、未驱逐窗口（watermark+计数+去重指纹+已告警）、
 * 投递去重键、告警（含处置状态）、守恒统计与拒绝原因分布。</p>
 *
 * <p>恢复顺序经过设计，保证版本不串、窗口不悬空：</p>
 * <ol>
 *   <li>来源 -> 统计 -> 去重键 -> 告警（与判定无关，先放好）；</li>
 *   <li>规则：按 ruleId 分组、版本号升序逐条部署，使每个 {@code ruleId#version}
 *       （含已被更新版本取代的旧版本）都拥有独立窗口槽位；</li>
 *   <li>窗口：按备忘录回填到各自的版本槽位，旧版本窗口绝不会被新版本读到。</li>
 * </ol>
 */
public class StateSnapshotService {

    private static final Logger log = LoggerFactory.getLogger(StateSnapshotService.class);

    private final Clock clock;

    public StateSnapshotService(Clock clock) {
        this.clock = clock;
    }

    /** 从在线组件捕获一份快照。调用方须保证捕获期间无摄入写操作（停机或恢复闸门下）。 */
    public StateMemento capture(InMemoryStore store, CorrelationEngine engine,
                               SourceRegistry registry) {
        List<SourceMemento> sources = registry.list().stream()
                .map(StateSnapshotService::toSourceMemento)
                .toList();
        List<RuleMemento> rules = store.exportRules().stream()
                .map(StateSnapshotService::toRuleMemento)
                .toList();
        List<WindowMemento> windows = engine.exportWindows();
        List<String> dedupKeys = List.copyOf(store.exportDedupKeys());
        List<AlertMemento> alerts = store.exportAlerts();
        StatsMemento stats = store.exportStats();
        return new StateMemento(StateMemento.FORMAT_VERSION, clock.millis(), sources, rules,
                windows, dedupKeys, alerts, stats);
    }

    /**
     * 把快照应用回空的在线组件（仅允许在启动恢复阶段调用一次）。
     *
     * @return 恢复内容摘要（来源/规则/窗口/键/告警/统计计数），供日志与恢复状态展示
     */
    public String restore(StateMemento memento, InMemoryStore store, CorrelationEngine engine,
                         SourceRegistry registry) {
        for (SourceMemento s : memento.sources()) {
            registry.restore(fromSourceMemento(s));
        }
        store.restoreStats(memento.stats());
        store.restoreDedupKeys(new HashSet<>(memento.dedupKeys()));
        for (AlertMemento a : memento.alerts()) {
            store.restoreAlert(a);
        }

        // 规则按 (ruleId, version) 升序部署：保证旧版本槽位先建，且不触发“版本必须递增”之外的冲突
        List<RuleMemento> orderedRules = memento.rules().stream()
                .sorted(java.util.Comparator.comparing(RuleMemento::ruleId)
                        .thenComparingInt(RuleMemento::version))
                .toList();
        Set<String> deployedRuleKeys = new HashSet<>();
        for (RuleMemento r : orderedRules) {
            CorrelationRule rule = fromRuleMemento(r);
            // deployRule 要求同 ruleId 版本严格递增；同版本备忘录不应重复出现
            engine.deployRule(rule);
            store.restoreRule(rule);
            deployedRuleKeys.add(r.ruleId() + "#v" + r.version());
        }

        engine.importWindows(memento.windows());

        long windows = memento.windows().size();
        long liveEvents = memento.windows().stream()
                .mapToLong(w -> w.windows().stream().mapToLong(fw -> fw.events().size()).sum())
                .sum();
        String summary = String.format(
                "恢复来源 %d、规则版本 %d、窗口状态 %d（存活事件指纹 %d）、去重键 %d、告警 %d；stats=%s",
                memento.sources().size(), memento.rules().size(), windows, liveEvents,
                memento.dedupKeys().size(), memento.alerts().size(), memento.stats());
        log.info("[RECOVERY] {}", summary);
        return summary;
    }

    private static SourceMemento toSourceMemento(SourceDescriptor d) {
        return new SourceMemento(d.sourceId(), d.entityKeys(), d.typeKeys(), d.timeKeys(),
                d.severityKeys(), d.allowedSeverities(), d.fixedType());
    }

    private static SourceDescriptor fromSourceMemento(SourceMemento m) {
        return new SourceDescriptor(m.sourceId(), m.entityKeys(), m.typeKeys(), m.timeKeys(),
                m.severityKeys(), m.allowedSeverities(), m.fixedType());
    }

    private static RuleMemento toRuleMemento(CorrelationRule r) {
        return new RuleMemento(r.ruleId(), r.version(), r.eventTypes(), r.entityScope(),
                r.windowMillis(), r.threshold(), r.lateToleranceMillis());
    }

    private static CorrelationRule fromRuleMemento(RuleMemento m) {
        return new CorrelationRule(m.ruleId(), m.version(), m.eventTypes(), m.entityScope(),
                m.windowMillis(), m.threshold(), m.lateToleranceMillis());
    }
}
