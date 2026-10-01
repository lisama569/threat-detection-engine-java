package com.github.lisama569.threatdetectionenginejava.detection;

import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowSnapshot;
import com.github.lisama569.threatdetectionenginejava.persistence.WindowMemento;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * 基于固定窗口的关联检测引擎（纯内存、可独立构造用于重放）。
 *
 * 版本化语义：
 * <ul>
 *   <li>每个 ruleId 仅保留最新部署版本，新事件一律按最新版本判定；</li>
 *   <li>不同版本的窗口状态按 ruleId#version + 实体隔离，互不污染；</li>
 *   <li>重放 = 新引擎 + 固定规则版本集合 + 同批事件（同顺序）=> 可复现结论。</li>
 * </ul>
 *
 * 本类对规则注册表自身线程安全；窗口判定的串行化由上层按实体加锁保证。
 */
public class CorrelationEngine {

    /** ruleId -> 最新规则 */
    private final ConcurrentMap<String, CorrelationRule> latestRules = new ConcurrentHashMap<>();
    /** ruleId#version -> (entityId -> WindowState) */
    private final ConcurrentMap<String, ConcurrentMap<String, WindowState>> windows =
            new ConcurrentHashMap<>();

    public CorrelationEngine() {
    }

    /**
     * 部署规则。同一 ruleId 的新版本必须严格递增，否则拒绝（防止旧版本回灌破坏可复现性）。
     */
    public void deployRule(CorrelationRule rule) {
        validate(rule);
        CorrelationRule existing = latestRules.get(rule.ruleId());
        if (existing != null && rule.version() <= existing.version()) {
            throw new IllegalArgumentException(
                    "规则版本必须严格递增: ruleId=" + rule.ruleId()
                            + ", 已部署=" + existing.version() + ", 提交=" + rule.version());
        }
        latestRules.put(rule.ruleId(), rule);
        windows.putIfAbsent(key(rule.ruleId(), rule.version()), new ConcurrentHashMap<>());
    }

    private static void validate(CorrelationRule rule) {
        if (rule == null || rule.ruleId() == null || rule.ruleId().isBlank()) {
            throw new IllegalArgumentException("ruleId 不能为空");
        }
        if (rule.eventTypes().isEmpty()) {
            throw new IllegalArgumentException("规则至少配置一个事件类型: " + rule.ruleId());
        }
        if (rule.windowMillis() <= 0) {
            throw new IllegalArgumentException("windowMillis 必须为正数: " + rule.ruleId());
        }
        if (rule.threshold() <= 0) {
            throw new IllegalArgumentException("threshold 必须为正数: " + rule.ruleId());
        }
        if (rule.lateToleranceMillis() < 0) {
            throw new IllegalArgumentException("lateToleranceMillis 不能为负: " + rule.ruleId());
        }
    }

    public Optional<CorrelationRule> getRule(String ruleId) {
        return Optional.ofNullable(latestRules.get(ruleId));
    }

    public List<CorrelationRule> listRules() {
        return List.copyOf(latestRules.values());
    }

    /** 对事件在所有适用规则上判定（乱序安全、迟到容忍、内容幂等）。调用方需持有实体锁。 */
    public List<Evaluation> evaluate(SecurityEvent event) {
        List<Evaluation> results = new ArrayList<>();
        for (CorrelationRule rule : latestRules.values()) {
            if (!matches(rule, event)) {
                continue;
            }
            WindowState state = stateFor(rule, event.entityId());
            results.add(state.accept(event, rule.lateToleranceMillis(), rule.threshold()));
        }
        return results;
    }

    private WindowState stateFor(CorrelationRule rule, String entityId) {
        ConcurrentMap<String, WindowState> byEntity =
                windows.computeIfAbsent(key(rule.ruleId(), rule.version()),
                        k -> new ConcurrentHashMap<>());
        return byEntity.computeIfAbsent(entityId,
                e -> new WindowState(rule.ruleId(), rule.version(), entityId, rule.windowMillis()));
    }

    private static boolean matches(CorrelationRule rule, SecurityEvent event) {
        if (!rule.eventTypes().contains(event.eventType())) {
            return false;
        }
        return rule.entityScope().isEmpty() || rule.entityScope().contains(event.entityId());
    }

    private static String key(String ruleId, int version) {
        return ruleId + "#v" + version;
    }

    /** 调试：按规则版本、实体、窗口起点排序的全部窗口快照。 */
    public List<WindowSnapshot> debugWindows() {
        List<WindowSnapshot> all = new ArrayList<>();
        for (ConcurrentMap<String, WindowState> byEntity : windows.values()) {
            for (WindowState state : byEntity.values()) {
                all.addAll(state.snapshots());
            }
        }
        all.sort(java.util.Comparator
                .comparing(WindowSnapshot::ruleId)
                .thenComparingInt(WindowSnapshot::ruleVersion)
                .thenComparing(WindowSnapshot::entityId)
                .thenComparingLong(WindowSnapshot::windowStart));
        return all;
    }

    /** 测试/重放辅助：直接访问某规则版本某实体的窗口状态。 */
    public Optional<WindowState> findState(String ruleId, int version, String entityId) {
        Map<String, WindowState> byEntity = windows.get(key(ruleId, version));
        return byEntity == null ? Optional.empty() : Optional.ofNullable(byEntity.get(entityId));
    }

    /**
     * 导出全部规则版本、全部实体下尚未驱逐的窗口状态（版本按 {@code ruleId#version} 隔离）。
     * 调用方应在无摄入并发时进行（停机快照或恢复闸门下）。
     */
    public List<WindowMemento> exportWindows() {
        List<WindowMemento> result = new ArrayList<>();
        for (ConcurrentMap<String, WindowState> byEntity : windows.values()) {
            for (WindowState state : byEntity.values()) {
                result.add(state.toMemento());
            }
        }
        return result;
    }

    /**
     * 导入窗口状态；要求对应 ruleId#version 的规则槽位已存在（调用方先按版本顺序部署规则）。
     * 不同规则版本的窗口各自回到自己的槽位，旧版本窗口不会被新版本规则读到，互不串用。
     *
     * @throws IllegalStateException 对应规则版本尚未部署
     */
    public void importWindows(List<WindowMemento> mementos) {
        if (mementos == null) {
            return;
        }
        for (WindowMemento m : mementos) {
            ConcurrentMap<String, WindowState> byEntity = windows.get(key(m.ruleId(), m.ruleVersion()));
            if (byEntity == null) {
                throw new IllegalStateException(
                        "恢复窗口状态时缺少对应规则版本槽位: " + key(m.ruleId(), m.ruleVersion())
                                + "，应先恢复该版本规则");
            }
            byEntity.put(m.entityId(), WindowState.fromMemento(m));
        }
    }
}
