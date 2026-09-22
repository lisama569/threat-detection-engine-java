package com.github.lisama569.threatdetectionenginejava.rule;

import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 关联规则注册表。
 * <p>
 * 每个 ruleId 维护一条不可变的版本链；新版本号必须严格大于当前版本，否则拒绝。
 * 历史版本全部保留，使“同批事件 + 同一规则版本”的重放结论可复现。
 */
@Component
public class RuleRegistry {

    private final Map<String, NavigableMap<Integer, CorrelationRule>> versions = new ConcurrentHashMap<>();
    private final ReentrantLock putLock = new ReentrantLock();

    /**
     * 登记规则版本。
     *
     * @return 已登记的规则
     * @throws IllegalArgumentException 版本号不大于当前版本，或规则内容非法
     */
    public CorrelationRule put(CorrelationRule rule) {
        validate(rule);
        putLock.lock();
        try {
            NavigableMap<Integer, CorrelationRule> chain =
                    versions.computeIfAbsent(rule.ruleId(), k -> new TreeMap<>());
            Map.Entry<Integer, CorrelationRule> latest = chain.lastEntry();
            if (latest != null && rule.version() <= latest.getKey()) {
                throw new IllegalArgumentException(
                        "rule version must strictly increase: ruleId=" + rule.ruleId()
                                + ", given=" + rule.version() + ", current=" + latest.getKey());
            }
            chain.put(rule.version(), rule);
            return rule;
        } finally {
            putLock.unlock();
        }
    }

    private void validate(CorrelationRule rule) {
        if (rule == null || rule.ruleId() == null || rule.ruleId().isBlank()) {
            throw new IllegalArgumentException("ruleId must not be blank");
        }
        if (rule.version() < 1) {
            throw new IllegalArgumentException("rule version must be >= 1: " + rule.version());
        }
        if (rule.eventTypes() == null || rule.eventTypes().isEmpty()) {
            throw new IllegalArgumentException("rule must subscribe to at least one event type");
        }
        if (rule.threshold() < 1) {
            throw new IllegalArgumentException("threshold must be >= 1: " + rule.threshold());
        }
        if (rule.windowSizeMs() <= 0) {
            throw new IllegalArgumentException("windowSizeMs must be positive");
        }
        if (rule.allowedLatenessMs() < 0) {
            throw new IllegalArgumentException("allowedLatenessMs must be >= 0");
        }
    }

    public Optional<CorrelationRule> current(String ruleId) {
        NavigableMap<Integer, CorrelationRule> chain = versions.get(ruleId);
        if (chain == null) {
            return Optional.empty();
        }
        synchronized (chain) {
            Map.Entry<Integer, CorrelationRule> last = chain.lastEntry();
            return last == null ? Optional.empty() : Optional.of(last.getValue());
        }
    }

    public Optional<CorrelationRule> getVersion(String ruleId, int version) {
        NavigableMap<Integer, CorrelationRule> chain = versions.get(ruleId);
        return chain == null ? Optional.empty() : Optional.ofNullable(chain.get(version));
    }

    public List<CorrelationRule> currentRules() {
        List<CorrelationRule> snapshot = new ArrayList<>();
        for (NavigableMap<Integer, CorrelationRule> chain : versions.values()) {
            synchronized (chain) {
                Map.Entry<Integer, CorrelationRule> last = chain.lastEntry();
                if (last != null) {
                    snapshot.add(last.getValue());
                }
            }
        }
        snapshot.sort(Comparator.comparing(CorrelationRule::ruleId));
        return List.copyOf(snapshot);
    }
}
