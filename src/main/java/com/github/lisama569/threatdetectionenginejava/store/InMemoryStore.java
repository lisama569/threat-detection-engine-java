package com.github.lisama569.threatdetectionenginejava.store;

import com.github.lisama569.threatdetectionenginejava.dedup.DeliveryDeduplicator;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 本地内存态（模拟进程持久层）：规则、告警、去重键、守恒计数器、实体锁。
 *
 * 并发策略：
 * <ul>
 *   <li>计数器全部使用原子类型；</li>
 *   <li>同一实体的窗口判定通过分段锁串行化，不同实体互不阻塞；</li>
 *   <li>规则保留全部历史版本，latest* 视图供在线判定，指定版本查询供重放核对。</li>
 * </ul>
 */
public class InMemoryStore {

    private static final int LOCK_STRIPES = 64;

    private final DeliveryDeduplicator deduplicator;

    /** ruleId -> (version -> rule) */
    private final ConcurrentMap<String, TreeMap<Integer, CorrelationRule>> ruleHistory =
            new ConcurrentHashMap<>();

    private final ConcurrentMap<String, Alert> alerts = new ConcurrentHashMap<>();

    private final AtomicLong total = new AtomicLong();
    private final AtomicLong rejected = new AtomicLong();
    private final AtomicLong duplicate = new AtomicLong();
    private final AtomicLong tooLate = new AtomicLong();
    private final AtomicLong acceptedNoAlert = new AtomicLong();
    private final AtomicLong acceptedAlert = new AtomicLong();
    private final ConcurrentMap<RejectReason, AtomicLong> rejectionBreakdown =
            new ConcurrentHashMap<>();

    private final Lock[] entityLocks;

    public InMemoryStore() {
        this(new DeliveryDeduplicator());
    }

    public InMemoryStore(DeliveryDeduplicator deduplicator) {
        this.deduplicator = deduplicator;
        this.entityLocks = new Lock[LOCK_STRIPES];
        for (int i = 0; i < LOCK_STRIPES; i++) {
            this.entityLocks[i] = new ReentrantLock();
        }
    }

    public DeliveryDeduplicator deduplicator() {
        return deduplicator;
    }

    // ---- 规则（版本化保留全部版本） ----
    public void saveRule(CorrelationRule rule) {
        ruleHistory.computeIfAbsent(rule.ruleId(), k -> new TreeMap<>())
                .put(rule.version(), rule);
    }

    public Optional<CorrelationRule> latestRule(String ruleId) {
        TreeMap<Integer, CorrelationRule> versions = ruleHistory.get(ruleId);
        return versions == null || versions.isEmpty()
                ? Optional.empty()
                : Optional.of(versions.lastEntry().getValue());
    }

    public List<CorrelationRule> latestRules() {
        List<CorrelationRule> result = new ArrayList<>();
        for (TreeMap<Integer, CorrelationRule> versions : ruleHistory.values()) {
            if (!versions.isEmpty()) {
                result.add(versions.lastEntry().getValue());
            }
        }
        return result;
    }

    public Optional<CorrelationRule> ruleVersion(String ruleId, int version) {
        TreeMap<Integer, CorrelationRule> versions = ruleHistory.get(ruleId);
        return versions == null ? Optional.empty() : Optional.ofNullable(versions.get(version));
    }

    // ---- 告警 ----
    public void saveAlert(Alert alert) {
        alerts.put(alert.getAlertId(), alert);
    }

    public Optional<Alert> findAlert(String alertId) {
        return Optional.ofNullable(alerts.get(alertId));
    }

    public List<Alert> listAlerts() {
        return new ArrayList<>(alerts.values());
    }

    // ---- 守恒计数 ----
    public void increment(IngestOutcome outcome) {
        total.incrementAndGet();
        switch (outcome) {
            case REJECTED -> rejected.incrementAndGet();
            case DUPLICATE -> duplicate.incrementAndGet();
            case TOO_LATE -> tooLate.incrementAndGet();
            case ACCEPTED_NO_ALERT -> acceptedNoAlert.incrementAndGet();
            case ACCEPTED_ALERT -> acceptedAlert.incrementAndGet();
        }
    }

    public void incrementRejected(RejectReason reason) {
        rejectionBreakdown.computeIfAbsent(reason, r -> new AtomicLong()).incrementAndGet();
    }

    public IngestStats stats() {
        return new IngestStats(total.get(), rejected.get(), duplicate.get(), tooLate.get(),
                acceptedNoAlert.get(), acceptedAlert.get());
    }

    public Map<String, Long> rejectionBreakdown() {
        Map<String, Long> result = new java.util.HashMap<>();
        rejectionBreakdown.forEach((reason, count) -> result.put(reason.name(), count.get()));
        return result;
    }

    /** 对同一实体的判定串行化（分段锁，避免全局锁瓶颈）。 */
    public Lock entityLock(String entityId) {
        int index = Math.floorMod(entityId.hashCode(), LOCK_STRIPES);
        return entityLocks[index];
    }
}
