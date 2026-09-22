package com.github.lisama569.threatdetectionenginejava.alert;

import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.TransitionReject;
import com.github.lisama569.threatdetectionenginejava.model.TransitionResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 告警存储与生命周期状态迁移管理。
 * <p>
 * 合法迁移：OPEN -&gt; ACKNOWLEDGED、OPEN -&gt; RESOLVED、ACKNOWLEDGED -&gt; RESOLVED。
 * 其余迁移（含回退、从 RESOLVED 再迁移）被拒绝，原因可区分为
 * ALERT_NOT_FOUND / ALREADY_IN_TARGET_STATUS / ILLEGAL_TRANSITION。
 */
@Component
public class AlertLifecycleManager {

    private static final Logger log = LoggerFactory.getLogger(AlertLifecycleManager.class);

    private static final Map<AlertStatus, Set<AlertStatus>> ALLOWED;

    static {
        ALLOWED = new EnumMap<>(AlertStatus.class);
        ALLOWED.put(AlertStatus.OPEN, Set.of(AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED));
        ALLOWED.put(AlertStatus.ACKNOWLEDGED, Set.of(AlertStatus.RESOLVED));
        ALLOWED.put(AlertStatus.RESOLVED, Set.of());
    }

    private final Map<String, Alert> alerts = new ConcurrentHashMap<>();

    /**
     * 幂等登记：同一 alertId 只创建一次。
     */
    public RegisterOutcome registerIfAbsent(Alert alert) {
        Alert existing = alerts.putIfAbsent(alert.alertId(), alert);
        if (existing != null) {
            log.info("alert already exists, suppress duplicate: alertId={}", alert.alertId());
            return new RegisterOutcome(existing, false);
        }
        log.info("alert raised: alertId={} rule={}#v{} entity={} window=[{},{}) count={}/{}",
                alert.alertId(), alert.ruleId(), alert.ruleVersion(), alert.entityId(),
                alert.windowStartMs(), alert.windowEndMs(), alert.eventCount(), alert.status());
        return new RegisterOutcome(alert, true);
    }

    public Optional<Alert> get(String alertId) {
        return Optional.ofNullable(alerts.get(alertId));
    }

    public List<Alert> listByEntity(String entityId) {
        return alerts.values().stream()
                .filter(a -> a.entityId().equals(entityId))
                .toList();
    }

    public List<Alert> all() {
        return alerts.values().stream()
                .sorted(java.util.Comparator.comparingLong(Alert::createdAtMs)
                        .thenComparing(Alert::alertId))
                .toList();
    }

    /**
     * 校验并执行状态迁移。并发下对单个告警加锁，避免丢失/覆盖迁移。
     */
    public TransitionResult transition(String alertId, AlertStatus target) {
        Alert alert = alerts.get(alertId);
        if (alert == null) {
            return TransitionRejects.deny(TransitionReject.ALERT_NOT_FOUND,
                    "alert not found: " + alertId, null);
        }
        synchronized (alert) {
            Alert current = alerts.get(alertId);
            if (current.status() == target) {
                return TransitionRejects.deny(TransitionReject.ALREADY_IN_TARGET_STATUS,
                        "alert " + alertId + " is already " + target, current);
            }
            if (!ALLOWED.getOrDefault(current.status(), Set.of()).contains(target)) {
                return TransitionRejects.deny(TransitionReject.ILLEGAL_TRANSITION,
                        "illegal transition " + current.status() + " -> " + target
                                + " for alert " + alertId, current);
            }
            Alert moved = new Alert(
                    current.alertId(), current.ruleId(), current.ruleVersion(),
                    current.entityId(), current.windowStartMs(), current.windowEndMs(),
                    current.eventCount(), current.firstEventTimeMs(), current.lastEventTimeMs(),
                    current.createdAtMs(), target);
            alerts.put(alertId, moved);
            log.info("alert transition: alertId={} {} -> {}", alertId, current.status(), target);
            return new TransitionResult(true, null, "transitioned to " + target, moved);
        }
    }

    public record RegisterOutcome(Alert alert, boolean created) {
    }

    private static final class TransitionRejects {
        static TransitionResult deny(TransitionReject reason, String message, Alert alert) {
            log.warn("alert transition rejected: reason={} message={}", reason, message);
            return new TransitionResult(false, reason, message, alert);
        }
    }
}
