package com.github.lisama569.threatdetectionenginejava.alert;

import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;

import java.time.Clock;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/** 告警生命周期：创建与状态迁移校验。非法迁移抛 {@link InvalidAlertTransitionException}。 */
public class AlertLifecycleService {

    private static final Map<AlertStatus, Set<AlertStatus>> ALLOWED = new EnumMap<>(AlertStatus.class);

    static {
        ALLOWED.put(AlertStatus.OPEN,
                EnumSet.of(AlertStatus.ACKNOWLEDGED, AlertStatus.SUPPRESSED, AlertStatus.RESOLVED));
        ALLOWED.put(AlertStatus.ACKNOWLEDGED,
                EnumSet.of(AlertStatus.RESOLVED, AlertStatus.SUPPRESSED));
        ALLOWED.put(AlertStatus.SUPPRESSED,
                EnumSet.of(AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED));
        ALLOWED.put(AlertStatus.RESOLVED, EnumSet.noneOf(AlertStatus.class));
    }

    private static final Set<AlertStatus> TERMINAL = Set.of(AlertStatus.RESOLVED);

    private final Clock clock;

    public AlertLifecycleService(Clock clock) {
        this.clock = clock;
    }

    public Alert open(String alertId, String ruleId, int ruleVersion, String entityId,
                      long triggerEventTime, int triggerCount) {
        long now = clock.millis();
        return new Alert(alertId, ruleId, ruleVersion, entityId, now, triggerEventTime,
                triggerCount, AlertStatus.OPEN, now, null);
    }

    /** 校验并执行迁移；同状态重复迁移也视为非法（区分于合法迁移）。 */
    public Alert transition(Alert alert, AlertStatus to, String note) {
        if (alert == null) {
            throw new InvalidAlertTransitionException(null, to, "告警不存在");
        }
        AlertStatus from = alert.getStatus();
        if (to == null) {
            throw new InvalidAlertTransitionException(from, null, "目标状态不能为空");
        }
        if (from == to) {
            throw new InvalidAlertTransitionException(from, to,
                    "重复迁移被拒绝: 告警 " + alert.getAlertId() + " 已处于 " + from);
        }
        if (!isLegal(from, to)) {
            throw new InvalidAlertTransitionException(from, to,
                    "非法状态迁移被拒绝: alertId=" + alert.getAlertId() + ", " + from + " -> " + to
                            + (isTerminal(from) ? "（" + from + " 为终态）" : ""));
        }
        alert.setStatus(to);
        alert.setStatusUpdatedAt(clock.millis());
        if (note != null) {
            alert.setResolutionNote(note);
        }
        return alert;
    }

    public boolean isLegal(AlertStatus from, AlertStatus to) {
        return from != null && to != null && ALLOWED.getOrDefault(from, Set.of()).contains(to);
    }

    public boolean isTerminal(AlertStatus status) {
        return TERMINAL.contains(status);
    }
}
