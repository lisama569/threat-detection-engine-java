package com.github.lisama569.threatdetectionenginejava.alert;

import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;

/** 非法告警状态迁移，携带 from/to 以便区分拒绝原因。 */
public class InvalidAlertTransitionException extends RuntimeException {

    private final AlertStatus from;
    private final AlertStatus to;

    public InvalidAlertTransitionException(AlertStatus from, AlertStatus to, String message) {
        super(message);
        this.from = from;
        this.to = to;
    }

    public AlertStatus getFrom() { return from; }
    public AlertStatus getTo() { return to; }
}
