package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 告警状态迁移被拒绝的可区分原因。
 */
public enum TransitionReject {
    ALERT_NOT_FOUND,
    ILLEGAL_TRANSITION,
    ALREADY_IN_TARGET_STATUS
}
