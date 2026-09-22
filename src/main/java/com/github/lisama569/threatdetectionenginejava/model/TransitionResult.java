package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 告警状态迁移结果。
 */
public record TransitionResult(
        boolean accepted,
        TransitionReject rejectReason,
        String message,
        Alert alert
) {
}
