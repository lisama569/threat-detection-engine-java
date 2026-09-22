package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 单条事件摄入结果，用于守恒统计与可解释输出。
 */
public record IngestResult(
        String eventId,
        IngestStatus status,
        RejectReason rejectReason,
        String message,
        String ruleId,
        Integer ruleVersion,
        Long windowStartMs,
        Integer windowCount,
        Boolean thresholdReached,
        String alertId
) {
}
