package com.github.lisama569.threatdetectionenginejava.model;

import java.util.List;

/**
 * 单条原始事件的完整摄入结论：归一化结论 + 每条匹配规则的判定。
 *
 * @param duplicatedDelivery 本次调用是否为重复投递（true 时 status=DUPLICATE，
 *                           ruleEvaluations 为首次处理的结论快照，不重新计数）
 */
public record IngestOutcome(
        String deduplicatedEventId,
        IngestStatus status,
        RejectReason rejectReason,
        String message,
        SecurityEvent event,
        List<IngestResult> ruleEvaluations,
        boolean duplicatedDelivery
) {
    public IngestOutcome(String deduplicatedEventId, IngestStatus status, RejectReason rejectReason,
                         String message, SecurityEvent event, List<IngestResult> ruleEvaluations) {
        this(deduplicatedEventId, status, rejectReason, message, event, ruleEvaluations, false);
    }
}
