package com.github.lisama569.threatdetectionenginejava.detection;

import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.IngestStatus;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;

/**
 * IngestResult 构造小工具。
 */
final class IngestResults {

    private IngestResults() {
    }

    static IngestResult build(String eventId, IngestStatus status, RejectReason rejectReason,
                              String message, CorrelationRule rule, Long windowStart,
                              Integer windowCount, Boolean thresholdReached, String alertId) {
        return new IngestResult(
                eventId,
                status,
                rejectReason,
                message,
                rule == null ? null : rule.ruleId(),
                rule == null ? null : rule.version(),
                windowStart,
                windowCount,
                thresholdReached,
                alertId);
    }

    static IngestResult skipped(com.github.lisama569.threatdetectionenginejava.model.SecurityEvent event,
                                CorrelationRule rule, Long windowStart, Integer windowCount,
                                Boolean thresholdReached, String message) {
        return build(event.eventId(), IngestStatus.ACCEPTED, null, message,
                rule, windowStart, windowCount, thresholdReached, null);
    }
}
