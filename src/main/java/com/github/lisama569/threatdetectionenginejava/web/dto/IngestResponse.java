package com.github.lisama569.threatdetectionenginejava.web.dto;

import com.github.lisama569.threatdetectionenginejava.model.IngestResult;

/** REST 摄入响应。 */
public record IngestResponse(String outcome, String eventId, String rejectReason,
                             String alertId, String detail) {

    public static IngestResponse from(IngestResult r) {
        return new IngestResponse(
                r.outcome().name(),
                r.eventId(),
                r.rejectReason() == null ? null : r.rejectReason().name(),
                r.alertId(),
                r.detail());
    }
}
