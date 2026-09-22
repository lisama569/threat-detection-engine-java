package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 摄入处理结果（可解释）。
 *
 * @param outcome 结论
 * @param eventId 归一化事件指纹（拒绝时可能为 null）
 * @param rejectReason 拒绝原因（仅 REJECTED 时非空）
 * @param alertId 产生的告警 ID（仅 ACCEPTED_ALERT 时非空）
 * @param detail 判定依据的可读说明
 */
public record IngestResult(
        IngestOutcome outcome,
        String eventId,
        RejectReason rejectReason,
        String alertId,
        String detail) {

    public static IngestResult rejected(RejectReason reason, String detail) {
        return new IngestResult(IngestOutcome.REJECTED, null, reason, null, detail);
    }

    public static IngestResult of(IngestOutcome outcome, String eventId, String detail) {
        return new IngestResult(outcome, eventId, null, null, detail);
    }

    public static IngestResult alert(String eventId, String alertId, String detail) {
        return new IngestResult(IngestOutcome.ACCEPTED_ALERT, eventId, null, alertId, detail);
    }
}
