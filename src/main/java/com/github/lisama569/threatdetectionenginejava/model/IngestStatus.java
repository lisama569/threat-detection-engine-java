package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 单条事件摄入的处理结果状态。
 */
public enum IngestStatus {
    /** 首次接受并完成处理 */
    ACCEPTED,
    /** 重复投递（同一 eventId 已处理过），直接返回既有结论，不重复计数 */
    DUPLICATE,
    /** 乱序但在容忍范围内，已稳定计入 */
    LATE_WITHIN_TOLERANCE,
    /** 超出容忍范围的迟到事件，明确标记且不计数 */
    LATE_BEYOND_TOLERANCE,
    /** 归一化或校验失败，被拒绝 */
    REJECTED
}
