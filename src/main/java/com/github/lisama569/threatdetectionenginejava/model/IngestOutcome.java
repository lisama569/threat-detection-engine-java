package com.github.lisama569.threatdetectionenginejava.model;

/** 单条事件摄入的最终结论。 */
public enum IngestOutcome {
    /** 归一化被拒绝（未进入判定） */
    REJECTED,
    /** 重复投递，幂等忽略 */
    DUPLICATE,
    /** 迟到超过容忍窗口，明确标记但不参与窗口判定 */
    TOO_LATE,
    /** 正常摄入，落在已有窗口内，未越阈 */
    ACCEPTED_NO_ALERT,
    /** 正常摄入且导致阈值跨越，产生新告警 */
    ACCEPTED_ALERT
}
