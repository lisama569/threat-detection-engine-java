package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 事件被拒绝归一化/摄入的可区分原因。
 */
public enum RejectReason {
    SOURCE_NOT_REGISTERED,
    MISSING_ENTITY_ID,
    MISSING_EVENT_TYPE,
    MISSING_EVENT_ID,
    INVALID_TIMESTAMP,
    TIMESTAMP_OUT_OF_RANGE,
    PAYLOAD_EMPTY,
    UNKNOWN
}
