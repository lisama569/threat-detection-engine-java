package com.github.lisama569.threatdetectionenginejava.model;

/** 归一化拒绝原因，可区分。 */
public enum RejectReason {
    UNKNOWN_SOURCE,
    MISSING_ENTITY,
    MISSING_EVENT_TYPE,
    INVALID_TIMESTAMP,
    FUTURE_TIMESTAMP,
    EMPTY_PAYLOAD
}
