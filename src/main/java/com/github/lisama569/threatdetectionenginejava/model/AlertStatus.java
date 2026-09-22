package com.github.lisama569.threatdetectionenginejava.model;

/** 告警生命周期状态。合法迁移：OPEN->ACKNOWLEDGED->RESOLVED；OPEN/ACKNOWLEDGED->SUPPRESSED；SUPPRESSED->OPEN/ACKNOWLEDGED。 */
public enum AlertStatus {
    OPEN,
    ACKNOWLEDGED,
    SUPPRESSED,
    RESOLVED
}
