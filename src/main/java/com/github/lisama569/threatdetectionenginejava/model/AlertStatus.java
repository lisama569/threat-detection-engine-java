package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 告警生命周期状态。
 * OPEN -> ACKNOWLEDGED -> RESOLVED 为合法迁移链；
 * OPEN -> RESOLVED 亦允许；任何回退/重复迁移均为非法。
 */
public enum AlertStatus {
    OPEN,
    ACKNOWLEDGED,
    RESOLVED
}
