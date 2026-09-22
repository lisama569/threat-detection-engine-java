package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 告警。alertId 由 (ruleId, ruleVersion, entityId, windowStart) 确定性派生，
 * 保证重复投递/窗口抖动/重放/重启下不重复。
 */
public record Alert(
        String alertId,
        String ruleId,
        int ruleVersion,
        String entityId,
        long windowStartMs,
        long windowEndMs,
        int eventCount,
        long firstEventTimeMs,
        long lastEventTimeMs,
        long createdAtMs,
        AlertStatus status
) {
}
