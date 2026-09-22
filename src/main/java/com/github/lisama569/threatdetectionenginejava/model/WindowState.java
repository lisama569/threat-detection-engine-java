package com.github.lisama569.threatdetectionenginejava.model;

import java.util.List;

/**
 * 单个 (规则版本, 实体, 时间窗) 的计数状态（可解释判定依据）。
 */
public record WindowState(
        String ruleId,
        int ruleVersion,
        String entityId,
        long windowStartMs,
        long windowEndMs,
        int count,
        int threshold,
        boolean thresholdReached,
        boolean closed,
        boolean alertRaised,
        List<String> contributingEventIds,
        long lastUpdatedMs
) {
}
