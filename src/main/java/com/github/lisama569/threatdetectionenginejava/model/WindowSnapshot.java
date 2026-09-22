package com.github.lisama569.threatdetectionenginejava.model;

import java.util.List;

/**
 * 窗口状态快照（用于日志与可解释输出）。
 */
public record WindowSnapshot(
        String ruleId,
        int ruleVersion,
        String entityId,
        long windowStart,
        long windowEnd,
        int count,
        List<String> eventIds,
        long watermark,
        boolean alerted) {

    public WindowSnapshot {
        eventIds = eventIds == null ? List.of() : List.copyOf(eventIds);
    }
}
