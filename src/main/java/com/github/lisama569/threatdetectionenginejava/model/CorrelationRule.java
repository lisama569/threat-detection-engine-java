package com.github.lisama569.threatdetectionenginejava.model;

import java.util.List;

/**
 * 关联检测规则（按版本不可变）。
 *
 * @param ruleId        规则 ID
 * @param version       规则版本（单调递增整数）
 * @param eventTypes    参与计数的事件类型集合
 * @param threshold     时间窗内产生告警所需的最小事件数（&gt;= 该值即告警）
 * @param windowSizeMs  窗口长度
 * @param allowedLatenessMs 乱序/迟到容忍时间
 */
public record CorrelationRule(
        String ruleId,
        int version,
        List<EventType> eventTypes,
        int threshold,
        long windowSizeMs,
        long allowedLatenessMs
) {
}
