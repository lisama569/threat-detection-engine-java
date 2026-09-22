package com.github.lisama569.threatdetectionenginejava.model;

import java.util.List;

/**
 * 可配置关联规则（不可变，带版本）。
 *
 * @param ruleId 规则 ID（更新时保持不变）
 * @param version 单调递增版本号，同一批事件+同一版本重放结论必须可复现
 * @param eventTypes 命中事件类型集合
 * @param entityScope 限定实体范围（空表示全部实体）
 * @param windowMillis 关联窗口长度
 * @param threshold 窗口内去重事件数阈值（>=threshold 时告警）
 * @param lateToleranceMillis 迟到/乱序容忍：eventTime 早于 watermark 不超过该值仍可参与判定
 */
public record CorrelationRule(
        String ruleId,
        int version,
        List<String> eventTypes,
        List<String> entityScope,
        long windowMillis,
        int threshold,
        long lateToleranceMillis) {

    public CorrelationRule {
        eventTypes = eventTypes == null ? List.of() : List.copyOf(eventTypes);
        entityScope = entityScope == null ? List.of() : List.copyOf(entityScope);
    }
}
