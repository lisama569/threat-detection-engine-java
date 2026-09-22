package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 归一化后的统一安全事件模型。
 *
 * @param eventId       全局唯一事件 ID（source + 原始 eventId 派生）
 * @param source        来源标识
 * @param entityId      关联实体（如用户名 / 主机 / IP）
 * @param type          统一事件类型
 * @param eventTimeMs   事件发生时间（epoch millis）
 * @param ingestTimeMs  引擎接收时间（epoch millis）
 */
public record SecurityEvent(
        String eventId,
        String source,
        String entityId,
        EventType type,
        long eventTimeMs,
        long ingestTimeMs
) {
}
