package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 归一化后的统一安全事件模型。
 *
 * @param eventId 内容指纹（幂等键），相同事件重复投递 eventId 不变
 * @param sourceId 来源标识
 * @param entityId 关联实体（如主机/IP/用户）
 * @param eventType 归一化事件类型
 * @param severity 归一化严重级别
 * @param eventTime 事件发生时间（epochMillis）
 * @param ingestTime 被本服务接收的时间（epochMillis）
 * @param sequence 来源内单调序号（可为 null，无法解析时为 null）
 */
public record SecurityEvent(
        String eventId,
        String sourceId,
        String entityId,
        String eventType,
        String severity,
        long eventTime,
        long ingestTime,
        Long sequence) {
}
