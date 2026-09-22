package com.github.lisama569.threatdetectionenginejava.model;

import java.util.Map;

/**
 * 已注册日志来源的字段映射描述。
 *
 * @param source            来源标识
 * @param entityIdField     实体 ID 字段名
 * @param eventTypeField    事件类型字段名（值为来源本地类型词表）
 * @param timestampField    时间戳字段名（为空则取 RawEvent.timestamp）
 * @param typeMapping       本地类型词表 -> 统一 EventType
 */
public record SourceDescriptor(
        String source,
        String entityIdField,
        String eventTypeField,
        String timestampField,
        Map<String, EventType> typeMapping
) {
}
