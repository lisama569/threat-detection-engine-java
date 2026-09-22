package com.github.lisama569.threatdetectionenginejava.model;

import java.util.Map;

/**
 * 原始接入事件（多来源格式）。
 *
 * @param source    来源标识，如 firewall-a / edp-host-1 / web-gateway
 * @param eventId   来源侧事件唯一 ID，用于幂等去重
 * @param timestamp 事件发生时间；来源可能给 epochMillis(long) 或 ISO-8601 字符串
 * @param fields    来源原始字段
 */
public record RawEvent(
        String source,
        String eventId,
        Object timestamp,
        Map<String, Object> fields
) {
}
