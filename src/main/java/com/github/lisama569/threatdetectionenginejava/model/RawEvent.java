package com.github.lisama569.threatdetectionenginejava.model;

import java.util.Map;

/**
 * 原始安全事件：来源系统投递的原始记录，字段名/格式由来源决定。
 *
 * @param sourceId 来源标识，如 firewall / edr / syslog
 * @param deliveryId 投递方提供的去重键（可为空，为空时按内容指纹去重）
 * @param payload 原始字段
 */
public record RawEvent(String sourceId, String deliveryId, Map<String, Object> payload) {
    public RawEvent {
        payload = payload == null ? Map.of() : Map.copyOf(payload);
    }
}
