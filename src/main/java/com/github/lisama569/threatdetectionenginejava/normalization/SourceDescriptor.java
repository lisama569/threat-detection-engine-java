package com.github.lisama569.threatdetectionenginejava.normalization;

import java.util.List;
import java.util.Map;

/**
 * 来源格式描述：声明该来源 payload 中各归一化字段的取值路径。
 *
 * @param sourceId 来源标识
 * @param entityKeys 实体字段候选键（按顺序取第一个非空）
 * @param typeKeys 事件类型字段候选键
 * @param timeKeys 时间戳字段候选键
 * @param severityKeys 严重级别字段候选键
 * @param allowedSeverities 允许的严重级别（小写归一后校验，空表示不校验）
 * @param fixedType 固定类型（payload 不含类型字段时使用，可空）
 */
public record SourceDescriptor(
        String sourceId,
        List<String> entityKeys,
        List<String> typeKeys,
        List<String> timeKeys,
        List<String> severityKeys,
        List<String> allowedSeverities,
        String fixedType) {

    public SourceDescriptor {
        entityKeys = entityKeys == null ? List.of() : List.copyOf(entityKeys);
        typeKeys = typeKeys == null ? List.of() : List.copyOf(typeKeys);
        timeKeys = timeKeys == null ? List.of() : List.copyOf(timeKeys);
        severityKeys = severityKeys == null ? List.of() : List.copyOf(severityKeys);
        allowedSeverities = allowedSeverities == null ? List.of() : List.copyOf(allowedSeverities);
    }

    /** 点路径取嵌套字段，如 host.id；任一层缺失返回 null。 */
    public static Object readPath(Map<String, Object> payload, String path) {
        if (payload == null || path == null || path.isEmpty()) {
            return null;
        }
        Object current = payload;
        for (String segment : path.split("\\.")) {
            if (!(current instanceof Map<?, ?> map)) {
                return null;
            }
            current = map.get(segment);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    private static String firstNonBlank(Map<String, Object> payload, List<String> keys) {
        for (String key : keys) {
            Object value = readPath(payload, key);
            if (value != null && !value.toString().isBlank()) {
                return value.toString().trim();
            }
        }
        return null;
    }

    public String readEntity(Map<String, Object> payload) {
        return firstNonBlank(payload, entityKeys);
    }

    public String readType(Map<String, Object> payload) {
        String type = firstNonBlank(payload, typeKeys);
        return type != null ? type : fixedType;
    }

    public String readSeverity(Map<String, Object> payload) {
        String severity = firstNonBlank(payload, severityKeys);
        return severity == null ? null : severity.toLowerCase();
    }

    public Object readRawTime(Map<String, Object> payload) {
        for (String key : timeKeys) {
            Object value = readPath(payload, key);
            if (value != null && !value.toString().isBlank()) {
                return value;
            }
        }
        return null;
    }

    public boolean severityAllowed(String severity) {
        return allowedSeverities.isEmpty() || (severity != null && allowedSeverities.contains(severity));
    }
}
