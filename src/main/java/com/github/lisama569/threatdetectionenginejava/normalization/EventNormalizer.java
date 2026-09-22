package com.github.lisama569.threatdetectionenginejava.normalization;

import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 多来源原始事件 -> 统一模型；非法输入抛 {@link NormalizationException}，绝不静默丢弃。
 *
 * 时间戳约定：
 * <ul>
 *   <li>数字：绝对值 &lt; 1e12 视为 epoch 秒，否则视为 epoch 毫秒；</li>
 *   <li>字符串：先按数字解析（同上），否则按 ISO-8601（如 2026-09-22T10:00:00Z）解析；</li>
 *   <li>超过当前时间 {@link #FUTURE_SLACK_MILLIS} 视为未来时间拒绝。</li>
 * </ul>
 */
public class EventNormalizer {

    /** 未来时间容忍（时钟偏差），超过即拒绝。 */
    public static final long FUTURE_SLACK_MILLIS = 60_000L;

    private static final List<String> SEQUENCE_KEYS = List.of("sequence", "seq", "eventSeq");

    private final SourceRegistry registry;
    private final Clock clock;

    public EventNormalizer(SourceRegistry registry, Clock clock) {
        this.registry = registry;
        this.clock = clock;
    }

    public SourceRegistry getRegistry() {
        return registry;
    }

    public SecurityEvent normalize(RawEvent raw) {
        if (raw == null) {
            throw new NormalizationException(RejectReason.EMPTY_PAYLOAD, "原始事件为空");
        }
        String sourceId = raw.sourceId();
        SourceDescriptor source = registry.find(sourceId)
                .orElseThrow(() -> new NormalizationException(
                        RejectReason.UNKNOWN_SOURCE, "来源未注册: " + sourceId));

        Map<String, Object> payload = raw.payload();
        if (payload.isEmpty()) {
            throw new NormalizationException(RejectReason.EMPTY_PAYLOAD,
                    "来源 " + sourceId + " 的 payload 为空");
        }

        String entityId = source.readEntity(payload);
        if (entityId == null) {
            throw new NormalizationException(RejectReason.MISSING_ENTITY,
                    "实体字段缺失，候选键=" + source.entityKeys() + "，source=" + sourceId);
        }

        String eventType = source.readType(payload);
        if (eventType == null) {
            throw new NormalizationException(RejectReason.MISSING_EVENT_TYPE,
                    "事件类型字段缺失，候选键=" + source.typeKeys() + "，source=" + sourceId);
        }

        Object rawTime = source.readRawTime(payload);
        long eventTime = parseTimestamp(rawTime, sourceId);

        long now = clock.millis();
        if (eventTime > now + FUTURE_SLACK_MILLIS) {
            throw new NormalizationException(RejectReason.FUTURE_TIMESTAMP,
                    "事件时间在未来: eventTime=" + eventTime + " now=" + now + " source=" + sourceId);
        }

        String severity = source.readSeverity(payload);
        if (severity == null) {
            severity = "unknown";
        } else if (!source.severityAllowed(severity)) {
            severity = "unknown";
        }

        Long sequence = readSequence(payload);
        String eventId = fingerprint(sourceId, entityId, eventType, eventTime, payload);

        return new SecurityEvent(eventId, sourceId, entityId, eventType, severity,
                eventTime, now, sequence);
    }

    private static Long readSequence(Map<String, Object> payload) {
        for (String key : SEQUENCE_KEYS) {
            Object value = payload.get(key);
            if (value instanceof Number n) {
                return n.longValue();
            }
            if (value != null) {
                try {
                    return Long.parseLong(value.toString().trim());
                } catch (NumberFormatException ignored) {
                    // 尝试下一个候选键
                }
            }
        }
        return null;
    }

    static long parseTimestamp(Object rawTime, String sourceId) {
        if (rawTime == null) {
            throw new NormalizationException(RejectReason.INVALID_TIMESTAMP,
                    "时间戳字段缺失，source=" + sourceId);
        }
        if (rawTime instanceof Number n) {
            return normalizeEpoch(n.longValue(), sourceId);
        }
        String text = rawTime.toString().trim();
        if (text.isEmpty()) {
            throw new NormalizationException(RejectReason.INVALID_TIMESTAMP,
                    "时间戳为空字符串，source=" + sourceId);
        }
        // 纯数字字符串按 epoch 处理
        if (text.chars().allMatch(Character::isDigit)) {
            try {
                return normalizeEpoch(Long.parseLong(text), sourceId);
            } catch (NumberFormatException e) {
                throw new NormalizationException(RejectReason.INVALID_TIMESTAMP,
                        "时间戳数字无法解析: " + text + "，source=" + sourceId);
            }
        }
        try {
            return Instant.parse(text).toEpochMilli();
        } catch (Exception e) {
            throw new NormalizationException(RejectReason.INVALID_TIMESTAMP,
                    "时间戳既非 epoch 数字也非 ISO-8601: " + text + "，source=" + sourceId);
        }
    }

    private static long normalizeEpoch(long v, String sourceId) {
        if (v <= 0) {
            throw new NormalizationException(RejectReason.INVALID_TIMESTAMP,
                    "时间戳必须为正数: " + v + "，source=" + sourceId);
        }
        return Math.abs(v) < 1_000_000_000_000L ? v * 1000L : v;
    }

    /**
     * 事件内容指纹：归一化关键字段 + 载荷的规范化（键排序）序列化。
     * 同一物理事件重复投递（即使 deliveryId 缺失）指纹一致。
     */
    static String fingerprint(String sourceId, String entityId, String eventType,
                              long eventTime, Map<String, Object> payload) {
        String canonical = "src=" + sourceId
                + "|ent=" + entityId
                + "|type=" + eventType
                + "|t=" + eventTime
                + "|payload=" + canonical(payload);
        return sha1(canonical);
    }

    @SuppressWarnings("unchecked")
    private static String canonical(Object value) {
        if (value instanceof Map<?, ?> map) {
            // 键排序保证嵌套 Map 的序列化稳定
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                sorted.put(String.valueOf(e.getKey()), e.getValue());
            }
            StringBuilder sb = new StringBuilder("{");
            List<String> parts = new ArrayList<>();
            for (Map.Entry<String, Object> e : sorted.entrySet()) {
                parts.add(e.getKey() + "=" + canonical(e.getValue()));
            }
            sb.append(String.join(",", parts)).append('}');
            return sb.toString();
        }
        if (value instanceof Iterable<?> iterable) {
            List<String> parts = new ArrayList<>();
            for (Object o : iterable) {
                parts.add(canonical(o));
            }
            return "[" + String.join(",", parts) + "]";
        }
        return String.valueOf(value);
    }

    private static String sha1(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(40);
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 不可用", e);
        }
    }
}
