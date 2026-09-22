package com.github.lisama569.threatdetectionenginejava.normalize;

import com.github.lisama569.threatdetectionenginejava.model.EventType;
import com.github.lisama569.threatdetectionenginejava.model.NormalizeResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.SourceDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Map;

/**
 * 多来源事件归一化器。
 * <p>
 * 校验顺序固定，拒绝原因互不重叠、可区分：
 * <ol>
 *   <li>负载为空：PAYLOAD_EMPTY</li>
 *   <li>来源未注册：SOURCE_NOT_REGISTERED</li>
 *   <li>缺少 eventId：MISSING_EVENT_ID</li>
 *   <li>时间戳非法：INVALID_TIMESTAMP</li>
 *   <li>缺少实体 ID：MISSING_ENTITY_ID</li>
 *   <li>缺少事件类型/类型词无法映射：MISSING_EVENT_TYPE</li>
 * </ol>
 * 归一化后的全局 eventId 为 {@code source + "#" + 原始eventId}，天然区分不同来源。
 */
@Component
public class EventNormalizer {

    private static final Logger log = LoggerFactory.getLogger(EventNormalizer.class);

    /**
     * 拒绝明显不合理的时间（1970 之前或 100 年之后），作为 TIMESTAMP_OUT_OF_RANGE 区分。
     */
    private static final long MIN_EVENT_TIME_MS = 0L;
    private static final long MAX_EVENT_TIME_MS = 4_102_444_800_000L; // 2100-01-01
    /** 小于该阈值的纯数字 epoch 视为秒（2001-09-09 之前的 millis 不可能出现） */
    private static final long SECONDS_EPOCH_BOUNDARY = 1_000_000_000_000L;

    private final SourceRegistry sourceRegistry;

    public EventNormalizer(SourceRegistry sourceRegistry) {
        this.sourceRegistry = sourceRegistry;
    }

    public NormalizeResult normalize(RawEvent raw) {
        if (raw == null) {
            return reject(RejectReason.PAYLOAD_EMPTY, "raw event is null", null);
        }
        if (raw.fields() == null || raw.fields().isEmpty()) {
            return reject(RejectReason.PAYLOAD_EMPTY,
                    "event payload fields are empty: source=" + raw.source(), raw);
        }

        SourceDescriptor descriptor = sourceRegistry.find(raw.source())
                .orElse(null);
        if (descriptor == null) {
            return reject(RejectReason.SOURCE_NOT_REGISTERED,
                    "source is not registered: " + raw.source(), raw);
        }

        String originEventId = trimToNull(raw.eventId());
        if (originEventId == null) {
            return reject(RejectReason.MISSING_EVENT_ID,
                    "missing event id from source " + raw.source(), raw);
        }

        Long eventTime = parseTimestamp(raw, descriptor);
        if (eventTime == null) {
            return reject(RejectReason.INVALID_TIMESTAMP,
                    "invalid or unparseable timestamp: " + raw.timestamp()
                            + " (source=" + raw.source() + ")", raw);
        }
        if (eventTime < MIN_EVENT_TIME_MS || eventTime > MAX_EVENT_TIME_MS) {
            return reject(RejectReason.TIMESTAMP_OUT_OF_RANGE,
                    "timestamp out of accepted range [1970,2100]: " + eventTime, raw);
        }

        String entityId = stringField(raw.fields(), descriptor.entityIdField());
        if (entityId == null) {
            return reject(RejectReason.MISSING_ENTITY_ID,
                    "missing entity id field '" + descriptor.entityIdField()
                            + "' from source " + raw.source(), raw);
        }

        Object rawType = raw.fields().get(descriptor.eventTypeField());
        if (rawType == null || trimToNull(String.valueOf(rawType)) == null) {
            return reject(RejectReason.MISSING_EVENT_TYPE,
                    "missing event type field '" + descriptor.eventTypeField()
                            + "' from source " + raw.source(), raw);
        }
        EventType type = descriptor.typeMapping().get(String.valueOf(rawType).trim());
        if (type == null) {
            return reject(RejectReason.MISSING_EVENT_TYPE,
                    "unmapped local event type vocabulary '" + rawType
                            + "' from source " + raw.source(), raw);
        }

        String globalId = raw.source() + "#" + originEventId;
        SecurityEvent event = new SecurityEvent(
                globalId,
                raw.source(),
                entityId,
                type,
                eventTime,
                System.currentTimeMillis());

        log.debug("normalized: rawSource={} event={}", raw.source(), event);
        return new NormalizeResult.Ok(event);
    }

    private Long parseTimestamp(RawEvent raw, SourceDescriptor descriptor) {
        Object value = raw.timestamp();
        if (descriptor.timestampField() != null && !descriptor.timestampField().isBlank()) {
            Object fieldValue = raw.fields().get(descriptor.timestampField());
            if (fieldValue != null) {
                value = fieldValue;
            }
        }
        if (value == null) {
            return null;
        }
        try {
            long epoch;
            if (value instanceof Number number) {
                epoch = number.longValue();
            } else {
                String text = String.valueOf(value).trim();
                if (text.isEmpty()) {
                    return null;
                }
                // 纯数字一律视为 epoch；非数字走 ISO-8601
                if (text.chars().allMatch(Character::isDigit)) {
                    epoch = Long.parseLong(text);
                } else {
                    return Instant.parse(text).toEpochMilli();
                }
            }
            // 秒级 epoch（数字或纯数字字符串）自动换算为毫秒
            return Math.abs(epoch) < SECONDS_EPOCH_BOUNDARY ? epoch * 1000L : epoch;
        } catch (DateTimeParseException | NumberFormatException e) {
            log.debug("timestamp parse failed for value={}: {}", value, e.getMessage());
            return null;
        }
    }

    private String stringField(Map<String, Object> fields, String name) {
        Object value = fields.get(name);
        if (value == null) {
            return null;
        }
        return trimToNull(String.valueOf(value));
    }

    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private NormalizeResult reject(RejectReason reason, String message, RawEvent raw) {
        log.warn("event rejected: reason={} message={}", reason, message);
        return new NormalizeResult.Rejected(reason, message, raw);
    }
}
