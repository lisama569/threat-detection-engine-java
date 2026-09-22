package com.github.lisama569.threatdetectionenginejava.tests;

import com.github.lisama569.threatdetectionenginejava.model.EventType;
import com.github.lisama569.threatdetectionenginejava.model.NormalizeResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.normalize.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalize.SourceRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 归一化约定测试：多来源格式、字段缺失、非法时间戳、未注册来源必须给出可区分拒绝原因。
 */
class NormalizationTest {

    private static final Logger log = LoggerFactory.getLogger(NormalizationTest.class);

    private EventNormalizer normalizer;

    @BeforeEach
    void setUp() {
        SourceRegistry registry = new SourceRegistry();
        registry.register(new SourceDescriptor("auth-sys", "username", "action", "ts",
                Map.of("auth_fail", EventType.FAILED_LOGIN,
                        "auth_ok", EventType.SUCCESSFUL_LOGIN)));
        registry.register(new SourceDescriptor("edp-agent", "host", "eventType", null,
                Map.of("fail_login", EventType.FAILED_LOGIN)));
        normalizer = new EventNormalizer(registry);
    }

    @Test
    @DisplayName("ISO-8601 时间戳的 auth-sys 事件可正常归一化")
    void normalizeIsoTimestamp() {
        RawEvent raw = new RawEvent("auth-sys", "e-1", null, Map.of(
                "username", "alice",
                "action", "auth_fail",
                "ts", "2026-09-22T08:00:00Z"));

        NormalizeResult result = normalizer.normalize(raw);

        assertThat(result).isInstanceOf(NormalizeResult.Ok.class);
        SecurityEvent event = ((NormalizeResult.Ok) result).event();
        log.info("[NORMALIZE-OK] raw={} -> event={}", raw, event);
        assertThat(event.eventId()).isEqualTo("auth-sys#e-1");
        assertThat(event.entityId()).isEqualTo("alice");
        assertThat(event.type()).isEqualTo(EventType.FAILED_LOGIN);
        assertThat(event.eventTimeMs()).isEqualTo(java.time.Instant.parse("2026-09-22T08:00:00Z").toEpochMilli());
    }

    @Test
    @DisplayName("epoch millis / 秒级数字时间戳均被接受")
    void normalizeEpochVariants() {
        RawEvent millis = new RawEvent("edp-agent", "h-1", 1_789_000_000_000L,
                Map.of("host", "host-7", "eventType", "fail_login"));
        RawEvent seconds = new RawEvent("auth-sys", "e-2", null, Map.of(
                "username", "bob", "action", "auth_ok", "ts", "1789000000"));

        SecurityEvent m = ((NormalizeResult.Ok) normalizer.normalize(millis)).event();
        SecurityEvent s = ((NormalizeResult.Ok) normalizer.normalize(seconds)).event();
        log.info("[NORMALIZE-MILLIS] {}", m);
        log.info("[NORMALIZE-SECONDS] {}", s);

        assertThat(m.eventTimeMs()).isEqualTo(1_789_000_000_000L);
        assertThat(s.eventTimeMs()).isEqualTo(1_789_000_000_000L);
    }

    @Test
    @DisplayName("未注册来源返回 SOURCE_NOT_REGISTERED")
    void rejectUnknownSource() {
        RawEvent raw = new RawEvent("rogue-device", "x", 1L, Map.of("u", "a"));
        NormalizeResult.Rejected rejected = reject(raw);
        log.info("[REJECT] reason={} message={}", rejected.reason(), rejected.message());
        assertThat(rejected.reason()).isEqualTo(RejectReason.SOURCE_NOT_REGISTERED);
    }

    @Test
    @DisplayName("空负载返回 PAYLOAD_EMPTY")
    void rejectEmptyPayload() {
        RawEvent raw = new RawEvent("auth-sys", "x", 1L, Map.of());
        assertThat(reject(raw).reason()).isEqualTo(RejectReason.PAYLOAD_EMPTY);
    }

    @Test
    @DisplayName("缺少 eventId 返回 MISSING_EVENT_ID")
    void rejectMissingEventId() {
        RawEvent raw = new RawEvent("auth-sys", "  ", null,
                Map.of("username", "a", "action", "auth_fail", "ts", "2026-01-01T00:00:00Z"));
        assertThat(reject(raw).reason()).isEqualTo(RejectReason.MISSING_EVENT_ID);
    }

    @Test
    @DisplayName("非法时间戳返回 INVALID_TIMESTAMP，且不静默丢弃")
    void rejectInvalidTimestamp() {
        RawEvent raw = new RawEvent("auth-sys", "e", null,
                Map.of("username", "a", "action", "auth_fail", "ts", "not-a-time"));
        NormalizeResult.Rejected rejected = reject(raw);
        log.info("[REJECT] reason={} message={}", rejected.reason(), rejected.message());
        assertThat(rejected.reason()).isEqualTo(RejectReason.INVALID_TIMESTAMP);
    }

    @Test
    @DisplayName("时间戳超出合理范围返回 TIMESTAMP_OUT_OF_RANGE")
    void rejectOutOfRangeTimestamp() {
        RawEvent raw = new RawEvent("edp-agent", "e", -5L,
                Map.of("host", "h", "eventType", "fail_login"));
        assertThat(reject(raw).reason()).isEqualTo(RejectReason.TIMESTAMP_OUT_OF_RANGE);
    }

    @Test
    @DisplayName("缺少实体字段返回 MISSING_ENTITY_ID")
    void rejectMissingEntity() {
        RawEvent raw = new RawEvent("auth-sys", "e", null,
                Map.of("action", "auth_fail", "ts", "2026-01-01T00:00:00Z"));
        assertThat(reject(raw).reason()).isEqualTo(RejectReason.MISSING_ENTITY_ID);
    }

    @Test
    @DisplayName("缺少/无法映射的类型词返回 MISSING_EVENT_TYPE")
    void rejectUnknownType() {
        RawEvent missing = new RawEvent("auth-sys", "e", null,
                Map.of("username", "a", "ts", "2026-01-01T00:00:00Z"));
        RawEvent unmapped = new RawEvent("auth-sys", "e2", null,
                Map.of("username", "a", "action", "something-weird", "ts", "2026-01-01T00:00:00Z"));
        assertThat(reject(missing).reason()).isEqualTo(RejectReason.MISSING_EVENT_TYPE);
        assertThat(reject(unmapped).reason()).isEqualTo(RejectReason.MISSING_EVENT_TYPE);
    }

    private NormalizeResult.Rejected reject(RawEvent raw) {
        NormalizeResult result = normalizer.normalize(raw);
        assertThat(result).isInstanceOf(NormalizeResult.Rejected.class);
        return (NormalizeResult.Rejected) result;
    }
}
