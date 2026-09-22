package com.github.lisama569.threatdetectionenginejava.tests.normalization;

import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalization.NormalizationException;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.EDR;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.fixedClock;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.defaultRegistry;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.firewall;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logIngest;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.newService;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** 归一化：字段缺失 / 时间戳非法 / 来源未注册 / 未来时间 -> 可区分拒绝原因。 */
class NormalizationTest {

    private static final Logger log = LoggerFactory.getLogger(NormalizationTest.class);

    private static final long T = 1_790_000_000_000L;

    private SourceRegistry registry;
    private EventNormalizer normalizer;

    @BeforeEach
    void setUp() {
        registry = defaultRegistry();
        normalizer = new EventNormalizer(registry, fixedClock());
    }

    private RawEvent raw(String source, Map<String, Object> payload) {
        return new RawEvent(source, null, payload);
    }

    private Map<String, Object> edrPayload(String host, Object ts) {
        Map<String, Object> p = new LinkedHashMap<>();
        if (host != null) {
            p.put("hostId", host);
        }
        p.put("eventType", "login_failure");
        p.put("timestamp", ts);
        p.put("severity", "high");
        return p;
    }

    @Test
    @DisplayName("edr 毫秒时间戳正常归一化")
    void normalizesEdrMillis() {
        SecurityEvent e = normalizer.normalize(raw(EDR, edrPayload("host-1", T)));
        assertEquals("host-1", e.entityId());
        assertEquals("login_failure", e.eventType());
        assertEquals("high", e.severity());
        assertEquals(T, e.eventTime());
        assertNotNull(e.eventId());
        log.info("normalized event={}", e);
    }

    @Test
    @DisplayName("firewall 嵌套字段 + ISO-8601 时间正常归一化")
    void normalizesFirewallNestedIso() {
        SecurityEvent e = normalizer.normalize(firewall("d1", "host-2", T));
        assertEquals("host-2", e.entityId());
        assertEquals(T, e.eventTime());
        log.info("normalized firewall event={}", e);
    }

    @Test
    @DisplayName("秒级 epoch（数字与数字字符串）归一化为毫秒")
    void normalizesEpochSeconds() {
        long seconds = T / 1000;
        assertEquals(T - (T % 1000), normalizer.normalize(raw(EDR, edrPayload("h", seconds))).eventTime());
        assertEquals(T - (T % 1000),
                normalizer.normalize(raw(EDR, edrPayload("h", String.valueOf(seconds)))).eventTime());
    }

    @Test
    @DisplayName("来源未注册 -> UNKNOWN_SOURCE")
    void rejectsUnknownSource() {
        NormalizationException ex = assertThrows(NormalizationException.class,
                () -> normalizer.normalize(raw("ghost", edrPayload("h", T))));
        assertEquals(RejectReason.UNKNOWN_SOURCE, ex.getReason());
        log.info("拒绝原因可区分: reason={}, message={}", ex.getReason(), ex.getMessage());
    }

    @Test
    @DisplayName("payload 为空 -> EMPTY_PAYLOAD")
    void rejectsEmptyPayload() {
        NormalizationException ex = assertThrows(NormalizationException.class,
                () -> normalizer.normalize(raw(EDR, Map.of())));
        assertEquals(RejectReason.EMPTY_PAYLOAD, ex.getReason());
    }

    @Test
    @DisplayName("实体缺失 -> MISSING_ENTITY")
    void rejectsMissingEntity() {
        NormalizationException ex = assertThrows(NormalizationException.class,
                () -> normalizer.normalize(raw(EDR, edrPayload(null, T))));
        assertEquals(RejectReason.MISSING_ENTITY, ex.getReason());
    }

    @Test
    @DisplayName("事件类型缺失 -> MISSING_EVENT_TYPE")
    void rejectsMissingType() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("hostId", "h");
        p.put("timestamp", T);
        NormalizationException ex = assertThrows(NormalizationException.class,
                () -> normalizer.normalize(raw(EDR, p)));
        assertEquals(RejectReason.MISSING_EVENT_TYPE, ex.getReason());
    }

    @Test
    @DisplayName("时间戳缺失/非数字非ISO/非正数 -> INVALID_TIMESTAMP")
    void rejectsInvalidTimestamp() {
        NormalizationException missing = assertThrows(NormalizationException.class,
                () -> normalizer.normalize(raw(EDR, edrPayload("h", null)
                        .entrySet().stream().filter(en -> !en.getKey().equals("timestamp"))
                        .collect(LinkedHashMap::new, (m, en) -> m.put(en.getKey(), en.getValue()),
                                LinkedHashMap::putAll))));
        assertEquals(RejectReason.INVALID_TIMESTAMP, missing.getReason());

        assertEquals(RejectReason.INVALID_TIMESTAMP,
                assertThrows(NormalizationException.class,
                        () -> normalizer.normalize(raw(EDR, edrPayload("h", "not-a-timestamp"))))
                        .getReason());
        assertEquals(RejectReason.INVALID_TIMESTAMP,
                assertThrows(NormalizationException.class,
                        () -> normalizer.normalize(raw(EDR, edrPayload("h", -5L)))).getReason());
    }

    @Test
    @DisplayName("未来时间超过容忍 -> FUTURE_TIMESTAMP")
    void rejectsFutureTimestamp() {
        long future = fixedClock().millis() + EventNormalizer.FUTURE_SLACK_MILLIS + 60_000L;
        NormalizationException ex = assertThrows(NormalizationException.class,
                () -> normalizer.normalize(raw(EDR, edrPayload("h", future))));
        assertEquals(RejectReason.FUTURE_TIMESTAMP, ex.getReason());
    }

    @Test
    @DisplayName("非法记录经服务摄入不被静默丢弃：返回 REJECTED 与可区分原因，并计入守恒统计")
    void serviceReturnsDistinctRejections() {
        DetectionService service = newService(registry, fixedClock());

        RawEvent unknown = raw("ghost", edrPayload("h", T));
        RawEvent noEntity = raw(EDR, edrPayload(null, T));
        RawEvent badTs = raw(EDR, edrPayload("h", "bad"));

        IngestResult r1 = service.ingest(unknown);
        IngestResult r2 = service.ingest(noEntity);
        IngestResult r3 = service.ingest(badTs);
        logIngest(1, unknown, r1);
        logIngest(2, noEntity, r2);
        logIngest(3, badTs, r3);

        assertEquals(IngestOutcome.REJECTED, r1.outcome());
        assertEquals(RejectReason.UNKNOWN_SOURCE, r1.rejectReason());
        assertEquals(RejectReason.MISSING_ENTITY, r2.rejectReason());
        assertEquals(RejectReason.INVALID_TIMESTAMP, r3.rejectReason());
        assertEquals(3, service.stats().total());
        assertEquals(3, service.stats().rejected());
        assertEquals(3, service.rejectionBreakdown().values().stream().mapToLong(Long::longValue).sum());
    }
}
