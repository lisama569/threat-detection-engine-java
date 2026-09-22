package com.github.lisama569.threatdetectionenginejava.tests.support;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowSnapshot;
import com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.store.IngestStats;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 单测公共支撑：固定时钟（事件时间允许在“未来”），默认来源注册表，
 * 以及把事件、窗口状态、判定依据打印到测试日志的工具。
 */
public final class EngineTestFixtures {

    private static final Logger log = LoggerFactory.getLogger(EngineTestFixtures.class);

    public static final String EDR = "edr";
    public static final String FIREWALL = "firewall";

    private EngineTestFixtures() {
    }

    /** 固定时钟；normalize 的未来时间校验相对该时钟，测试可用 {@link MutableClock} 推进。 */
    public static MutableClock fixedClock() {
        return new MutableClock(Instant.parse("2026-09-22T12:00:00Z").toEpochMilli());
    }

    public static SourceRegistry defaultRegistry() {
        SourceRegistry registry = new SourceRegistry();
        for (SourceDescriptor d : defaultSources()) {
            registry.register(d);
        }
        return registry;
    }

    public static List<SourceDescriptor> defaultSources() {
        return List.of(
                new SourceDescriptor(EDR, List.of("hostId", "host"), List.of("eventType", "type"),
                        List.of("timestamp", "ts"), List.of("severity", "sev"),
                        List.of("low", "medium", "high", "critical"), null),
                new SourceDescriptor(FIREWALL, List.of("host.id", "srcIp"),
                        List.of("event.type", "type"), List.of("event.time", "@timestamp"),
                        List.of("event.severity"),
                        List.of("low", "medium", "high", "critical"), null));
    }

    public static CorrelationRule rule(int version, long windowMillis, int threshold,
                                       long lateToleranceMillis) {
        return new CorrelationRule("R-BRUTE-FORCE", version, List.of("login_failure"),
                List.of(), windowMillis, threshold, lateToleranceMillis);
    }

    public static DetectionService newService(SourceRegistry registry, Clock clock) {
        InMemoryStore store = new InMemoryStore();
        CorrelationEngine engine = new CorrelationEngine();
        EventNormalizer normalizer = new EventNormalizer(registry, clock);
        AlertLifecycleService lifecycle = new AlertLifecycleService(clock);
        return new DetectionService(store, registry, engine, normalizer, lifecycle, clock);
    }

    public static DetectionService newServiceWithRule(CorrelationRule rule) {
        MutableClock clock = fixedClock();
        DetectionService service = newService(defaultRegistry(), clock);
        service.deployRule(rule);
        return service;
    }

    public static RawEvent edr(String deliveryId, String host, long eventTime) {
        return edr(EDR, deliveryId, host, "login_failure", eventTime);
    }

    public static RawEvent edr(String source, String deliveryId, String host, String type,
                               Object eventTime) {
        Map<String, Object> payload = new LinkedHashMap<>();
        if (host != null) {
            payload.put("hostId", host);
        }
        payload.put("eventType", type);
        payload.put("timestamp", eventTime);
        payload.put("severity", "low");
        return new RawEvent(source, deliveryId, payload);
    }

    public static RawEvent firewall(String deliveryId, String host, long eventTime) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("type", "login_failure");
        event.put("time", Instant.ofEpochMilli(eventTime).toString());
        event.put("severity", "high");
        Map<String, Object> hostNode = new LinkedHashMap<>();
        hostNode.put("id", host);
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("host", hostNode);
        payload.put("event", event);
        return new RawEvent(FIREWALL, deliveryId, payload);
    }

    /** 打印一条投递与判定结论（测试日志要求：事件 + 判定依据）。 */
    public static void logIngest(int index, RawEvent raw, IngestResult result) {
        log.info("[case#{}] raw source={}, deliveryId={}, payload={} => outcome={}, eventId={}, "
                        + "rejectReason={}, alertId={}, reason={}",
                index, raw.sourceId(), raw.deliveryId(), raw.payload(),
                result.outcome(), result.eventId(), result.rejectReason(),
                result.alertId(), result.detail());
    }

    public static void logBatch(String title, List<RawEvent> batch, List<IngestResult> results) {
        log.info("---------- {} ({} 条) ----------", title, batch.size());
        for (int i = 0; i < batch.size(); i++) {
            logIngest(i + 1, batch.get(i), results.get(i));
        }
    }

    public static void logWindows(String title, DetectionService service) {
        List<WindowSnapshot> windows = service.debugWindows();
        log.info("---------- {} ({} 个窗口) ----------", title, windows.size());
        for (WindowSnapshot w : windows) {
            log.info("window rule={} v{} entity={} [{},{}) count={} alerted={} eventIds={} watermark={}",
                    w.ruleId(), w.ruleVersion(), w.entityId(), w.windowStart(), w.windowEnd(),
                    w.count(), w.alerted(), w.eventIds(), w.watermark());
        }
    }

    public static void logStats(DetectionService service) {
        IngestStats s = service.stats();
        log.info("stats={} rejectionBreakdown={} 守恒成立={}",
                s, service.rejectionBreakdown(),
                s.total() == s.rejected() + s.duplicate() + s.tooLate()
                        + s.acceptedNoAlert() + s.acceptedAlert());
    }

    /** 可推进的固定时钟，用于模拟“进程重启后时间继续流逝”。 */
    public static final class MutableClock extends Clock {
        private long millis;

        public MutableClock(long millis) {
            this.millis = millis;
        }

        public void advanceMillis(long delta) {
            this.millis += delta;
        }

        public void setMillis(long millis) {
            this.millis = millis;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis);
        }
    }
}
