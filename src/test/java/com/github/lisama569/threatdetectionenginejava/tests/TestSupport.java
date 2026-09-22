package com.github.lisama569.threatdetectionenginejava.tests;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleManager;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.ingest.IngestService;
import com.github.lisama569.threatdetectionenginejava.journal.EventJournal;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.EventType;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.normalize.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalize.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.rule.RuleRegistry;

import java.util.List;
import java.util.Map;

/**
 * 测试用引擎装配工具：手工构造与生产一致的组件链。
 */
final class TestSupport {

    /**
     * 取当前时刻之后约 30 秒的窗口起点作为测试基准：所有构造的事件时间（BASE+1..3s）
     * 都晚于测试运行的真实时钟，因此到达时间必然在容忍内，且精确落在同一 10 秒窗口。
     */
    static final long BASE = ((System.currentTimeMillis() + 30_000L) / 10_000L) * 10_000L;

    private TestSupport() {
    }

    record EngineHarness(IngestService service,
                         CorrelationEngine engine,
                         AlertLifecycleManager alerts,
                         RuleRegistry rules,
                         EventJournal journal,
                         SourceRegistry sources) {
    }

    static EngineHarness harness(String journalPath) {
        SourceRegistry sources = new SourceRegistry();
        sources.register(new SourceDescriptor("auth-sys", "username", "action", "ts",
                Map.of("auth_fail", EventType.FAILED_LOGIN,
                        "auth_ok", EventType.SUCCESSFUL_LOGIN)));
        sources.register(new SourceDescriptor("edp-agent", "host", "eventType", "occurredAt",
                Map.of("fail_login", EventType.FAILED_LOGIN,
                        "malware", EventType.MALWARE_DETECTED)));
        EventNormalizer normalizer = new EventNormalizer(sources);
        RuleRegistry rules = new RuleRegistry();
        rules.put(new CorrelationRule("brute-force-login", 1,
                List.of(EventType.FAILED_LOGIN), 3, 10_000L, 5_000L));
        AlertLifecycleManager alerts = new AlertLifecycleManager();
        CorrelationEngine engine = new CorrelationEngine(rules, alerts);
        EventJournal journal = new EventJournal(journalPath == null ? "" : journalPath);
        journal.init();
        journal.clear();
        IngestService service = new IngestService(normalizer, engine, journal, false);
        return new EngineHarness(service, engine, alerts, rules, journal, sources);
    }

    static RawEvent loginFail(String id, String user, long eventTimeMs) {
        return new RawEvent("auth-sys", id, null, Map.of(
                "username", user,
                "action", "auth_fail",
                "ts", java.time.Instant.ofEpochMilli(eventTimeMs).toString()));
    }
}
