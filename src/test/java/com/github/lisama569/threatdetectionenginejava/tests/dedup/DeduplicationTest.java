package com.github.lisama569.threatdetectionenginejava.tests.dedup;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService;
import com.github.lisama569.threatdetectionenginejava.dedup.DeliveryDeduplicator;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.List;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.fixedClock;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.defaultRegistry;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logBatch;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logIngest;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logWindows;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.newServiceWithRule;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 重复投递（相同 deliveryId）、无 deliveryId 的内容指纹去重、
 * 窗口边界抖动（投递 ID 变化但事件内容相同）、进程重启后基于已存键集合恢复：
 * 不重复告警、不漏报。
 */
class DeduplicationTest {

    private static final Logger log = LoggerFactory.getLogger(DeduplicationTest.class);

    private static final long T = 1_790_000_000_000L;
    private static final long WINDOW = 60_000L;
    private static final long TOLERANCE = 30_000L;
    private static final int THRESHOLD = 3;

    private DetectionService newService() {
        return newServiceWithRule(rule(1, WINDOW, THRESHOLD, TOLERANCE));
    }

    @Test
    @DisplayName("相同 deliveryId 重复投递：仅首次计数，后续全部 DUPLICATE，不重复告警")
    void sameDeliveryIdIsIdempotent() {
        DetectionService service = newService();
        List<RawEvent> triple = List.of(
                edr("same-id", "host-A", T + 1_000),
                edr("same-id", "host-A", T + 1_000),
                edr("same-id", "host-A", T + 1_000));

        List<IngestResult> r = logAndWindows(service, triple, "相同deliveryId重复3次");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(0).outcome());
        assertEquals(IngestOutcome.DUPLICATE, r.get(1).outcome());
        assertEquals(IngestOutcome.DUPLICATE, r.get(2).outcome());
        assertEquals(1, service.debugWindows().get(0).count(), "窗口计数不得膨胀");
        assertEquals(0, service.listAlerts().size());
    }

    @Test
    @DisplayName("无 deliveryId 时按内容指纹幂等：重复内容不计数、不告警")
    void contentFingerprintDedupWithoutDeliveryId() {
        DetectionService service = newService();
        List<RawEvent> batch = List.of(
                edr(null, "host-B", T + 2_000),
                edr(null, "host-B", T + 3_000),
                edr(null, "host-B", T + 3_000)); // 与上一条内容完全相同

        List<IngestResult> r = logAndWindows(service, batch, "无deliveryId内容指纹");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(0).outcome());
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(1).outcome());
        assertEquals(IngestOutcome.DUPLICATE, r.get(2).outcome(), "内容相同必须识别为重复");
        assertEquals(2, service.debugWindows().get(0).count());
    }

    @Test
    @DisplayName("窗口边界抖动：投递系统更换 deliveryId 重发同一事件，仍按内容去重且不影响达阈")
    void redeliveryWithDifferentIdButSameContent() {
        DetectionService service = newService();
        List<RawEvent> batch = List.of(
                edr("retry-1", "host-C", T + 4_000),
                edr("retry-2", "host-C", T + 5_000),
                // 投递侧重试，ID 变了但内容与上一条一致
                edr("retry-2-again", "host-C", T + 5_000),
                edr("retry-3", "host-C", T + 6_000));

        List<IngestResult> r = logAndWindows(service, batch, "投递ID抖动");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(0).outcome());
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(1).outcome());
        assertEquals(IngestOutcome.DUPLICATE, r.get(2).outcome());
        assertEquals(IngestOutcome.ACCEPTED_ALERT, r.get(3).outcome(), "去重后第 3 个不同事件仍准确达阈");
        assertEquals(1, service.listAlerts().size());
        // 再来一遍相同 4 条（整批重投）：不得再产生告警
        for (RawEvent raw : batch) {
            IngestResult again = service.ingest(raw);
            logIngest(9, raw, again);
            assertEquals(IngestOutcome.DUPLICATE, again.outcome());
        }
        assertEquals(1, service.listAlerts().size(), "整批重投不得重复告警");
    }

    @Test
    @DisplayName("进程重启：用已存投递键集合恢复去重器，重放旧投递不二次计数")
    void restartRestoresDedupKeys() {
        SourceRegistry registry = defaultRegistry();
        Clock clock = fixedClock();

        // —— 重启前进程 ——
        InMemoryStore oldStore = new InMemoryStore();
        DetectionService before = buildService(oldStore, registry, clock);
        before.deployRule(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        RawEvent first = edr("persisted-1", "host-D", T + 7_000);
        IngestResult beforeResult = before.ingest(first);
        logIngest(1, first, beforeResult);
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, beforeResult.outcome());

        // 模拟持久化的投递键集合（生产中来自存储层；内存版用快照模拟）
        var restoredKeys = oldStore.deduplicator().snapshotKeys();
        log.info("重启前持久化投递键: {}", restoredKeys);

        // —— 重启后进程：以恢复键集合构造去重器 ——
        InMemoryStore newStore = new InMemoryStore(new DeliveryDeduplicator(restoredKeys));
        DetectionService after = buildService(newStore, registry, clock);
        after.deployRule(rule(1, WINDOW, THRESHOLD, TOLERANCE));

        // 同一投递在重启后重放：必须被识别为重复，不产生计数/告警
        IngestResult replayAfterRestart = after.ingest(first);
        logIngest(2, first, replayAfterRestart);
        assertEquals(IngestOutcome.DUPLICATE, replayAfterRestart.outcome());
        assertEquals(0, after.debugWindows().size(), "重复投递不得重建窗口状态");
        assertEquals(0, after.listAlerts().size());
    }

    @Test
    @DisplayName("进程重启后告警 ID 确定性一致：同一规则版本/实体/窗口派生出相同 alertId")
    void alertIdIsStableAcrossRestart() {
        DetectionService s1 = newService();
        DetectionService s2 = newService();
        RawEvent a = edr("k-1", "host-E", T + 8_000);
        RawEvent b = edr("k-2", "host-E", T + 9_000);
        RawEvent c = edr("k-3", "host-E", T + 10_000);

        IngestResult r1 = s1.ingestBatch(List.of(a, b, c)).get(2);
        IngestResult r2 = s2.ingestBatch(List.of(a, b, c)).get(2);
        logIngest(1, c, r1);
        logIngest(2, c, r2);
        assertEquals(IngestOutcome.ACCEPTED_ALERT, r1.outcome());
        assertEquals(r1.alertId(), r2.alertId(), "跨进程告警 ID 必须可确定性复现");
    }

    @Test
    @DisplayName("DeliveryDeduplicator 单元语义：首次登记 true，重复 false，恢复集合立即生效")
    void deduplicatorPrimitiveSemantics() {
        DeliveryDeduplicator d = new DeliveryDeduplicator();
        assertTrue(d.markIfFirst("x"));
        assertFalse(d.markIfFirst("x"));
        assertTrue(d.isDuplicate("x"));
        DeliveryDeduplicator restored = new DeliveryDeduplicator(d.snapshotKeys());
        assertFalse(restored.markIfFirst("x"));
    }

    private static DetectionService buildService(InMemoryStore store, SourceRegistry registry,
                                                 Clock clock) {
        CorrelationEngine engine = new CorrelationEngine();
        EventNormalizer normalizer = new EventNormalizer(registry, clock);
        AlertLifecycleService lifecycle = new AlertLifecycleService(clock);
        return new DetectionService(store, registry, engine, normalizer, lifecycle, clock);
    }

    private static List<IngestResult> logAndWindows(DetectionService service, List<RawEvent> batch,
                                                    String title) {
        List<IngestResult> results = service.ingestBatch(batch);
        logBatch(title, batch, results);
        logWindows(title + "-窗口", service);
        return results;
    }
}
