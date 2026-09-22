package com.github.lisama569.threatdetectionenginejava.tests.detection;

import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.fixedClock;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logBatch;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logWindows;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.newService;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.defaultRegistry;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则更新后重放：
 * 同一批事件 + 同一规则版本（同顺序）=> 可复现；不同版本结论按版本隔离且可不同；
 * 在线更新规则只影响新到事件，不回写历史；重放使用隔离引擎，不污染在线状态与计数。
 */
class RuleReplayTest {

    private static final Logger log = LoggerFactory.getLogger(RuleReplayTest.class);

    private static final long T = 1_790_000_000_000L;

    private static CorrelationRule v1() {
        // v1：60s 窗口、阈值 3、容忍 10s
        return new CorrelationRule("R-BRUTE-FORCE", 1, List.of("login_failure"),
                List.of(), 60_000L, 3, 10_000L);
    }

    private static CorrelationRule v2() {
        // v2：30s 窗口、阈值 2、容忍 10s
        return new CorrelationRule("R-BRUTE-FORCE", 2, List.of("login_failure"),
                List.of(), 30_000L, 2, 10_000L);
    }

    private static List<RawEvent> batch() {
        return List.of(
                edr("e1", "host-1", T + 5_000),
                edr("e2", "host-1", T + 1_000),
                edr("e1", "host-1", T + 5_000),            // 重复投递
                edr("e3", "host-1", T + 20_000),
                edr("e4", "host-1", T + 40_000));
    }

    private static List<String> signature(List<IngestResult> results) {
        return results.stream()
                .map(r -> r.outcome() + "|" + (r.alertId() == null ? "-" : r.alertId())
                        + "|" + (r.rejectReason() == null ? "-" : r.rejectReason()))
                .toList();
    }

    @Test
    @DisplayName("同一批事件+同一规则版本重放两次：结论与告警 ID 完全一致")
    void replaySameVersionIsReproducible() {
        DetectionService service = newService(defaultRegistry(), fixedClock());
        service.deployRule(v1());
        List<RawEvent> batch = batch();

        List<IngestResult> r1 = service.replay(batch, List.of(v1()));
        List<IngestResult> r2 = service.replay(batch, List.of(v1()));
        logBatch("v1 重放-1", batch, r1);
        logBatch("v1 重放-2", batch, r2);

        assertEquals(signature(r1), signature(r2));
        long alerts = r1.stream().filter(r -> r.outcome() == IngestOutcome.ACCEPTED_ALERT).count();
        assertEquals(1, alerts, "v1：0s/1s/20s 三事件在 60s 窗达阈，恰一条告警");
    }

    @Test
    @DisplayName("不同规则版本重放：结论随版本不同且告警 ID 带版本隔离")
    void replayDifferentVersionsProducesVersionedResults() {
        DetectionService service = newService(defaultRegistry(), fixedClock());
        service.deployRule(v1());
        List<RawEvent> batch = batch();

        List<IngestResult> rv1 = service.replay(batch, List.of(v1()));
        List<IngestResult> rv2 = service.replay(batch, List.of(v2()));
        logBatch("按 v1 重放", batch, rv1);
        logBatch("按 v2 重放", batch, rv2);

        assertNotEquals(signature(rv1), signature(rv2));
        // v1 在第 4 条（20s，第三个不同事件）达阈；v2 在第 4 条（20s 落在 [0,30s) 窗，第二个不同事件）即达阈，
        // 且第 5 条（40s）进入 v2 的 [30s,60s) 新窗不告警
        String v1AlertId = rv1.stream().filter(r -> r.outcome() == IngestOutcome.ACCEPTED_ALERT)
                .findFirst().orElseThrow().alertId();
        String v2AlertId = rv2.stream().filter(r -> r.outcome() == IngestOutcome.ACCEPTED_ALERT)
                .findFirst().orElseThrow().alertId();
        assertTrue(v1AlertId.contains("-v1-"));
        assertTrue(v2AlertId.contains("-v2-"));
        assertNotEquals(v1AlertId, v2AlertId);
    }

    @Test
    @DisplayName("在线规则更新只影响新到事件；之后用 v1 重放仍可复现更新前的历史结论")
    void onlineUpdateDoesNotRewriteHistory() {
        DetectionService service = newService(defaultRegistry(), fixedClock());
        service.deployRule(v1());

        // 更新前：v1 下两个事件，未达阈
        List<IngestResult> before = service.ingestBatch(List.of(
                edr("e1", "host-9", T + 1_000),
                edr("e2", "host-9", T + 2_000)));
        logBatch("v1 在线期", batch().subList(0, 0), before);
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, before.get(1).outcome());
        assertEquals(0, service.listAlerts().size());

        // 更新为 v2
        service.deployRule(v2());
        logWindows("更新为 v2 后，v1 窗口仍保留", service);

        // 新到事件按 v2 判定：[0,30s) 窗内 v2 从空状态开始，需 2 个事件才达阈
        List<IngestResult> after = service.ingestBatch(List.of(
                edr("e3", "host-9", T + 20_000),
                edr("e4", "host-9", T + 25_000)));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, after.get(0).outcome());
        assertEquals(IngestOutcome.ACCEPTED_ALERT, after.get(1).outcome());
        assertTrue(after.get(1).alertId().contains("-v2-"), "新事件必须归属 v2");
        assertEquals(1, service.listAlerts().size());

        // 用 v1 重放全部 4 条：结论应等同于“从未更新过规则”——60s 窗内 4 个不同事件在第 3 条即达阈
        List<RawEvent> allFour = List.of(
                edr("e1", "host-9", T + 1_000),
                edr("e2", "host-9", T + 2_000),
                edr("e3", "host-9", T + 20_000),
                edr("e4", "host-9", T + 25_000));
        List<IngestResult> replayV1 = service.replay(allFour, List.of(v1()));
        logBatch("更新后按 v1 重放历史", allFour, replayV1);
        assertEquals(IngestOutcome.ACCEPTED_ALERT, replayV1.get(2).outcome());
        assertTrue(replayV1.get(2).alertId().contains("-v1-"));
    }

    @Test
    @DisplayName("重放不污染在线状态：在线告警/计数/窗口在重放前后保持不变")
    void replayIsIsolatedFromOnlineState() {
        DetectionService service = newService(defaultRegistry(), fixedClock());
        service.deployRule(v1());
        service.ingestBatch(List.of(
                edr("o1", "host-7", T + 1_000),
                edr("o2", "host-7", T + 2_000),
                edr("o3", "host-7", T + 3_000)));

        int alertsBefore = service.listAlerts().size();
        long totalBefore = service.stats().total();
        int windowsBefore = service.debugWindows().size();

        service.replay(batch(), List.of(v1()));
        service.replay(batch(), List.of(v2()));

        assertEquals(alertsBefore, service.listAlerts().size());
        assertEquals(totalBefore, service.stats().total());
        assertEquals(windowsBefore, service.debugWindows().size());
        log.info("重放隔离校验通过: alerts={}, total={}, windows={}",
                alertsBefore, totalBefore, windowsBefore);
    }

    @Test
    @DisplayName("规则版本号必须严格递增，回灌旧版本被拒绝")
    void deployRejectsNonIncrementingVersion() {
        DetectionService service = newService(defaultRegistry(), fixedClock());
        service.deployRule(v2());
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> service.deployRule(v1()));
        assertTrue(ex.getMessage().contains("版本必须严格递增"));
        log.info("旧版本回灌被拒绝: {}", ex.getMessage());
    }
}
