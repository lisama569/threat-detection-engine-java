package com.github.lisama569.threatdetectionenginejava.tests.detection;

import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logBatch;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logWindows;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.newServiceWithRule;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * 乱序/迟到事件：
 * 容忍范围内乱序判定稳定可解释；恰好等于容忍边界仍接受；超过容忍明确标记 TOO_LATE 且不计数；
 * 固定窗口边界两侧各计各的，不重复告警不漏报。
 */
class OutOfOrderAndLateEventTest {

    private static final Logger log = LoggerFactory.getLogger(OutOfOrderAndLateEventTest.class);

    private static final long T = 1_790_000_000_000L;
    private static final long WINDOW = 60_000L;
    private static final long TOLERANCE = 10_000L;
    private static final int THRESHOLD = 3;

    private DetectionService newService() {
        return newServiceWithRule(rule(1, WINDOW, THRESHOLD, TOLERANCE));
    }

    private static List<IngestResult> outcomes(DetectionService s, List<RawEvent> batch, String title) {
        List<IngestResult> results = s.ingestBatch(batch);
        logBatch(title, batch, results);
        logWindows(title + "-窗口", s);
        return results;
    }

    @Test
    @DisplayName("乱序到达但在容忍内：计数稳定，阈值跨越恰好告警一次")
    void outOfOrderWithinToleranceFiresExactlyOnce() {
        DetectionService service = newService();
        List<RawEvent> batch = List.of(
                edr("d-5s", "host-A", T + 5_000),
                // 迟到 4s 的更早事件（乱序）
                edr("d-1s", "host-A", T + 1_000),
                edr("d-9s", "host-A", T + 9_000));

        List<IngestResult> r = outcomes(service, batch, "乱序容忍内");

        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(0).outcome());
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(1).outcome());
        assertEquals(IngestOutcome.ACCEPTED_ALERT, r.get(2).outcome());
        assertEquals(1, service.listAlerts().size(), "窗口内只能产生一条告警");
        assertNotNull(service.listAlerts().get(0).getAlertId());
        // 阈值后再来一条不重复告警
        IngestResult extra = service.ingest(edr("d-10s", "host-A", T + 10_000));
        log.info("阈值后的第四条结论: {}", extra);
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, extra.outcome());
        assertNull(extra.alertId());
        assertEquals(1, service.listAlerts().size());
    }

    @Test
    @DisplayName("恰好等于容忍边界（watermark-eventTime == tolerance）仍接受并计数")
    void exactlyAtToleranceBoundaryAccepted() {
        DetectionService service = newService();
        List<RawEvent> batch = List.of(
                edr("b-20s", "host-B", T + 20_000),
                // 落后恰好 10_000ms == 容忍，必须接受
                edr("b-10s", "host-B", T + 10_000),
                edr("b-21s", "host-B", T + 20_001));

        List<IngestResult> r = outcomes(service, batch, "容忍边界");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(0).outcome());
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(1).outcome(),
                "等于容忍边界不应判 TOO_LATE");
        assertEquals(IngestOutcome.ACCEPTED_ALERT, r.get(2).outcome());
        assertEquals(1, service.listAlerts().size());
    }

    @Test
    @DisplayName("超过容忍 1ms 即标记 TOO_LATE，不计数，不漏掉后续告警")
    void beyondToleranceMarkedTooLateAndNotCounted() {
        DetectionService service = newService();
        List<RawEvent> batch = List.of(
                edr("l-30s", "host-C", T + 30_000),
                // 落后 15s，超过 10s 容忍
                edr("l-15s", "host-C", T + 15_000));

        List<IngestResult> r = outcomes(service, batch, "超容忍迟到");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, r.get(0).outcome());
        assertEquals(IngestOutcome.TOO_LATE, r.get(1).outcome());
        org.junit.jupiter.api.Assertions.assertTrue(r.get(1).detail().contains("TOO_LATE"),
                "结论必须显式标记并解释迟到");

        // 窗口计数仍为 1：迟到事件未参与计数
        assertEquals(1, service.debugWindows().get(0).count());

        // 后续正常事件仍可把计数推到阈值，不漏报
        List<RawEvent> follow = List.of(
                edr("l-31s", "host-C", T + 31_000),
                edr("l-32s", "host-C", T + 32_000));
        List<IngestResult> r2 = outcomes(service, follow, "迟到后的补数");
        assertEquals(IngestOutcome.ACCEPTED_ALERT, r2.get(1).outcome());
        assertEquals(1, service.listAlerts().size());
    }

    @Test
    @DisplayName("固定窗口边界两侧互不串窗：59999 与 60000 分属两窗，各自独立达阈各自告警一次")
    void windowBoundaryDoesNotMergeOrDuplicate() {
        // 必须使用 60000 对齐的基准，否则 59999/60000 可能同窗
        long aligned = (T / WINDOW) * WINDOW + WINDOW;
        DetectionService service = newService();
        List<RawEvent> batch = new ArrayList<>();
        // 第一窗 [aligned, aligned+60000)：aligned+59997/59998/59999
        batch.add(edr("w1-a", "host-D", aligned + 59_997));
        batch.add(edr("w1-b", "host-D", aligned + 59_998));
        batch.add(edr("w1-c", "host-D", aligned + 59_999));
        // 第二窗 [aligned+60000, aligned+120000)：60000/60001/60002
        batch.add(edr("w2-a", "host-D", aligned + 60_000));
        batch.add(edr("w2-b", "host-D", aligned + 60_001));
        batch.add(edr("w2-c", "host-D", aligned + 60_002));

        List<IngestResult> r = outcomes(service, batch, "窗口边界");
        assertEquals(IngestOutcome.ACCEPTED_ALERT, r.get(2).outcome());
        assertEquals(IngestOutcome.ACCEPTED_ALERT, r.get(5).outcome());
        assertEquals(2, service.listAlerts().size(), "两个窗口各告警一次");
        assertEquals(2, service.debugWindows().size());
    }

    @Test
    @DisplayName("乱序不改变可复现性：相同输入顺序两次独立运行结论一致")
    void deterministicAcrossIndependentRuns() {
        List<RawEvent> batch = List.of(
                edr("p-9s", "host-E", T + 9_000),
                edr("p-1s", "host-E", T + 1_000),
                edr("p-50s", "host-E", T + 50_000),
                edr("p-35s", "host-E", T + 35_000));

        DetectionService s1 = newService();
        DetectionService s2 = newService();
        List<IngestResult> r1 = outcomes(s1, batch, "独立运行-1");
        List<IngestResult> r2 = outcomes(s2, batch, "独立运行-2");

        List<IngestOutcome> o1 = r1.stream().map(IngestResult::outcome).toList();
        List<IngestOutcome> o2 = r2.stream().map(IngestResult::outcome).toList();
        assertEquals(o1, o2);
        // 50s 到达后，35s 落后 15s 超容忍
        assertEquals(IngestOutcome.TOO_LATE, o1.get(3));
    }
}
