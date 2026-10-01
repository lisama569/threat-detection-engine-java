package com.github.lisama569.threatdetectionenginejava.tests.recovery;

import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryPhase;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures;
import com.github.lisama569.threatdetectionenginejava.tests.support.RestartHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logWindows;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 正常重启续跑：正常停掉 -> 用同一份本地状态重启 -> 未结束窗口接着算；
 * 计数、去重指纹、watermark（迟到基准）、告警及处置状态全部延续；
 * 重启后继续投事件的最终结论，与“从头到尾没重启过、同顺序同输入”完全一致。
 */
class RestartResumeTest {

    private static final Logger log = LoggerFactory.getLogger(RestartResumeTest.class);

    private static final long WINDOW = 60_000L;
    private static final long TOLERANCE = 10_000L;
    private static final int THRESHOLD = 3;
    private static final long T = 1_790_000_000_000L;

    private CorrelationRule ruleV1() {
        return rule(1, WINDOW, THRESHOLD, TOLERANCE);
    }

    /** 全程事件：重启点之前窗口计数=2 未越阈；重启后继续，含乱序/重复/迟到/跨窗。 */
    private List<RawEvent> fullBatch() {
        return List.of(
                // --- 重启前：host-A 窗口内 2 条（未越阈）---
                edr("dlv-a1", "host-A", T + 2_000),
                edr("dlv-a2", "host-A", T + 4_000),
                // --- 重启后继续 ---
                // 乱序但在容忍内（watermark 已到 T+4000，落后 3s，接受）：第 3 条 -> 越阈告警
                edr("dlv-a3", "host-A", T + 1_000),
                // 同 deliveryId 重复投递：DUPLICATE，不计数
                edr("dlv-a1", "host-A", T + 2_000),
                // 同内容无 deliveryId（内容指纹一致）：窗口内容去重 DUPLICATE
                edr(null, "host-A", T + 4_000),
                // 迟到超容忍：watermark 已推进到更高点；落后 30s => TOO_LATE 不计数
                edr("dlv-aLate", "host-A", T - 26_000),
                // 跨到下一窗口的新事件，独立计数
                edr("dlv-aW2", "host-A", T + 70_000),
                // host-B 重启后才出现的实体：独立计数，达阈告警
                edr("dlv-b1", "host-B", T + 5_000),
                edr("dlv-b2", "host-B", T + 6_000),
                edr("dlv-b3", "host-B", T + 7_000));
    }

    @Test
    @DisplayName("正常停机重启：未结束窗口/计数/去重/watermark/告警处置延续，续跑结论与未重启完全一致")
    void resumeAfterGracefulRestartMatchesNoRestartRun(@TempDir Path dir) {
        Path stateFile = dir.resolve("state.json");
        EngineTestFixtures.MutableClock clock =
                new EngineTestFixtures.MutableClock(T + 600_000L);

        // ===== 基线：一个进程从头到尾不重启 =====
        DetectionService baseline = EngineTestFixtures.newService(EngineTestFixtures.defaultRegistry(), clock);
        baseline.deployRule(ruleV1());
        List<IngestResult> baselineAll = ingestLogged(baseline, fullBatch(), "基线-全程");
        // 基线中对 host-A 告警做一次处置迁移，验证处置状态也延续
        String alertA = baselineAll.get(2).alertId();
        assertNotNull(alertA);
        baseline.transitionAlert(alertA, AlertStatus.ACKNOWLEDGED, "重启前已确认");
        baseline.transitionAlert(alertA, AlertStatus.RESOLVED, "重启前已解决");

        // ===== 重启路线：投前 2 条 -> 正常停机快照 -> 重启 -> 投剩余 =====
        RestartHarness harness = new RestartHarness(stateFile, clock);
        harness.service().deployRule(ruleV1());

        List<RawEvent> beforeRestart = fullBatch().subList(0, 2);
        List<IngestResult> preResults = ingestLogged(harness.service(), beforeRestart, "重启前");
        logWindows("重启前窗口", harness.service());
        assertEquals(2, harness.service().debugWindows().get(0).count(), "重启前窗口计数应为 2");
        assertEquals(0, harness.service().listAlerts().size(), "重启前不应有告警");

        // 正常停机：原子快照落盘
        assertTrue(harness.shutdownCheckpoint(), "ACTIVE 实例停机必须成功落盘");
        assertEquals(RecoveryPhase.ACTIVE_FRESH, harness.gate().phase());

        // —— 滚动重启：全新内存组件 + 同一状态文件 ——
        DetectionService restarted = harness.restart();
        assertEquals(RecoveryPhase.ACTIVE_RESTORED, harness.gate().phase(),
                "有历史快照时必须以 ACTIVE_RESTORED 就绪");
        assertTrue(harness.service().recoveryStatus().restored());
        log.info("[重启后恢复状态] {}", harness.service().recoveryStatus());
        logWindows("重启后窗口(应延续计数=2)", restarted);

        assertEquals(2, restarted.debugWindows().get(0).count(), "重启后窗口计数必须延续为 2");
        assertEquals(0, restarted.listAlerts().size(), "重启前未告警的窗口不得被补告警");

        // 继续投递剩余事件
        List<RawEvent> afterRestart = fullBatch().subList(2, fullBatch().size());
        List<IngestResult> postResults = ingestLogged(restarted, afterRestart, "重启后续跑");
        logWindows("续跑后窗口", restarted);

        // 越阈告警：第 3 条（乱序到达的第 1 秒事件）必须在重启后的实例上产生且只产生一次
        assertEquals(IngestOutcome.ACCEPTED_ALERT, postResults.get(0).outcome());
        assertEquals(alertA, postResults.get(0).alertId(), "确定性告警 ID 必须与基线一致");

        // 告警总数与基线一致（host-A 窗1 + host-B 窗1 = 2）
        Map<String, Alert> restartedAlerts = restarted.listAlerts().stream()
                .collect(Collectors.toMap(Alert::getAlertId, a -> a));
        assertEquals(2, restartedAlerts.size(), "不能多告警也不能漏告警");
        // 处置状态：本路线未在重启前处置，host-A 告警应为 OPEN（状态延续语义在下面的用例单独验证）

        // ===== 逐结论与基线对比 =====
        List<IngestOutcome> expected = baselineAll.stream().map(IngestResult::outcome).toList();
        List<IngestOutcome> actual = new ArrayList<>();
        actual.addAll(preResults.stream().map(IngestResult::outcome).toList());
        actual.addAll(postResults.stream().map(IngestResult::outcome).toList());
        log.info("[结论对比] 基线={}", expected);
        log.info("[结论对比] 重启={}", actual);
        assertEquals(expected, actual, "重启路线逐条结论必须与未重启完全一致");

        // 守恒统计一致
        log.info("[统计对比] 基线={} 重启={}", baseline.stats(), restarted.stats());
        assertEquals(baseline.stats(), restarted.stats(), "重启后守恒统计必须延续且与基线一致");
        assertEquals(baseline.rejectionBreakdown(), restarted.rejectionBreakdown());

        // 多次重启幂等：再停再起，状态不丢不重
        assertTrue(harness.shutdownCheckpoint());
        DetectionService second = harness.restart();
        assertEquals(RecoveryPhase.ACTIVE_RESTORED, harness.gate().phase());
        assertEquals(2, second.listAlerts().size());
        assertEquals(baseline.stats(), second.stats());
        assertFalse(second.ingest(edr("dlv-a1", "host-A", T + 2_000)).outcome()
                .equals(IngestOutcome.ACCEPTED_NO_ALERT), "重启后旧 deliveryId 仍须判重");
        assertEquals(IngestOutcome.DUPLICATE,
                second.ingest(edr("dlv-a1", "host-A", T + 2_000)).outcome(),
                "历史投递键恢复后重复投递仍判 DUPLICATE");
    }

    @Test
    @DisplayName("已产生告警的处置状态跨重启保留，恢复后继续受生命周期校验约束")
    void alertLifecycleStateSurvivesRestart(@TempDir Path dir) {
        Path stateFile = dir.resolve("state-lifecycle.json");
        EngineTestFixtures.MutableClock clock =
                new EngineTestFixtures.MutableClock(T + 600_000L);
        RestartHarness harness = new RestartHarness(stateFile, clock);
        harness.service().deployRule(ruleV1());

        ingestLogged(harness.service(), List.of(
                edr("c1", "host-C", T + 1_000),
                edr("c2", "host-C", T + 2_000),
                edr("c3", "host-C", T + 3_000)), "产生告警");
        String alertId = harness.service().listAlerts().get(0).getAlertId();
        harness.service().transitionAlert(alertId, AlertStatus.SUPPRESSED, "重启前抑制");
        assertTrue(harness.shutdownCheckpoint());

        DetectionService restarted = harness.restart();
        Alert restored = restarted.listAlerts().get(0);
        assertEquals(alertId, restored.getAlertId());
        assertEquals(AlertStatus.SUPPRESSED, restored.getStatus(), "处置状态必须延续");
        assertEquals("重启前抑制", restored.getResolutionNote());
        // 抑制态可恢复到 ACKNOWLEDGED
        restarted.transitionAlert(alertId, AlertStatus.ACKNOWLEDGED, "重启后恢复");
        // 再重启，状态继续延续
        assertTrue(harness.shutdownCheckpoint());
        DetectionService again = harness.restart();
        assertEquals(AlertStatus.ACKNOWLEDGED, again.listAlerts().get(0).getStatus());
    }

    private static List<IngestResult> ingestLogged(DetectionService s, List<RawEvent> batch,
                                                   String title) {
        List<IngestResult> results = s.ingestBatch(batch);
        EngineTestFixtures.logBatch(title, batch, results);
        return results;
    }
}
