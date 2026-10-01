package com.github.lisama569.threatdetectionenginejava.tests.recovery;

import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowSnapshot;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures;
import com.github.lisama569.threatdetectionenginejava.tests.support.RestartHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 规则换过版本再重启：各版本自己的窗口（计数/watermark/去重）和告警严格隔离，互不串用；
 * 新版本只影响新到达事件；历史版本告警连同其版本号原样恢复。
 */
class RuleVersionSwitchRestartTest {

    private static final Logger log = LoggerFactory.getLogger(RuleVersionSwitchRestartTest.class);

    private static final long T = 1_790_000_000_000L;

    private CorrelationRule v1() {
        // v1：60s 窗口、阈值 3、容忍 10s
        return rule(1, 60_000L, 3, 10_000L);
    }

    private CorrelationRule v2() {
        // v2：30s 窗口、阈值 2、容忍 10s（版本严格递增）
        return rule(2, 30_000L, 2, 10_000L);
    }

    @Test
    @DisplayName("v1 运行->部署 v2->停机->重启：两版本窗口/告警各自恢复且隔离，新版本只影响新事件")
    void windowsAndAlertsIsolatedByVersionAcrossRestart(@TempDir Path dir) {
        Path stateFile = dir.resolve("version.json");
        var clock = new EngineTestFixtures.MutableClock(T + 600_000L);
        RestartHarness harness = new RestartHarness(stateFile, clock);
        DetectionService svc = harness.service();

        // ---- v1 阶段：host-A 在 60s 窗来 2 条（未越 v1 阈值 3）----
        svc.deployRule(v1());
        List<IngestResult> v1Results = svc.ingestBatch(List.of(
                edr("v1-a", "host-A", T + 1_000),
                edr("v1-b", "host-A", T + 2_000)));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, v1Results.get(1).outcome());
        assertEquals(0, svc.listAlerts().size());

        // ---- 在线升级 v2（旧 v1 窗口状态保留，新版本只影响新事件）----
        svc.deployRule(v2());
        // v2 用 30s 窗口、阈值 2：T+1s/T+2s 落在 v2 的第一个 30s 窗，但它们是按 v1 处理的，
        // 不会被回放到 v2；v2 新事件落在 v2 窗口
        List<IngestResult> v2Results = svc.ingestBatch(List.of(
                edr("v2-a", "host-A", T + 40_000),
                edr("v2-b", "host-A", T + 41_000)));
        // 40s/41s 同在 30s 窗 [T+30s,T+60s)，两条 => 越 v2 阈值 2，告警一次
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, v2Results.get(0).outcome());
        assertEquals(IngestOutcome.ACCEPTED_ALERT, v2Results.get(1).outcome());
        String v2AlertId = v2Results.get(1).alertId();
        assertTrue(v2AlertId.contains("-v2-"), "告警 ID 必须带 v2 版本: " + v2AlertId);

        // 此刻同时存在：v1 窗口（计数 2，未告警）与 v2 窗口（计数 2，已告警）
        Map<Integer, List<WindowSnapshot>> byVersion = svc.debugWindows().stream()
                .collect(Collectors.groupingBy(WindowSnapshot::ruleVersion));
        log.info("[停机前] 窗口按版本分组: {}", byVersion);
        assertEquals(2, byVersion.get(1).get(0).count(), "v1 同窗两条事件计数应为 2");
        assertEquals(2, byVersion.get(2).get(0).count());
        assertTrue(byVersion.get(2).get(0).alerted());
        assertEquals(1, svc.listAlerts().size());

        // ---- 正常停机 -> 重启恢复（两版本规则都恢复）----
        assertTrue(harness.shutdownCheckpoint());
        DetectionService restarted = harness.restart();
        assertNotNull(restarted);

        // 在线最新规则仍是 v2（不回退）
        assertEquals(2, restarted.getEngine().getRule("R-BRUTE-FORCE").orElseThrow().version());

        // 两版本窗口都恢复，且各自独立
        Map<Integer, List<WindowSnapshot>> restored = restarted.debugWindows().stream()
                .collect(Collectors.groupingBy(WindowSnapshot::ruleVersion));
        log.info("[重启后] 窗口按版本分组: {}", restored);
        assertEquals(2, restored.get(1).get(0).count(), "v1 窗口计数必须原样恢复，不被 v2 串改");
        assertFalse(restored.get(1).get(0).alerted(), "v1 窗口从未告警，恢复后也不得告警");
        assertEquals(2, restored.get(2).get(0).count(), "v2 窗口计数必须原样恢复");
        assertTrue(restored.get(2).get(0).alerted(), "v2 已告警标记必须延续");

        // 历史告警按版本恢复
        Map<String, Alert> alerts = restarted.listAlerts().stream()
                .collect(Collectors.toMap(Alert::getAlertId, a -> a));
        assertEquals(1, alerts.size());
        Alert v2Alert = alerts.get(v2AlertId);
        assertEquals(2, v2Alert.getRuleVersion(), "告警必须挂在 v2 版本下");

        // ---- 重启后新事件按 v2 判定，不回写 v1 ----
        // v1 窗口里再补一个本可越 v1 阈值的事件：但它是“新到达”，按 v2 处理；
        // T+3s 对 v2 当前 watermark（~T+41s）落后 38s > 10s => TOO_LATE（v2 判定），v1 计数不变
        IngestResult late = restarted.ingest(edr("after-v1c", "host-A", T + 3_000));
        assertEquals(IngestOutcome.TOO_LATE, late.outcome(),
                "重启后的新到达事件按 v2 判定：落后 v2 watermark 超容忍 => TOO_LATE");
        assertEquals(2, restarted.debugWindows().stream()
                .filter(w -> w.ruleVersion() == 1).findFirst().orElseThrow().count(),
                "迟到事件不得回写 v1 窗口");

        // v2 窗口再来事件：v2 已告警窗口不重复告警；另一个 v2 新窗口可独立计数/告警
        IngestResult sameWindowDupContent = restarted.ingest(edr("v2-c", "host-A", T + 42_000));
        assertFalse(sameWindowDupContent.outcome() == IngestOutcome.ACCEPTED_ALERT,
                "v2 已告警窗口再进事件不得重复告警");
        List<IngestResult> newWindow = restarted.ingestBatch(List.of(
                edr("v2-w3-a", "host-A", T + 80_000),
                edr("v2-w3-b", "host-A", T + 81_000)));
        assertEquals(IngestOutcome.ACCEPTED_ALERT, newWindow.get(1).outcome());
        assertTrue(newWindow.get(1).alertId().contains("-v2-"));

        // 全程只有两条告警（v2 的两个不同窗口），v1 从未告警
        List<Alert> all = restarted.listAlerts();
        assertEquals(2, all.size(), "版本隔离下不能多/漏告警");
        assertTrue(all.stream().allMatch(a -> a.getRuleVersion() == 2),
                "v1 历史窗口不得在重启后被补告警");
        log.info("[版本隔离结论] alerts={}, stats={}",
                all.stream().map(a -> a.getAlertId() + "/" + a.getRuleVersion()).toList(),
                restarted.stats());
    }
}
