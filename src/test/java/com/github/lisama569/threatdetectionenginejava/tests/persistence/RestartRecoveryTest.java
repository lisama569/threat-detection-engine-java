package com.github.lisama569.threatdetectionenginejava.tests.persistence;

import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryPhase;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryReport;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;

import com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.MutableClock;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.RestartableHarness;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.fixedClock;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logStats;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logWindows;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.newService;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 重启续跑：正常续跑、恢复期间并发摄入、状态缺失/损坏、回收边界、规则版本切换后重启。
 */
class RestartRecoveryTest {

    private static final Logger log = LoggerFactory.getLogger(RestartRecoveryTest.class);

    private static final long T = 1_790_000_000_000L;
    private static final long WINDOW = 60_000L;
    private static final long TOLERANCE = 10_000L;
    private static final int THRESHOLD = 3;

    @TempDir
    Path tempDir;

    @Test
    @DisplayName("正常重启续跑：窗口计数/去重/迟到基准/告警状态延续，结论与从不重启完全一致")
    void restartResumesAndConclusionsMatchNoRestart() {
        MutableClock clock = fixedClock();
        RestartableHarness h = new RestartableHarness(tempDir.resolve("normal"), clock);
        h.seedRuleIfFresh(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        DetectionService restarted = h.service;

        // 全序列：重启前喂前 8 条，重启后喂后 4 条（含重复/内容去重/越阈/迟到/非法）
        RawEvent e1 = edr("n-1s", "host-A", T + 1_000);
        RawEvent e2 = edr("n-5s", "host-A", T + 5_000);
        RawEvent e3 = edr("n-1s", "host-A", T + 1_000);   // 投递层重复
        RawEvent e4 = edr(null, "host-A", T + 5_000);     // 无 deliveryId 同内容 => 窗口内内容去重
        RawEvent e5 = edr("n-9s", "host-A", T + 9_000);   // 第 3 个去重事件 => 越阈告警
        RawEvent e6 = edr("n-late1", "host-A", T - 6_000);// watermark=9s，落后 15s => TOO_LATE
        RawEvent e7 = edr("unknown-src", "n-x", "host-A", "login_failure", T + 2_000); // REJECTED
        RawEvent e8 = edr("n-5s", "host-A", T + 5_000);   // 再投历史事件 => 投递层重复
        RawEvent e9 = edr("n-61s", "host-A", T + 61_000); // 第二窗
        RawEvent e10 = edr("n-62s", "host-A", T + 62_000);
        RawEvent e11 = edr("n-1s", "host-A", T + 1_000);  // 重启后再投历史投递 => 仍重复
        RawEvent e12 = edr("n-63s", "host-A", T + 63_000);// 第二窗越阈
        List<RawEvent> all = List.of(e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12);

        List<IngestResult> pre = restarted.ingestBatch(all.subList(0, 8));
        assertEquals(IngestOutcome.DUPLICATE, pre.get(2).outcome());
        assertEquals(IngestOutcome.DUPLICATE, pre.get(3).outcome());
        assertEquals(IngestOutcome.ACCEPTED_ALERT, pre.get(4).outcome());
        assertEquals(IngestOutcome.TOO_LATE, pre.get(5).outcome());
        assertEquals(IngestOutcome.REJECTED, pre.get(6).outcome());
        assertEquals(IngestOutcome.DUPLICATE, pre.get(7).outcome());
        logWindows("重启前-窗口", restarted);

        // 重启前确认告警并加备注，验证处置状态延续
        String alertId = pre.get(4).alertId();
        restarted.transitionAlert(alertId, AlertStatus.ACKNOWLEDGED, "重启前已人工确认");

        // ---- 优雅停机 + 用同一本地状态重启 ----
        RecoveryReport report = h.restart();
        log.info("===== 重启完成：report={} =====", report);
        assertEquals("RESTORED", report.status());
        assertEquals(RecoveryPhase.ACTIVE, h.recovery.phase());
        assertEquals(1, report.restoredAlerts());
        assertEquals(1, report.restoredWindowStates());
        assertEquals(5, report.restoredDedupKeys(),
                "登记键=e1/e2/e5/e8 四个投递键 + e4 的无 deliveryId 指纹键；迟到与拒绝不登记");
        DetectionService resumed = h.service;
        logWindows("重启后-窗口（计数/指纹/watermark 应延续）", resumed);

        Alert alert = resumed.listAlerts().stream()
                .filter(a -> a.getAlertId().equals(alertId)).findFirst().orElseThrow();
        assertEquals(AlertStatus.ACKNOWLEDGED, alert.getStatus(), "告警处置状态必须延续");
        assertEquals("重启前已人工确认", alert.getResolutionNote());

        List<IngestResult> post = resumed.ingestBatch(all.subList(8, 12));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, post.get(0).outcome());
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, post.get(1).outcome());
        assertEquals(IngestOutcome.DUPLICATE, post.get(2).outcome(), "重启后历史投递仍须判重");
        assertEquals(IngestOutcome.ACCEPTED_ALERT, post.get(3).outcome());
        logWindows("重启后再投-窗口", resumed);
        logStats(resumed);

        // ---- 对照组：从头到尾不重启，按同样顺序投同一批事件 ----
        DetectionService control = newService(h.registry, clock);
        control.deployRule(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        List<IngestResult> controlAll = control.ingestBatch(all);
        control.transitionAlert(alertId, AlertStatus.ACKNOWLEDGED, "重启前已人工确认");

        List<IngestResult> resumedAll = concatResults(pre, post);
        for (int i = 0; i < all.size(); i++) {
            assertEquals(controlAll.get(i).outcome(), resumedAll.get(i).outcome(),
                    "第 " + (i + 1) + " 条事件结论必须与从不重启一致");
            assertEquals(controlAll.get(i).alertId(), resumedAll.get(i).alertId(),
                    "第 " + (i + 1) + " 条告警 ID 必须与从不重启一致");
        }
        assertEquals(control.stats(), resumed.stats(), "重启续跑的守恒统计必须与从不重启一致");
        assertEquals(control.rejectionBreakdown(), resumed.rejectionBreakdown());
        assertEquals(control.listAlerts().size(), resumed.listAlerts().size(), "不多告警也不漏告警");
        assertEquals(2, resumed.listAlerts().size());
        assertEquals(1, resumed.listAlerts().stream()
                .filter(a -> a.getAlertId().equals(alertId)).count(), "第一窗不能因重启再告警");
    }

    private static List<IngestResult> concatResults(List<IngestResult> a, List<IngestResult> b) {
        java.util.ArrayList<IngestResult> all = new java.util.ArrayList<>(a);
        all.addAll(b);
        return all;
    }

    @Test
    @DisplayName("恢复期间并发摄入：恢复中的请求被 503 挡住，恢复后不丢不重、计数守恒")
    void ingestDuringRecoveryIsRejectedAndNoDoubleCountAfter() throws Exception {
        MutableClock clock = fixedClock();
        Path dir = tempDir.resolve("concurrent");
        RestartableHarness h = new RestartableHarness(dir, clock);
        h.seedRuleIfFresh(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        // 重启前先放 2 条（计数 2/3，watermark=T+2s）
        h.service.ingest(edr("c-2s", "host-A", T + 2_000));
        h.service.ingest(edr("c-1s", "host-A", T + 1_000));
        // 停机前再在“当前窗口”放 2 条（参考时间附近，重启后该窗口仍存活、计数 2/3 可见）
        long now = clock.millis();
        h.service.ingest(edr("c-now1", "host-A", now));
        h.service.ingest(edr("c-now2", "host-A", now + 1_000));
        h.stop();

        // 停机后直接启动一套新组件但“先不恢复”，让服务停在 RECOVERING
        h.boot(false);
        assertEquals(RecoveryPhase.RECOVERING, h.service.getPhase());

        // 恢复期间多线程并发投同一实体：全部必须被 RECOVERING 挡下，不能按空实例计数
        int threads = 16;
        java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ExecutorService pool =
                java.util.concurrent.Executors.newFixedThreadPool(threads);
        java.util.List<java.util.concurrent.Future<Boolean>> futures = new java.util.ArrayList<>();
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            futures.add(pool.submit(() -> {
                start.await();
                try {
                    h.service.ingest(edr("c-during-" + idx, "host-A", T + 3_000 + idx));
                    return false; // 不应该成功
                } catch (com.github.lisama569.threatdetectionenginejava.persistence
                        .RecoveryInProgressException expected) {
                    return true;
                }
            }));
        }
        start.countDown();
        for (java.util.concurrent.Future<Boolean> f : futures) {
            assertEquals(Boolean.TRUE, f.get(), "恢复期间的摄入必须被拒绝（503），不能按空实例处理");
        }
        pool.shutdown();
        log.info("恢复期间 {} 个并发摄入请求全部被 RECOVERING 拒绝，计数未被污染", threads);

        // 完成恢复：恢复期间被拒的请求没有被计入，也不会在恢复后被重复补算
        RecoveryReport report = h.recovery.initialize();
        assertEquals("RESTORED", report.status());
        assertEquals(RecoveryPhase.ACTIVE, h.service.getPhase());
        logWindows("恢复完成后-窗口（当前窗应为 2/3，旧窗已安全回收）", h.service);
        // 当前存活窗口计数仍是停机前的 2，恢复期间被拒请求一律没计入
        long liveCount = h.service.debugWindows().stream()
                .mapToLong(w -> w.windowStart() <= now && now < w.windowEnd() ? w.count() : 0)
                .sum();
        assertEquals(2, liveCount, "恢复期间被拒请求不得计入仍存活窗口");

        // 恢复后同实体高并发：30 个不同事件/30 线程，去重计数精确、越阈告警恰好一条
        int n = 30;
        java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.ExecutorService pool2 =
                java.util.concurrent.Executors.newFixedThreadPool(n);
        java.util.List<java.util.concurrent.Future<IngestOutcome>> outs =
                new java.util.ArrayList<>();
        for (int i = 0; i < n; i++) {
            final int idx = i;
            outs.add(pool2.submit(() -> {
                go.await();
                return h.service.ingest(edr("c-after-" + idx, "host-A", now + 2_000 + idx)).outcome();
            }));
        }
        go.countDown();
        int alerts = 0;
        for (java.util.concurrent.Future<IngestOutcome> f : outs) {
            if (f.get() == IngestOutcome.ACCEPTED_ALERT) {
                alerts++;
            }
        }
        pool2.shutdown();
        assertEquals(1, alerts, "恢复后并发摄入，同一窗口只能产生一条告警");
        logStats(h.service);
    }

    @Test
    @DisplayName("状态缺失=全新启动；状态损坏默认拒绝服务，允许丢弃时才可区分地全新启动")
    void missingStateIsFreshAndCorruptStateIsRejected() throws Exception {
        MutableClock clock = fixedClock();

        // 1) 状态缺失：全新目录 => FRESH 且正常放行（与损坏明确区分）
        RestartableHarness fresh = new RestartableHarness(tempDir.resolve("missing"), clock);
        RecoveryReport freshReport = fresh.recovery.report();
        assertEquals("FRESH", freshReport.status());
        assertEquals(RecoveryPhase.ACTIVE, fresh.service.getPhase());
        log.info("缺失状态恢复结论: {}", freshReport);

        // 2) 造一份合法状态
        fresh.seedRuleIfFresh(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        fresh.service.ingest(edr("m-1s", "host-A", T + 1_000));
        fresh.stop();

        // 3) 损坏状态文件（篡改内容，校验和必然不匹配）
        Path stateFile = tempDir.resolve("missing").resolve("state.json");
        java.nio.file.Files.writeString(stateFile,
                java.nio.file.Files.readString(stateFile).replace("\"threshold\":3", "\"threshold\":9"));

        // 默认策略：损坏 => initialize 不杀进程，实例进入 FAILED，写入被拒，且不覆盖现场
        RestartableHarness corrupt =
                RestartableHarness.uninitialized(tempDir.resolve("missing"), clock);
        RecoveryReport corruptReport = corrupt.recovery.initialize();
        assertEquals("CORRUPT", corruptReport.status());
        assertEquals(RecoveryPhase.FAILED, corrupt.service.getPhase());
        assertThrowsAsRuntime(com.github.lisama569.threatdetectionenginejava.persistence
                .RecoveryFailedException.class, () -> corrupt.service.ingest(
                edr("m-after", "host-A", T + 2_000)));
        // 读路径仍可用：统计/恢复状态可见
        log.info("FAILED 阶段 /api/stats 视角: stats={}, recovery.status={}",
                corrupt.service.stats(), corrupt.recovery.report().status());
        // 损坏文件仍然保留，便于运维排查（未被空状态覆盖）
        org.junit.jupiter.api.Assertions.assertTrue(
                java.nio.file.Files.readString(stateFile).contains("\"threshold\":9"));

        // fail-fast 开关：显式要求时 initialize 直接抛 RecoveryFailedException（阻止启动）
        RestartableHarness failFast =
                RestartableHarness.uninitialized(tempDir.resolve("missing"), clock);
        failFast.recovery.setFailFastOnCorrupt(true);
        assertThrowsAsRuntime(com.github.lisama569.threatdetectionenginejava.persistence
                .RecoveryFailedException.class, () -> failFast.recovery.initialize());

        // 4) 显式允许丢弃：同一损坏目录 => 清空并全新启动，状态结论可区分（status=CORRUPT 但 ACTIVE）
        RestartableHarness wiped =
                RestartableHarness.uninitializedAllowingFresh(tempDir.resolve("missing"), clock);
        wiped.recovery.initialize();
        RecoveryReport wipedReport = wiped.recovery.report();
        assertEquals(RecoveryPhase.ACTIVE, wiped.service.getPhase());
        assertEquals("CORRUPT", wipedReport.status(), "即使全新放行，状态结论仍标记为 CORRUPT 可追溯");
        log.warn("允许丢弃后的恢复结论: {}", wipedReport);
        // 全新实例：无历史窗口/告警，可正常摄入
        wiped.seedRuleIfFresh(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT,
                wiped.service.ingest(edr("m-clean", "host-A", T + 1_000)).outcome());
    }

    private static <T extends RuntimeException> void assertThrowsAsRuntime(Class<T> type,
                                                                            Runnable r) {
        try {
            r.run();
        } catch (RuntimeException e) {
            if (type.isInstance(e)) {
                return;
            }
            throw new AssertionError("期望异常 " + type + "，实际 " + e.getClass(), e);
        }
        throw new AssertionError("期望异常 " + type + " 但未抛出");
    }

    @Test
    @DisplayName("停机前空闲一段再重启：仍在迟到容忍内的窗口计数/告警态必须延续，逐条结论与从不重启一致")
    void idleGapBeforeRestartKeepsWindowsWithinLateTolerance() {
        MutableClock clock = fixedClock();
        long base = clock.millis(); // 已对齐 60s 窗口
        RestartableHarness h = new RestartableHarness(tempDir.resolve("idle"), clock);
        h.seedRuleIfFresh(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        DetectionService svc = h.service;

        // host-A：第一窗 [base, base+60s) 计数 2/3，未告警；事件靠近窗口尾部，模拟“最后一批事件后安静下来”
        RawEvent a1 = edr("i-a-1", "host-A", base + 57_000);
        RawEvent a2 = edr("i-a-2", "host-A", base + 58_000);
        // host-B：第一窗计数已到 3，已告警（验证“是否已告警”状态也必须延续）
        RawEvent b1 = edr("i-b-1", "host-B", base + 57_000);
        RawEvent b2 = edr("i-b-2", "host-B", base + 58_000);
        RawEvent b3 = edr("i-b-3", "host-B", base + 59_000);

        List<IngestResult> pre = svc.ingestBatch(List.of(a1, a2, b1, b2, b3));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, pre.get(0).outcome());
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, pre.get(1).outcome());
        assertEquals(IngestOutcome.ACCEPTED_ALERT, pre.get(4).outcome(),
                "host-B 第 3 条越阈告警");
        String bAlertId = pre.get(4).alertId();
        logWindows("停机前（空闲前）-窗口", svc);

        // ---- 停机前安静 12s 没有任何新事件 ----
        // watermark 停在 base+58s/base+59s（窗内），窗末 base+60s；
        // 旧实现拿墙钟 base+71s 减容忍 = base+61s >= 窗末，把仍可接受迟到事件的第一窗误删；
        // 连续运行的进程空闲时根本不触发回收，窗口本应原样保留。
        clock.setMillis(base + 71_000);

        RecoveryReport report = h.restart();
        log.info("===== 空闲后重启完成：report={} =====", report);
        assertEquals("RESTORED", report.status());

        List<Long> retainedStarts = h.service.debugWindows().stream()
                .map(w -> w.windowStart()).sorted().toList();
        log.info("空闲后重启保留的窗口起点: {}", retainedStarts);
        org.junit.jupiter.api.Assertions.assertTrue(retainedStarts.contains(base),
                "空闲再重启后，按事件时间仍在迟到容忍内的第一窗不能被当成过期窗口丢掉");

        var aState = h.service.findWindowStateForTest("R-BRUTE-FORCE", 1, "host-A").orElseThrow();
        h.service.findWindowStateForTest("R-BRUTE-FORCE", 1, "host-B").orElseThrow();
        assertEquals(base + 58_000, aState.getWatermark(), "watermark（迟到基准）必须延续");
        // 重启后补投前先把两实体窗口态打印出来，日志可直接看到计数延续
        logWindows("重启后、补投前-窗口（host-A 应仍为 2/3 未告警；host-B 应仍为 3/3 已告警）",
                h.service);

        // ---- 重启后逐条补投：边界对照 + 同窗补一条凑阈值 ----
        // 重启后 host-A watermark=base+58s：
        // 1) 恰好等于迟到容忍边界（落后正好 10000ms）=> 接受（落在同一个 60s 窗，成为第 3 个去重事件 => 越阈告警）
        RawEvent aEq = edr("i-a-eq-tol", "host-A", base + 58_000 - TOLERANCE);
        // 2) 再多超 1ms => 必须判 TOO_LATE，且不推进 watermark
        RawEvent aOver = edr("i-a-over-tol-1ms", "host-A", base + 58_000 - TOLERANCE - 1);
        // 3) 边界事件已凑够阈值后，再投同窗事件 => 接受但不能重复告警
        RawEvent a3 = edr("i-a-3", "host-A", base + 58_500);
        // host-B：已告警窗口再补一条同窗事件 => 接受但绝不能重复告警，统计也不能多记告警
        RawEvent b4 = edr("i-b-4", "host-B", base + 59_500);

        List<RawEvent> postBatch = List.of(aEq, aOver, a3, b4);
        List<IngestResult> post = h.service.ingestBatch(postBatch);
        EngineTestFixtures.logBatch("空闲重启后补投", postBatch, post);
        assertEquals(IngestOutcome.ACCEPTED_ALERT, post.get(0).outcome(),
                "恰好等于迟到容忍边界必须接受（重启前后一致），且接续停机前计数 2->3 越阈告警");
        assertEquals(IngestOutcome.TOO_LATE, post.get(1).outcome(),
                "超出容忍 1ms 必须判迟到（重启前后一致）");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, post.get(2).outcome(),
                "已告警窗口内再投事件不能重复告警");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, post.get(3).outcome(),
                "host-B 已告警窗口重启后续投不能重复告警");
        logWindows("重启后补投后-窗口", h.service);
        logStats(h.service);

        // 告警集合：host-B 停机前的告警 + host-A 重启后凑够阈值的告警，各一条，不多不少
        List<String> resumedAlerts = h.service.listAlerts().stream()
                .map(Alert::getAlertId).sorted().toList();
        log.info("空闲重启实例最终告警集合: {}", resumedAlerts);
        assertEquals(2, resumedAlerts.size(), "不多告警也不漏告警");
        org.junit.jupiter.api.Assertions.assertTrue(resumedAlerts.contains(bAlertId),
                "停机前已产生的告警必须延续，不能因重启再产生一条");
        org.junit.jupiter.api.Assertions.assertTrue(resumedAlerts.contains(post.get(0).alertId()),
                "重启后接续计数越阈（恰在容忍边界那条成为第 3 个去重事件）必须产生告警");
        org.junit.jupiter.api.Assertions.assertNotEquals(bAlertId, post.get(0).alertId(),
                "host-A 的新告警与 host-B 停机前的告警是两条不同告警");

        // ---- 对照组：进程从头到尾不重启，时钟同样空闲推进，按同样顺序投同一批事件 ----
        MutableClock controlClock = fixedClock();
        DetectionService control = newService(h.registry, controlClock);
        control.deployRule(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        List<IngestResult> cPre = control.ingestBatch(List.of(a1, a2, b1, b2, b3));
        controlClock.setMillis(base + 58_000); // 同样空闲，但不重启、不回收
        List<IngestResult> cPost = control.ingestBatch(postBatch);
        EngineTestFixtures.logBatch("对照组（从不重启）空闲后补投", postBatch, cPost);

        List<IngestResult> resumedAll = concatResults(pre, post);
        List<IngestResult> controlAll = concatResults(cPre, cPost);
        for (int i = 0; i < controlAll.size(); i++) {
            assertEquals(controlAll.get(i).outcome(), resumedAll.get(i).outcome(),
                    "第 " + (i + 1) + " 条事件结论（计数/告警/重复/迟到/拒绝）必须与从不重启一致");
            assertEquals(controlAll.get(i).alertId(), resumedAll.get(i).alertId(),
                    "第 " + (i + 1) + " 条事件的告警 ID 必须与从不重启一致");
        }
        assertEquals(control.stats(), h.service.stats(),
                "守恒统计必须完全一致：不能多记一条告警，也不能漏记");
        assertEquals(control.rejectionBreakdown(), h.service.rejectionBreakdown());
        List<String> controlAlerts = control.listAlerts().stream()
                .map(Alert::getAlertId).sorted().toList();
        assertEquals(controlAlerts, resumedAlerts, "最终告警集合必须与从不重启一致");
    }

    @Test
    @DisplayName("状态回收后的边界事件：恰好等于容忍/窗口边界的判定在重启前后不改变")
    void boundaryEventsAfterCompactionUnchanged() {
        MutableClock clock = fixedClock();
        RestartableHarness h = new RestartableHarness(tempDir.resolve("compaction"), clock);
        h.seedRuleIfFresh(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        DetectionService svc = h.service;

        // 已对齐窗口：aligned 是某个 60s 窗的起点
        long aligned = Math.floorDiv(T, WINDOW) * WINDOW + WINDOW;

        // 旧窗 [aligned, aligned+60s) 内 3 个事件 => 越阈产生旧窗告警
        svc.ingest(edr("b-old-1", "host-A", aligned + 1_000));
        svc.ingest(edr("b-old-2", "host-A", aligned + 2_000));
        IngestResult oldAlert = svc.ingest(edr("b-old-3", "host-A", aligned + 3_000));
        assertEquals(IngestOutcome.ACCEPTED_ALERT, oldAlert.outcome());

        // 推进“当前时间”到很久以后（远超旧窗+容忍），停机时旧窗会被安全回收
        long now = aligned + 600_000L;
        clock.setMillis(now);
        // host-A 自身也有“更新的事件时间”推进 watermark：只有这样旧窗才真正越过
        // watermark - 容忍 的安全线（连续运行的进程也是靠事件推进 watermark 才驱逐旧窗，
        // 单纯墙钟流逝/空闲不能成为回收依据）。放 2 条到“当前窗”（计数 2/3，不告警）。
        svc.ingest(edr("b-a-now-1", "host-A", now));
        svc.ingest(edr("b-a-now-2", "host-A", now + 1_000));
        // host-B 当前存活窗放 2 条（计数 2/3，watermark=now+1s），停机后该窗存活
        svc.ingest(edr("b-now-1", "host-B", now));
        svc.ingest(edr("b-now-2", "host-B", now + 1_000));

        h.stop();
        RecoveryReport report = h.restart();
        log.info("回收后重启报告: {}", report);
        // host-A 的旧窗（aligned）已按事件时间安全回收；host-A/host-B 当前窗保留
        List<Long> retainedStarts = h.service.debugWindows().stream()
                .map(w -> w.windowStart()).sorted().toList();
        log.info("重启后保留的窗口起点: {}", retainedStarts);
        org.junit.jupiter.api.Assertions.assertFalse(retainedStarts.contains(aligned),
                "watermark 已远超窗末+容忍：真正不可能再影响判定的旧窗必须被安全回收");
        // 空闲安全保障：当前窗（now 所在窗，仍在迟到容忍内）即使经历空闲也不能被回收带走
        long currentStart = Math.floorDiv(now, WINDOW) * WINDOW;
        org.junit.jupiter.api.Assertions.assertTrue(retainedStarts.contains(currentStart),
                "仍在迟到容忍内的当前窗不能因停机回收被带走");

        // 边界事件 1：恰好等于容忍边界（watermark-eventTime == 10s）=> 与连续运行一致，接受
        IngestResult atBoundary = h.service.ingest(edr("b-eq-tol", "host-B", now + 1_000 - TOLERANCE));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, atBoundary.outcome(),
                "watermark 延续：恰好等于容忍边界必须接受（不能因回收变成别的结论）");
        // 再超 1ms => TOO_LATE
        IngestResult beyond = h.service.ingest(edr("b-over-tol", "host-B", now + 1_000 - TOLERANCE - 1));
        assertEquals(IngestOutcome.TOO_LATE, beyond.outcome());

        // 边界事件 2：旧窗（已回收）里重投历史事件 => 因 watermark 已远超容忍，仍判 TOO_LATE，不复活旧窗
        IngestResult ghost = h.service.ingest(edr("b-old-2", "host-A", aligned + 2_000));
        assertEquals(IngestOutcome.DUPLICATE, ghost.outcome(),
                "旧投递键保留：重投旧事件仍先在投递层判重，不影响任何窗口");
        IngestResult ghostLate = h.service.ingest(edr("b-old-verylate", "host-A", aligned - 15_000));
        assertEquals(IngestOutcome.TOO_LATE, ghostLate.outcome(),
                "回收掉的旧窗不可能再计数：落后 watermark 超容忍的旧时间事件只能判 TOO_LATE");
        org.junit.jupiter.api.Assertions.assertFalse(h.service.debugWindows().stream()
                .anyMatch(w -> w.windowStart() == aligned), "旧窗不得因迟到事件被复活");
        // 更旧窗口也不得被迟到事件创建出来
        long ghostStart = Math.floorDiv(aligned - 15_000, WINDOW) * WINDOW;
        org.junit.jupiter.api.Assertions.assertFalse(h.service.debugWindows().stream()
                .anyMatch(w -> w.windowStart() == ghostStart), "迟到事件不得新建任何窗口");

        // 边界事件 3：窗口对齐边界 now 窗第 3 个事件越阈告警，且旧窗告警仍是旧的那一条
        IngestResult newAlert = h.service.ingest(edr("b-now-3", "host-B", now + 2_000));
        assertEquals(IngestOutcome.ACCEPTED_ALERT, newAlert.outcome());
        org.junit.jupiter.api.Assertions.assertNotEquals(oldAlert.alertId(), newAlert.alertId());
        logWindows("回收边界验证后-窗口", h.service);
        logStats(h.service);

        // 与“从不重启（同样经历回收）”的连续运行对照最终态
        MutableClock controlClock = fixedClock();
        DetectionService control = newService(h.registry, controlClock);
        control.deployRule(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        control.ingest(edr("b-old-1", "host-A", aligned + 1_000));
        control.ingest(edr("b-old-2", "host-A", aligned + 2_000));
        control.ingest(edr("b-old-3", "host-A", aligned + 3_000));
        controlClock.setMillis(now);
        control.ingest(edr("b-a-now-1", "host-A", now));
        control.ingest(edr("b-a-now-2", "host-A", now + 1_000));
        control.ingest(edr("b-now-1", "host-B", now));
        control.ingest(edr("b-now-2", "host-B", now + 1_000));
        control.compactHistory(now); // 连续运行也做同样的回收（按 watermark，结论与不回收一致）
        // 对照组喂同样的“回收后边界事件”
        IngestResult cAt = control.ingest(edr("b-eq-tol", "host-B", now + 1_000 - TOLERANCE));
        IngestResult cOver = control.ingest(edr("b-over-tol", "host-B", now + 1_000 - TOLERANCE - 1));
        IngestResult cGhost = control.ingest(edr("b-old-2", "host-A", aligned + 2_000));
        IngestResult cGhostLate = control.ingest(edr("b-old-verylate", "host-A", aligned - 15_000));
        IngestResult cNewAlert = control.ingest(edr("b-now-3", "host-B", now + 2_000));

        assertEquals(cAt.outcome(), atBoundary.outcome());
        assertEquals(cOver.outcome(), beyond.outcome());
        assertEquals(cGhost.outcome(), ghost.outcome());
        assertEquals(cGhostLate.outcome(), ghostLate.outcome());
        assertEquals(cNewAlert.outcome(), newAlert.outcome());
        assertEquals(control.stats(), h.service.stats(), "回收与不回收必须得到相同守恒统计");
        assertEquals(control.listAlerts().size(), h.service.listAlerts().size());
        // 核心守恒：恢复实例最终 acceptedAlert=2（旧窗 1 + 当前窗 1），不多不少
        assertEquals(2, h.service.stats().acceptedAlert(), "回收不能改变告警数量");
        assertEquals(2, h.service.listAlerts().size());
    }

    @Test
    @DisplayName("停机回收只按 watermark：真正越过 watermark-容忍 的历史窗回收，空闲窗保留，回收不改变结论")
    void shutdownCompactionReclaimsOnlyWatermarkDeadWindows() {
        MutableClock clock = fixedClock();
        long base = clock.millis();
        RestartableHarness h = new RestartableHarness(tempDir.resolve("compact-direct"), clock);
        h.seedRuleIfFresh(rule(1, WINDOW, THRESHOLD, TOLERANCE));
        DetectionService svc = h.service;

        // host-A：旧窗 [base,base+60s) 计数 1
        svc.ingest(edr("d-old", "host-A", base + 1_000));
        // host-A：新事件时间 = base+75s => watermark=base+75s，旧窗 end=base+60s <= 75-10=65s
        // 在线 accept 内部会即时 evict，旧窗当场就没了（这是连续运行的正常行为）。
        svc.ingest(edr("d-new", "host-A", base + 75_000));
        // host-B：事件在 base+58s，然后空闲；其窗 [base,base+60s) 相对 watermark 仍在容忍内
        svc.ingest(edr("d-b-1", "host-B", base + 58_000));

        // 手工把 host-A 的“已死窗口”放回状态（模拟从未触发在线 evict 的历史积累，
        // 例如旧版本窗口、或只做停机回收的实现），验证停机 compact 会按 watermark 安全回收它；
        // 而 host-B 的空闲存活窗即使墙钟领先也必须保留。
        var deadState = com.github.lisama569.threatdetectionenginejava.detection.WindowState.restore(
                "R-BRUTE-FORCE", 1, "host-A", WINDOW, base + 75_000,
                java.util.List.of(new com.github.lisama569.threatdetectionenginejava.detection.WindowState
                        .PersistedWindow(base, java.util.List.of("dead-fp"), false)));
        svc.restoreWindowStates("R-BRUTE-FORCE", 1, java.util.List.of(deadState));
        org.junit.jupiter.api.Assertions.assertTrue(svc.debugWindows().stream()
                .anyMatch(w -> w.entityId().equals("host-A") && w.windowStart() == base),
                "前置：已死旧窗当前仍在内存里，等待停机回收");

        // 墙钟空闲推进到 base+200s（远超一切窗口），停机回收
        clock.setMillis(base + 200_000);
        int reclaimed = svc.compactHistory(clock.millis());
        log.info("停机回收窗口数={}（应只回收 host-A 的已死窗，host-B 空闲存活窗保留）", reclaimed);
        assertEquals(1, reclaimed, "只有真正越过 watermark-容忍 的历史窗被回收");

        List<WindowSnapshotForLog> survivors = svc.debugWindows().stream()
                .map(w -> new WindowSnapshotForLog(w.entityId(), w.windowStart(), w.count(),
                        w.alerted(), w.watermark()))
                .toList();
        log.info("回收后存活窗口: {}", survivors);
        org.junit.jupiter.api.Assertions.assertFalse(svc.debugWindows().stream()
                        .anyMatch(w -> w.entityId().equals("host-A") && w.windowStart() == base),
                "host-A 已死旧窗必须回收");
        org.junit.jupiter.api.Assertions.assertTrue(svc.debugWindows().stream()
                        .anyMatch(w -> w.entityId().equals("host-B") && w.windowStart() == base),
                "host-B 空闲存活窗（watermark=base+58s，窗内事件仍可能到达）不能因墙钟被回收");

        // 回收后判定不变：host-B 补一条仍在容忍内的同窗事件（watermark-eventTime=9s）
        IngestResult accepted = svc.ingest(edr("d-b-2", "host-B", base + 49_000));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, accepted.outcome(),
                "空闲存活窗回收后仍正常计数，结论与不回收一致");
        // host-A 回投死窗里的旧指纹 => 因死窗已回收且 watermark 远超，先看投递层去重/再判迟到
        IngestResult tooLate = svc.ingest(edr("d-a-ghost", "host-A", base + 2_000));
        assertEquals(IngestOutcome.TOO_LATE, tooLate.outcome(),
                "已回收死窗里的历史事件时间落后 watermark 超容忍，只能 TOO_LATE，不复活窗口");
        org.junit.jupiter.api.Assertions.assertFalse(svc.debugWindows().stream()
                .anyMatch(w -> w.entityId().equals("host-A") && w.windowStart() == base),
                "迟到事件不得复活已回收窗口");
    }

    private record WindowSnapshotForLog(String entityId, long windowStart, long count,
                                        boolean alerted, long watermark) {
    }

    @Test
    @DisplayName("规则版本切换后重启：v1/v2 各自窗口与告警互不串，结论与连续运行一致")
    void ruleVersionSwitchAcrossRestartStaysIsolated() {
        MutableClock clock = fixedClock();
        RestartableHarness h = new RestartableHarness(tempDir.resolve("versions"), clock);
        h.seedRuleIfFresh(rule(1, 60_000L, 3, TOLERANCE));
        DetectionService svc = h.service;

        // v1 阶段：同一 60s 窗放 2 条（v1 阈值 3，不告警）
        svc.ingest(edr("v1-a", "host-A", T + 1_000));
        svc.ingest(edr("v1-b", "host-A", T + 2_000));
        // 升级 v2：窗口 30s、阈值 2。新事件按 v2 判定；v1 窗口/计数原样保留不回写
        svc.deployRule(rule(2, 30_000L, 2, TOLERANCE));
        IngestResult v2Alert = svc.ingest(edr("v2-a", "host-A", T + 31_000));
        IngestResult v2Second = svc.ingest(edr("v2-b", "host-A", T + 32_000));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, v2Alert.outcome());
        assertEquals(IngestOutcome.ACCEPTED_ALERT, v2Second.outcome(), "v2 阈值 2，第二条越阈");
        logWindows("版本切换后、重启前", svc);

        // 让停机参考时间紧跟最后事件：此时 v1(60s) 与 v2(30s) 窗口都仍存活，可验证计数延续
        clock.setMillis(T + 33_000);

        // 重启：v1、v2 规则版本与各自窗口/告警都必须恢复，且不串
        RecoveryReport report = h.restart();
        assertEquals("RESTORED", report.status());
        assertEquals(2, report.restoredRules(), "v1 与 v2 两个规则版本都必须恢复");
        logWindows("版本切换后、重启后", h.service);

        // v1 窗口仍在（60s 窗，计数 2，未告警）；v2 窗口（30s 窗）已告警
        var v1State = h.service.findWindowStateForTest("R-BRUTE-FORCE", 1, "host-A");
        var v2State = h.service.findWindowStateForTest("R-BRUTE-FORCE", 2, "host-A");
        org.junit.jupiter.api.Assertions.assertTrue(v1State.isPresent(), "v1 窗口态必须恢复");
        org.junit.jupiter.api.Assertions.assertTrue(v2State.isPresent(), "v2 窗口态必须恢复");

        // 重启后再来一条落在 v1 老窗口时间范围的事件：当前在线规则是 v2，必须按 v2 判，
        // 不能把事件错误计入 v1 窗口（版本不串）
        IngestResult after = h.service.ingest(edr("v-after", "host-A", T + 3_000));
        // 对 v2（30s 窗）而言 T+3s 与 T+31s/32s 不同窗；watermark=T+32s，落后 29s >10s => TOO_LATE
        assertEquals(IngestOutcome.TOO_LATE, after.outcome(),
                "重启后事件只能按在线的 v2 判定，v1 历史窗口不参与，不能串版本");
        // v1 窗口计数仍是 2，未被重启后的事件污染
        long v1Count = h.service.debugWindows().stream()
                .filter(w -> w.ruleVersion() == 1
                        && w.windowStart() == Math.floorDiv(T + 1_000, 60_000L) * 60_000L)
                .mapToLong(w -> w.count()).sum();
        assertEquals(2, v1Count, "v1 窗口计数不得被 v2 阶段/重启后的事件改变");

        // v2 告警恰好一条且 ID 带 v2；没有任何 v1 告警
        List<String> alertIds = h.service.listAlerts().stream().map(Alert::getAlertId).toList();
        log.info("版本隔离重启后告警集合: {}", alertIds);
        org.junit.jupiter.api.Assertions.assertTrue(alertIds.contains(v2Second.alertId()));
        org.junit.jupiter.api.Assertions.assertTrue(
                alertIds.stream().noneMatch(id -> id.contains("-v1-")), "v1 从未越阈，不得有 v1 告警");
        org.junit.jupiter.api.Assertions.assertEquals(1, alertIds.size(), "不多告警不漏告警");
        logStats(h.service);
    }
}
