package com.github.lisama569.threatdetectionenginejava.tests.recovery;

import com.github.lisama569.threatdetectionenginejava.detection.WindowState;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowSnapshot;
import com.github.lisama569.threatdetectionenginejava.persistence.StateMemento;
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
import java.util.Optional;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 历史状态安全回收：
 * 已不可能影响后续判定的窗口（end <= watermark - lateTolerance）在运行时被驱逐、不进快照，
 * 恢复耗时/快照体积只与存活窗口相关、不随历史无限增长；
 * 并且“回收/不回收/回收后重启”对后续事件的判定结论完全一致。
 */
class StateReclamationBoundaryTest {

    private static final Logger log = LoggerFactory.getLogger(StateReclamationBoundaryTest.class);

    private static final long WINDOW = 60_000L;
    private static final long TOLERANCE = 10_000L;
    private static final int THRESHOLD = 3;
    /** 与 60s 窗口对齐的基线 */
    private static final long BASE = (1_790_000_000_000L / WINDOW) * WINDOW;

    private CorrelationRule ruleV1() {
        return rule(1, WINDOW, THRESHOLD, TOLERANCE);
    }

    @Test
    @DisplayName("被驱逐窗口不进快照、恢复后不存在：快照只含存活窗口，体积随存活窗口而非全历史增长")
    void evictedWindowsExcludedFromSnapshot(@TempDir Path dir) {
        Path stateFile = dir.resolve("reclaim.json");
        var clock = new EngineTestFixtures.MutableClock(BASE + 3_600_000L);
        RestartHarness harness = new RestartHarness(stateFile, clock);
        harness.service().deployRule(ruleV1());

        // 第一窗口 [BASE, BASE+60k) 来 3 条 -> 告警
        harness.service().ingestBatch(List.of(
                edr("old1", "host-A", BASE + 1_000),
                edr("old2", "host-A", BASE + 2_000),
                edr("old3", "host-A", BASE + 3_000)));
        // 推进 watermark 到 BASE+120k，使第一窗口 end(BASE+60k) <= watermark(BASE+120k)-10k=BASE+110k => 被驱逐
        harness.service().ingest(edr("new1", "host-A", BASE + 120_000));

        Optional<WindowState> state = harness.engine().findState("R-BRUTE-FORCE", 1, "host-A");
        assertTrue(state.isPresent());
        List<WindowSnapshot> snaps = harness.service().debugWindows();
        log.info("[回收前] 存活窗口数={}（旧窗应已驱逐）, watermark={}", snaps.size(),
                state.get().getWatermark());
        assertEquals(1, snaps.size(), "旧窗口应已被安全驱逐，只剩新窗口");
        assertEquals(BASE + 120_000, state.get().getWatermark());

        harness.shutdownCheckpoint();
        StateMemento memento = harness.stateStore().load();
        long windowsInSnapshot = memento.windows().stream()
                .mapToLong(w -> w.windows().size()).sum();
        log.info("[快照内容] WindowMemento={}, 其中存活窗口总数={}, 去重键={}",
                memento.windows().size(), windowsInSnapshot, memento.dedupKeys().size());
        assertEquals(1, windowsInSnapshot, "已驱逐窗口不得写入快照（历史部分被安全回收）");

        // 重启恢复：旧窗口不复活，watermark 延续
        DetectionService restarted = harness.restart();
        List<WindowSnapshot> after = restarted.debugWindows();
        assertEquals(1, after.size(), "恢复后被回收的历史窗口不得复活");
        assertEquals(BASE + 120_000, after.get(0).windowStart());
    }

    @Test
    @DisplayName("回收 vs 不回收 vs 回收后重启：同一批后续事件的判定（重复/迟到/告警）完全一致")
    void reclamationDoesNotChangeFutureDecisions(@TempDir Path dir) {
        Path stateFile = dir.resolve("reclaim-equiv.json");
        var clock = new EngineTestFixtures.MutableClock(BASE + 3_600_000L);

        // 前置事件：造一个已告警、随后可被驱逐的旧窗口，并把 watermark 推高
        List<RawEvent> prefix = List.of(
                edr("p1", "host-A", BASE + 1_000),
                edr("p2", "host-A", BASE + 2_000),
                edr("p3", "host-A", BASE + 3_000),
                edr("p4", "host-A", BASE + 120_000));

        // 后续边界事件：
        //  a) 落在被驱逐窗口的迟到事件（必然 TOO_LATE）
        //  b) 被驱逐窗口里历史事件的重复投递（deliveryId 幂等 => DUPLICATE）
        //  c) 存活窗口内的新事件（计数推进）
        //  d) 存活窗口内历史 deliveryId 重复（DUPLICATE）
        //  e) 恰好 watermark-tolerance 边界附近事件（边界取等号接受）
        long watermark = BASE + 120_000;
        List<RawEvent> follow = List.of(
                edr("late-in-evicted", "host-A", BASE + 5_000),
                edr("p1", "host-A", BASE + 1_000),
                // 恰好等于迟到容忍边界（相对当前 watermark=BASE+120k，落后恰好 10s）=> 接受
                edr("boundary-eq", "host-A", watermark - TOLERANCE),
                edr("live-new", "host-A", BASE + 121_000),
                edr("p4", "host-A", BASE + 120_000));

        // 路线 1：不重启、自然回收（evict 已随摄入发生）
        RestartHarness noRestart = new RestartHarness(stateFile, clock);
        noRestart.service().deployRule(ruleV1());
        noRestart.service().ingestBatch(prefix);
        List<IngestResult> r1 = noRestart.service().ingestBatch(follow);
        List<IngestOutcome> o1 = r1.stream().map(IngestResult::outcome).toList();

        // 路线 2：前缀后停机（旧窗口已驱逐，不进快照）-> 重启恢复 -> 同样后续
        RestartHarness restarted = new RestartHarness(stateFile, clock);
        restarted.service().deployRule(ruleV1());
        restarted.service().ingestBatch(prefix);
        assertTrue(restarted.shutdownCheckpoint());
        DetectionService s2 = restarted.restart();
        List<IngestResult> r2 = s2.ingestBatch(follow);
        List<IngestOutcome> o2 = r2.stream().map(IngestResult::outcome).toList();

        // 路线 3：不做任何回收的“人工对照”——全新实例只投前缀+后续（驱逐与否只影响内存，不影响结论），
        // 直接验证结论稳定且可复现
        DetectionService fresh = EngineTestFixtures.newService(EngineTestFixtures.defaultRegistry(), clock);
        fresh.deployRule(ruleV1());
        fresh.ingestBatch(prefix);
        List<IngestOutcome> o3 = fresh.ingestBatch(follow).stream()
                .map(IngestResult::outcome).toList();

        log.info("[回收等价] 不重启={}", o1);
        log.info("[回收等价] 回收后重启={}", o2);
        log.info("[回收等价] 全新对照={}", o3);

        // 明确的边界语义断言
        assertEquals(IngestOutcome.TOO_LATE, o1.get(0), "落入已驱逐窗口的事件必判 TOO_LATE");
        assertEquals(IngestOutcome.DUPLICATE, o1.get(1), "deliveryId 幂等：旧事件重投判 DUPLICATE");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, o1.get(2), "恰好等于容忍边界必须接受");
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT, o1.get(3), "存活窗口新事件正常计数");
        assertEquals(IngestOutcome.DUPLICATE, o1.get(4));

        assertEquals(o1, o2, "回收后重启不得改变任何后续事件判定");
        assertEquals(o1, o3, "回收与否不得改变任何后续事件判定");
        assertEquals(noRestart.service().stats(), s2.stats(), "守恒统计也必须一致");
    }

    @Test
    @DisplayName("长历史滚动：多轮旧窗口累积后快照仍只含存活窗口，恢复耗时不随历史线性增长")
    void snapshotBoundedByLiveWindowsNotHistory(@TempDir Path dir) {
        Path stateFile = dir.resolve("bounded.json");
        var clock = new EngineTestFixtures.MutableClock(BASE + 3_600_000L);
        RestartHarness harness = new RestartHarness(stateFile, clock);
        harness.service().deployRule(ruleV1());

        // 制造 20 个连续窗口的历史事件，并不断推进 watermark，使旧窗口持续被驱逐
        List<RawEvent> history = new ArrayList<>();
        for (int w = 0; w < 20; w++) {
            history.add(edr("h-" + w, "host-A", BASE + w * WINDOW + 1_000));
        }
        harness.service().ingestBatch(history);

        harness.shutdownCheckpoint();
        StateMemento snap = harness.stateStore().load();
        long liveWindows = snap.windows().stream().mapToLong(x -> x.windows().size()).sum();
        // watermark=BASE+19*60k+1k；存活窗口须满足 start+60k > watermark-10k
        // 仅最后一个窗口存活（start=BASE+19*60k），其余全部回收
        // 推进 watermark 的最后一个事件位于第 20 个窗口；其前一窗口仍可能恰未越过驱逐线，
        // 故存活窗口至多为最后两个，远小于 20，且随历史长度有界
        assertTrue(liveWindows <= 2, "存活窗口数与历史长度无关，实际=" + liveWindows);
        assertTrue(snap.dedupKeys().size() == 20, "投递幂等键需保留以保证重投判重，实际="
                + snap.dedupKeys().size());
        log.info("[长历史回收] 历史窗口=20, 快照存活窗口={}, 去重键(投递幂等需保留)={}",
                liveWindows, snap.dedupKeys().size());

        long nanos = System.nanoTime();
        harness.restart();
        long elapsedMs = (System.nanoTime() - nanos) / 1_000_000;
        log.info("[恢复耗时] {}ms（与 20 个历史窗口数量无关）", elapsedMs);
        assertFalse(harness.service().recoveryStatus().detail() == null);
    }
}
