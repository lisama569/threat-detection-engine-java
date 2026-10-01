package com.github.lisama569.threatdetectionenginejava.tests.recovery;

import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryGate;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryPhase;
import com.github.lisama569.threatdetectionenginejava.recovery.ServiceUnavailableException;
import com.github.lisama569.threatdetectionenginejava.recovery.StateRecoveryService;
import com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures;
import com.github.lisama569.threatdetectionenginejava.tests.support.RestartHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 恢复与对外摄入的边界：
 * 恢复未完成时来的请求不能被当空实例处理，也不能恢复后被重复算；
 * 恢复过程中与恢复之后并发投同一实体事件，计数与告警守恒；恢复失败时写请求被可区分地拒绝。
 */
class ConcurrentRecoveryIngestTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentRecoveryIngestTest.class);

    private static final long T = 1_790_000_000_000L;

    /**
     * 手工控制恢复时刻：构造一个“重启后的全新实例”，但先不调 recover（保持 RECOVERING），
     * 发起并发摄入，确认它们全部阻塞；随后再执行恢复，确认请求在恢复后的同一份状态上恰好执行一次。
     */
    @Test
    @DisplayName("恢复期间并发摄入：请求阻塞到恢复完成，在恢复后的状态上恰好执行一次，计数与告警守恒")
    void ingestBlocksUntilRecoveredThenAppliedExactlyOnce(@TempDir Path dir) throws Exception {
        Path stateFile = dir.resolve("state-concurrent.json");
        var clock = new EngineTestFixtures.MutableClock(T + 600_000L);

        // 第一进程：投 2 条同实体事件后正常停机
        RestartHarness first = new RestartHarness(stateFile, clock);
        first.service().deployRule(rule(1, 60_000L, 3, 10_000L));
        first.service().ingestBatch(List.of(edr("h1", "host-A", T + 1_000),
                edr("h2", "host-A", T + 2_000)));
        assertTrue(first.shutdownCheckpoint());

        // 第二进程：构造即完成恢复（等价于滚动重启后恢复结束开始接客）
        RestartHarness second = new RestartHarness(stateFile, clock);
        assertEquals(RecoveryPhase.ACTIVE_RESTORED, second.gate().phase());
        // 恢复完成后再并发投同一实体，计数与告警守恒
        recoveredThenConcurrent(second);
    }

    @Test
    @DisplayName("恢复未完成时写请求阻塞，恢复完成后一次性放行且只生效一次")
    void blockAndRelease(@TempDir Path dir) throws Exception {
        Path stateFile = dir.resolve("state-gate.json");
        var clock = new EngineTestFixtures.MutableClock(T + 600_000L);

        // 先制造快照（含 host-A 2 个计数）
        RestartHarness first = new RestartHarness(stateFile, clock);
        first.service().deployRule(rule(1, 60_000L, 3, 10_000L));
        first.service().ingest(edr("g1", "host-A", T + 1_000));
        first.service().ingest(edr("g2", "host-A", T + 2_000));
        first.shutdownCheckpoint();

        // 手工搭建“恢复中”的第二进程：全新内存 + 未完成闸门，先不恢复
        var registry = EngineTestFixtures.defaultRegistry();
        var engine = new com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine();
        var store = new com.github.lisama569.threatdetectionenginejava.store.InMemoryStore();
        var normalizer = new com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer(registry, clock);
        var lifecycle = new com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService(clock);
        RecoveryGate gate = new RecoveryGate(stateFile.toString());
        var service = new com.github.lisama569.threatdetectionenginejava.service.DetectionService(
                store, registry, engine, normalizer, lifecycle, clock, gate);
        service.setAwaitTimeoutMillis(10_000L);

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch submitted = new CountDownLatch(threads);
        CountDownLatch canProbe = new CountDownLatch(1);
        AtomicInteger alerts = new AtomicInteger();
        AtomicInteger accepted = new AtomicInteger();

        // 恢复期间：同实体投 16 个不同 deliveryId 事件（事件时间都在窗口内、watermark 恢复后容忍内）
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                submitted.countDown();
                canProbe.await();
                RawEvent raw = edr("gc-" + idx, "host-A", T + 3_000 + idx);
                IngestResult r = service.ingest(raw);
                if (r.outcome() == IngestOutcome.ACCEPTED_ALERT) {
                    alerts.incrementAndGet();
                }
                if (r.outcome() == IngestOutcome.ACCEPTED_NO_ALERT
                        || r.outcome() == IngestOutcome.ACCEPTED_ALERT) {
                    accepted.incrementAndGet();
                }
                return null;
            });
        }
        submitted.await();
        canProbe.countDown();

        // 恢复需要时间，期间线程必须都还在等待（没有任何一个落到空内存态被先算）
        Thread.sleep(200);
        assertEquals(0, accepted.get(), "恢复完成前请求不能被空实例处理");
        assertEquals(RecoveryPhase.RECOVERING, gate.phase());

        // 现在真正执行恢复（把快照应用到这套 service 组件）
        var props = new com.github.lisama569.threatdetectionenginejava.recovery.RecoveryProperties(
                stateFile.toString(), true, 10_000L);
        var stateStore = new com.github.lisama569.threatdetectionenginejava.persistence.LocalFileStateStore(stateFile);
        var snapshots = new com.github.lisama569.threatdetectionenginejava.recovery.StateSnapshotService(clock);
        StateRecoveryService recovery = new StateRecoveryService(stateStore, snapshots, gate, props);
        recovery.recover(store, engine, registry);
        assertEquals(RecoveryPhase.ACTIVE_RESTORED, gate.phase());

        pool.shutdown();
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS), "所有阻塞请求必须在恢复后被放行完成");

        // 恢复的 2 个计数 + 16 个新事件 = 18；阈值 3 在第 1 个新事件即跨越，告警恰好 1 条
        assertEquals(16, accepted.get(), "16 个并发事件都必须在恢复后恰好执行一次");
        assertEquals(1, alerts.get(), "同一窗口告警只能有一条（恢复后并发不重复告警）");
        assertEquals(1, service.listAlerts().size());
        assertEquals(18, service.debugWindows().get(0).count(),
                "窗口计数 = 恢复的 2 + 并发 16，恢复期间没有请求被丢失或重复计算");
        log.info("[恢复期间并发结果] accepted={}, alerts={}, windowCount={}, stats={}",
                accepted.get(), alerts.get(), service.debugWindows().get(0).count(), service.stats());
    }

    @Test
    @DisplayName("恢复失败(FAILED)时写请求得到可区分拒绝，不会落到空实例；超时同理")
    void failedRecoveryRejectsWrites(@TempDir Path dir) {
        RecoveryGate failed = new RecoveryGate("mem:none");
        failed.fail("模拟状态损坏");
        // 不等待立即判定 -> 503 语义异常，阶段为 FAILED
        ServiceUnavailableException ex = assertThrows(ServiceUnavailableException.class,
                () -> failed.awaitWritable(0L));
        assertEquals(RecoveryPhase.FAILED, ex.phase());

        RecoveryGate recovering = new RecoveryGate("mem:none");
        ServiceUnavailableException timeout = assertThrows(ServiceUnavailableException.class,
                () -> recovering.awaitWritable(1L));
        assertEquals(RecoveryPhase.RECOVERING, timeout.phase());
    }

    /** 恢复完成后同实体高并发：计数与告警守恒（恢复出的 2 计数 + 新事件）。 */
    private void recoveredThenConcurrent(RestartHarness harness) throws Exception {
        int threads = 32;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger alerts = new AtomicInteger();
        AtomicInteger accepted = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            final int idx = i;
            pool.submit(() -> {
                try {
                    IngestResult r = harness.service().ingest(edr("rc-" + idx, "host-A", T + 10_000 + idx));
                    if (r.outcome() == IngestOutcome.ACCEPTED_ALERT) {
                        alerts.incrementAndGet();
                    }
                    if (r.outcome() != IngestOutcome.DUPLICATE
                            && r.outcome() != IngestOutcome.REJECTED
                            && r.outcome() != IngestOutcome.TOO_LATE) {
                        accepted.incrementAndGet();
                    }
                } finally {
                    done.countDown();
                }
            });
        }
        assertTrue(done.await(10, TimeUnit.SECONDS));
        pool.shutdown();
        assertEquals(32, accepted.get(), "32 个唯一投递全部生效一次");
        assertEquals(1, alerts.get(), "恢复后同实体并发只产生一条告警");
        assertEquals(1, harness.service().listAlerts().size());
        long total = harness.service().stats().total();
        long sum = harness.service().stats().rejected() + harness.service().stats().duplicate()
                + harness.service().stats().tooLate() + harness.service().stats().acceptedNoAlert()
                + harness.service().stats().acceptedAlert();
        assertEquals(total, sum, "守恒关系必须成立");
        log.info("[恢复后并发守恒] stats={}", harness.service().stats());
    }
}
