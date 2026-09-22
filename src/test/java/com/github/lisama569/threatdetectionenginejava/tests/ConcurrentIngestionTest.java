package com.github.lisama569.threatdetectionenginejava.tests;

import com.github.lisama569.threatdetectionenginejava.model.BatchReport;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestStatus;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.BASE;
import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.harness;
import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.loginFail;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * 并发摄入测试：同一实体大量并发 + 重复投递混杂，
 * 计数不得丢失或重复，告警恰好一次，统计满足守恒。
 */
class ConcurrentIngestionTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentIngestionTest.class);

    @RepeatedTest(20)
    @DisplayName("同一实体 300 条唯一事件并发摄入：计数精确、恰好一个告警")
    void concurrentSameEntityCountIsExact() {
        var h = harness("");
        int threads = 12;
        int unique = 300;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(unique);
        AtomicInteger alertsSeen = new AtomicInteger();

        for (int i = 0; i < unique; i++) {
            long eventTime = BASE + 1_000 + (i % 8_000); // 全部落在同一 10s 窗口
            RawEvent raw = loginFail("c-" + i, "victim", eventTime);
            pool.submit(() -> {
                try {
                    start.await();
                    IngestOutcome o = h.service().ingest(raw);
                    if (o.ruleEvaluations().stream().anyMatch(e -> e.alertId() != null)) {
                        alertsSeen.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        await(done, pool);

        WindowState state = h.engine()
                .windowState("brute-force-login", 1, "victim", BASE).orElseThrow();
        log.info("[CONCURRENT] unique={} windowCount={} alertsSeenAtIngest={} storedAlerts={}",
                unique, state.count(), alertsSeen.get(),
                h.alerts().all().stream().filter(a -> a.entityId().equals("victim")).count());

        assertThat(state.count()).isEqualTo(unique);
        assertThat(alertsSeen.get()).isEqualTo(1);
        assertThat(h.alerts().all().stream().filter(a -> a.entityId().equals("victim")).count())
                .isEqualTo(1);
    }

    @Test
    @DisplayName("并发摄入中混杂重复投递：去重正确且批量统计守恒")
    void concurrentWithDuplicatesConservation() throws InterruptedException {
        var h = harness("");
        int unique = 100;
        int copies = 3; // 每条唯一事件再重复投递 2 次
        List<RawEvent> all = new ArrayList<>();
        for (int i = 0; i < unique; i++) {
            RawEvent raw = loginFail("d-" + i, "target", BASE + 1_000 + (i % 8_000));
            for (int c = 0; c < copies; c++) {
                all.add(raw);
            }
        }
        java.util.Collections.shuffle(all);

        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        ConcurrentLinkedQueue<IngestOutcome> outcomes = new ConcurrentLinkedQueue<>();
        CountDownLatch done = new CountDownLatch(all.size());
        for (RawEvent raw : all) {
            pool.submit(() -> {
                try {
                    start.await();
                    outcomes.add(h.service().ingest(raw));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        await(done, pool);

        Map<IngestStatus, Integer> tally = new ConcurrentHashMap<>();
        outcomes.forEach(o -> tally.merge(o.status(), 1, Integer::sum));
        log.info("[CONCURRENT-DUP] total={} tally={}", outcomes.size(), tally);

        // 守恒：接受 + 重复 == 总数
        assertThat(tally.values().stream().mapToInt(Integer::intValue).sum()).isEqualTo(all.size());
        assertThat(tally.getOrDefault(IngestStatus.ACCEPTED, 0)
                + tally.getOrDefault(IngestStatus.LATE_WITHIN_TOLERANCE, 0)).isEqualTo(unique);
        assertThat(tally.getOrDefault(IngestStatus.DUPLICATE, 0)).isEqualTo(unique * (copies - 1));

        WindowState state = h.engine()
                .windowState("brute-force-login", 1, "target", BASE).orElseThrow();
        assertThat(state.count()).isEqualTo(unique);
        assertThat(h.alerts().all().stream().filter(a -> a.entityId().equals("target")).count())
                .isEqualTo(1);
    }

    @Test
    @DisplayName("批量并行摄入报告守恒：accepted+duplicate+lateWithin+lateBeyond+rejected == total")
    void batchReportConservation() {
        var h = harness("");
        List<RawEvent> batch = new ArrayList<>();
        for (int i = 0; i < 50; i++) {
            batch.add(loginFail("b-" + i, "multi", BASE + 1_000 + (i % 8_000)));
        }
        for (int i = 0; i < 20; i++) {
            batch.add(loginFail("b-" + i, "multi", BASE + 1_000 + (i % 8_000))); // 重复
        }
        batch.add(new RawEvent("unknown-src", "x", 1L, Map.of("a", "b"))); // 拒绝
        batch.add(new RawEvent("auth-sys", "late-1", null, Map.of(
                "username", "multi", "action", "auth_fail",
                "ts", java.time.Instant.ofEpochMilli(BASE - 100_000).toString()))); // 超容忍迟到

        BatchReport report = h.service().ingestBatch(batch);
        log.info("[BATCH] {}", report);

        int classified = report.accepted() + report.duplicate()
                + report.lateWithinTolerance() + report.lateBeyondTolerance() + report.rejected();
        assertThat(classified).isEqualTo(report.total());
        assertThat(report.duplicate()).isEqualTo(20);
        assertThat(report.rejected()).isEqualTo(1);
        assertThat(report.lateBeyondTolerance()).isEqualTo(1);
    }

    private void await(CountDownLatch done, ExecutorService pool) {
        try {
            assertThat(done.await(30, TimeUnit.SECONDS)).isTrue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        } finally {
            pool.shutdown();
        }
    }
}
