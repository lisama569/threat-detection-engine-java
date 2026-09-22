package com.github.lisama569.threatdetectionenginejava.tests.concurrency;

import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.store.IngestStats;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.logStats;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.newServiceWithRule;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 并发摄入：
 * 同一实体高并发下计数不丢失、告警恰好一条；处理结果可做守恒统计；
 * 并发重复投递只生效一次；多实体并发互不干扰且总量守恒。
 */
class ConcurrentIngestTest {

    private static final Logger log = LoggerFactory.getLogger(ConcurrentIngestTest.class);

    /** 与窗口对齐的基准，保证所有测试事件落在同一固定窗口。 */
    private static final long T = (1_790_000_000_000L / 60_000L) * 60_000L;

    private static List<IngestResult> runConcurrently(DetectionService service, List<RawEvent> events,
                                                      int threads) throws InterruptedException {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(events.size());
        List<IngestResult> results = new ArrayList<>(events.size());
        for (int i = 0; i < events.size(); i++) {
            results.add(null);
        }
        for (int i = 0; i < events.size(); i++) {
            final int index = i;
            pool.submit(() -> {
                try {
                    start.await();
                    results.set(index, service.ingest(events.get(index)));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "并发任务必须全部完成");
        pool.shutdown();
        pool.awaitTermination(5, TimeUnit.SECONDS);
        return results;
    }

    private static long count(List<IngestResult> results, IngestOutcome outcome) {
        return results.stream().filter(r -> r.outcome() == outcome).count();
    }

    @Test
    @DisplayName("同一实体 100 个事件/50 线程并发：去重计数=100，告警恰好 1 条，无丢失无重复")
    void sameEntityConcurrentCountIsExactAndAlertOnce() throws InterruptedException {
        DetectionService service = newServiceWithRule(rule(1, 60_000L, 50, 60_000L));
        int n = 100;
        List<RawEvent> events = new ArrayList<>();
        // 所有 eventTime 在同一窗口内且乱序跨度小于 60s 容忍，迟到也不发生
        for (int i = 1; i <= n; i++) {
            events.add(edr("c-" + i, "hot-host", T + i * 100L));
        }
        // 打乱投递顺序，模拟真实乱序
        java.util.Collections.shuffle(events, new java.util.Random(42));

        List<IngestResult> results = runConcurrently(service, events, 50);

        log.info("同实体并发结果: total={}, noAlert={}, alert={}, duplicates={}, tooLate={}",
                results.size(), count(results, IngestOutcome.ACCEPTED_NO_ALERT),
                count(results, IngestOutcome.ACCEPTED_ALERT),
                count(results, IngestOutcome.DUPLICATE), count(results, IngestOutcome.TOO_LATE));
        logStats(service);

        assertEquals(n, service.debugWindows().get(0).count(), "计数不得因并发丢失或重复");
        assertEquals(1, count(results, IngestOutcome.ACCEPTED_ALERT), "阈值跨越只能发生一次");
        assertEquals(1, service.listAlerts().size(), "告警不得重复");
        assertEquals(n - 1, count(results, IngestOutcome.ACCEPTED_NO_ALERT));

        // 同一批事件再次并发重投：全部 DUPLICATE，不再有告警
        List<IngestResult> redelivery = runConcurrently(service, events, 50);
        assertEquals(n, count(redelivery, IngestOutcome.DUPLICATE));
        assertEquals(0, count(redelivery, IngestOutcome.ACCEPTED_ALERT));
        assertEquals(1, service.listAlerts().size());
        logStats(service);
    }

    @Test
    @DisplayName("守恒统计：并发处理结果满足 total = 各类结论之和，告警数 == ACCEPTED_ALERT 数")
    void concurrentOutcomesConserve() throws InterruptedException {
        DetectionService service = newServiceWithRule(rule(1, 60_000L, 10, 30_000L));
        int perEntity = 20;
        int entities = 10;
        List<RawEvent> events = new ArrayList<>();
        for (int e = 0; e < entities; e++) {
            String entity = "entity-" + e;
            for (int i = 1; i <= perEntity; i++) {
                events.add(edr("m-" + e + "-" + i, entity, T + i * 100L));
            }
        }
        java.util.Collections.shuffle(events, new java.util.Random(7));

        List<IngestResult> results = runConcurrently(service, events, 32);

        long alertResults = count(results, IngestOutcome.ACCEPTED_ALERT);
        IngestStats s = service.stats();
        log.info("多实体并发: {}", s);
        logStats(service);
        assertEquals(entities * perEntity, s.total());
        assertEquals(s.total(),
                s.rejected() + s.duplicate() + s.tooLate()
                        + s.acceptedNoAlert() + s.acceptedAlert(),
                "摄入结果必须守恒");
        assertEquals(alertResults, s.acceptedAlert());
        assertEquals(service.listAlerts().size(), s.acceptedAlert(),
                "持久告警数必须与 ACCEPTED_ALERT 结论数一致");
        // 每个实体 20 个事件、阈值 10 => 每实体恰好 1 条告警
        assertEquals(entities, service.listAlerts().size());
    }

    @Test
    @DisplayName("同一 deliveryId 被 64 线程并发首投：仅一条生效，其余全部 DUPLICATE")
    void concurrentSameDeliveryIdAppliedOnce() throws InterruptedException {
        DetectionService service = newServiceWithRule(rule(1, 60_000L, 3, 60_000L));
        int n = 64;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(n);
        ExecutorService pool = Executors.newFixedThreadPool(16);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger duplicate = new AtomicInteger();
        Map<IngestOutcome, AtomicInteger> breakdown = new ConcurrentHashMap<>();
        RawEvent shared = edr("race-delivery-id", "race-host", T + 1_000);

        for (int i = 0; i < n; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    IngestResult r = service.ingest(shared);
                    breakdown.computeIfAbsent(r.outcome(), k -> new AtomicInteger()).incrementAndGet();
                    if (r.outcome() == IngestOutcome.ACCEPTED_NO_ALERT) {
                        accepted.incrementAndGet();
                    } else if (r.outcome() == IngestOutcome.DUPLICATE) {
                        duplicate.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS));
        pool.shutdown();

        log.info("同一投递并发结果分布: {}", breakdown);
        assertEquals(1, accepted.get(), "同一 deliveryId 只能有一次生效");
        assertEquals(n - 1, duplicate.get());
        assertEquals(0, service.listAlerts().size());
        logStats(service);
    }

    @Test
    @DisplayName("并发中混入非法与迟到事件：各按可区分原因计数，守恒仍然成立")
    void concurrentRejectedAndLateAlsoConserve() throws InterruptedException {
        DetectionService service = newServiceWithRule(rule(1, 60_000L, 5, 1_000L));
        List<RawEvent> events = new ArrayList<>();
        for (int i = 1; i <= 30; i++) {
            events.add(edr("g-" + i, "good-host", T + i * 100L));
        }
        // 制造迟到：先投递一个很“晚”的水位事件，再投落后超过 1s 的旧事件
        events.add(edr("g-late-anchor", "late-host", T + 30_000));
        events.add(edr("g-late-1", "late-host", T + 1_000));
        events.add(edr("g-late-2", "late-host", T + 2_000));
        // 非法：未注册来源
        events.add(edr("unknown-src", "bad-1", "x-host", "login_failure", T + 1_000));
        // 非法：时间戳坏
        events.add(edr("edr", "bad-2", "bad-host", "login_failure", "garbage-ts"));
        java.util.Collections.shuffle(events, new java.util.Random(99));

        List<IngestResult> results = runConcurrently(service, events, 24);
        log.info("混合并发分布: NO_ALERT={}, ALERT={}, DUPLICATE={}, TOO_LATE={}, REJECTED={}",
                count(results, IngestOutcome.ACCEPTED_NO_ALERT),
                count(results, IngestOutcome.ACCEPTED_ALERT),
                count(results, IngestOutcome.DUPLICATE),
                count(results, IngestOutcome.TOO_LATE),
                count(results, IngestOutcome.REJECTED));
        logStats(service);
        log.info("拒绝原因分布: {}", service.rejectionBreakdown());

        IngestStats s = service.stats();
        assertEquals(events.size(), s.total());
        assertEquals(s.total(), s.rejected() + s.duplicate() + s.tooLate()
                + s.acceptedNoAlert() + s.acceptedAlert());
        assertTrue(s.tooLate() >= 1, "迟到事件必须被标记");
        assertEquals(2, s.rejected());
    }
}
