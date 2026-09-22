package com.github.lisama569.threatdetectionenginejava.tests;

import com.github.lisama569.threatdetectionenginejava.alert.AlertIds;
import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleManager;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.TransitionReject;
import com.github.lisama569.threatdetectionenginejava.model.TransitionResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 告警生命周期与幂等登记测试，非法迁移原因必须可区分。
 */
class AlertLifecycleTest {

    private static final Logger log = LoggerFactory.getLogger(AlertLifecycleTest.class);

    private AlertLifecycleManager manager;

    @BeforeEach
    void setUp() {
        manager = new AlertLifecycleManager();
    }

    private Alert sample(String id) {
        return new Alert(id, "r", 1, "alice", 0L, 10_000L, 3, 1L, 9L, 123L, AlertStatus.OPEN);
    }

    @Test
    @DisplayName("合法迁移链 OPEN->ACKNOWLEDGED->RESOLVED")
    void legalChain() {
        manager.registerIfAbsent(sample("a1"));
        TransitionResult ack = manager.transition("a1", AlertStatus.ACKNOWLEDGED);
        TransitionResult resolved = manager.transition("a1", AlertStatus.RESOLVED);
        log.info("[TRANSITION] ack={} resolved={}", ack.accepted(), resolved.accepted());
        assertThat(ack.accepted()).isTrue();
        assertThat(resolved.accepted()).isTrue();
        assertThat(manager.get("a1").orElseThrow().status()).isEqualTo(AlertStatus.RESOLVED);
    }

    @Test
    @DisplayName("允许 OPEN 直接迁移到 RESOLVED")
    void openToResolvedDirectly() {
        manager.registerIfAbsent(sample("a2"));
        TransitionResult result = manager.transition("a2", AlertStatus.RESOLVED);
        assertThat(result.accepted()).isTrue();
    }

    @Test
    @DisplayName("告警不存在：ALERT_NOT_FOUND")
    void notFound() {
        TransitionResult result = manager.transition("nope", AlertStatus.RESOLVED);
        log.info("[TRANSITION-REJECT] reason={} message={}", result.rejectReason(), result.message());
        assertThat(result.accepted()).isFalse();
        assertThat(result.rejectReason()).isEqualTo(TransitionReject.ALERT_NOT_FOUND);
    }

    @Test
    @DisplayName("重复迁移到同一状态：ALREADY_IN_TARGET_STATUS")
    void alreadyInStatus() {
        manager.registerIfAbsent(sample("a3"));
        manager.transition("a3", AlertStatus.ACKNOWLEDGED);
        TransitionResult result = manager.transition("a3", AlertStatus.ACKNOWLEDGED);
        log.info("[TRANSITION-REJECT] reason={} message={}", result.rejectReason(), result.message());
        assertThat(result.accepted()).isFalse();
        assertThat(result.rejectReason()).isEqualTo(TransitionReject.ALREADY_IN_TARGET_STATUS);
    }

    @Test
    @DisplayName("回退迁移 RESOLVED->OPEN 与 ACKNOWLEDGED->OPEN 均为 ILLEGAL_TRANSITION")
    void illegalBackwardTransitions() {
        manager.registerIfAbsent(sample("a4"));
        manager.transition("a4", AlertStatus.RESOLVED);
        TransitionResult reopen = manager.transition("a4", AlertStatus.OPEN);
        assertThat(reopen.accepted()).isFalse();
        assertThat(reopen.rejectReason()).isEqualTo(TransitionReject.ILLEGAL_TRANSITION);

        manager.registerIfAbsent(sample("a5"));
        manager.transition("a5", AlertStatus.ACKNOWLEDGED);
        TransitionResult unack = manager.transition("a5", AlertStatus.OPEN);
        log.info("[TRANSITION-REJECT] reason={} message={}", unack.rejectReason(), unack.message());
        assertThat(unack.accepted()).isFalse();
        assertThat(unack.rejectReason()).isEqualTo(TransitionReject.ILLEGAL_TRANSITION);
    }

    @Test
    @DisplayName("RESOLVED 后不允许再迁移：ILLEGAL_TRANSITION")
    void resolvedIsTerminal() {
        manager.registerIfAbsent(sample("a6"));
        manager.transition("a6", AlertStatus.RESOLVED);
        TransitionResult result = manager.transition("a6", AlertStatus.ACKNOWLEDGED);
        assertThat(result.rejectReason()).isEqualTo(TransitionReject.ILLEGAL_TRANSITION);
    }

    @Test
    @DisplayName("幂等登记：相同 alertId 并发登记只创建一次")
    void concurrentRegisterIsIdempotent() throws InterruptedException {
        String alertId = AlertIds.derive("r", 1, "alice", 0L);
        int threads = 16;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        for (int i = 0; i < threads; i++) {
            pool.submit(() -> {
                try {
                    start.await();
                    manager.registerIfAbsent(sample(alertId));
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            });
        }
        start.countDown();
        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();
        pool.shutdown();

        long created = manager.all().stream().filter(a -> a.alertId().equals(alertId)).count();
        log.info("[IDEMPOTENT-REGISTER] stored alerts with same id = {}", created);
        assertThat(created).isEqualTo(1);
    }
}
