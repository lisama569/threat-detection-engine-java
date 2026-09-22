package com.github.lisama569.threatdetectionenginejava.tests;

import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestStatus;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.RejectReason;
import com.github.lisama569.threatdetectionenginejava.model.WindowState;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.BASE;
import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.harness;
import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.loginFail;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * 重复投递测试：同一事件（相同 source+eventId）多次投递不得重复计数或重复告警，
 * 且重复投递返回状态与首次结论可区分。
 */
class DuplicateDeliveryTest {

    private static final Logger log = LoggerFactory.getLogger(DuplicateDeliveryTest.class);

    @Test
    @DisplayName("同一事件重复投递：计数不变、告警只产生一次、返回 DUPLICATE 与首次结论")
    void duplicateDoesNotRecount() {
        var h = harness("");

        RawEvent e1 = loginFail("e1", "alice", BASE + 1_000);
        RawEvent e2 = loginFail("e2", "alice", BASE + 2_000);

        IngestOutcome first = h.service().ingest(e1);
        IngestOutcome second = h.service().ingest(e2);
        IngestOutcome dup1 = h.service().ingest(e1);   // 第 3 次调用，但仍是同一条 e1
        IngestOutcome dup2 = h.service().ingest(e1);   // 再次重复
        IngestOutcome third = h.service().ingest(loginFail("e3", "alice", BASE + 3_000));

        WindowState before = h.engine().windowState("brute-force-login", 1, "alice", BASE).orElseThrow();
        log.info("[DUP] statuses first={} dup1={} dup2={} third={}",
                first.status(), dup1.status(), dup2.status(), third.status());
        log.info("[DUP] window={}", before);
        log.info("[DUP] alerts={}", h.alerts().all());

        assertThat(dup1.status()).isEqualTo(IngestStatus.DUPLICATE);
        assertThat(dup1.duplicatedDelivery()).isTrue();
        assertThat(dup2.status()).isEqualTo(IngestStatus.DUPLICATE);
        // 首次评估结论被原样带回，便于解释
        assertThat(dup1.ruleEvaluations()).hasSize(1);
        assertThat(dup1.ruleEvaluations().get(0).windowCount()).isEqualTo(1);

        assertThat(before.count()).isEqualTo(3);
        assertThat(h.alerts().all()).hasSize(1);

        // e3 才让计数达到阈值；重复的 e1 不参与第二次达阈
        assertThat(third.ruleEvaluations().get(0).alertId()).isNotNull();
        assertThat(h.alerts().all()).hasSize(1);
    }

    @Test
    @DisplayName("不同来源使用相同原始 eventId 不被误判为重复")
    void sameOriginIdDifferentSourceIsDistinct() {
        var h = harness("");
        RawEvent fromA = new com.github.lisama569.threatdetectionenginejava.model.RawEvent(
                "auth-sys", "dup-id", null,
                java.util.Map.of("username", "alice", "action", "auth_fail",
                        "ts", java.time.Instant.ofEpochMilli(BASE + 1_000).toString()));
        RawEvent fromB = new com.github.lisama569.threatdetectionenginejava.model.RawEvent(
                "edp-agent", "dup-id", BASE + 2_000,
                java.util.Map.of("host", "alice", "eventType", "fail_login"));

        IngestOutcome a = h.service().ingest(fromA);
        IngestOutcome b = h.service().ingest(fromB);
        log.info("[DUP] globalIds {} / {}", a.deduplicatedEventId(), b.deduplicatedEventId());
        assertThat(a.status()).isNotEqualTo(IngestStatus.DUPLICATE);
        assertThat(b.status()).isNotEqualTo(IngestStatus.DUPLICATE);
        assertThat(a.deduplicatedEventId()).isNotEqualTo(b.deduplicatedEventId());
    }

    @Test
    @DisplayName("重复投递一条非法记录：返回 DUPLICATE 且保留原始可区分拒绝原因")
    void duplicateOfRejectedRecord() {
        var h = harness("");
        RawEvent bad = new RawEvent("unknown-source", "x", 1L, java.util.Map.of("a", "b"));
        IngestOutcome first = h.service().ingest(bad);
        IngestOutcome again = h.service().ingest(bad);
        log.info("[DUP-REJECT] first={}/{} again={}/{}",
                first.status(), first.rejectReason(), again.status(), again.rejectReason());
        assertThat(first.status()).isEqualTo(IngestStatus.REJECTED);
        assertThat(first.rejectReason()).isEqualTo(RejectReason.SOURCE_NOT_REGISTERED);
        assertThat(again.status()).isEqualTo(IngestStatus.DUPLICATE);
        assertThat(again.rejectReason()).isEqualTo(RejectReason.SOURCE_NOT_REGISTERED);
    }
}
