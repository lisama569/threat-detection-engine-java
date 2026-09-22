package com.github.lisama569.threatdetectionenginejava.tests;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleManager;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.EventType;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.IngestStatus;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowState;
import com.github.lisama569.threatdetectionenginejava.rule.RuleRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 乱序、迟到容忍与窗口阈值测试。
 * 规则：窗口 10s、阈值 3、容忍 5s，仅统计 FAILED_LOGIN。
 */
class OutOfOrderAndLatenessTest {

    private static final Logger log = LoggerFactory.getLogger(OutOfOrderAndLatenessTest.class);

    private static final long T = 1_000_000_000_000L; // 对齐基准
    private RuleRegistry rules;
    private AlertLifecycleManager alerts;
    private CorrelationEngine engine;

    @BeforeEach
    void setUp() {
        rules = new RuleRegistry();
        rules.put(new CorrelationRule("r", 1, List.of(EventType.FAILED_LOGIN), 3, 10_000L, 5_000L));
        alerts = new AlertLifecycleManager();
        engine = new CorrelationEngine(rules, alerts);
    }

    private SecurityEvent evt(String id, String entity, long eventTime) {
        return new SecurityEvent(id, "auth-sys", entity, EventType.FAILED_LOGIN, eventTime, eventTime);
    }

    @Test
    @DisplayName("乱序但在容忍范围内：结论与顺序到达一致，恰好产生一次告警")
    void outOfOrderWithinToleranceIsStable() {
        // 事件时间 1s/3s/2s（同一 10s 窗口），到达时间正常递增（近实时小抖动）
        IngestResult a = engine.evaluate(evt("a", "alice", T + 1_000), T + 1_500).get(0);
        IngestResult c = engine.evaluate(evt("c", "alice", T + 3_000), T + 3_500).get(0);
        IngestResult b = engine.evaluate(evt("b", "alice", T + 2_000), T + 3_800).get(0);

        // 到达顺序 a,c,b（b 乱序），但抖动仅 0.3s，未超过 5s 容忍量：
        // 不标迟到、稳定计数，与按序输入得到完全相同的窗口状态
        log.info("[OOO] a.status={} b.status={} c.status={}", a.status(), b.status(), c.status());
        assertThat(a.status()).isEqualTo(IngestStatus.ACCEPTED);
        assertThat(c.status()).isEqualTo(IngestStatus.ACCEPTED);
        assertThat(b.status()).isEqualTo(IngestStatus.ACCEPTED);

        WindowState state = engine.windowState("r", 1, "alice", T).orElseThrow();
        log.info("[WINDOW] state={}", state);
        assertThat(state.count()).isEqualTo(3);
        assertThat(state.thresholdReached()).isTrue();
        assertThat(state.contributingEventIds()).containsExactly("a", "b", "c");

        long alertCount = alerts.all().stream()
                .filter(x -> x.entityId().equals("alice")).count();
        assertThat(alertCount).isEqualTo(1);
        assertThat(alerts.all().get(0).alertId())
                .isEqualTo("r#v1#alice#" + T);
    }

    @Test
    @DisplayName("容忍范围内的迟到事件仍可补足阈值并产生告警")
    void lateWithinToleranceCanTrigger() {
        // 先到达 4s 与 6s 两个事件；watermark 随后为 6s-5s=1s。
        // 0.5s 的事件在 12s 才到达：窗口 [0,10) deadline=15s 未超容忍，
        // 但事件时间早于 watermark，标记为 LATE_WITHIN_TOLERANCE 且正常计数
        engine.evaluate(evt("e", "bob", T + 4_000), T + 4_500);
        engine.evaluate(evt("f", "bob", T + 6_000), T + 6_500);
        IngestResult late = engine.evaluate(evt("d", "bob", T + 500), T + 12_000).get(0);

        log.info("[LATE-WITHIN] status={}", late.status());
        assertThat(late.status()).isEqualTo(IngestStatus.LATE_WITHIN_TOLERANCE);
        WindowState state = engine.windowState("r", 1, "bob", T).orElseThrow();
        log.info("[WINDOW] state={}", state);
        assertThat(state.count()).isEqualTo(3);
        assertThat(alerts.all()).hasSize(1);
    }

    @Test
    @DisplayName("超出容忍范围的迟到事件被明确标记且不计数、不告警")
    void lateBeyondToleranceMarkedAndNotCounted() {
        engine.evaluate(evt("g", "carol", T + 6_000), T + 6_500);
        engine.evaluate(evt("h", "carol", T + 7_000), T + 7_500);
        // 1s 的事件在 20s 才到达：窗口 [0,10) 容忍到 15s，已超容忍
        IngestResult tooLate = engine.evaluate(evt("i", "carol", T + 1_000), T + 20_000).get(0);

        log.info("[LATE-BEYOND] status={} message={}", tooLate.status(), tooLate.message());
        assertThat(tooLate.status()).isEqualTo(IngestStatus.LATE_BEYOND_TOLERANCE);

        WindowState state = engine.windowState("r", 1, "carol", T).orElseThrow();
        log.info("[WINDOW] state={}", state);
        assertThat(state.count()).isEqualTo(2);
        assertThat(state.thresholdReached()).isFalse();
        assertThat(alerts.all()).isEmpty();
    }

    @Test
    @DisplayName("边界：到达时间恰好等于窗口结束+容忍，仍在容忍内（左闭右闭边界）")
    void boundaryExactlyAtDeadlineAccepted() {
        engine.evaluate(evt("j", "dave", T + 8_000), T + 8_500);
        engine.evaluate(evt("k", "dave", T + 9_000), T + 9_500);
        // 2s 事件恰在 deadline=15s 到达
        IngestResult edge = engine.evaluate(evt("l", "dave", T + 2_000), T + 15_000).get(0);
        log.info("[BOUNDARY] status={}", edge.status());
        assertThat(edge.status()).isNotEqualTo(IngestStatus.LATE_BEYOND_TOLERANCE);
        assertThat(engine.windowState("r", 1, "dave", T).orElseThrow().count()).isEqualTo(3);
        assertThat(alerts.all()).hasSize(1);
    }

    @Test
    @DisplayName("窗口边界抖动：落在相邻窗口的事件不计入同一告警，各自独立判定")
    void windowBoundaryIsolation() {
        // 窗口 [0,10) 两个，窗口 [10,20) 一个 -> 都不告警
        engine.evaluate(evt("m1", "erin", T + 9_999), T + 10_100);
        engine.evaluate(evt("m2", "erin", T + 1_000), T + 10_200);
        engine.evaluate(evt("m3", "erin", T + 10_000), T + 10_300);

        WindowState first = engine.windowState("r", 1, "erin", T).orElseThrow();
        WindowState second = engine.windowState("r", 1, "erin", T + 10_000).orElseThrow();
        log.info("[BOUNDARY] first={} second={}", first, second);
        assertThat(first.count()).isEqualTo(2);
        assertThat(second.count()).isEqualTo(1);
        assertThat(first.thresholdReached()).isFalse();
        assertThat(second.thresholdReached()).isFalse();
        assertThat(alerts.all()).isEmpty();
    }
}
