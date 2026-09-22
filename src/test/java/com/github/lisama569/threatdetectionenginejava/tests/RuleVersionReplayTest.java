package com.github.lisama569.threatdetectionenginejava.tests;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleManager;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.EventType;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.rule.RuleRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.BASE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * 规则版本与重放可复现性测试。
 */
class RuleVersionReplayTest {

    private static final Logger log = LoggerFactory.getLogger(RuleVersionReplayTest.class);

    private static List<SecurityEvent> reversed(List<SecurityEvent> in) {
        List<SecurityEvent> copy = new java.util.ArrayList<>(in);
        java.util.Collections.reverse(copy);
        return copy;
    }

    private SecurityEvent fail(String id, long t) {
        return new SecurityEvent(id, "auth-sys", "alice", EventType.FAILED_LOGIN, t, t);
    }

    @Test
    @DisplayName("规则版本必须单调递增，旧版本永久保留可按版本号取回")
    void versionsMonotonicAndRetained() {
        RuleRegistry rules = new RuleRegistry();
        rules.put(new CorrelationRule("r", 1, List.of(EventType.FAILED_LOGIN), 3, 10_000L, 5_000L));
        rules.put(new CorrelationRule("r", 2, List.of(EventType.FAILED_LOGIN), 2, 10_000L, 5_000L));

        assertThat(rules.current("r").orElseThrow().version()).isEqualTo(2);
        assertThat(rules.getVersion("r", 1).orElseThrow().threshold()).isEqualTo(3);

        assertThatThrownBy(() ->
                rules.put(new CorrelationRule("r", 2, List.of(EventType.FAILED_LOGIN), 5, 10_000L, 0L)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("version must strictly increase");
    }

    @Test
    @DisplayName("同批事件按同一规则版本重放：计数与告警结论完全可复现")
    void replaySameVersionIsReproducible() {
        // 首次引擎实例（模拟首次运行），使用 v1 阈值 3
        RuleRegistry rules1 = new RuleRegistry();
        rules1.put(new CorrelationRule("r", 1, List.of(EventType.FAILED_LOGIN), 3, 10_000L, 5_000L));
        AlertLifecycleManager alerts1 = new AlertLifecycleManager();
        CorrelationEngine engine1 = new CorrelationEngine(rules1, alerts1);

        List<SecurityEvent> batch = List.of(
                fail("e1", BASE + 1_000),
                fail("e2", BASE + 2_000),
                fail("e3", BASE + 3_000));

        for (SecurityEvent e : batch) {
            engine1.evaluateWith(e, e.ingestTimeMs(), "r", 1);
        }
        // 再次“重放”同一批（乱序）：不得新增计数或告警
        for (SecurityEvent e : reversed(batch)) {
            IngestResult r = engine1.evaluateWith(e, e.ingestTimeMs(), "r", 1);
            log.info("[REPLAY-1] eventId={} count={} alertId={}",
                    r.eventId(), r.windowCount(), r.alertId());
        }
        assertThat(engine1.windowState("r", 1, "alice", BASE).orElseThrow().count()).isEqualTo(3);
        assertThat(alerts1.all()).hasSize(1);

        // 全新引擎实例 + 同版本规则，重放同一批事件：结论一致
        RuleRegistry rules2 = new RuleRegistry();
        rules2.put(new CorrelationRule("r", 1, List.of(EventType.FAILED_LOGIN), 3, 10_000L, 5_000L));
        AlertLifecycleManager alerts2 = new AlertLifecycleManager();
        CorrelationEngine engine2 = new CorrelationEngine(rules2, alerts2);
        for (SecurityEvent e : reversed(batch)) {
            engine2.evaluateWith(e, e.ingestTimeMs(), "r", 1);
        }
        var state2 = engine2.windowState("r", 1, "alice", BASE).orElseThrow();
        log.info("[REPLAY-FRESH] state={}", state2);
        assertThat(state2.count()).isEqualTo(3);
        assertThat(state2.contributingEventIds()).containsExactly("e1", "e2", "e3");
        assertThat(alerts2.all()).hasSize(1);
        assertThat(alerts2.all().get(0).alertId()).isEqualTo(alerts1.all().get(0).alertId());
    }

    @Test
    @DisplayName("规则更新为 v2 后：历史事件按 v1 重放结论不变，按 v2 评估得到新版本独立结论")
    void ruleUpdateDoesNotRewriteHistory() {
        RuleRegistry rules = new RuleRegistry();
        rules.put(new CorrelationRule("r", 1, List.of(EventType.FAILED_LOGIN), 3, 10_000L, 5_000L));
        AlertLifecycleManager alerts = new AlertLifecycleManager();
        CorrelationEngine engine = new CorrelationEngine(rules, alerts);

        List<SecurityEvent> batch = List.of(
                fail("e1", BASE + 1_000),
                fail("e2", BASE + 2_000));

        // v1：2 个事件不告警
        for (SecurityEvent e : batch) {
            engine.evaluateWith(e, e.ingestTimeMs(), "r", 1);
        }
        assertThat(alerts.all()).isEmpty();

        // 更新规则：阈值降为 2
        rules.put(new CorrelationRule("r", 2, List.of(EventType.FAILED_LOGIN), 2, 10_000L, 5_000L));

        // 按 v1 重放历史：仍然不告警（结论不被规则更新改写）
        AlertLifecycleManager v1ReplayAlerts = new AlertLifecycleManager();
        CorrelationEngine v1Replay = new CorrelationEngine(rules, v1ReplayAlerts);
        for (SecurityEvent e : batch) {
            v1Replay.evaluateWith(e, e.ingestTimeMs(), "r", 1);
        }
        log.info("[AFTER-UPDATE] v1 replay alerts={}", v1ReplayAlerts.all().size());
        assertThat(v1ReplayAlerts.all()).isEmpty();

        // 按 v2 评估同样两事件：产生 v2 的独立告警（alertId 含版本号，与 v1 空间隔离）
        AlertLifecycleManager v2Alerts = new AlertLifecycleManager();
        CorrelationEngine v2Engine = new CorrelationEngine(rules, v2Alerts);
        for (SecurityEvent e : batch) {
            v2Engine.evaluateWith(e, e.ingestTimeMs(), "r", 2);
        }
        log.info("[AFTER-UPDATE] v2 alerts={}", v2Alerts.all());
        assertThat(v2Alerts.all()).hasSize(1);
        assertThat(v2Alerts.all().get(0).alertId()).contains("#v2#");
        assertThat(engine.windowState("r", 1, "alice", BASE).orElseThrow().count()).isEqualTo(2);
    }
}
