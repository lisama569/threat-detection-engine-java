package com.github.lisama569.threatdetectionenginejava.tests.alert;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService;
import com.github.lisama569.threatdetectionenginejava.alert.InvalidAlertTransitionException;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.fixedClock;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.newService;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.defaultRegistry;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** 告警生命周期：合法迁移成功，非法/重复/终态迁移被拒绝且 from/to 可区分。 */
class AlertLifecycleTest {

    private static final Logger log = LoggerFactory.getLogger(AlertLifecycleTest.class);

    private static final long T = 1_790_000_000_000L;

    private final AlertLifecycleService lifecycle = new AlertLifecycleService(fixedClock());

    @Test
    @DisplayName("合法迁移链：OPEN -> ACKNOWLEDGED -> RESOLVED")
    void legalChainSucceeds() {
        Alert alert = lifecycle.open("alert-1", "R-1", 1, "host-1", T, 3);
        assertEquals(AlertStatus.OPEN, alert.getStatus());
        lifecycle.transition(alert, AlertStatus.ACKNOWLEDGED, "认领");
        assertEquals(AlertStatus.ACKNOWLEDGED, alert.getStatus());
        lifecycle.transition(alert, AlertStatus.RESOLVED, "处置完成");
        assertEquals(AlertStatus.RESOLVED, alert.getStatus());
        assertEquals("处置完成", alert.getResolutionNote());
        log.info("合法迁移完成: alertId={}, final={}", alert.getAlertId(), alert.getStatus());
    }

    @Test
    @DisplayName("抑制与恢复：OPEN -> SUPPRESSED -> ACKNOWLEDGED -> RESOLVED")
    void suppressAndResumeSucceeds() {
        Alert alert = lifecycle.open("alert-2", "R-1", 1, "host-1", T, 3);
        lifecycle.transition(alert, AlertStatus.SUPPRESSED, "误报抑制");
        assertEquals(AlertStatus.SUPPRESSED, alert.getStatus());
        lifecycle.transition(alert, AlertStatus.ACKNOWLEDGED, "确认为真");
        assertEquals(AlertStatus.ACKNOWLEDGED, alert.getStatus());
        lifecycle.transition(alert, AlertStatus.RESOLVED, null);
        assertEquals(AlertStatus.RESOLVED, alert.getStatus());
    }

    @Test
    @DisplayName("非法迁移 OPEN -> RESOLVED 之外的跳跃（OPEN 不能直接 ACK 后再回 OPEN）被拒绝并区分 from/to")
    void illegalBackwardTransitionRejected() {
        Alert alert = lifecycle.open("alert-3", "R-1", 1, "host-1", T, 3);
        lifecycle.transition(alert, AlertStatus.ACKNOWLEDGED, null);
        InvalidAlertTransitionException ex = assertThrows(InvalidAlertTransitionException.class,
                () -> lifecycle.transition(alert, AlertStatus.OPEN, null));
        assertEquals(AlertStatus.ACKNOWLEDGED, ex.getFrom());
        assertEquals(AlertStatus.OPEN, ex.getTo());
        assertEquals(AlertStatus.ACKNOWLEDGED, alert.getStatus(), "非法迁移不得改变状态");
        log.info("非法迁移被拒绝: {} -> {}, message={}", ex.getFrom(), ex.getTo(), ex.getMessage());
    }

    @Test
    @DisplayName("重复迁移（from == to）被拒绝，与非法迁移可区分")
    void sameStateTransitionRejected() {
        Alert alert = lifecycle.open("alert-4", "R-1", 1, "host-1", T, 3);
        InvalidAlertTransitionException ex = assertThrows(InvalidAlertTransitionException.class,
                () -> lifecycle.transition(alert, AlertStatus.OPEN, null));
        assertEquals(AlertStatus.OPEN, ex.getFrom());
        assertEquals(AlertStatus.OPEN, ex.getTo());
        assertTrue(ex.getMessage().contains("重复迁移"));
        assertFalse(lifecycle.isLegal(AlertStatus.OPEN, AlertStatus.OPEN));
    }

    @Test
    @DisplayName("终态 RESOLVED 任何迁出均被拒绝并标注终态")
    void resolvedIsTerminal() {
        Alert alert = lifecycle.open("alert-5", "R-1", 1, "host-1", T, 3);
        lifecycle.transition(alert, AlertStatus.RESOLVED, null);
        InvalidAlertTransitionException ex = assertThrows(InvalidAlertTransitionException.class,
                () -> lifecycle.transition(alert, AlertStatus.ACKNOWLEDGED, null));
        assertEquals(AlertStatus.RESOLVED, ex.getFrom());
        assertTrue(ex.getMessage().contains("终态"));
        assertTrue(lifecycle.isTerminal(AlertStatus.RESOLVED));
    }

    @Test
    @DisplayName("通过服务对真实告警执行迁移：不存在告警 ID 与非法迁移分别给出可区分错误")
    void serviceTransitionIntegration() {
        DetectionService service = newService(defaultRegistry(), fixedClock());
        service.deployRule(rule(1, 60_000L, 2, 10_000L));
        List<RawEvent> batch = List.of(
                edr("s1", "host-8", T + 1_000),
                edr("s2", "host-8", T + 2_000));
        List<IngestResult> results = service.ingestBatch(batch);
        String alertId = results.get(1).alertId();
        assertEquals("alert-R-BRUTE-FORCE-v1-host-8-w" + (T - T % 60_000L), alertId);

        Alert acked = service.transitionAlert(alertId, AlertStatus.ACKNOWLEDGED, "认领");
        assertEquals(AlertStatus.ACKNOWLEDGED, acked.getStatus());

        assertThrows(IllegalArgumentException.class,
                () -> service.transitionAlert("not-exist", AlertStatus.RESOLVED, null));
        assertThrows(InvalidAlertTransitionException.class,
                () -> service.transitionAlert(alertId, AlertStatus.OPEN, null));

        Alert resolved = service.transitionAlert(alertId, AlertStatus.RESOLVED, "已处置");
        assertEquals(AlertStatus.RESOLVED, resolved.getStatus());
        log.info("真实告警生命周期结束: id={}, status={}", alertId, resolved.getStatus());
    }
}
