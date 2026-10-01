package com.github.lisama569.threatdetectionenginejava.tests.recovery;

import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryPhase;
import com.github.lisama569.threatdetectionenginejava.recovery.ServiceUnavailableException;
import com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures;
import com.github.lisama569.threatdetectionenginejava.tests.support.RestartHarness;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.edr;
import static com.github.lisama569.threatdetectionenginejava.tests.support.EngineTestFixtures.rule;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 本地状态缺失/损坏的可区分处理：
 * 无文件=合法空首启(ACTIVE_FRESH)；文件损坏默认保守停服(FAILED, 拒绝摄入, 统计/状态可见)；
 * 显式配置允许时损坏后重置为全新实例，但带 corruptionReset 标记，可与正常首启区分。
 */
class StateCorruptionRecoveryTest {

    private static final Logger log = LoggerFactory.getLogger(StateCorruptionRecoveryTest.class);

    private static final long T = 1_790_000_000_000L;

    @Test
    @DisplayName("无状态文件：合法全新启动 ACTIVE_FRESH，可正常摄入，与损坏场景可区分")
    void missingStateStartsFresh(@TempDir Path dir) {
        Path stateFile = dir.resolve("never-existed.json");
        var clock = new EngineTestFixtures.MutableClock(T + 600_000L);
        RestartHarness harness = new RestartHarness(stateFile, clock);

        assertEquals(RecoveryPhase.ACTIVE_FRESH, harness.gate().phase());
        assertFalse(harness.service().recoveryStatus().restored());
        assertFalse(harness.service().recoveryStatus().corruptionReset(),
                "正常首启不得带损坏重置标记");
        harness.service().deployRule(rule(1, 60_000L, 3, 10_000L));
        assertEquals(IngestOutcome.ACCEPTED_NO_ALERT,
                harness.service().ingest(edr("f1", "host-A", T + 1_000)).outcome());
        log.info("[无文件首启] recovery={}", harness.service().recoveryStatus());
    }

    @Test
    @DisplayName("状态损坏：默认保守停服 FAILED，写请求被可区分拒绝且不会按空实例处理；统计/状态可见")
    void corruptStateFailsClosed(@TempDir Path dir) throws Exception {
        Path stateFile = dir.resolve("corrupt.json");
        var clock = new EngineTestFixtures.MutableClock(T + 600_000L);

        // 先制造一份有效快照
        RestartHarness first = new RestartHarness(stateFile, clock);
        first.service().deployRule(rule(1, 60_000L, 3, 10_000L));
        first.service().ingestBatch(List.of(
                edr("x1", "host-A", T + 1_000),
                edr("x2", "host-A", T + 2_000)));
        assertTrue(first.shutdownCheckpoint());

        // 模拟落盘截断/磁盘损坏：写坏 JSON 与错误校验和
        Files.writeString(stateFile, "{ this is : not-valid-json ,,,");
        Files.writeString(Path.of(stateFile + ".sha256"), "deadbeef");

        // failOnCorrupt=true（默认）：重启必须 FAILED，不能静默按空实例继续
        RestartHarness broken = new RestartHarness(stateFile, clock, true);
        assertEquals(RecoveryPhase.FAILED, broken.gate().phase());
        assertFalse(broken.service().recoveryStatus().restored());
        log.warn("[损坏停服] recovery={}", broken.service().recoveryStatus());

        // 写请求立即被拒绝（不等待），且不是被空实例正常接收
        ServiceUnavailableException ex = assertThrows(ServiceUnavailableException.class,
                () -> broken.service().ingest(edr("after-corrupt", "host-A", T + 3_000)));
        assertEquals(RecoveryPhase.FAILED, ex.phase());
        // 状态转移写操作同样拒绝
        assertThrows(ServiceUnavailableException.class, () -> broken.service()
                .transitionAlert("alert-x", com.github.lisama569.threatdetectionenginejava.model.AlertStatus.OPEN, null));

        // FAILED 实例绝不能落盘覆盖那份损坏文件（避免“看起来已保存”的假象）
        assertFalse(broken.checkpointNow(), "FAILED 阶段禁止快照落盘");

        // 内存里也没有偷偷恢复出历史（不是静默空实例，也不是半恢复）
        assertEquals(0, broken.service().listAlerts().size());
        assertEquals(0, broken.service().stats().total());
        log.warn("[损坏后统计仍可见恢复阶段] recovery={}, stats={}",
                broken.service().recoveryStatus(), broken.service().stats());

        // 校验和被篡改（JSON 合法但摘要错误）也必须判 CORRUPT -> FAILED：
        // 先让实例恢复成功（此前写坏的文件此刻仍存在，故先删除再走全新首启生成新快照）
        Files.deleteIfExists(stateFile);
        Files.deleteIfExists(Path.of(stateFile + ".sha256"));
        RestartHarness good = new RestartHarness(stateFile, clock, true);
        assertEquals(RecoveryPhase.ACTIVE_FRESH, good.gate().phase());
        good.service().deployRule(rule(1, 60_000L, 3, 10_000L));
        good.service().ingest(edr("y1", "host-A", T + 1_000));
        good.shutdownCheckpoint();
        Files.writeString(Path.of(stateFile + ".sha256"),
                "0000000000000000000000000000000000000000000000000000000000000000");
        RestartHarness checksumBad = new RestartHarness(stateFile, clock, true);
        assertEquals(RecoveryPhase.FAILED, checksumBad.gate().phase());
    }

    @Test
    @DisplayName("显式 fail-on-corrupt=false：损坏后重置为全新实例，但 corruptionReset 可与正常首启区分")
    void corruptStateCanResetButMarked(@TempDir Path dir) throws Exception {
        Path stateFile = dir.resolve("corrupt-reset.json");
        var clock = new EngineTestFixtures.MutableClock(T + 600_000L);

        RestartHarness first = new RestartHarness(stateFile, clock);
        first.service().deployRule(rule(1, 60_000L, 3, 10_000L));
        first.service().ingest(edr("z1", "host-A", T + 1_000));
        first.shutdownCheckpoint();
        Files.write(stateFile, "garbage".getBytes(StandardCharsets.UTF_8));

        RestartHarness reset = new RestartHarness(stateFile, clock, false);
        assertEquals(RecoveryPhase.ACTIVE_FRESH, reset.gate().phase());
        assertTrue(reset.service().recoveryStatus().corruptionReset(),
                "损坏后重置必须带 corruptionReset 标记，与正常首启区分");
        assertFalse(reset.service().recoveryStatus().restored());
        // 重置后是全新空实例：历史计数不带入
        assertEquals(0, reset.service().stats().total());
        log.warn("[损坏后重置] recovery={}", reset.service().recoveryStatus());
    }
}
