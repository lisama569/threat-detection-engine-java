package com.github.lisama569.threatdetectionenginejava.tests.support;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.persistence.LocalFileStateStore;
import com.github.lisama569.threatdetectionenginejava.persistence.StateStore;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryGate;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryPhase;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryProperties;
import com.github.lisama569.threatdetectionenginejava.recovery.StateCheckpointService;
import com.github.lisama569.threatdetectionenginejava.recovery.StateRecoveryService;
import com.github.lisama569.threatdetectionenginejava.recovery.StateSnapshotService;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;

import java.nio.file.Path;
import java.time.Clock;
import java.util.function.BooleanSupplier;

/**
 * “进程重启”模拟器：每次 {@link #restart()} 都用同一状态文件、同一时钟、全新的内存组件
 * 重建一个 {@link DetectionService}，并在返回前完成启动恢复（语义等价于滚动重启后新进程）。
 */
public final class RestartHarness {

    private final Path stateFile;
    private final EngineTestFixtures.MutableClock clock;
    private final boolean failOnCorrupt;

    private DetectionService service;
    private SourceRegistry registry;
    private CorrelationEngine engine;
    private InMemoryStore store;
    private StateStore stateStore;
    private RecoveryGate gate;
    private StateSnapshotService snapshotService;
    private StateCheckpointService checkpointService;
    private int generation;

    public RestartHarness(Path stateFile, EngineTestFixtures.MutableClock clock) {
        this(stateFile, clock, true);
    }

    /** 用显式时钟基准（epochMillis）构造，便于让事件时间相对时钟落在过去。 */
    public RestartHarness(Path stateFile, long clockBaseMillis) {
        this(stateFile, new EngineTestFixtures.MutableClock(clockBaseMillis), true);
    }

    public RestartHarness(Path stateFile, EngineTestFixtures.MutableClock clock,
                          boolean failOnCorrupt) {
        this.stateFile = stateFile;
        this.clock = clock;
        this.failOnCorrupt = failOnCorrupt;
        boot();
    }

    /** 启动一个全新进程实例（空内存），立即执行本地状态恢复。 */
    public DetectionService restart() {
        generation++;
        boot();
        return service;
    }

    private void boot() {
        registry = EngineTestFixtures.defaultRegistry();
        engine = new CorrelationEngine();
        store = new InMemoryStore();
        EventNormalizer normalizer = new EventNormalizer(registry, clock);
        AlertLifecycleService lifecycle = new AlertLifecycleService(clock);
        gate = new RecoveryGate(stateFile.toString());
        snapshotService = new StateSnapshotService(clock);
        RecoveryProperties properties = new RecoveryProperties(stateFile.toString(),
                failOnCorrupt, 10_000L);
        stateStore = new LocalFileStateStore(stateFile);
        StateRecoveryService recoveryService = new StateRecoveryService(
                stateStore, snapshotService, gate, properties);
        checkpointService = new StateCheckpointService(stateStore, gate);
        service = new DetectionService(store, registry, engine, normalizer, lifecycle, clock, gate);

        recoveryService.recover(store, engine, registry);
    }

    /** 正常停机：优雅停机阶段的原子快照（只有 ACTIVE 才真正落盘）。 */
    public boolean shutdownCheckpoint() {
        return checkpointService.checkpoint(() -> service.captureState(snapshotService));
    }

    /** 测试用：直接在当前实例手动落盘（等价于停机快照）。 */
    public boolean checkpointNow() {
        return shutdownCheckpoint();
    }

    public void awaitPhase(RecoveryPhase expected) {
        waitUntil(() -> gate.phase() == expected, "等待恢复阶段 " + expected);
    }

    static void waitUntil(BooleanSupplier condition, String desc) {
        long deadline = System.nanoTime() + 10_000_000_000L;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("超时: " + desc);
            }
            try {
                Thread.sleep(2);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError(e);
            }
        }
    }

    public DetectionService service() { return service; }
    public SourceRegistry registry() { return registry; }
    public CorrelationEngine engine() { return engine; }
    public InMemoryStore store() { return store; }
    public RecoveryGate gate() { return gate; }
    public StateStore stateStore() { return stateStore; }
    public StateSnapshotService snapshotService() { return snapshotService; }
    public Clock clock() { return clock; }
    public int generation() { return generation; }
    public Path stateFile() { return stateFile; }
}
