package com.github.lisama569.threatdetectionenginejava.recovery;

import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.stereotype.Component;

/**
 * 重启续跑生命周期：
 * <ol>
 *   <li>所有单例就绪后、Web 容器开始接受请求前，执行一次本地状态恢复
 *       （{@link SmartInitializingSingleton} 早于 CommandLineRunner / 容器接客）；</li>
 *   <li>正常停机（SIGTERM/容器滚动重启的优雅终止阶段）时，在 ACTIVE 状态下原子保存快照；
 *       恢复中/恢复失败绝不下盘，避免半份/空态覆盖历史。</li>
 * </ol>
 */
@Component
public class RecoveryLifecycle implements SmartInitializingSingleton {

    private static final Logger log = LoggerFactory.getLogger(RecoveryLifecycle.class);

    private final DetectionService service;
    private final InMemoryStore store;
    private final CorrelationEngine engine;
    private final SourceRegistry registry;
    private final StateRecoveryService recoveryService;
    private final StateCheckpointService checkpointService;
    private final StateSnapshotService snapshotService;

    public RecoveryLifecycle(DetectionService service, InMemoryStore store,
                             CorrelationEngine engine, SourceRegistry registry,
                             StateRecoveryService recoveryService,
                             StateCheckpointService checkpointService,
                             StateSnapshotService snapshotService) {
        this.service = service;
        this.store = store;
        this.engine = engine;
        this.registry = registry;
        this.recoveryService = recoveryService;
        this.checkpointService = checkpointService;
        this.snapshotService = snapshotService;
    }

    @Override
    public void afterSingletonsInstantiated() {
        recoveryService.recover(store, engine, registry);
    }

    @PreDestroy
    public void onShutdown() {
        boolean saved = checkpointService.checkpoint(() -> service.captureState(snapshotService));
        log.info("[SHUTDOWN] 优雅停机状态快照 {}", saved ? "已保存" : "未保存（实例不在 ACTIVE 阶段）");
    }
}
