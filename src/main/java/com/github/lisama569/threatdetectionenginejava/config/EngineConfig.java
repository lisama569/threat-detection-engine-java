package com.github.lisama569.threatdetectionenginejava.config;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.persistence.LocalStateStore;
import com.github.lisama569.threatdetectionenginejava.persistence.StateCodec;
import com.github.lisama569.threatdetectionenginejava.persistence.StateRecoveryCoordinator;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.time.Clock;

/** 引擎组件装配（含重启续跑：本地状态存储与恢复协调器）。 */
@Configuration
public class EngineConfig {

    @Bean
    public Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    public InMemoryStore inMemoryStore() {
        return new InMemoryStore();
    }

    @Bean
    public SourceRegistry sourceRegistry() {
        return new SourceRegistry();
    }

    @Bean
    public EventNormalizer eventNormalizer(SourceRegistry registry, Clock clock) {
        return new EventNormalizer(registry, clock);
    }

    @Bean
    public AlertLifecycleService alertLifecycleService(Clock clock) {
        return new AlertLifecycleService(clock);
    }

    @Bean
    public CorrelationEngine correlationEngine() {
        return new CorrelationEngine();
    }

    @Bean
    public DetectionService detectionService(InMemoryStore store, SourceRegistry registry,
                                             CorrelationEngine engine, EventNormalizer normalizer,
                                             AlertLifecycleService lifecycle, Clock clock) {
        return new DetectionService(store, registry, engine, normalizer, lifecycle, clock);
    }

    /** 本地状态目录：默认 ./data/state，可用 --engine.state-dir 覆盖。 */
    @Bean
    public LocalStateStore localStateStore(
            @Value("${engine.state-dir:data/state}") String stateDir) {
        return new LocalStateStore(Path.of(stateDir));
    }

    @Bean
    public StateCodec stateCodec() {
        return new StateCodec();
    }

    /**
     * 重启续跑协调器：构造即把服务置为 RECOVERING；@PostConstruct 完成恢复，
     * @PreDestroy 在优雅停机时落盘。状态损坏默认进入 FAILED 在线拒绝写入（不静默全新实例），
     * 可用 engine.state.fail-fast-on-corrupt=true 改为直接终止启动。
     */
    @Bean
    public StateRecoveryCoordinator stateRecoveryCoordinator(
            DetectionService service, LocalStateStore stateStore, StateCodec codec, Clock clock,
            @Value("${engine.state.enabled:true}") boolean stateEnabled,
            @Value("${engine.state.allow-fresh-on-corrupt:false}") boolean allowFreshOnCorrupt,
            @Value("${engine.state.fail-fast-on-corrupt:false}") boolean failFastOnCorrupt) {
        StateRecoveryCoordinator coordinator =
                new StateRecoveryCoordinator(service, stateStore, codec, clock, allowFreshOnCorrupt);
        coordinator.setEnabled(stateEnabled);
        coordinator.setFailFastOnCorrupt(failFastOnCorrupt);
        return coordinator;
    }
}
