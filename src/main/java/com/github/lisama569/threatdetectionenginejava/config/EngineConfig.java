package com.github.lisama569.threatdetectionenginejava.config;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleService;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.normalization.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 引擎组件装配。 */
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
}
