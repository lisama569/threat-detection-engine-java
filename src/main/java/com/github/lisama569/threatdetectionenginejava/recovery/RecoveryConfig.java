package com.github.lisama569.threatdetectionenginejava.recovery;

import com.github.lisama569.threatdetectionenginejava.persistence.LocalFileStateStore;
import com.github.lisama569.threatdetectionenginejava.persistence.StateCodec;
import com.github.lisama569.threatdetectionenginejava.persistence.StateStore;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Paths;
import java.time.Clock;

/** 重启续跑能力的本地装配：文件状态库、编解码、恢复闸门与编排服务。 */
@Configuration
public class RecoveryConfig {

    @Bean
    public StateStore stateStore(RecoveryProperties properties) {
        return new LocalFileStateStore(Paths.get(properties.getStatePath()));
    }

    @Bean
    public StateCodec stateCodec() {
        return new StateCodec();
    }

    @Bean
    public RecoveryGate recoveryGate(RecoveryProperties properties) {
        return new RecoveryGate(properties.getStatePath());
    }

    @Bean
    public StateSnapshotService stateSnapshotService(Clock clock) {
        return new StateSnapshotService(clock);
    }

    @Bean
    public StateRecoveryService stateRecoveryService(StateStore stateStore,
                                                     StateSnapshotService snapshotService,
                                                     RecoveryGate recoveryGate,
                                                     RecoveryProperties properties) {
        return new StateRecoveryService(stateStore, snapshotService, recoveryGate, properties);
    }

    @Bean
    public StateCheckpointService stateCheckpointService(StateStore stateStore,
                                                         RecoveryGate recoveryGate) {
        return new StateCheckpointService(stateStore, recoveryGate);
    }
}
