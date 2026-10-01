package com.github.lisama569.threatdetectionenginejava.recovery;

import com.github.lisama569.threatdetectionenginejava.persistence.StateMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.StateStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Supplier;

/**
 * 快照落盘编排。
 *
 * <p>关键边界：只有 {@link RecoveryGate#isActive()} 时才允许写出。恢复中（内存态不完整）
 * 或恢复失败（空内存态）都绝不能落盘，否则会用半份/空状态覆盖上一份可用快照。</p>
 */
public class StateCheckpointService {

    private static final Logger log = LoggerFactory.getLogger(StateCheckpointService.class);

    private final StateStore stateStore;
    private final RecoveryGate gate;

    public StateCheckpointService(StateStore stateStore, RecoveryGate gate) {
        this.stateStore = stateStore;
        this.gate = gate;
    }

    /**
     * 立即写出一份快照。
     *
     * @param supplier 从在线组件捕获备忘录的回调（只在确认可写后才调用）
     * @return true=已落盘；false=因阶段不允许而跳过
     */
    public boolean checkpoint(Supplier<StateMemento> supplier) {
        if (!gate.isActive()) {
            log.warn("[CHECKPOINT] 当前阶段 {} 不允许落盘，跳过快照（防止半份/空态覆盖历史状态）",
                    gate.phase());
            return false;
        }
        StateMemento memento = supplier.get();
        stateStore.save(memento);
        log.info("[CHECKPOINT] 状态快照已保存: file={}, 窗口={}, 去重键={}, 告警={}, total={}",
                stateStore.location(), memento.windows().size(), memento.dedupKeys().size(),
                memento.alerts().size(), memento.stats().total());
        return true;
    }
}
