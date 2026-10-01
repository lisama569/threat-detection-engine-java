package com.github.lisama569.threatdetectionenginejava.recovery;

import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.persistence.StateMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.StateStore;
import com.github.lisama569.threatdetectionenginejava.persistence.StateStoreException;
import com.github.lisama569.threatdetectionenginejava.store.InMemoryStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 启动恢复编排：加载本地快照 -> 区分“无快照 / 损坏 / 正常” -> 应用回在线组件 -> 翻转恢复闸门。
 *
 * <ul>
 *   <li>无快照文件：视为首次启动的合法空态，{@code ACTIVE_FRESH}，正常对外服务；</li>
 *   <li>快照存在且校验通过：恢复后 {@code ACTIVE_RESTORED}，在同一份状态上接着算；</li>
 *   <li>快照缺失以外的任何读取/校验失败（CORRUPT/IO_ERROR）：默认 {@code failOnCorruptState=true}
 *       时进入 {@code FAILED} 保守停服，绝不用空实例冒充恢复继续摄入；当显式配置
 *       {@code detection.state.fail-on-corrupt=false} 时，才以“损坏后重置”的全新实例启动，
 *       并在恢复状态与日志中明确标记，与正常空首启可区分。</li>
 * </ul>
 */
public class StateRecoveryService {

    private static final Logger log = LoggerFactory.getLogger(StateRecoveryService.class);

    private final StateStore stateStore;
    private final StateSnapshotService snapshotService;
    private final RecoveryGate gate;
    private final RecoveryProperties properties;

    public StateRecoveryService(StateStore stateStore, StateSnapshotService snapshotService,
                                RecoveryGate gate, RecoveryProperties properties) {
        this.stateStore = stateStore;
        this.snapshotService = snapshotService;
        this.gate = gate;
        this.properties = properties;
    }

    /** 执行一次启动恢复（幂等：闸门离开 RECOVERING 后不再重复执行）。 */
    public synchronized void recover(InMemoryStore store, CorrelationEngine engine,
                                     SourceRegistry registry) {
        if (gate.phase() != com.github.lisama569.threatdetectionenginejava.recovery.RecoveryPhase.RECOVERING) {
            log.info("[RECOVERY] 已处于 {} 阶段，跳过重复恢复", gate.phase());
            return;
        }
        StateMemento memento;
        try {
            memento = stateStore.load();
        } catch (StateStoreException e) {
            handleLoadFailure(e);
            return;
        }

        try {
            String summary = snapshotService.restore(memento, store, engine, registry);
            gate.finish(true, "本地状态恢复成功: " + summary);
            log.info("[RECOVERY] 恢复完成，实例以 ACTIVE_RESTORED 就绪，stateFile={}",
                    stateStore.location());
        } catch (RuntimeException e) {
            // 快照语义不合法（如窗口缺规则槽位、枚举无法识别）也视为损坏，保守停服
            String detail = "本地状态恢复应用失败（状态可能损坏）: " + e.getMessage();
            log.error("[RECOVERY] {}", detail, e);
            gate.fail(detail);
        }
    }

    private void handleLoadFailure(StateStoreException e) {
        if (e.kind() == StateStoreException.Kind.MISSING) {
            gate.finish(false, "未发现历史状态文件，以全新空实例启动: " + stateStore.location());
            log.info("[RECOVERY] {}，阶段=ACTIVE_FRESH", gate.detail());
            return;
        }
        String detail = "本地状态不可用: kind=" + e.kind() + ", " + e.getMessage()
                + ", file=" + stateStore.location();
        if (properties.isFailOnCorruptState()) {
            log.error("[RECOVERY] {}；按 fail-on-corrupt=true 保守停服（FAILED），"
                    + "请修复/移走损坏文件后再启动", detail);
            gate.fail(detail);
        } else {
            log.warn("[RECOVERY] {}；按 fail-on-corrupt=false 重置为全新实例"
                    + "（corruptionReset=true，与正常首启可区分）", detail);
            gate.finish(false, true, "检测到损坏状态后按配置重置为全新实例 | " + detail);
        }
    }
}
