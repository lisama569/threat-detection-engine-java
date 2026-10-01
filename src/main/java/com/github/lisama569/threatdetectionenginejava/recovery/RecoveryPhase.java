package com.github.lisama569.threatdetectionenginejava.recovery;

/**
 * 实例恢复生命周期阶段。
 *
 * <ul>
 *   <li>{@link #RECOVERING}：正在从本地快照恢复，对外写请求不可用（阻塞等待或拒绝）；</li>
 *   <li>{@link #ACTIVE_FRESH}：无历史快照，以全新实例启动并已就绪；</li>
 *   <li>{@link #ACTIVE_RESTORED}：快照恢复成功并已就绪；</li>
 *   <li>{@link #FAILED}：状态缺失/损坏且策略要求保守停服，所有写请求被拒绝。</li>
 * </ul>
 */
public enum RecoveryPhase {
    RECOVERING,
    ACTIVE_FRESH,
    ACTIVE_RESTORED,
    FAILED
}
