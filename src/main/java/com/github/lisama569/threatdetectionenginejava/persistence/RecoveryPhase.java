package com.github.lisama569.threatdetectionenginejava.persistence;

/**
 * 服务实例相对于“重启续跑”的生命周期阶段。
 *
 * <ul>
 *   <li>{@link #RECOVERING}：正在从本地状态恢复，对外摄入必须被挡在门外；</li>
 *   <li>{@link #ACTIVE}：恢复完成（或全新启动），正常对外服务；</li>
 *   <li>{@link #FAILED}：本地状态损坏且不允许静默全新启动，对外拒绝服务；</li>
 * </ul>
 */
public enum RecoveryPhase {
    RECOVERING,
    ACTIVE,
    FAILED
}
