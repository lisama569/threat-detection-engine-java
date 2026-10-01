package com.github.lisama569.threatdetectionenginejava.recovery;

/**
 * 恢复结果/当前状态的可读视图（供 /api/stats、/api/recovery 与日志使用）。
 *
 * @param phase 当前阶段
 * @param restored 是否成功恢复了历史状态
 * @param corruptionReset 是否因检测到损坏状态而按配置重置为全新实例（与正常首启区分）
 * @param detail 说明（恢复了多少窗口/告警/键；失败原因）
 * @param stateFile 使用的状态文件位置
 */
public record RecoveryStatus(RecoveryPhase phase, boolean restored, boolean corruptionReset,
                            String detail, String stateFile) {

    public static RecoveryStatus recovering(String stateFile) {
        return new RecoveryStatus(RecoveryPhase.RECOVERING, false, false, "恢复进行中", stateFile);
    }
}
