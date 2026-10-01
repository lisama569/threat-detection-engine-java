package com.github.lisama569.threatdetectionenginejava.persistence;

/**
 * 最近一次启动时本地状态恢复的结论（用于 /api/stats 与日志，可区分状态缺失/损坏/成功）。
 *
 * @param phase                 恢复后服务阶段
 * @param status                机器可读状态：FRESH（无状态全新启动）/ RESTORED（成功恢复）/
 *                              MISSING（未找到状态文件）/ CORRUPT（状态损坏）/ SKIPPED / DISABLED / FAILED
 * @param detail                人类可读说明
 * @param restoredAlerts        恢复的告警数
 * @param restoredWindowStates  恢复的（规则版本+实体）窗口态条数
 * @param restoredDedupKeys     恢复的投递去重键数
 * @param restoredRules         恢复的规则版本总数
 * @param retainedWindows       恢复时保留下来的固定窗口数（其余已安全回收）
 * @param generation            状态代数（每次保存 +1）
 */
public record RecoveryReport(
        RecoveryPhase phase,
        String status,
        String detail,
        int restoredAlerts,
        int restoredWindowStates,
        int restoredDedupKeys,
        int restoredRules,
        int retainedWindows,
        long generation) {

    public static RecoveryReport fresh(String detail) {
        return new RecoveryReport(RecoveryPhase.ACTIVE, "FRESH", detail, 0, 0, 0, 0, 0, 0L);
    }

    public static RecoveryReport skipped(String detail) {
        return new RecoveryReport(RecoveryPhase.ACTIVE, "SKIPPED", detail, 0, 0, 0, 0, 0, 0L);
    }

    public static RecoveryReport disabled(String detail) {
        return new RecoveryReport(RecoveryPhase.ACTIVE, "DISABLED", detail, 0, 0, 0, 0, 0, 0L);
    }
}
