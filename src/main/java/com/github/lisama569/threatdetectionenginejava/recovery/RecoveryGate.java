package com.github.lisama569.threatdetectionenginejava.recovery;

/**
 * 恢复边界闸门：恢复完成前，对外写操作不能被当成空实例处理，也不能在恢复后被重复算一遍。
 *
 * <p>语义：</p>
 * <ul>
 *   <li>{@link #finish} / {@link #fail} 之前为 RECOVERING；期间来的写请求在
 *       {@link #awaitWritable} 上阻塞等待（而不是落到空内存态被算一遍）；</li>
 *   <li>恢复成功后所有等待者一次性放行——被阻塞的请求在恢复后的同一份状态上恰好执行一次，
 *       既不会按空实例处理，也不会重复计算；</li>
 *   <li>恢复失败（状态缺失/损坏且策略保守）后置 FAILED：等待中与后续的写请求立即/唤醒后得到
 *       可区分的 {@link ServiceUnavailableException}（REST 映射 503），实例绝不带空态继续服务；</li>
 *   <li>显式配置允许“损坏后重置”时，以全新实例就绪，但携带 corruptionReset 标记，
 *       在状态查询/统计/日志中与正常首启区分。</li>
 * </ul>
 *
 * 本类自身线程安全（内置监视器）；放行后的判定串行化仍由业务层实体分段锁负责。
 */
public final class RecoveryGate {

    private RecoveryPhase phase = RecoveryPhase.RECOVERING;
    private String detail;
    private boolean corruptionReset;
    private final String stateFile;

    public RecoveryGate(String stateFile) {
        this.stateFile = stateFile;
        this.detail = "恢复进行中";
    }

    public synchronized RecoveryPhase phase() {
        return phase;
    }

    public synchronized String detail() {
        return detail;
    }

    public synchronized boolean isCorruptionReset() {
        return corruptionReset;
    }

    public String stateFile() {
        return stateFile;
    }

    /** 标记恢复成功。restored=true 表示延续了历史状态；false 表示确认无快照、全新空态启动。 */
    public void finish(boolean restored, String detail) {
        finish(restored, false, detail);
    }

    /** 标记恢复成功，可额外携带“损坏后重置”标记（与正常首启区分）。 */
    public synchronized void finish(boolean restored, boolean corruptionReset, String detail) {
        if (phase != RecoveryPhase.RECOVERING) {
            return;
        }
        this.phase = restored ? RecoveryPhase.ACTIVE_RESTORED : RecoveryPhase.ACTIVE_FRESH;
        this.corruptionReset = corruptionReset;
        this.detail = detail;
        notifyAll();
    }

    /** 标记恢复失败：实例进入保守停服状态，不接受任何对外写操作。 */
    public synchronized void fail(String detail) {
        if (phase == RecoveryPhase.FAILED) {
            return;
        }
        this.phase = RecoveryPhase.FAILED;
        this.detail = detail;
        notifyAll();
    }

    public boolean isActive() {
        RecoveryPhase p = phase;
        return p == RecoveryPhase.ACTIVE_FRESH || p == RecoveryPhase.ACTIVE_RESTORED;
    }

    /**
     * 阻塞直到实例可写。
     *
     * @param timeoutMillis 最长等待毫秒数；&lt;=0 表示不等待立即判定
     * @throws ServiceUnavailableException 恢复失败或等待超时
     */
    public void awaitWritable(long timeoutMillis) {
        long deadline = System.nanoTime() + Math.max(0L, timeoutMillis) * 1_000_000L;
        synchronized (this) {
            boolean timed = timeoutMillis > 0;
            while (phase == RecoveryPhase.RECOVERING) {
                if (!timed) {
                    throw new ServiceUnavailableException(phase,
                            "实例正在从本地状态恢复，当前不接收写请求");
                }
                long remainingMillis = (deadline - System.nanoTime()) / 1_000_000L;
                if (remainingMillis <= 0) {
                    throw new ServiceUnavailableException(phase,
                            "等待本地状态恢复超时（" + timeoutMillis + "ms），写请求被拒绝");
                }
                try {
                    wait(remainingMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new ServiceUnavailableException(phase, "等待恢复期间线程被中断");
                }
            }
            if (!isActive()) {
                throw new ServiceUnavailableException(phase,
                        "实例恢复失败，已停止对外写服务: " + detail);
            }
        }
    }

    public synchronized RecoveryStatus status() {
        return new RecoveryStatus(phase, phase == RecoveryPhase.ACTIVE_RESTORED,
                corruptionReset, detail, stateFile);
    }
}
