package com.github.lisama569.threatdetectionenginejava.recovery;

/**
 * 服务当前不可用于对外写操作：恢复尚未完成、恢复失败或等待恢复超时。
 * 与“空实例正常接收”可明确区分（REST 层映射为 503）。
 */
public class ServiceUnavailableException extends RuntimeException {

    private final RecoveryPhase phase;

    public ServiceUnavailableException(RecoveryPhase phase, String message) {
        super(message);
        this.phase = phase;
    }

    public RecoveryPhase phase() {
        return phase;
    }
}
