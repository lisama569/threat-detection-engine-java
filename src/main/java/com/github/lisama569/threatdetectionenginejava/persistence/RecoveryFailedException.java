package com.github.lisama569.threatdetectionenginejava.persistence;

/** 本地状态恢复失败（损坏等）且未配置允许丢弃时，实例进入 FAILED 后拒绝一切写请求。 */
public class RecoveryFailedException extends RuntimeException {

    public RecoveryFailedException(String message) {
        super(message);
    }

    public RecoveryFailedException(String message, Throwable cause) {
        super(message, cause);
    }
}
