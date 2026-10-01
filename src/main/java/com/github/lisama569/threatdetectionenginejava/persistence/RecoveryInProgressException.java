package com.github.lisama569.threatdetectionenginejava.persistence;

/** 恢复尚未完成时到达的摄入/迁移请求被拒绝：既不能按空实例处理，也不会在恢复后被重复计算。 */
public class RecoveryInProgressException extends RuntimeException {

    public RecoveryInProgressException(String message) {
        super(message);
    }
}
