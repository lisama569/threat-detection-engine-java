package com.github.lisama569.threatdetectionenginejava.persistence;

/**
 * 本地状态读写异常（文件缺失、IO 失败、校验和不匹配、格式损坏等）。
 *
 * @param kind 可区分的失败类别
 */
public class StateStoreException extends RuntimeException {

    public enum Kind {
        /** 状态文件不存在（首次启动属正常空态） */
        MISSING,
        /** 状态文件存在但无法读取/解析/校验通过 */
        CORRUPT,
        /** 写入或落盘失败 */
        IO_ERROR
    }

    private final Kind kind;

    public StateStoreException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public StateStoreException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
