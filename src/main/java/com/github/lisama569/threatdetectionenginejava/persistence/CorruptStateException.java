package com.github.lisama569.threatdetectionenginejava.persistence;

/** 本地运行状态缺失关键字段、无法解析或校验和不匹配时抛出；绝不允许静默按全新实例继续。 */
public class CorruptStateException extends RuntimeException {

    private final String stateFile;

    public CorruptStateException(String stateFile, String message) {
        super(message);
        this.stateFile = stateFile;
    }

    public CorruptStateException(String stateFile, String message, Throwable cause) {
        super(message, cause);
        this.stateFile = stateFile;
    }

    public String getStateFile() {
        return stateFile;
    }
}
