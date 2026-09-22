package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 归一化结果：成功携带事件，失败携带可区分拒绝原因与说明。
 */
public sealed interface NormalizeResult
        permits NormalizeResult.Ok, NormalizeResult.Rejected {

    record Ok(SecurityEvent event) implements NormalizeResult {
    }

    record Rejected(RejectReason reason, String message, RawEvent rawEvent) implements NormalizeResult {
    }
}
