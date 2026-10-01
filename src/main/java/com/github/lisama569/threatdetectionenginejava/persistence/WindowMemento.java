package com.github.lisama569.threatdetectionenginejava.persistence;

import java.util.List;

/**
 * 单（规则版本, 实体）维度窗口状态的持久化形态。
 *
 * @param ruleId 规则 ID
 * 规则版本、实体、窗口长度、迟到基准 watermark、未驱逐窗口列表
 */
public record WindowMemento(String ruleId, int ruleVersion, String entityId, long windowMillis,
                            long watermark, List<FixedWindowMemento> windows) {
    public WindowMemento {
        windows = windows == null ? List.of() : List.copyOf(windows);
    }
}
