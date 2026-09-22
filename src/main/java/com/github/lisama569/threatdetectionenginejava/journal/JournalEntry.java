package com.github.lisama569.threatdetectionenginejava.journal;

import com.github.lisama569.threatdetectionenginejava.model.RawEvent;

/**
 * 日志条目：原始事件 + 引擎实际接收时刻（epoch millis）。
 * <p>
 * 接收时刻必须持久化：重放时以它作为到达时间，迟到判定与首次处理完全一致，
 * 否则重放发生在很久以后会把全部历史事件误判为超容忍迟到。
 */
public record JournalEntry(RawEvent event, long receivedAtMs) {
}
