package com.github.lisama569.threatdetectionenginejava.persistence;

import java.util.List;

/**
 * 单个固定窗口的持久化状态。
 *
 * @param start 窗口起点（epochMillis）
 * @param alerted 该窗口是否已产生告警（恢复后不得重复告警）
 * @param events 窗口内已接收的去重事件引用
 */
public record FixedWindowMemento(long start, boolean alerted, List<EventRefMemento> events) {
    public FixedWindowMemento {
        events = events == null ? List.of() : List.copyOf(events);
    }
}
