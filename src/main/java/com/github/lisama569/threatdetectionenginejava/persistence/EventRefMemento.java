package com.github.lisama569.threatdetectionenginejava.persistence;

/**
 * 窗口内已接收事件的持久化引用（仅保留判定所需信息，不存原始 payload）。
 *
 * @param eventId 事件内容指纹（窗口内去重依据）
 * @param eventTime 事件发生时间（恢复后判定顺序与迟到判断需要）
 */
public record EventRefMemento(String eventId, long eventTime) {
}
