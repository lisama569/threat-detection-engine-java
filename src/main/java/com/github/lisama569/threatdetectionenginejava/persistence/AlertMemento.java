package com.github.lisama569.threatdetectionenginejava.persistence;

/** 告警及其生命周期处置状态的持久化形态。 */
public record AlertMemento(String alertId, String ruleId, int ruleVersion, String entityId,
                          long createdAt, long triggerEventTime, int triggerCount,
                          String status, long statusUpdatedAt, String resolutionNote) {
}
