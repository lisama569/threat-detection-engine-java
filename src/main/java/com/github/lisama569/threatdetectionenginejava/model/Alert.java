package com.github.lisama569.threatdetectionenginejava.model;

/** 告警聚合根（生命周期可变，迁移经 {@code AlertLifecycleService} 校验）。 */
public final class Alert {

    private final String alertId;
    private final String ruleId;
    private final int ruleVersion;
    private final String entityId;
    private final long createdAt;
    private final long triggerEventTime;
    private final int triggerCount;
    private volatile AlertStatus status;
    private volatile long statusUpdatedAt;
    private volatile String resolutionNote;

    public Alert(String alertId, String ruleId, int ruleVersion, String entityId,
                 long createdAt, long triggerEventTime, int triggerCount,
                 AlertStatus status, long statusUpdatedAt, String resolutionNote) {
        this.alertId = alertId;
        this.ruleId = ruleId;
        this.ruleVersion = ruleVersion;
        this.entityId = entityId;
        this.createdAt = createdAt;
        this.triggerEventTime = triggerEventTime;
        this.triggerCount = triggerCount;
        this.status = status;
        this.statusUpdatedAt = statusUpdatedAt;
        this.resolutionNote = resolutionNote;
    }

    public String getAlertId() { return alertId; }
    public String getRuleId() { return ruleId; }
    public int getRuleVersion() { return ruleVersion; }
    public String getEntityId() { return entityId; }
    public long getCreatedAt() { return createdAt; }
    public long getTriggerEventTime() { return triggerEventTime; }
    public int getTriggerCount() { return triggerCount; }
    public AlertStatus getStatus() { return status; }
    public long getStatusUpdatedAt() { return statusUpdatedAt; }
    public String getResolutionNote() { return resolutionNote; }

    public void setStatus(AlertStatus status) { this.status = status; }
    public void setStatusUpdatedAt(long statusUpdatedAt) { this.statusUpdatedAt = statusUpdatedAt; }
    public void setResolutionNote(String resolutionNote) { this.resolutionNote = resolutionNote; }
}
