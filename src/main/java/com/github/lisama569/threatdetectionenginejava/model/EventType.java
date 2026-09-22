package com.github.lisama569.threatdetectionenginejava.model;

/**
 * 归一化后的统一事件类型。未知来源类型在归一化时被拒绝。
 */
public enum EventType {
    FAILED_LOGIN,
    SUCCESSFUL_LOGIN,
    PRIVILEGE_ESCALATION,
    MALWARE_DETECTED,
    FIREWALL_BLOCK,
    WEB_ATTACK
}
