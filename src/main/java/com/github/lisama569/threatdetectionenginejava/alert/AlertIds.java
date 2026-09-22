package com.github.lisama569.threatdetectionenginejava.alert;

/**
 * 确定性告警 ID 派生。
 * <p>
 * alertId = ruleId#v{version}#{entityId}#{windowStart}，
 * 不包含随机量，使重复投递、窗口边界抖动、进程重启重放都不会产生第二个告警。
 */
public final class AlertIds {

    private AlertIds() {
    }

    public static String derive(String ruleId, int ruleVersion, String entityId, long windowStartMs) {
        return ruleId + "#v" + ruleVersion + "#" + entityId + "#" + windowStartMs;
    }
}
