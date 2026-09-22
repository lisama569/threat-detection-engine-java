package com.github.lisama569.threatdetectionenginejava.window;

/**
 * 对齐时间窗（tumbling window）计算工具。
 * <p>
 * 窗口边界以 epoch millis 对齐：windowStart = floor(eventTime / windowSize) * windowSize，
 * 因此边界是纯函数，不依赖到达顺序，保证乱序/窗口抖动/重放时窗口归属一致。
 */
public final class WindowMath {

    private WindowMath() {
    }

    /**
     * 计算事件所属窗口的起始时间。
     *
     * @param eventTimeMs  事件时间
     * @param windowSizeMs 窗口长度（必须为正）
     */
    public static long windowStart(long eventTimeMs, long windowSizeMs) {
        if (windowSizeMs <= 0) {
            throw new IllegalArgumentException("windowSizeMs must be positive: " + windowSizeMs);
        }
        return Math.floorDiv(eventTimeMs, windowSizeMs) * windowSizeMs;
    }

    /**
     * 窗口结束时间（左闭右开）。
     */
    public static long windowEnd(long windowStartMs, long windowSizeMs) {
        return windowStartMs + windowSizeMs;
    }

    /**
     * 判断事件对某窗口是否迟到：事件到达时该窗口已超过容忍关闭点。
     *
     * @param windowEndMs      窗口结束时间
     * @param arrivalTimeMs    事件到达引擎的时间（重放时使用原始 ingestTime）
     * @param allowedLatenessMs 允许迟到时长
     * @return true 表示超出容忍范围
     */
    public static boolean isBeyondTolerance(long windowEndMs, long arrivalTimeMs, long allowedLatenessMs) {
        return arrivalTimeMs > windowEndMs + allowedLatenessMs;
    }
}
