package com.github.lisama569.threatdetectionenginejava.detection;

import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowSnapshot;
import com.github.lisama569.threatdetectionenginejava.persistence.EventRefMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.FixedWindowMemento;
import com.github.lisama569.threatdetectionenginejava.persistence.WindowMemento;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * 单（规则版本, 实体）维度的窗口状态。
 *
 * 确定性语义（只依赖事件内容与到达顺序）：
 * <ul>
 *   <li>固定窗口按 eventTime 对齐：windowStart = floor(eventTime / windowMillis) * windowMillis；</li>
 *   <li>watermark = 已见最大 eventTime；事件满足 watermark - eventTime &lt;= lateTolerance 才被接受，
 *       否则标记 TOO_LATE，不参与计数；</li>
 *   <li>窗口内按 eventId 内容去重，重复内容不重复计数；</li>
 *   <li>每个窗口最多告警一次：去重计数首次达到阈值时 crossedThreshold=true；</li>
 *   <li>窗口 end &lt;= watermark - lateTolerance 时，其中任何事件都必被判迟到，安全驱逐。</li>
 * </ul>
 *
 * 本类非线程安全，由上层按实体加锁保护。
 */
public final class WindowState {

    private static final java.util.Comparator<SecurityEvent> EVENT_ORDER =
            java.util.Comparator.comparingLong(SecurityEvent::eventTime)
                    .thenComparing(SecurityEvent::eventId);

    private final String ruleId;
    private final int ruleVersion;
    private final String entityId;
    private final long windowMillis;

    /** windowStart -> 固定窗口 */
    private final NavigableMap<Long, FixedWindow> windows = new TreeMap<>();
    private long watermark = Long.MIN_VALUE;

    public WindowState(String ruleId, int ruleVersion, String entityId, long windowMillis) {
        if (windowMillis <= 0) {
            throw new IllegalArgumentException("windowMillis 必须为正数");
        }
        this.ruleId = ruleId;
        this.ruleVersion = ruleVersion;
        this.entityId = entityId;
        this.windowMillis = windowMillis;
    }

    public String getRuleId() { return ruleId; }
    public int getRuleVersion() { return ruleVersion; }
    public String getEntityId() { return entityId; }
    public long getWindowMillis() { return windowMillis; }
    public long getWatermark() { return watermark == Long.MIN_VALUE ? 0L : watermark; }

    /**
     * 判定一个事件。
     *
     * @param event         归一化事件
     * @param lateTolerance 迟到容忍（毫秒）
     * @param threshold     规则阈值
     * @return 判定结论
     */
    public Evaluation accept(SecurityEvent event, long lateTolerance, int threshold) {
        if (lateTolerance < 0) {
            throw new IllegalArgumentException("lateTolerance 不能为负");
        }
        long priorWatermark = watermark;
        boolean tooLate = priorWatermark != Long.MIN_VALUE
                && priorWatermark - event.eventTime() > lateTolerance;

        long start = windowStart(event.eventTime());
        FixedWindow target = windows.get(start);

        if (tooLate) {
            WindowSnapshot current = target == null ? null : snapshot(target);
            String reason = "事件超过迟到容忍被标记 TOO_LATE: eventTime=" + event.eventTime()
                    + ", watermark=" + priorWatermark
                    + ", 落后=" + (priorWatermark - event.eventTime()) + "ms"
                    + ", 容忍=" + lateTolerance + "ms";
            return new Evaluation(false, false, false, true, event, current, current, reason);
        }

        WindowSnapshot before = target == null
                ? new WindowSnapshot(ruleId, ruleVersion, entityId, start, start + windowMillis,
                        0, List.of(), getWatermark(), false)
                : snapshot(target);

        boolean contentDuplicate = target != null && target.eventIds.contains(event.eventId());
        boolean crossed = false;
        if (target == null) {
            target = new FixedWindow(start);
            windows.put(start, target);
        }
        if (!contentDuplicate) {
            target.eventIds.add(event.eventId());
            target.events.add(event);
            if (!target.alerted && target.eventIds.size() >= threshold) {
                target.alerted = true;
                crossed = true;
            }
        }

        if (event.eventTime() > watermark) {
            watermark = event.eventTime();
        }
        evict(lateTolerance);

        String reason;
        if (contentDuplicate) {
            reason = "窗口内已存在相同内容事件(eventId=" + event.eventId() + ")，不重复计数";
        } else if (crossed) {
            reason = "窗口 [" + start + "," + (start + windowMillis) + ") 去重计数 "
                    + target.eventIds.size() + " 首次达到阈值 " + threshold + "，产生告警";
        } else {
            reason = "事件计入窗口 [" + start + "," + (start + windowMillis) + ")，当前去重计数 "
                    + target.eventIds.size() + "/" + threshold + "，未越阈";
        }
        return new Evaluation(true, crossed, contentDuplicate, false, event, before,
                snapshot(target), reason);
    }

    /** 窗口 end &lt;= watermark - lateTolerance 时驱逐（其中任何事件今后都必被判 TOO_LATE）。 */
    public void evict(long lateTolerance) {
        if (watermark == Long.MIN_VALUE) {
            return;
        }
        long boundary = watermark - lateTolerance;
        windows.entrySet().removeIf(e -> e.getKey() + windowMillis <= boundary);
    }

    private long windowStart(long eventTime) {
        return Math.floorDiv(eventTime, windowMillis) * windowMillis;
    }

    private WindowSnapshot snapshot(FixedWindow w) {
        List<String> ids = w.events.stream().map(SecurityEvent::eventId).toList();
        return new WindowSnapshot(ruleId, ruleVersion, entityId, w.start, w.start + windowMillis,
                w.eventIds.size(), ids, getWatermark(), w.alerted);
    }

    /** 最近一个窗口的快照（无窗口时返回空快照）。 */
    public WindowSnapshot snapshot() {
        Map.Entry<Long, FixedWindow> last = windows.lastEntry();
        return last == null
                ? new WindowSnapshot(ruleId, ruleVersion, entityId, 0L, windowMillis,
                        0, List.of(), getWatermark(), false)
                : snapshot(last.getValue());
    }

    public List<WindowSnapshot> snapshots() {
        List<WindowSnapshot> result = new ArrayList<>();
        for (FixedWindow w : windows.values()) {
            result.add(snapshot(w));
        }
        return result;
    }

    /** 调试：watermark 所在窗口内的事件（按 eventTime 排序）。 */
    public List<SecurityEvent> debugEvents() {
        if (watermark == Long.MIN_VALUE) {
            return List.of();
        }
        FixedWindow current = windows.get(windowStart(watermark));
        return current == null ? List.of() : List.copyOf(current.events);
    }

    /**
     * 导出持久化备忘录：watermark（迟到判断基准）+ 全部尚未驱逐的窗口
     * （计数、去重指纹、已告警标记）。已被 {@link #evict} 回收的窗口不导出。
     */
    public WindowMemento toMemento() {
        List<FixedWindowMemento> windowMementos = new ArrayList<>();
        for (FixedWindow w : windows.values()) {
            List<EventRefMemento> refs = w.events.stream()
                    .map(e -> new EventRefMemento(e.eventId(), e.eventTime()))
                    .toList();
            windowMementos.add(new FixedWindowMemento(w.start, w.alerted, refs));
        }
        long restoredWatermark = watermark == Long.MIN_VALUE ? 0L : watermark;
        return new WindowMemento(ruleId, ruleVersion, entityId, windowMillis,
                restoredWatermark, windowMementos);
    }

    /**
     * 从持久化备忘录重建窗口状态：watermark、窗口内去重指纹与已告警标记逐项延续，
     * 因此重启后的迟到判断、内容去重与“同一窗口不重复告警”结论与未重启完全一致。
     */
    public static WindowState fromMemento(WindowMemento m) {
        WindowState state = new WindowState(m.ruleId(), m.ruleVersion(), m.entityId(),
                m.windowMillis());
        if (m.windows().isEmpty()) {
            // 没有存活窗口时 watermark 无判定意义，保持初始值
            return state;
        }
        state.watermark = m.watermark();
        for (FixedWindowMemento wm : m.windows()) {
            FixedWindow w = new FixedWindow(wm.start());
            w.alerted = wm.alerted();
            for (EventRefMemento ref : wm.events()) {
                w.eventIds.add(ref.eventId());
                // 仅判定/调试所需字段（指纹+时间）；source/类型等原始字段不参与窗口判定
                w.events.add(new SecurityEvent(ref.eventId(), m.ruleId(), m.entityId(),
                        null, null, ref.eventTime(), 0L, null));
            }
            state.windows.put(wm.start(), w);
        }
        return state;
    }

    private static final class FixedWindow {
        final long start;
        final TreeSet<String> eventIds = new TreeSet<>();
        final TreeSet<SecurityEvent> events = new TreeSet<>(EVENT_ORDER);
        boolean alerted = false;

        FixedWindow(long start) {
            this.start = start;
        }
    }
}
