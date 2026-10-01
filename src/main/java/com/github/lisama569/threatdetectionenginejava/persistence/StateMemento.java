package com.github.lisama569.threatdetectionenginejava.persistence;

import java.util.List;

/**
 * 全量本地运行状态的持久化根对象（一次快照 = 一个原子文件）。
 *
 * <p>覆盖：快照版本、保存时间、来源、全部历史规则版本、未驱逐窗口、投递去重键、
 * 告警（含处置状态）、守恒统计。已驱逐窗口不在其中（见 {@code StateCodec} 的回收说明）。</p>
 */
public record StateMemento(int formatVersion, long savedAtMillis, List<SourceMemento> sources,
                          List<RuleMemento> rules, List<WindowMemento> windows,
                          List<String> dedupKeys, List<AlertMemento> alerts,
                          StatsMemento stats) {

    /** 当前快照格式版本，后续不兼容演进时递增。 */
    public static final int FORMAT_VERSION = 1;

    public StateMemento {
        sources = sources == null ? List.of() : List.copyOf(sources);
        rules = rules == null ? List.of() : List.copyOf(rules);
        windows = windows == null ? List.of() : List.copyOf(windows);
        dedupKeys = dedupKeys == null ? List.of() : List.copyOf(dedupKeys);
        alerts = alerts == null ? List.of() : List.copyOf(alerts);
    }
}
