package com.github.lisama569.threatdetectionenginejava.persistence;

import java.util.Map;

/** 守恒统计与拒绝原因分布的持久化形态（重启后累计延续）。 */
public record StatsMemento(long total, long rejected, long duplicate, long tooLate,
                          long acceptedNoAlert, long acceptedAlert,
                          Map<String, Long> rejectionBreakdown) {
    public StatsMemento {
        rejectionBreakdown = rejectionBreakdown == null ? Map.of() : Map.copyOf(rejectionBreakdown);
    }
}
