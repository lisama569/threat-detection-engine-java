package com.github.lisama569.threatdetectionenginejava.store;

/**
 * 摄入守恒统计：按结论分类计数。
 * 守恒关系：total = rejected + duplicate + tooLate + acceptedNoAlert + acceptedAlert
 * （acceptedAlert 与产生的告警数一一对应）。
 */
public record IngestStats(long total, long rejected, long duplicate, long tooLate,
                          long acceptedNoAlert, long acceptedAlert) {

    public static IngestStats zeros() {
        return new IngestStats(0, 0, 0, 0, 0, 0);
    }
}
