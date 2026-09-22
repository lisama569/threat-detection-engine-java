package com.github.lisama569.threatdetectionenginejava.model;

import java.util.List;

/**
 * 批量摄入报告，各分项之和恒等于 total，可做守恒统计。
 */
public record BatchReport(
        int total,
        int accepted,
        int duplicate,
        int lateWithinTolerance,
        int lateBeyondTolerance,
        int rejected,
        int alertsRaised,
        List<IngestOutcome> outcomes
) {
}
