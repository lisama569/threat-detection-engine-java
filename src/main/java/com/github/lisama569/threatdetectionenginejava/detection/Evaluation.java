package com.github.lisama569.threatdetectionenginejava.detection;

import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.model.WindowSnapshot;

/**
 * 单事件在单规则上的窗口判定结论（引擎内部使用）。
 *
 * @param accepted 是否参与了窗口计数
 * @param crossedThreshold 是否由本事件导致阈值跨越（窗口首次达到阈值）
 * @param contentDuplicate 是否窗口内重复内容事件（不计数）
 * @param tooLate 是否超过迟到容忍
 * @param event 归一化事件
 * @param before 判定前窗口快照（迟到时取该事件所属窗口当前状态，可能为 null）
 * @param after 判定后窗口快照（迟到且窗口不存在时为 null）
 * @param reason 判定依据可读说明
 */
public record Evaluation(
        boolean accepted,
        boolean crossedThreshold,
        boolean contentDuplicate,
        boolean tooLate,
        SecurityEvent event,
        WindowSnapshot before,
        WindowSnapshot after,
        String reason) {
}
