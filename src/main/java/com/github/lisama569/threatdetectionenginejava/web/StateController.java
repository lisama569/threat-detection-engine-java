package com.github.lisama569.threatdetectionenginejava.web;

import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.model.WindowState;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * 可解释性查询接口：watermark 与窗口状态。骨架。
 */
@RestController
@RequestMapping("/api/state")
public class StateController {

    private final CorrelationEngine engine;

    public StateController(CorrelationEngine engine) {
        this.engine = engine;
    }

    @GetMapping("/watermark")
    public long watermark() {
        return engine.currentWatermarkMs();
    }

    @GetMapping("/window")
    public WindowState window(@RequestParam String ruleId,
                              @RequestParam int version,
                              @RequestParam String entityId,
                              @RequestParam long windowStartMs) {
        return engine.windowState(ruleId, version, entityId, windowStartMs).orElse(null);
    }
}
