package com.github.lisama569.threatdetectionenginejava.web;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleManager;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.TransitionResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * 告警查询与生命周期管理 REST 接口。骨架。
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertLifecycleManager alertManager;

    public AlertController(AlertLifecycleManager alertManager) {
        this.alertManager = alertManager;
    }

    @GetMapping
    public List<Alert> list() {
        return alertManager.all();
    }

    @PostMapping("/{alertId}/transition")
    public ResponseEntity<TransitionResult> transition(@PathVariable String alertId,
                                                       @RequestBody Map<String, String> body) {
        AlertStatus target = AlertStatus.valueOf(body.get("status"));
        TransitionResult result = alertManager.transition(alertId, target);
        return result.accepted() ? ResponseEntity.ok(result) : ResponseEntity.badRequest().body(result);
    }
}
