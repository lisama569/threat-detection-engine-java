package com.github.lisama569.threatdetectionenginejava.web;

import com.github.lisama569.threatdetectionenginejava.alert.InvalidAlertTransitionException;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryFailedException;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryInProgressException;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryReport;
import com.github.lisama569.threatdetectionenginejava.persistence.StateRecoveryCoordinator;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import com.github.lisama569.threatdetectionenginejava.web.dto.IngestRequest;
import com.github.lisama569.threatdetectionenginejava.web.dto.IngestResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** 本地验证用 REST 接口。 */
@RestController
@RequestMapping("/api")
public class DetectionController {

    private final DetectionService service;
    private final StateRecoveryCoordinator recovery;

    public DetectionController(DetectionService service, StateRecoveryCoordinator recovery) {
        this.service = service;
        this.recovery = recovery;
    }

    @PostMapping("/events")
    public IngestResponse ingest(@RequestBody IngestRequest request) {
        RawEvent raw = new RawEvent(request.sourceId(), request.deliveryId(), request.payload());
        return IngestResponse.from(service.ingest(raw));
    }

    @PostMapping("/events/batch")
    public List<IngestResponse> ingestBatch(@RequestBody List<IngestRequest> requests) {
        List<RawEvent> raws = requests.stream()
                .map(r -> new RawEvent(r.sourceId(), r.deliveryId(), r.payload()))
                .toList();
        return service.ingestBatch(raws).stream().map(IngestResponse::from).toList();
    }

    @GetMapping("/alerts")
    public List<Alert> listAlerts() {
        return service.listAlerts();
    }

    @PostMapping("/alerts/{id}/transition")
    public Alert transition(@PathVariable String id, @RequestParam AlertStatus to,
                            @RequestParam(required = false) String note) {
        return service.transitionAlert(id, to, note);
    }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("stats", service.stats());
        body.put("rejectionBreakdown", service.rejectionBreakdown());
        body.put("recovery", recoveryView());
        return body;
    }

    /** 重启恢复结论：阶段/状态/代数/恢复计数/详情，任何阶段都可查看。 */
    @GetMapping("/recovery")
    public Map<String, Object> recovery() {
        return recoveryView();
    }

    private Map<String, Object> recoveryView() {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("phase", recovery.phase().name());
        view.put("generation", recovery.generation());
        RecoveryReport report = recovery.report();
        if (report != null) {
            view.put("status", report.status());
            view.put("detail", report.detail());
            view.put("restoredAlerts", report.restoredAlerts());
            view.put("restoredWindowStates", report.restoredWindowStates());
            view.put("restoredDedupKeys", report.restoredDedupKeys());
            view.put("restoredRules", report.restoredRules());
            view.put("retainedWindows", report.retainedWindows());
        }
        return view;
    }

    @GetMapping("/debug/windows")
    public Object debugWindows() {
        return service.debugWindows();
    }

    /** 恢复进行中：503，请求未被处理，客户端应稍后重试，恢复后不会被重复计算。 */
    @ExceptionHandler(RecoveryInProgressException.class)
    public ResponseEntity<Map<String, Object>> handleRecovering(RecoveryInProgressException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "RECOVERY_IN_PROGRESS");
        body.put("phase", recovery.phase().name());
        body.put("detail", e.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    /** 本地状态恢复失败：503，实例拒绝写入，绝不静默按空实例服务。 */
    @ExceptionHandler(RecoveryFailedException.class)
    public ResponseEntity<Map<String, Object>> handleRecoveryFailed(RecoveryFailedException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "RECOVERY_FAILED");
        body.put("phase", recovery.phase().name());
        RecoveryReport report = recovery.report();
        if (report != null) {
            body.put("recoveryStatus", report.status());
        }
        body.put("detail", e.getMessage());
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }

    /** 非法告警迁移：409 冲突，结构化区分 from/to。 */
    @ExceptionHandler(InvalidAlertTransitionException.class)
    public ResponseEntity<Map<String, Object>> handleTransition(InvalidAlertTransitionException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "INVALID_ALERT_TRANSITION");
        body.put("from", e.getFrom());
        body.put("to", e.getTo());
        body.put("detail", e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
    }

    /** 资源不存在或规则版本非法等参数类错误：400/404，结构化可区分，不返回 500。 */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException e) {
        boolean notFound = e.getMessage() != null && e.getMessage().contains("不存在");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", notFound ? "NOT_FOUND" : "INVALID_ARGUMENT");
        body.put("detail", e.getMessage());
        return ResponseEntity.status(notFound ? HttpStatus.NOT_FOUND : HttpStatus.BAD_REQUEST).body(body);
    }
}
