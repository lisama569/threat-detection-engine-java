package com.github.lisama569.threatdetectionenginejava.web;

import com.github.lisama569.threatdetectionenginejava.alert.InvalidAlertTransitionException;
import com.github.lisama569.threatdetectionenginejava.model.Alert;
import com.github.lisama569.threatdetectionenginejava.model.AlertStatus;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.recovery.RecoveryStatus;
import com.github.lisama569.threatdetectionenginejava.recovery.ServiceUnavailableException;
import com.github.lisama569.threatdetectionenginejava.recovery.StateCheckpointService;
import com.github.lisama569.threatdetectionenginejava.recovery.StateSnapshotService;
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
    private final StateCheckpointService checkpointService;
    private final StateSnapshotService snapshotService;

    public DetectionController(DetectionService service, StateCheckpointService checkpointService,
                               StateSnapshotService snapshotService) {
        this.service = service;
        this.checkpointService = checkpointService;
        this.snapshotService = snapshotService;
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
        body.put("recovery", service.recoveryStatus());
        return body;
    }

    /** 恢复状态：恢复中/已恢复/全新/失败、是否损坏重置、状态文件、说明。 */
    @GetMapping("/recovery")
    public RecoveryStatus recovery() {
        return service.recoveryStatus();
    }

    /** 手动把当前运行状态原子落盘（本地滚动重启/演示与测试用；非 ACTIVE 阶段返回 409）。 */
    @PostMapping("/state/checkpoint")
    public ResponseEntity<Map<String, Object>> checkpoint() {
        boolean saved = checkpointService.checkpoint(
                () -> service.captureState(snapshotService));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("saved", saved);
        body.put("recovery", service.recoveryStatus());
        return ResponseEntity.status(saved ? HttpStatus.OK : HttpStatus.CONFLICT).body(body);
    }

    @GetMapping("/debug/windows")
    public Object debugWindows() {
        return service.debugWindows();
    }

    /**
     * 恢复未完成/恢复失败导致写服务不可用：503，带恢复阶段，与“空实例正常接收”明确区分。
     * 注意：恢复期间请求在业务层会阻塞等待恢复结束；只有恢复失败或等待超时才回到这里。
     */
    @ExceptionHandler(ServiceUnavailableException.class)
    public ResponseEntity<Map<String, Object>> handleUnavailable(ServiceUnavailableException e) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "SERVICE_UNAVAILABLE");
        body.put("recoveryPhase", e.phase());
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
