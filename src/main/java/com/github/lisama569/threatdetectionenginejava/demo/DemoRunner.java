package com.github.lisama569.threatdetectionenginejava.demo;

import com.github.lisama569.threatdetectionenginejava.config.CorrelationRuleBootstrap;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 本地演示：--spring.profiles.active=demo 时向内存引擎投递一批
 * 乱序/重复/迟到/非法事件并打印结论、窗口状态与守恒统计。
 */
@Component
@Profile("demo")
@Order(20)
public class DemoRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoRunner.class);

    /** 固定演示基线：2026-09-22T10:00:00Z，避免结果随运行时间漂移。 */
    static final long BASE = java.time.Instant.parse("2026-09-22T10:00:00Z").toEpochMilli();

    private final DetectionService service;

    public DemoRunner(DetectionService service) {
        this.service = service;
    }

    @Override
    public void run(String... args) {
        List<RawEvent> batch = scenarioBatch();

        log.info("===== 场景批投递（共 {} 条，含乱序/重复/迟到/非法） =====", batch.size());
        List<IngestResult> online = service.ingestBatch(batch);
        for (int i = 0; i < batch.size(); i++) {
            RawEvent raw = batch.get(i);
            log.info("#{} source={} deliveryId={} => {}",
                    i + 1, raw.sourceId(), raw.deliveryId(), online.get(i));
        }

        log.info("===== 在线窗口状态 =====");
        service.debugWindows().forEach(w -> log.info("window: {}", w));

        log.info("===== 在线告警 =====");
        service.listAlerts().forEach(a -> log.info("alert: id={} rule={} v{} entity={} status={} count={}",
                a.getAlertId(), a.getRuleId(), a.getRuleVersion(), a.getEntityId(),
                a.getStatus(), a.getTriggerCount()));

        log.info("===== 守恒统计（total = rejected+duplicate+tooLate+acceptedNoAlert+acceptedAlert）=====");
        log.info("stats={}, rejectionBreakdown={}", service.stats(), service.rejectionBreakdown());

        CorrelationRule v1 = CorrelationRuleBootstrap.bruteForceRuleV1();
        List<IngestResult> replay1 = service.replay(batch, List.of(v1));
        List<IngestResult> replay2 = service.replay(batch, List.of(v1));
        log.info("===== 可复现性：v1 规则重放两次结论一致 = {} =====", replay1.equals(replay2));

        CorrelationRule v2 = CorrelationRuleBootstrap.bruteForceRuleV2();
        List<IngestResult> replayV2 = service.replay(batch, List.of(v2));
        log.info("===== 规则更新对比：v1 vs v2 结论不同 = {} =====", !onlineSummary(replay1).equals(onlineSummary(replayV2)));
        log.info("v1 重放结论: {}", onlineSummary(replay1));
        log.info("v2 重放结论: {}", onlineSummary(replayV2));
    }

    /** 演示场景：主机 host-1 在 60s 窗口内触发阈值；host-2 全部迟到超容忍。 */
    static List<RawEvent> scenarioBatch() {
        return List.of(
                // host-1：第 1、3 条乱序到达，第 2 条重复投递（deliveryId 相同）
                event("edr", "dlv-001", "host-1", "login_failure", BASE + 5_000, "low"),
                event("edr", "dlv-003", "host-1", "login_failure", BASE + 1_000, "low"),
                event("edr", "dlv-001", "host-1", "login_failure", BASE + 5_000, "low"), // 重复投递
                event("edr", "dlv-004", "host-1", "login_failure", BASE + 9_000, "medium"),
                // 同内容但无 deliveryId：靠内容指纹在窗口内去重（不重复计数）
                event("edr", null, "host-1", "login_failure", BASE + 9_000, "medium"),
                // host-2：先到 30s 事件，再来 2s 事件 => 落后 28s 超过 10s 容忍 => TOO_LATE
                firewallEvent("dlv-101", "host-2", "login_failure", BASE + 30_000, "high"),
                firewallEvent("dlv-102", "host-2", "login_failure", BASE + 2_000, "high"),
                // 非法记录：未注册来源 / 缺实体 / 时间戳非法
                event("unknown-src", "dlv-201", "host-3", "login_failure", BASE + 1_000, "low"),
                event("edr", "dlv-202", null, "login_failure", BASE + 1_000, "low"),
                event("edr", "dlv-203", "host-4", "login_failure", "not-a-timestamp", "low"));
    }

    private static RawEvent event(String source, String deliveryId, String host,
                                  String type, Object ts, String severity) {
        Map<String, Object> payload = new LinkedHashMap<>();
        if (host != null) {
            payload.put("hostId", host);
        }
        payload.put("eventType", type);
        payload.put("timestamp", ts);
        payload.put("severity", severity);
        return new RawEvent(source, deliveryId, payload);
    }

    private static RawEvent firewallEvent(String deliveryId, String host, String type,
                                          long ts, String severity) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("type", type);
        event.put("time", java.time.Instant.ofEpochMilli(ts).toString());
        event.put("severity", severity);
        Map<String, Object> payload = new LinkedHashMap<>();
        Map<String, Object> hostNode = new LinkedHashMap<>();
        hostNode.put("id", host);
        payload.put("host", hostNode);
        payload.put("event", event);
        return new RawEvent("firewall", deliveryId, payload);
    }

    private static List<String> onlineSummary(List<IngestResult> results) {
        return results.stream().map(r -> r.outcome() + ":" + r.alertId()).toList();
    }
}
