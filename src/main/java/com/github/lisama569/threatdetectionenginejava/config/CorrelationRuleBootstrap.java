package com.github.lisama569.threatdetectionenginejava.config;

import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.normalization.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.persistence.RecoveryReport;
import com.github.lisama569.threatdetectionenginejava.persistence.StateRecoveryCoordinator;
import com.github.lisama569.threatdetectionenginejava.service.DetectionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

import java.util.List;

/**
 * 启动时注册默认来源与初始规则（本地内存模拟）。
 *
 * <p>运行在 {@link StateRecoveryCoordinator} 恢复完成之后：来源注册幂等可重复；
 * 初始规则仅在“全新/禁用恢复（无历史规则）”时部署，已恢复的规则版本以快照为准，不被覆盖。</p>
 */
@Configuration
public class CorrelationRuleBootstrap {

    private static final Logger log = LoggerFactory.getLogger(CorrelationRuleBootstrap.class);

    /** 默认迟到/乱序容忍：10 秒。 */
    public static final long DEFAULT_LATE_TOLERANCE_MILLIS = 10_000L;

    @Bean
    @Order(0)
    public CommandLineRunner seedData(DetectionService service, StateRecoveryCoordinator recovery) {
        return args -> {
            for (SourceDescriptor source : defaultSources()) {
                service.registerSource(source);
            }
            RecoveryReport report = recovery.report();
            boolean restored = report != null && report.restoredRules() > 0;
            if (restored) {
                log.info("检测到已恢复 {} 个规则版本，跳过初始规则部署，规则以本地状态为准",
                        report.restoredRules());
            } else {
                service.deployRule(bruteForceRuleV1());
                log.info("默认来源 {} 个、初始规则 1 个已装载（恢复状态={}）",
                        defaultSources().size(), report == null ? "UNKNOWN" : report.status());
            }
        };
    }

    /** 初始规则 v1：60 秒窗口内同一主机出现 3 次登录失败即告警。 */
    public static CorrelationRule bruteForceRuleV1() {
        return new CorrelationRule(
                "R-BRUTE-FORCE", 1,
                List.of("login_failure"),
                List.of(),
                60_000L,
                3,
                DEFAULT_LATE_TOLERANCE_MILLIS);
    }

    /** 规则更新示例 v2：收紧窗口为 30 秒、阈值降为 2（用于重放对比演示）。 */
    public static CorrelationRule bruteForceRuleV2() {
        return new CorrelationRule(
                "R-BRUTE-FORCE", 2,
                List.of("login_failure"),
                List.of(),
                30_000L,
                2,
                DEFAULT_LATE_TOLERANCE_MILLIS);
    }

    static List<SourceDescriptor> defaultSources() {
        return List.of(
                // EDR：扁平 JSON，epoch 毫秒
                new SourceDescriptor(
                        "edr",
                        List.of("hostId", "host"),
                        List.of("eventType", "type"),
                        List.of("timestamp", "ts"),
                        List.of("severity", "sev"),
                        List.of("low", "medium", "high", "critical"),
                        null),
                // 防火墙：嵌套 host.id，ISO-8601 时间，动作映射为类型由 payload 直接给出
                new SourceDescriptor(
                        "firewall",
                        List.of("host.id", "srcIp"),
                        List.of("event.type", "type"),
                        List.of("event.time", "@timestamp"),
                        List.of("event.severity"),
                        List.of("low", "medium", "high", "critical"),
                        null),
                // Syslog：传统字段名，秒级 epoch
                new SourceDescriptor(
                        "syslog",
                        List.of("host_id", "hostname"),
                        List.of("event_code_desc", "msg_type"),
                        List.of("epoch", "time"),
                        List.of("level"),
                        List.of(),
                        null));
    }
}
