package com.github.lisama569.threatdetectionenginejava.config;

import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.EventType;
import com.github.lisama569.threatdetectionenginejava.model.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.normalize.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.rule.RuleRegistry;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;

/**
 * 默认来源映射与默认关联规则装配。
 * <p>
 * 三个演示来源：
 * <ul>
 *   <li>auth-sys：认证系统（ISO-8601 时间戳，类型词 auth_fail/auth_ok/priv_esc）</li>
 *   <li>edp-agent：终端检测代理（epoch millis 时间戳，类型词 fail_login/escalation/malware）</li>
 *   <li>web-gateway：Web 网关（秒级 epoch 数字时间戳，类型词 web_attack/blocked）</li>
 * </ul>
 * 默认规则 brute-force-login v1：10 秒窗口内同实体 3 次登录失败/封禁即告警，允许迟到 5 秒。
 */
@Configuration
@EnableConfigurationProperties(EngineProperties.class)
public class DefaultDataInitializer {

    private static final Logger log = LoggerFactory.getLogger(DefaultDataInitializer.class);

    private final SourceRegistry sourceRegistry;
    private final RuleRegistry ruleRegistry;
    private final EngineProperties properties;

    public DefaultDataInitializer(SourceRegistry sourceRegistry,
                                  RuleRegistry ruleRegistry,
                                  EngineProperties properties) {
        this.sourceRegistry = sourceRegistry;
        this.ruleRegistry = ruleRegistry;
        this.properties = properties;
    }

    @PostConstruct
    void initialize() {
        sourceRegistry.register(new SourceDescriptor(
                "auth-sys", "username", "action", "ts",
                Map.of(
                        "auth_fail", EventType.FAILED_LOGIN,
                        "auth_ok", EventType.SUCCESSFUL_LOGIN,
                        "priv_esc", EventType.PRIVILEGE_ESCALATION)));

        sourceRegistry.register(new SourceDescriptor(
                "edp-agent", "host", "eventType", "occurredAt",
                Map.of(
                        "fail_login", EventType.FAILED_LOGIN,
                        "escalation", EventType.PRIVILEGE_ESCALATION,
                        "malware", EventType.MALWARE_DETECTED)));

        sourceRegistry.register(new SourceDescriptor(
                "web-gateway", "srcIp", "kind", null,
                Map.of(
                        "web_attack", EventType.WEB_ATTACK,
                        "blocked", EventType.FIREWALL_BLOCK)));

        ruleRegistry.put(new CorrelationRule(
                "brute-force-login", 1,
                List.of(EventType.FAILED_LOGIN, EventType.FIREWALL_BLOCK),
                3, 10_000L, 5_000L));

        ruleRegistry.put(new CorrelationRule(
                "malware-or-escalation", 1,
                List.of(EventType.MALWARE_DETECTED, EventType.PRIVILEGE_ESCALATION),
                1, 10_000L, 5_000L));

        log.info("default sources and rules initialized (journalPath='{}', replayOnStart={})",
                properties.journalPath(), properties.replayOnStart());
    }
}
