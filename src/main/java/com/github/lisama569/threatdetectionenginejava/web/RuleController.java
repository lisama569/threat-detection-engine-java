package com.github.lisama569.threatdetectionenginejava.web;

import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.rule.RuleRegistry;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 规则版本管理 REST 接口。骨架。
 */
@RestController
@RequestMapping("/api/rules")
public class RuleController {

    private final RuleRegistry ruleRegistry;

    public RuleController(RuleRegistry ruleRegistry) {
        this.ruleRegistry = ruleRegistry;
    }

    @GetMapping
    public List<CorrelationRule> list() {
        return ruleRegistry.currentRules();
    }

    @PostMapping
    public CorrelationRule upsert(@RequestBody CorrelationRule rule) {
        return ruleRegistry.put(rule);
    }

    @GetMapping("/{ruleId}/versions/{version}")
    public CorrelationRule version(@PathVariable String ruleId, @PathVariable int version) {
        return ruleRegistry.getVersion(ruleId, version).orElse(null);
    }
}
