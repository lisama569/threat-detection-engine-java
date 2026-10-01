package com.github.lisama569.threatdetectionenginejava.persistence;

import java.util.List;

/** 关联规则的持久化形态（含全部历史版本中的一条）。 */
public record RuleMemento(String ruleId, int version, List<String> eventTypes,
                         List<String> entityScope, long windowMillis, int threshold,
                         long lateToleranceMillis) {
    public RuleMemento {
        eventTypes = eventTypes == null ? List.of() : List.copyOf(eventTypes);
        entityScope = entityScope == null ? List.of() : List.copyOf(entityScope);
    }
}
