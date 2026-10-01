package com.github.lisama569.threatdetectionenginejava.persistence;

import java.util.List;

/** 来源描述符的持久化形态。 */
public record SourceMemento(String sourceId, List<String> entityKeys, List<String> typeKeys,
                           List<String> timeKeys, List<String> severityKeys,
                           List<String> allowedSeverities, String fixedType) {
    public SourceMemento {
        entityKeys = entityKeys == null ? List.of() : List.copyOf(entityKeys);
        typeKeys = typeKeys == null ? List.of() : List.copyOf(typeKeys);
        timeKeys = timeKeys == null ? List.of() : List.copyOf(timeKeys);
        severityKeys = severityKeys == null ? List.of() : List.copyOf(severityKeys);
        allowedSeverities = allowedSeverities == null ? List.of() : List.copyOf(allowedSeverities);
    }
}
