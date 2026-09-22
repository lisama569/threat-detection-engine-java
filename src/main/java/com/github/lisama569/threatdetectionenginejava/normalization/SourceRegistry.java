package com.github.lisama569.threatdetectionenginejava.normalization;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** 已注册来源注册表（线程安全）。 */
public class SourceRegistry {

    private final ConcurrentMap<String, SourceDescriptor> descriptors = new ConcurrentHashMap<>();

    public void register(SourceDescriptor descriptor) {
        if (descriptor == null || descriptor.sourceId() == null || descriptor.sourceId().isBlank()) {
            throw new IllegalArgumentException("sourceId 不能为空");
        }
        descriptors.put(descriptor.sourceId(), descriptor);
    }

    public Optional<SourceDescriptor> find(String sourceId) {
        return Optional.ofNullable(descriptors.get(sourceId));
    }

    public boolean isRegistered(String sourceId) {
        return sourceId != null && descriptors.containsKey(sourceId);
    }
}
