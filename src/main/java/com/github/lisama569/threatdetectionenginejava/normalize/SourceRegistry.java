package com.github.lisama569.threatdetectionenginejava.normalize;

import com.github.lisama569.threatdetectionenginejava.model.SourceDescriptor;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 已注册日志来源注册表。
 * <p>
 * 未注册来源的事件不得被静默丢弃，归一化阶段返回 SOURCE_NOT_REGISTERED 拒绝原因。
 */
@Component
public class SourceRegistry {

    private final Map<String, SourceDescriptor> descriptors = new ConcurrentHashMap<>();

    public void register(SourceDescriptor descriptor) {
        if (descriptor == null || descriptor.source() == null || descriptor.source().isBlank()) {
            throw new IllegalArgumentException("source descriptor must carry a non-blank source id");
        }
        descriptors.put(descriptor.source(), descriptor);
    }

    public Optional<SourceDescriptor> find(String source) {
        if (source == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(descriptors.get(source));
    }
}
