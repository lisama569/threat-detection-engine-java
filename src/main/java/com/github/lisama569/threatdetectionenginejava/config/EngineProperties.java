package com.github.lisama569.threatdetectionenginejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 引擎本地配置。
 *
 * @param journalPath    本地事件日志文件路径（空表示仅内存、不落盘）
 * @param replayOnStart  启动时是否重放日志
 */
@ConfigurationProperties(prefix = "threat.engine")
public record EngineProperties(
        String journalPath,
        boolean replayOnStart
) {
    public EngineProperties {
        if (journalPath == null) {
            journalPath = "";
        }
    }
}
