package com.github.lisama569.threatdetectionenginejava.recovery;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** 重启续跑相关本地配置（均可通过 application.properties / 命令行覆盖）。 */
@Component
public class RecoveryProperties {

    /** 状态快照文件路径（仅本地文件）。 */
    private final String statePath;
    /** 状态文件存在但损坏/不可读时是否保守停服（true=FAILED 拒绝服务；false=全新启动并显式标记）。 */
    private final boolean failOnCorruptState;
    /** 恢复期间对外写请求最长阻塞等待毫秒数，超时返回 503。 */
    private final long awaitTimeoutMillis;

    public RecoveryProperties(
            @Value("${detection.state.path:./data/engine-state.json}") String statePath,
            @Value("${detection.state.fail-on-corrupt:true}") boolean failOnCorruptState,
            @Value("${detection.recovery.await-timeout-millis:10000}") long awaitTimeoutMillis) {
        this.statePath = statePath;
        this.failOnCorruptState = failOnCorruptState;
        this.awaitTimeoutMillis = awaitTimeoutMillis;
    }

    public String getStatePath() { return statePath; }
    public boolean isFailOnCorruptState() { return failOnCorruptState; }
    public long getAwaitTimeoutMillis() { return awaitTimeoutMillis; }
}
