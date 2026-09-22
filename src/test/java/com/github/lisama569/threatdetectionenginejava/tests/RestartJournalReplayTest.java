package com.github.lisama569.threatdetectionenginejava.tests;

import com.github.lisama569.threatdetectionenginejava.alert.AlertLifecycleManager;
import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.ingest.IngestService;
import com.github.lisama569.threatdetectionenginejava.journal.EventJournal;
import com.github.lisama569.threatdetectionenginejava.model.CorrelationRule;
import com.github.lisama569.threatdetectionenginejava.model.EventType;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.SourceDescriptor;
import com.github.lisama569.threatdetectionenginejava.normalize.EventNormalizer;
import com.github.lisama569.threatdetectionenginejava.normalize.SourceRegistry;
import com.github.lisama569.threatdetectionenginejava.rule.RuleRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.BASE;
import static com.github.lisama569.threatdetectionenginejava.tests.TestSupport.loginFail;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * 进程重启重放测试：用落盘日志 + 全新组件实例模拟重启，
 * 计数与告警必须完全恢复，且不产生重复告警。
 */
class RestartJournalReplayTest {

    private static final Logger log = LoggerFactory.getLogger(RestartJournalReplayTest.class);

    /** 手工构造一套与 TestSupport 一致但指向同一日志文件的全新组件（模拟新进程） */
    private IngestService freshService(Path journalPath) {
        SourceRegistry sources = new SourceRegistry();
        sources.register(new SourceDescriptor("auth-sys", "username", "action", "ts",
                Map.of("auth_fail", EventType.FAILED_LOGIN)));
        RuleRegistry rules = new RuleRegistry();
        rules.put(new CorrelationRule("brute-force-login", 1,
                List.of(EventType.FAILED_LOGIN), 3, 10_000L, 5_000L));
        AlertLifecycleManager alerts = new AlertLifecycleManager();
        CorrelationEngine engine = new CorrelationEngine(rules, alerts);
        EventJournal journal = new EventJournal(journalPath.toString());
        journal.init();
        // replayOnStart=true：手工 new 不触发 @PostConstruct，显式重放模拟进程启动恢复
        IngestService service = new IngestService(new EventNormalizer(sources), engine, journal, true);
        service.replayJournalOnStartup();
        return service;
    }

    @Test
    @DisplayName("重启后重放日志：窗口计数、阈值告警完整恢复，不重复不遗漏")
    void replayAfterRestart(@TempDir Path dir) {
        Path journalFile = dir.resolve("events.jsonl");

        // 第一次“进程”：摄入 2 个事件（未达阈值）
        IngestService first = freshService(journalFile);
        first.ingest(loginFail("j1", "alice", BASE + 1_000));
        first.ingest(loginFail("j2", "alice", BASE + 2_000));
        log.info("[RESTART] journal lines after first run = {}",
                new EventJournal(journalFile.toString()).readAll().size());

        // 模拟重启：全新实例从日志恢复
        IngestService second = freshService(journalFile);
        // 重放后重复投递一条旧事件：幂等，不改变结论
        IngestOutcome dup = second.ingest(loginFail("j1", "alice", BASE + 1_000));
        log.info("[RESTART] duplicate after restart status={}", dup.status());
        assertThat(dup.status().name()).isEqualTo("DUPLICATE");

        // 再补一条新事件使阈值达成
        IngestOutcome crossing = second.ingest(loginFail("j3", "alice", BASE + 3_000));
        log.info("[RESTART] crossing outcome={}", crossing.ruleEvaluations());
        assertThat(crossing.ruleEvaluations().get(0).windowCount()).isEqualTo(3);
        assertThat(crossing.ruleEvaluations().get(0).alertId()).isNotNull();

        // 再次重启：告警已由 j1/j2/j3 在重放中恢复，j3 不得产生第二个告警
        IngestService third = freshService(journalFile);
        for (RawEvent r : List.of(
                loginFail("j1", "alice", BASE + 1_000),
                loginFail("j2", "alice", BASE + 2_000),
                loginFail("j3", "alice", BASE + 3_000))) {
            IngestOutcome o = third.ingest(r);
            assertThat(o.status().name()).isEqualTo("DUPLICATE");
        }
        IngestOutcome post = third.ingest(loginFail("j3", "alice", BASE + 3_000));
        assertThat(post.ruleEvaluations().get(0).windowCount()).isEqualTo(3);
        assertThat(post.ruleEvaluations().get(0).alertId()).isNull();
        log.info("[RESTART] replay stable; final window count={}, alerts via fresh replay verified",
                post.ruleEvaluations().get(0).windowCount());
    }
}
