package com.github.lisama569.threatdetectionenginejava.ingest;

import com.github.lisama569.threatdetectionenginejava.detection.CorrelationEngine;
import com.github.lisama569.threatdetectionenginejava.journal.EventJournal;
import com.github.lisama569.threatdetectionenginejava.journal.JournalEntry;
import com.github.lisama569.threatdetectionenginejava.model.BatchReport;
import com.github.lisama569.threatdetectionenginejava.model.IngestOutcome;
import com.github.lisama569.threatdetectionenginejava.model.IngestResult;
import com.github.lisama569.threatdetectionenginejava.model.IngestStatus;
import com.github.lisama569.threatdetectionenginejava.model.NormalizeResult;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import com.github.lisama569.threatdetectionenginejava.model.SecurityEvent;
import com.github.lisama569.threatdetectionenginejava.normalize.EventNormalizer;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 摄入门面。
 * <p>
 * 处理链：归一化校验 -&gt; 按全局 eventId 幂等去重 -&gt; 追加事件日志 -&gt; 关联检测。
 * <ul>
 *   <li>重复投递：命中已处理 eventId 缓存，直接返回首次结论（DUPLICATE），不计数不重复告警；</li>
 *   <li>按 eventId 分段加锁（striped lock），并发摄入下同一实体串行、不同实体并行，计数不丢不重；</li>
 *   <li>启动时确定性重放日志，恢复计数/告警，重启不产生重复告警；</li>
 *   <li>批量报告各分项之和恒等于 total，可做守恒统计。</li>
 * </ul>
 */
@Service
public class IngestService {

    private static final Logger log = LoggerFactory.getLogger(IngestService.class);
    private static final int STRIPES = 64;

    private final EventNormalizer normalizer;
    private final CorrelationEngine engine;
    private final EventJournal journal;
    private final boolean replayOnStart;

    /** 已接受处理过的全局 eventId -> 首次结论（含每规则评估），用于幂等重复投递 */
    private final Map<String, IngestOutcome> processed = new ConcurrentHashMap<>();
    /** 被拒绝的原始事件指纹，重复投递同一条非法记录时仍返回相同拒绝结论 */
    private final Set<String> rejectedFingerprints = ConcurrentHashMap.newKeySet();

    private final ReentrantLock[] stripes;

    public IngestService(EventNormalizer normalizer,
                         CorrelationEngine engine,
                         EventJournal journal,
                         @Value("${threat.engine.replay-on-start:true}") boolean replayOnStart) {
        this.normalizer = normalizer;
        this.engine = engine;
        this.journal = journal;
        this.replayOnStart = replayOnStart;
        this.stripes = new ReentrantLock[STRIPES];
        for (int i = 0; i < STRIPES; i++) {
            stripes[i] = new ReentrantLock();
        }
    }

    @PostConstruct
    public void replayJournalOnStartup() {
        if (!replayOnStart) {
            return;
        }
        List<JournalEntry> recorded = journal.readEntries();
        if (recorded.isEmpty()) {
            return;
        }
        log.info("replaying {} journaled events after restart ...", recorded.size());
        for (JournalEntry entry : recorded) {
            doIngest(entry.event(), true, entry.receivedAtMs());
        }
        log.info("journal replay finished, {} unique events restored", processed.size());
    }

    public IngestOutcome ingest(RawEvent raw) {
        return doIngest(raw, false, 0L);
    }

    private IngestOutcome doIngest(RawEvent raw, boolean replay, long replayArrivalMs) {
        NormalizeResult result = normalizer.normalize(raw);
        if (result instanceof NormalizeResult.Rejected rejected) {
            // 重复投递同一条非法记录也幂等地给出同样的可区分拒绝原因
            String fingerprint = fingerprint(raw);
            if (!rejectedFingerprints.add(fingerprint)) {
                return new IngestOutcome(
                        null, IngestStatus.DUPLICATE, rejected.reason(),
                        "duplicate delivery of a previously rejected record: "
                                + rejected.message(), null, List.of(), true);
            }
            return new IngestOutcome(
                    null, IngestStatus.REJECTED, rejected.reason(),
                    rejected.message(), null, List.of());
        }

        SecurityEvent event = ((NormalizeResult.Ok) result).event();
        ReentrantLock lock = stripeFor(event.eventId());
        lock.lock();
        try {
            IngestOutcome existing = processed.get(event.eventId());
            if (existing != null) {
                log.info("duplicate delivery suppressed: eventId={} originalStatus={}",
                        event.eventId(), existing.status());
                return new IngestOutcome(
                        existing.deduplicatedEventId(), IngestStatus.DUPLICATE, null,
                        "duplicate delivery: returning first-seen conclusion without recounting",
                        existing.event(), existing.ruleEvaluations(), true);
            }

            // 到达时间：实时摄入取当前时刻；重放沿用日志持久化的接收时刻，
            // 保证迟到判定与首次处理一致。
            // restoring=true：恢复计数/告警状态，但重放结论不宣称新告警，重启不产生重复告警。
            long arrivalMs = replay ? replayArrivalMs : System.currentTimeMillis();
            List<IngestResult> evaluations = engine.evaluate(
                    new SecurityEvent(event.eventId(), event.source(), event.entityId(),
                            event.type(), event.eventTimeMs(), arrivalMs),
                    arrivalMs, replay);

            // 任一规则窗口内计数首次达阈即视为该事件产生了告警
            boolean raisedNow = evaluations.stream().anyMatch(e -> e.alertId() != null);

            IngestStatus status = aggregateStatus(evaluations);
            IngestOutcome outcome = new IngestOutcome(
                    event.eventId(), status, null,
                    replay ? "replayed from journal deterministically" : "processed",
                    event, List.copyOf(evaluations));

            // 先写日志再发布结论，保证崩溃重启后不漏（重放幂等，不重复）
            if (!replay) {
                journal.append(new JournalEntry(raw, arrivalMs));
            }
            // 首次处理与重放恢复都写入缓存：重启后重复投递旧事件必须识别为 DUPLICATE
            processed.put(event.eventId(), outcome);

            log.info("ingest accepted: eventId={} source={} entity={} type={} eventTime={} "
                            + "status={} raisedAlert={} replay={}",
                    event.eventId(), event.source(), event.entityId(), event.type(),
                    event.eventTimeMs(), status, raisedNow, replay);
            return outcome;
        } finally {
            lock.unlock();
        }
    }

    /**
     * 并发批量摄入。各事件可并行（同一 eventId/实体仍受分段锁保护），
     * 汇总统计保证守恒：accepted + duplicate + lateWithin + lateBeyond + rejected == total。
     */
    public BatchReport ingestBatch(List<RawEvent> raws) {
        List<IngestOutcome> outcomes = raws.parallelStream()
                .map(this::ingest)
                .toList();

        int accepted = 0;
        int duplicate = 0;
        int lateWithin = 0;
        int lateBeyond = 0;
        int rejected = 0;
        int alerts = 0;
        for (IngestOutcome o : outcomes) {
            switch (o.status()) {
                case ACCEPTED -> accepted++;
                case DUPLICATE -> duplicate++;
                case LATE_WITHIN_TOLERANCE -> lateWithin++;
                case LATE_BEYOND_TOLERANCE -> lateBeyond++;
                case REJECTED -> rejected++;
            }
            alerts += (int) o.ruleEvaluations().stream().filter(e -> e.alertId() != null).count();
        }

        int classified = accepted + duplicate + lateWithin + lateBeyond + rejected;
        if (classified != raws.size()) {
            throw new IllegalStateException(
                    "conservation broken: classified=" + classified + " total=" + raws.size());
        }
        return new BatchReport(raws.size(), accepted, duplicate, lateWithin, lateBeyond,
                rejected, alerts, outcomes);
    }

    private IngestStatus aggregateStatus(List<IngestResult> evaluations) {
        if (evaluations.isEmpty()) {
            return IngestStatus.ACCEPTED;
        }
        boolean lateWithin = false;
        for (IngestResult e : evaluations) {
            if (e.status() == IngestStatus.LATE_BEYOND_TOLERANCE) {
                return IngestStatus.LATE_BEYOND_TOLERANCE;
            }
            if (e.status() == IngestStatus.LATE_WITHIN_TOLERANCE) {
                lateWithin = true;
            }
        }
        return lateWithin ? IngestStatus.LATE_WITHIN_TOLERANCE : IngestStatus.ACCEPTED;
    }

    private ReentrantLock stripeFor(String eventId) {
        return stripes[Math.floorMod(eventId.hashCode(), STRIPES)];
    }

    private String fingerprint(RawEvent raw) {
        return String.valueOf(raw.source()) + '|' + String.valueOf(raw.eventId())
                + '|' + String.valueOf(raw.timestamp()) + '|' + String.valueOf(raw.fields());
    }
}
