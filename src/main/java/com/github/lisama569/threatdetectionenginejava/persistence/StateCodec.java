package com.github.lisama569.threatdetectionenginejava.persistence;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * 本地运行状态的 JSON 编解码（仅依赖 Jackson，随 Spring Boot 已提供，无外部中间件）。
 *
 * <p>落盘内容外包一层 {@link Envelope}：携带格式版本、状态代数与对 payload 的 SHA-256 校验和，
 * 任何字段缺失、JSON 损坏或被篡改都会在解码时抛 {@link CorruptStateException}，绝不静默按空实例启动。</p>
 */
public class StateCodec {

    public static final String FORMAT_VERSION = "1";

    private final ObjectMapper mapper;

    /** 落盘信封：checksum = sha256( compactJson(state) )。 */
    public record Envelope(String formatVersion, long generation, String checksum, StateSnapshot state) {
    }

    /** 一次完整运行状态的快照。 */
    public record StateSnapshot(
            List<RuleData> rules,
            List<AlertData> alerts,
            List<String> dedupKeys,
            List<RuleVersionWindows> windows,
            StatsData stats,
            Map<String, Long> rejectionBreakdown) {
    }

    public record RuleData(
            String ruleId, int version, List<String> eventTypes, List<String> entityScope,
            long windowMillis, int threshold, long lateToleranceMillis) {
    }

    public record AlertData(
            String alertId, String ruleId, int ruleVersion, String entityId, long createdAt,
            long triggerEventTime, int triggerCount, String status, long statusUpdatedAt,
            String resolutionNote) {
    }

    /** ruleId#version -> 各实体窗口态。 */
    public record RuleVersionWindows(String ruleId, int version, List<EntityWindows> entities) {
    }

    public record EntityWindows(String entityId, long windowMillis, long watermark,
                                List<WindowData> windows) {
    }

    /** 单个固定窗口；events 不持久化，只存去重指纹与是否已告警。 */
    public record WindowData(long windowStart, List<String> eventIds, boolean alerted) {
    }

    public record StatsData(long total, long rejected, long duplicate, long tooLate,
                            long acceptedNoAlert, long acceptedAlert) {
    }

    public StateCodec() {
        this.mapper = new ObjectMapper()
                .setSerializationInclusion(JsonInclude.Include.ALWAYS)
                .configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true)
                .configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true);
    }

    /** 序列化为信封 JSON（rejectionBreakdown 按键排序，保证同态同字节、校验和稳定）。 */
    public String encode(StateSnapshot snapshot, long generation) {
        if (snapshot == null) {
            throw new CorruptStateException(null, "状态快照为空");
        }
        StateSnapshot canonical = withSortedBreakdown(snapshot);
        String payloadJson = writeJson(canonical);
        Envelope envelope = new Envelope(FORMAT_VERSION, generation, sha256(payloadJson), canonical);
        return writeJson(envelope);
    }

    /** 反序列化并校验格式版本与校验和；损坏/缺失/被篡改一律抛 {@link CorruptStateException}。 */
    public Envelope decode(String json) {
        if (json == null || json.isBlank()) {
            throw new CorruptStateException(null, "状态文件为空");
        }
        Envelope envelope;
        try {
            envelope = mapper.readValue(json, Envelope.class);
        } catch (JsonProcessingException e) {
            throw new CorruptStateException(null, "状态文件不是合法 JSON: " + e.getOriginalMessage(), e);
        }
        if (envelope == null) {
            throw new CorruptStateException(null, "状态信封为空");
        }
        if (!FORMAT_VERSION.equals(envelope.formatVersion())) {
            throw new CorruptStateException(null,
                    "不支持的状态格式版本: " + envelope.formatVersion() + "，期望 " + FORMAT_VERSION);
        }
        if (envelope.state() == null) {
            throw new CorruptStateException(null, "状态信封缺少 payload");
        }
        if (envelope.checksum() == null || envelope.checksum().isBlank()) {
            throw new CorruptStateException(null, "状态信封缺少校验和");
        }
        // 用同一 mapper 重新序列化 payload，与写入时逐字节一致（record 顺序固定 + Map 排序）
        StateSnapshot reparsed = withSortedBreakdown(envelope.state());
        String actual = sha256(writeJson(reparsed));
        if (!constantTimeEquals(actual, envelope.checksum())) {
            throw new CorruptStateException(null,
                    "状态校验和不匹配：文件可能损坏或被篡改 (expected=" + envelope.checksum()
                            + ", actual=" + actual + ")");
        }
        validate(reparsed);
        return new Envelope(envelope.formatVersion(), envelope.generation(), envelope.checksum(), reparsed);
    }

    /** 结构性必填校验：任何关键字段缺失都视为损坏，不允许部分恢复。 */
    private void validate(StateSnapshot s) {
        if (s.rules() == null || s.alerts() == null || s.dedupKeys() == null
                || s.windows() == null || s.stats() == null || s.rejectionBreakdown() == null) {
            throw new CorruptStateException(null, "状态快照存在必填段落缺失");
        }
        for (RuleData r : s.rules()) {
            if (r == null || r.ruleId() == null || r.ruleId().isBlank()
                    || r.eventTypes() == null || r.eventTypes().isEmpty()
                    || r.windowMillis() <= 0 || r.threshold() <= 0 || r.lateToleranceMillis() < 0) {
                throw new CorruptStateException(null, "规则段落非法: " + r);
            }
        }
        for (AlertData a : s.alerts()) {
            if (a == null || a.alertId() == null || a.alertId().isBlank()
                    || a.ruleId() == null || a.status() == null) {
                throw new CorruptStateException(null, "告警段落非法: " + a);
            }
        }
        for (RuleVersionWindows rv : s.windows()) {
            if (rv == null || rv.ruleId() == null || rv.entities() == null) {
                throw new CorruptStateException(null, "窗口段落非法: " + rv);
            }
            for (EntityWindows ew : rv.entities()) {
                if (ew == null || ew.entityId() == null || ew.windowMillis() <= 0
                        || ew.windows() == null) {
                    throw new CorruptStateException(null, "实体窗口段落非法: " + ew);
                }
                for (WindowData w : ew.windows()) {
                    if (w == null || w.eventIds() == null) {
                        throw new CorruptStateException(null, "固定窗口段落非法: " + w);
                    }
                }
            }
        }
    }

    private StateSnapshot withSortedBreakdown(StateSnapshot s) {
        Map<String, Long> sorted = new TreeMap<>();
        if (s.rejectionBreakdown() != null) {
            sorted.putAll(s.rejectionBreakdown());
        }
        return new StateSnapshot(s.rules(), s.alerts(), s.dedupKeys(), s.windows(),
                s.stats(), sorted);
    }

    private String writeJson(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new CorruptStateException(null, "状态序列化失败: " + e.getMessage(), e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    /** 计算输入的 SHA-256（小写十六进制）。 */
    static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
