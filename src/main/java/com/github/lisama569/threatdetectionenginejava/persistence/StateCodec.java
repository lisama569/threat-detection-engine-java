package com.github.lisama569.threatdetectionenginejava.persistence;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@link StateMemento} 与字节内容之间的编解码 + 校验和。
 *
 * <ul>
 *   <li>编码：Jackson JSON（UTF-8），备忘录全部为不可变 record，字段名稳定；</li>
 *   <li>解码：任何 JSON 结构损坏 / 缺字段 / 格式版本不支持都统一归类为
 *       {@link StateStoreException.Kind#CORRUPT}，调用方据此保守处理，绝不静默按空实例启动；</li>
 *   <li>校验：对编码字节计算 SHA-256 十六进制摘要，随快照另存，读取时比对发现静默损坏。</li>
 * </ul>
 */
public final class StateCodec {

    private final ObjectMapper mapper;

    public StateCodec() {
        this(new ObjectMapper());
    }

    public StateCodec(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    /** 序列化为 UTF-8 JSON 字节。 */
    public byte[] encode(StateMemento memento) {
        if (memento == null) {
            throw new StateStoreException(StateStoreException.Kind.IO_ERROR, "备忘录为空，无法序列化");
        }
        try {
            return mapper.writeValueAsBytes(memento);
        } catch (Exception e) {
            throw new StateStoreException(StateStoreException.Kind.IO_ERROR,
                    "状态快照序列化失败: " + e.getMessage(), e);
        }
    }

    /** 反序列化；结构损坏/版本不支持抛 {@link StateStoreException}（CORRUPT）。 */
    public StateMemento decode(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            throw new StateStoreException(StateStoreException.Kind.CORRUPT, "状态内容为空");
        }
        StateMemento memento;
        try {
            memento = mapper.readValue(bytes, StateMemento.class);
        } catch (Exception e) {
            throw new StateStoreException(StateStoreException.Kind.CORRUPT,
                    "状态快照无法解析为受支持结构: " + e.getMessage(), e);
        }
        if (memento.formatVersion() != StateMemento.FORMAT_VERSION) {
            throw new StateStoreException(StateStoreException.Kind.CORRUPT,
                    "状态快照格式版本不受支持: fileVersion=" + memento.formatVersion()
                            + ", supported=" + StateMemento.FORMAT_VERSION);
        }
        if (memento.stats() == null) {
            throw new StateStoreException(StateStoreException.Kind.CORRUPT, "状态快照缺少统计段");
        }
        return memento;
    }

    /** 对编码后的字节计算十六进制 SHA-256 校验和。 */
    public String checksum(byte[] bytes) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(bytes);
            StringBuilder sb = new StringBuilder(64);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }

    public String toJson(StateMemento memento) {
        return new String(encode(memento), StandardCharsets.UTF_8);
    }
}
