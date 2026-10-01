package com.github.lisama569.threatdetectionenginejava.persistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * 基于本地文件的 {@link StateStore}：单个 JSON 快照 + 同名 {@code .sha256} 校验和旁车文件。
 *
 * <p>原子性与损坏识别：</p>
 * <ul>
 *   <li>保存：先把新校验和、新 JSON 各自写入临时文件并落盘，再先换校验和、最后原子换 JSON；
 *       正常停机（写出完整完成）后读到的必然是成对一致的快照；</li>
 *   <li>加载：JSON 文件不存在归类 {@link StateStoreException.Kind#MISSING}；
 *       文件为空、校验和缺失/不一致、JSON 无法解析或版本不支持，一律归类
 *       {@link StateStoreException.Kind#CORRUPT}——调用方据此保守处理，绝不静默按空实例启动；</li>
 *   <li>写入过程中的崩溃可能留下新旧不成对的文件，加载时表现为 CORRUPT 而非半份内容。</li>
 * </ul>
 */
public class LocalFileStateStore implements StateStore {

    private static final Logger log = LoggerFactory.getLogger(LocalFileStateStore.class);

    private final Path stateFile;
    private final Path checksumFile;
    private final Path tmpStateFile;
    private final Path tmpChecksumFile;
    private final StateCodec codec;

    public LocalFileStateStore(Path stateFile) {
        this(stateFile, new StateCodec());
    }

    public LocalFileStateStore(Path stateFile, StateCodec codec) {
        this.stateFile = stateFile;
        this.checksumFile = Path.of(stateFile.toString() + ".sha256");
        this.tmpStateFile = Path.of(stateFile.toString() + ".tmp");
        this.tmpChecksumFile = Path.of(stateFile.toString() + ".sha256.tmp");
        this.codec = codec;
    }

    @Override
    public boolean exists() {
        return Files.isRegularFile(stateFile);
    }

    @Override
    public StateMemento load() {
        if (!Files.isRegularFile(stateFile)) {
            throw new StateStoreException(StateStoreException.Kind.MISSING,
                    "本地状态文件不存在: " + location());
        }
        byte[] bytes;
        try {
            bytes = Files.readAllBytes(stateFile);
        } catch (IOException e) {
            throw new StateStoreException(StateStoreException.Kind.IO_ERROR,
                    "读取本地状态文件失败: " + location() + ", " + e.getMessage(), e);
        }
        if (bytes.length == 0) {
            throw new StateStoreException(StateStoreException.Kind.CORRUPT,
                    "本地状态文件为空: " + location());
        }
        if (!Files.isRegularFile(checksumFile)) {
            throw new StateStoreException(StateStoreException.Kind.CORRUPT,
                    "状态校验和文件缺失: " + checksumFile);
        }
        String expected;
        try {
            expected = Files.readString(checksumFile, StandardCharsets.UTF_8).trim();
        } catch (IOException e) {
            throw new StateStoreException(StateStoreException.Kind.CORRUPT,
                    "状态校验和无法读取: " + e.getMessage(), e);
        }
        String actual = codec.checksum(bytes);
        if (!actual.equalsIgnoreCase(expected)) {
            throw new StateStoreException(StateStoreException.Kind.CORRUPT,
                    "状态校验和不匹配（文件可能被截断/损坏）: expected=" + expected
                            + ", actual=" + actual + ", file=" + location());
        }
        return codec.decode(bytes);
    }

    @Override
    public synchronized void save(StateMemento memento) {
        byte[] bytes = codec.encode(memento);
        String checksum = codec.checksum(bytes);
        try {
            Path parent = stateFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(tmpChecksumFile, checksum.getBytes(StandardCharsets.UTF_8));
            Files.write(tmpStateFile, bytes);
            // 先换校验和（此时旧 JSON 仍在，崩溃只会让下次启动判 CORRUPT，不会读到半份）
            moveAtomically(tmpChecksumFile, checksumFile);
            // 最后原子换 JSON：此后读者看到的就是完整的新版本
            moveAtomically(tmpStateFile, stateFile);
            log.debug("状态快照已落盘: file={}, bytes={}, checksum={}", location(), bytes.length, checksum);
        } catch (IOException e) {
            throw new StateStoreException(StateStoreException.Kind.IO_ERROR,
                    "状态快照落盘失败: " + location() + ", " + e.getMessage(), e);
        } finally {
            deleteQuietly(tmpStateFile);
            deleteQuietly(tmpChecksumFile);
        }
    }

    private static void moveAtomically(Path from, Path to) throws IOException {
        try {
            Files.move(from, to, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(from, to, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteQuietly(Path path) {
        try {
            Files.deleteIfExists(path);
        } catch (IOException ignored) {
            // 临时文件清理失败不影响主流程
        }
    }

    @Override
    public String location() {
        return stateFile.toAbsolutePath().toString();
    }
}
