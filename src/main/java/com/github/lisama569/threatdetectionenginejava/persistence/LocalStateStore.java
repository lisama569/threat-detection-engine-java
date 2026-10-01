package com.github.lisama569.threatdetectionenginejava.persistence;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * 本地状态文件的读写边界（只用本地磁盘，不引入外部数据库/中间件）。
 *
 * <p>原子写：先写 {@code state.json.tmp} 再 {@code Files.move}（同目录 ATOMIC_MOVE）覆盖
 * {@code state.json}。滚动重启时要么读到完整上一代、要么读不到，绝不会读到半截文件。</p>
 */
public class LocalStateStore {

    private static final Logger log = LoggerFactory.getLogger(LocalStateStore.class);

    public static final String STATE_FILENAME = "state.json";
    public static final String TMP_SUFFIX = ".tmp";

    private final Path directory;
    private final Path stateFile;
    private final Path tmpFile;

    public LocalStateStore(Path directory) {
        if (directory == null) {
            throw new IllegalArgumentException("状态目录不能为空");
        }
        this.directory = directory;
        this.stateFile = directory.resolve(STATE_FILENAME);
        this.tmpFile = directory.resolve(STATE_FILENAME + TMP_SUFFIX);
    }

    public Path getDirectory() {
        return directory;
    }

    public Path getStateFile() {
        return stateFile;
    }

    /** 状态文件是否存在（空文件也算存在，交给编解码判定为损坏）。 */
    public boolean exists() {
        return Files.isRegularFile(stateFile);
    }

    /** 原子写入完整状态文本。 */
    public synchronized void writeAtomic(String json) {
        if (json == null || json.isBlank()) {
            throw new IllegalArgumentException("拒绝写入空状态");
        }
        try {
            Files.createDirectories(directory);
            try {
                Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
                Files.deleteIfExists(tmpFile);
                Files.createFile(tmpFile, PosixFilePermissions.asFileAttribute(perms));
                Files.writeString(tmpFile, json, StandardCharsets.UTF_8);
            } catch (UnsupportedOperationException | SecurityException posixUnsupported) {
                // 文件系统不支持 POSIX 权限时退回普通写入
                Files.deleteIfExists(tmpFile);
                Files.writeString(tmpFile, json, StandardCharsets.UTF_8);
            }
            try {
                Files.move(tmpFile, stateFile, StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException atomicUnsupported) {
                Files.move(tmpFile, stateFile, StandardCopyOption.REPLACE_EXISTING);
            }
            log.debug("状态已原子落盘: {} ({} 字节)", stateFile, json.length());
        } catch (IOException e) {
            throw new IllegalStateException("写入本地状态失败: " + stateFile, e);
        } finally {
            try {
                Files.deleteIfExists(tmpFile);
            } catch (IOException ignored) {
                // 临时文件清理失败不影响主流程
            }
        }
    }

    /** 读取完整状态文本；文件不存在返回 null。 */
    public synchronized String read() {
        if (!exists()) {
            return null;
        }
        try {
            return Files.readString(stateFile, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new CorruptStateException(stateFile.toString(),
                    "读取本地状态失败: " + e.getMessage(), e);
        }
    }

    /** 清空状态文件（允许丢弃、全新启动时使用）。 */
    public synchronized void clear() {
        try {
            Files.deleteIfExists(stateFile);
            Files.deleteIfExists(tmpFile);
        } catch (IOException e) {
            throw new IllegalStateException("清空本地状态失败: " + stateFile, e);
        }
    }
}
