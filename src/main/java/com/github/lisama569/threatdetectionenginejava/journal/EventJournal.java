package com.github.lisama569.threatdetectionenginejava.journal;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.lisama569.threatdetectionenginejava.model.RawEvent;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;

/**
 * 已接受原始事件的本地只追加日志（JSON Lines）。
 * <p>
 * 每条接受的事件在计数前同步 append（受摄入锁保护），条目同时持久化引擎接收时刻；
 * 进程重启后从文件按序重放，由于处理是确定性的（窗口边界、alertId 均为纯函数，
 * 到达时间沿用持久化值），重放得到相同计数与告警，不会因重启重复告警或漏报。
 * {@code threat.engine.journal-path} 为空时退化为纯内存模式。
 */
@Component
public class EventJournal {

    private static final Logger log = LoggerFactory.getLogger(EventJournal.class);

    private final ObjectMapper mapper = new ObjectMapper();
    private final List<JournalEntry> inMemory = new ArrayList<>();
    private final Path file;

    public EventJournal(@Value("${threat.engine.journal-path:}") String journalPath) {
        this.file = (journalPath == null || journalPath.isBlank()) ? null : Path.of(journalPath);
    }

    @PostConstruct
    public void init() {
        if (file != null) {
            try {
                if (file.getParent() != null) {
                    Files.createDirectories(file.getParent());
                }
                if (Files.notExists(file)) {
                    Files.createFile(file);
                }
                log.info("event journal backed by file: {}", file.toAbsolutePath());
            } catch (IOException e) {
                throw new UncheckedIOException("cannot initialize journal file: " + file, e);
            }
        } else {
            log.info("event journal running in memory-only mode");
        }
    }

    /**
     * 追加一条已接受事件。调用方（IngestService）保证持锁串行化，因此 append 与内存列表一致。
     */
    public synchronized void append(JournalEntry entry) {
        inMemory.add(entry);
        if (file != null) {
            try {
                String line = mapper.writeValueAsString(entry) + System.lineSeparator();
                Files.writeString(file, line, StandardCharsets.UTF_8,
                        StandardOpenOption.WRITE, StandardOpenOption.APPEND);
            } catch (IOException e) {
                throw new UncheckedIOException("failed to append journal entry", e);
            }
        }
    }

    /**
     * 读取全部已记录条目（优先文件，保证重启后可恢复）。
     */
    public synchronized List<JournalEntry> readEntries() {
        if (file == null) {
            return List.copyOf(inMemory);
        }
        List<JournalEntry> loaded = new ArrayList<>();
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read journal file", e);
        }
        for (String line : lines) {
            if (line.isBlank()) {
                continue;
            }
            try {
                loaded.add(mapper.readValue(line, new TypeReference<JournalEntry>() {
                }));
            } catch (IOException e) {
                throw new UncheckedIOException("corrupt journal line: " + line, e);
            }
        }
        return List.copyOf(loaded);
    }

    /** 便捷读取全部原始事件（不含接收时刻）。 */
    public List<RawEvent> readAll() {
        return readEntries().stream().map(JournalEntry::event).toList();
    }

    public synchronized int size() {
        return readEntries().size();
    }

    /**
     * 清空日志（主要供测试与本地演示重置使用）。
     */
    public synchronized void clear() {
        inMemory.clear();
        if (file != null) {
            try {
                Files.writeString(file, "", StandardCharsets.UTF_8,
                        StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
            } catch (IOException e) {
                throw new UncheckedIOException("failed to clear journal file", e);
            }
        }
    }
}
