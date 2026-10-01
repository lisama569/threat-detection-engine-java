package com.github.lisama569.threatdetectionenginejava.dedup;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 投递去重器：以 deliveryId（缺失时用 eventId 内容指纹）为幂等键。
 * 进程重启后通过已存键集合回放恢复，保证重复投递不产生重复计数。
 */
public class DeliveryDeduplicator {

    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    public DeliveryDeduplicator() {
    }

    public DeliveryDeduplicator(Set<String> restoredKeys) {
        if (restoredKeys != null) {
            seen.addAll(restoredKeys);
        }
    }

    /** @return true 表示首次出现并已登记；false 表示重复投递。 */
    public boolean markIfFirst(String dedupKey) {
        if (dedupKey == null || dedupKey.isBlank()) {
            throw new IllegalArgumentException("dedupKey 不能为空");
        }
        return seen.add(dedupKey);
    }

    public boolean isDuplicate(String dedupKey) {
        return dedupKey != null && seen.contains(dedupKey);
    }

    public Set<String> snapshotKeys() {
        return Collections.unmodifiableSet(Set.copyOf(seen));
    }

    /** 重启恢复：把历史去重键补录进来（与构造器注入等价，供内存态恢复使用）。 */
    public void restoreKeys(Set<String> keys) {
        if (keys != null) {
            seen.addAll(keys);
        }
    }

    public int size() {
        return seen.size();
    }
}
