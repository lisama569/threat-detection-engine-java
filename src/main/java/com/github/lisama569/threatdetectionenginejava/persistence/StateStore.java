package com.github.lisama569.threatdetectionenginejava.persistence;

/**
 * 本地运行状态的存取边界（仅依赖本地文件资源，不引入外部数据库/中间件）。
 *
 * <p>实现需保证 save 的原子性（读者要么读到上一份完整快照，要么读到新一份完整快照，
 * 绝不读到写坏的半份），并能在 load 时区分“不存在”与“损坏”。</p>
 */
public interface StateStore {

    /** 是否已有可加载的状态文件。 */
    boolean exists();

    /** 加载并校验最新快照；不存在抛 {@link StateStoreException}（MISSING），损坏抛 CORRUPT。 */
    StateMemento load();

    /** 原子保存一份快照（临时文件 + 校验和 + 落盘后 rename）。 */
    void save(StateMemento memento);

    /** 状态文件所在位置（日志/排障用）。 */
    String location();
}
