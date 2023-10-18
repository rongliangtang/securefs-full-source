#pragma once
#include "constants.h"
#include "exceptions.h"
#include "files.h"
#include "myutils.h"
#include "platform.h"
#include "streams.h"
#include "thread_safety_annotations.hpp"

#include <memory>
#include <string.h>
#include <unordered_map>
#include <utility>

// 这个文件里的类啥作用？？?

namespace securefs
{
class FileTableIO;

class AutoClosedFileBase;

// 文件表类，抽象类
class FileTable
{
public:
    FileTable() {}
    virtual ~FileTable();

    // 打开一个文件，返回基类对象
    virtual FileBase* open_as(const id_type& id, int type) = 0;
    // 纯虚函数
    // 创建文件，返回基类对象
    virtual FileBase* create_as(const id_type& id, int type) = 0;
    virtual void close(FileBase*) = 0;
    virtual bool is_readonly() const noexcept = 0;
    virtual bool is_auth_enabled() const noexcept = 0;
    virtual bool is_time_stored() const noexcept = 0;
    virtual void statfs(struct fuse_statvfs* fs_info) = 0;
    virtual bool has_padding() const noexcept = 0;
};

// 文件表实现类，继承FileTable
// 文件表存放了正在打开明文文件对应的密文缓存，用来加速访问密文文件，避免频繁从磁盘读密文文件
// 实现了一个文件表，缓存了密文文件中打开文件和关闭文件的记录，用来加速访问密文文件，避免频繁从磁盘读密文文件
class FileTableImpl final : public FileTable
{
private:
    // 定义类型别名，table_type类型实际为一个unordered_map容器
    // id_hash函数对象取出id的后sizeof(size_t)字节内容，作为hash值返回
    // 每个FileBase类型的unique_ptr表示一个文件
    typedef std::unordered_map<id_type, std::unique_ptr<FileBase>, id_hash> table_type;

private:
    // MAX_NUM_CLOSED为m_files缓存表中的最大已关闭文件记录容量
    // NUM_EJECT为每次从m_files缓存表中删除的已关闭文件数量
    static const int MAX_NUM_CLOSED = 101, NUM_EJECT = 8;

private:
    // c++互斥锁
    securefs::Mutex m_lock;
    // master_key
    key_type m_master_key;
    // files缓存，是一个unordered_map，里面存放了每个文件的<id,FileBase>
    // 存放<id,FileBase>在内存中，用来加速获取访问，包括打开文件缓存和最近关闭文件缓存
    table_type m_files THREAD_ANNOTATION_GUARDED_BY(m_lock);
    // 已关闭文件的id
    //（后面对m_files缓存表进行清理的时候，从已关闭文件id中找记录出来清理，道理很简单，如果没有关闭还在用，怎么能从缓存中清理呢）
    std::vector<id_type> m_closed_ids THREAD_ANNOTATION_GUARDED_BY(m_lock);
    // FileTableIO在file_table.cpp中定义
    // 作用是根据id来打开、创建、删除加密文件（数据文件和元文件）
    std::unique_ptr<FileTableIO> m_fio THREAD_ANNOTATION_GUARDED_BY(m_lock);
    // flags是命令设置的一些有关参数kOptionStoreTime、kOptionReadOnly等
    uint32_t m_flags;
    // block_size, iv_size, size
    unsigned m_block_size, m_iv_size, m_max_padding_size;
    // OSService类型的shared_ptr，里面存了加密数据根目录的文件描述符
    std::shared_ptr<const OSService> m_root;

private:
    void eject() THREAD_ANNOTATION_REQUIRES(m_lock);
    void finalize(std::unique_ptr<FileBase>&) THREAD_ANNOTATION_REQUIRES(m_lock);
    void gc() THREAD_ANNOTATION_REQUIRES(m_lock);

public:
    explicit FileTableImpl(int version,
                           std::shared_ptr<const OSService> root,
                           const key_type& master_key,
                           uint32_t flags,
                           unsigned block_size,
                           unsigned iv_size,
                           unsigned max_padding_size);
    ~FileTableImpl();
    // 根据id，优先从m_files缓存中找，找不到则打开数据文件和元数据文件，返回一个FileBase类的多态指针
    // 并将打开后获取的FileBase多态存入到m_files表中
    FileBase* open_as(const id_type& id, int type) override;
    // 创建id对应的文件流并返回指针
    // 并将打开后获取的FileBase多态存入到m_files表中
    FileBase* create_as(const id_type& id, int type) override;
    // 关闭文件
    // 并从m_files表中删去对应的记录
    void close(FileBase*) override;
    // 返回命令是否设置只读
    bool is_readonly() const noexcept override { return (m_flags & kOptionReadOnly) != 0; }
    // 返回命令是否设置不需要认证
    bool is_auth_enabled() const noexcept override
    {
        return (m_flags & kOptionNoAuthentication) == 0;
    }
    // 返回命令是否设置存储时间戳
    bool is_time_stored() const noexcept override { return (m_flags & kOptionStoreTime) != 0; }
    // 调用密文根目录的statfs函数
    void statfs(struct fuse_statvfs* fs_info) override { m_root->statfs(fs_info); }
    // 返回命令是否开启padding功能
    bool has_padding() const noexcept override { return m_max_padding_size > 0; }
};

// 分片的文件表实现类，继承FileTable
// 定义了一个FileTableImpl数组，利用id与FileTableImpl建立对应关系，用多个FileTableImpl来实现密文文件的操作
// 用多个FileTableImpl来实现密文文件的操作的作用是：防止一个表过大？
class ShardedFileTableImpl final : public FileTable
{
private:
    // m_shards为FileTableImpl对象vector，多个FileTableImpl来实现密文文件的操作
    // 默认的大小是4
    std::vector<std::unique_ptr<FileTableImpl>> m_shards;

    // 返回一个FileTableImpl类指针，根据id从m_shards数组中取出对象
    // id与FileTableImpl对象的对应关系如下，id前4个字节表示的无符号数对m_shards.size()进行取余
    FileTableImpl* get_shard_by_id(const id_type& id) noexcept;

public:
    // 构造函数
    explicit ShardedFileTableImpl(int version,
                                  std::shared_ptr<const OSService> root,
                                  const key_type& master_key,
                                  uint32_t flags,
                                  unsigned block_size,
                                  unsigned iv_size,
                                  unsigned max_padding_size);
    ~ShardedFileTableImpl();
    FileBase* open_as(const id_type& id, int type) override;
    FileBase* create_as(const id_type& id, int type) override;
    void close(FileBase* fb) override;
    // 调用m_shards中最后一个FileTableImpl对象的方法，因为这些方法与对象无关，调用谁都一样
    bool is_readonly() const noexcept override { return m_shards.back()->is_readonly(); }
    bool is_auth_enabled() const noexcept override { return m_shards.back()->is_auth_enabled(); }
    bool is_time_stored() const noexcept override { return m_shards.back()->is_time_stored(); }
    void statfs(struct fuse_statvfs* fs_info) { return m_shards.back()->statfs(fs_info); }
    bool has_padding() const noexcept override { return m_shards.back()->has_padding(); }
};

// AutoClosedFileBase类
// 建立文件表和文件流的对应关系，实现访问文件流属性的方法
class AutoClosedFileBase
{
private:
    // FileTable* m_ft的作用是reset改变指向的时候，可以调用对应table中的close函数
    FileTable* m_ft;
    FileBase* m_fb;

public:
    explicit AutoClosedFileBase(FileTable* ft, FileBase* fb) : m_ft(ft), m_fb(fb) {}

    AutoClosedFileBase(const AutoClosedFileBase&) = delete;
    AutoClosedFileBase& operator=(const AutoClosedFileBase&) = delete;

    AutoClosedFileBase(AutoClosedFileBase&& other) noexcept : m_ft(other.m_ft), m_fb(other.m_fb)
    {
        other.m_ft = nullptr;
        other.m_fb = nullptr;
    }

    AutoClosedFileBase& operator=(AutoClosedFileBase&& other) noexcept
    {
        if (this == &other)
            return *this;
        swap(other);
        return *this;
    }

    ~AutoClosedFileBase()
    {
        try
        {
            reset(nullptr);
        }
        catch (...)
        {
        }
    }

    FileBase* get() noexcept { return m_fb; }
    template <class T>
    T* get_as() noexcept
    {
        return m_fb->cast_as<T>();
    }
    FileBase& operator*() noexcept { return *m_fb; }
    FileBase* operator->() noexcept { return m_fb; }
    FileBase* release() noexcept
    {
        auto rt = m_fb;
        m_fb = nullptr;
        return rt;
    }
    // 让m_fb指向fb，关闭fb对应的FileTableImpl文件表
    void reset(FileBase* fb)
    {
        if (m_ft && m_fb)
        {
            m_ft->close(m_fb);
        }
        m_fb = fb;
    }
    void swap(AutoClosedFileBase& other) noexcept
    {
        std::swap(m_ft, other.m_ft);
        std::swap(m_fb, other.m_fb);
    }
};

inline AutoClosedFileBase open_as(FileTable& table, const id_type& id, int type)
{
    return AutoClosedFileBase(&table, table.open_as(id, type));
}

inline AutoClosedFileBase create_as(FileTable& table, const id_type& id, int type)
{
    return AutoClosedFileBase(&table, table.create_as(id, type));
}
}    // namespace securefs
