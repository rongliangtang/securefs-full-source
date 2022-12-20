#pragma once

#include "myutils.h"
#include "platform.h"
#include "streams.h"
#include "thread_safety_annotations.hpp"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rng.h>

namespace securefs
{
class RegularFile;
class Directory;
class Symlink;

// FileBase文件基类，类似于lite format中的File类
class THREAD_ANNOTATION_CAPABILITY("mutex") FileBase
{
private:
    // 一些静态常量
    static const size_t NUM_FLAGS = 7, HEADER_SIZE = 32, EXTENDED_HEADER_SIZE = 80,
                        ATIME_OFFSET = NUM_FLAGS * sizeof(uint32_t),
                        MTIME_OFFSET = ATIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t),
                        CTIME_OFFSET = MTIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t),
                        BTIME_OFFSET = CTIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t);

    // 判断常量是否有误
    static_assert(BTIME_OFFSET + sizeof(uint64_t) + sizeof(uint32_t) <= EXTENDED_HEADER_SIZE,
                  "Constants are wrong!");

private:
    // C++互斥锁
    securefs::Mutex m_lock;
    // ptrdiff_t实际为long类型
    // 表示这个对象的引用数量？？
    ptrdiff_t m_refcount;
    // HeaderBase类是支持固定大小的缓冲区来存储文件头文件的接口类，抽象类
    // meta文件加密类（实际和m_stream是同一个对象）
    // 实际为interal::AESGCMCryptStream类
    std::shared_ptr<HeaderBase> m_header THREAD_ANNOTATION_GUARDED_BY(*this);
    // 对应密文文件的id
    const id_type m_id;
    // 原子类型的密文flags，存放了mode、uid、gid、root_page、nlink、start_free_page、num_free_page
    std::atomic<uint32_t> m_flags[NUM_FLAGS];
    // fuse_timespec实际为timespec结构体，存放着自1970年7月1日（UTC）以来经过的秒和纳秒
    // atime表示最后访问时间
    // mtime表示最后文件内容修改时间
    // ctime表示最后元数据（权限，所有者等）的变化时间
    // birthtime表示创建时间
    fuse_timespec m_atime THREAD_ANNOTATION_GUARDED_BY(*this),
        m_mtime THREAD_ANNOTATION_GUARDED_BY(*this), m_ctime THREAD_ANNOTATION_GUARDED_BY(*this),
        m_birthtime THREAD_ANNOTATION_GUARDED_BY(*this);
    // 密文文件FileStream对象
    std::shared_ptr<FileStream> m_data_stream THREAD_ANNOTATION_GUARDED_BY(*this),
        m_meta_stream THREAD_ANNOTATION_GUARDED_BY(*this);
    // xattr加密器和解密器，用AES_GCM算法
    CryptoPP::GCM<CryptoPP::AES>::Encryption m_xattr_enc THREAD_ANNOTATION_GUARDED_BY(*this);
    CryptoPP::GCM<CryptoPP::AES>::Decryption m_xattr_dec THREAD_ANNOTATION_GUARDED_BY(*this);
    // m_dirty表示属性是否脏？？
    bool m_dirty THREAD_ANNOTATION_GUARDED_BY(*this);
    // m_check表示??
    // m_store_time表示要不要存储时间戳
    const bool m_check, m_store_time;

private:
    void read_header() THREAD_ANNOTATION_REQUIRES(*this);

    [[noreturn]] void throw_invalid_cast(int to_type);

protected:
    // 数据文件加密类（实际和m_header是同一个对象）
    // 实际为interal::AESGCMCryptStream类
    std::shared_ptr<StreamBase> m_stream THREAD_ANNOTATION_GUARDED_BY(*this);

    // 获取根结点
    uint32_t get_root_page() const noexcept { return m_flags[4]; }

    void set_root_page(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_flags[4] = value;
        m_dirty = true;
    }

    // 返回起始空闲页
    uint32_t get_start_free_page() const noexcept { return m_flags[5]; }

    // 设置起始空闲页
    void set_start_free_page(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_flags[5] = value;
        m_dirty = true;
    }

    // 返回空闲页的数量
    uint32_t get_num_free_page() const noexcept { return m_flags[6]; }

    // 设置空闲页的数，并把元数据置脏
    void set_num_free_page(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_flags[6] = value;
        m_dirty = true;
    }

    /**
     * Subclasss should override this if additional flush operations are needed
     */
    virtual void subflush() THREAD_ANNOTATION_REQUIRES(*this) {}

public:
    static const byte REGULAR_FILE = S_IFREG >> 12, SYMLINK = S_IFLNK >> 12,
                      DIRECTORY = S_IFDIR >> 12, BASE = 255;

    static_assert(REGULAR_FILE != SYMLINK && SYMLINK != DIRECTORY,
                  "The value assigned are indistinguishable");

    static int error_number_for_not(int type) noexcept
    {
        switch (type)
        {
        case REGULAR_FILE:
            return EPERM;
        case SYMLINK:
            return EINVAL;
        case DIRECTORY:
            return ENOTDIR;
        }
        return EINVAL;
    }

    // fuse_mode_t实际为unsigned short类型
    static fuse_mode_t mode_for_type(int type) noexcept { return type << 12; }

    static int type_for_mode(fuse_mode_t mode) noexcept { return mode >> 12; }

    static const char* type_name(int type) noexcept
    {
        switch (type)
        {
        case REGULAR_FILE:
            return "regular_file";
        case SYMLINK:
            return "symbolic_link";
        case DIRECTORY:
            return "directory";
        }
        return "unknown";
    }

public:
    explicit FileBase(std::shared_ptr<FileStream> data_stream,
                      std::shared_ptr<FileStream> meta_stream,
                      const key_type& key_,
                      const id_type& id_,
                      bool check,
                      unsigned block_size,
                      unsigned iv_size,
                      unsigned max_padding_size,
                      bool store_time);

    virtual ~FileBase();
    DISABLE_COPY_MOVE(FileBase)

    void lock() THREAD_ANNOTATION_ACQUIRE() { m_lock.lock(); }
    void unlock() THREAD_ANNOTATION_RELEASE() { m_lock.unlock(); }
    bool try_lock() THREAD_ANNOTATION_TRY_ACQUIRE(true) { return m_lock.try_lock(); }

    void initialize_empty(uint32_t mode, uint32_t uid, uint32_t gid)
        THREAD_ANNOTATION_REQUIRES(*this);

    // --Begin of getters and setters for stats---
    uint32_t get_mode() const noexcept { return m_flags[0]; }

    void set_mode(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (get_mode() == value)
            return;
        m_flags[0] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_uid() const noexcept { return m_flags[1]; }

    void set_uid(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (get_uid() == value)
            return;
        m_flags[1] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    uint32_t get_gid() const noexcept { return m_flags[2]; }

    void set_gid(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (get_gid() == value)
            return;
        m_flags[2] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    // nlink就指向该文件流的记录项，也就是有多少明文文件执行这个文件流
    uint32_t get_nlink() const noexcept { return m_flags[3]; }

    void set_nlink(uint32_t value) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (get_nlink() == value)
            return;
        m_flags[3] = value;
        update_ctime_helper();
        m_dirty = true;
    }

    // 获得atime
    void get_atime(fuse_timespec& out) const noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        out = m_atime;
    }

    // 获得mtime
    void get_mtime(fuse_timespec& out) const noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        out = m_mtime;
    }

    // 获得ctime
    void get_ctime(fuse_timespec& out) const noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        out = m_ctime;
    }

    // 获得birthtime
    void get_birthtime(fuse_timespec& out) const noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        out = m_birthtime;
    }

    // 设置atime
    void set_atime(const fuse_timespec& in) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_atime = in;
        m_dirty = true;
    }

    // 设置mtime
    void set_mtime(const fuse_timespec& in) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_mtime = in;
        m_dirty = true;
    }

    // 设置ctime
    void set_ctime(const fuse_timespec& in) noexcept THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_ctime = in;
        m_dirty = true;
    }

    // 更新atime，通过调用OSService::get_current_time()实现，并设元数据修改脏位
    void update_atime_helper() THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (m_store_time && (m_atime.tv_sec < m_mtime.tv_sec || m_atime.tv_sec < m_ctime.tv_sec))
        {
            OSService::get_current_time(m_atime);
            m_dirty = true;
        }
    }

    // 更新mtime，通过调用OSService::get_current_time()实现，并设元数据修改脏位
    void update_mtime_helper() THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (m_store_time)
        {
            OSService::get_current_time(m_mtime);
            m_ctime = m_mtime;
            m_dirty = true;
        }
    }

    // 更新ctime，通过调用OSService::get_current_time()实现，并设元数据修改脏位
    void update_ctime_helper() THREAD_ANNOTATION_REQUIRES(*this)
    {
        if (m_store_time)
        {
            OSService::get_current_time(m_ctime);
            m_dirty = true;
        }
    }

    // --End of getters and setters for stats---

    const id_type& get_id() const { return m_id; }

    ptrdiff_t incref() noexcept { return ++m_refcount; }

    ptrdiff_t decref() noexcept { return --m_refcount; }

    ptrdiff_t getref() const noexcept { return m_refcount; }

    void setref(ptrdiff_t value) noexcept { m_refcount = value; }

    virtual int type() const noexcept { return FileBase::BASE; }

    int get_real_type();

    bool is_unlinked() const noexcept { return get_nlink() <= 0; }

    void unlink() THREAD_ANNOTATION_REQUIRES(*this)
    {
        --m_flags[3];
        m_dirty = true;
    }

    void flush() THREAD_ANNOTATION_REQUIRES(*this);

    void fsync() THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_data_stream->fsync();
        m_meta_stream->fsync();
    }

    void utimens(const struct fuse_timespec ts[2]) THREAD_ANNOTATION_REQUIRES(*this);

    void stat(struct fuse_stat* st) THREAD_ANNOTATION_REQUIRES(*this);

    ssize_t listxattr(char* buffer, size_t size) THREAD_ANNOTATION_REQUIRES(*this);

    ssize_t getxattr(const char* name, char* value, size_t size) THREAD_ANNOTATION_REQUIRES(*this);

    void setxattr(const char* name, const char* value, size_t size, int flags)
        THREAD_ANNOTATION_REQUIRES(*this);

    void removexattr(const char* name) THREAD_ANNOTATION_REQUIRES(*this);

    // 作用：将本来为T*多态的this转为T*类型
    // cast_as是FileBase类的函数模版
    template <class T>
    T* cast_as()
    {
        // 获得对象的类型
        int type_ = type();
        // 若对象不是FileBase类，type的mode不是m_flags[0]&S_IFMT（文件类型）
        if (type_ != FileBase::BASE && mode_for_type(type_) != (get_mode() & S_IFMT))
            throwFileTypeInconsistencyException();
        // 若对象不是目标T类的多态，则抛出异常
        if (type_ != T::class_type())
            throw_invalid_cast(T::class_type());
        // 通过static_cast将本来为T*多态的this转为T*类型
        return static_cast<T*>(this);
    }
};

class RegularFile : public FileBase
{
public:
    static int class_type() { return FileBase::REGULAR_FILE; }

    template <class... Args>
    explicit RegularFile(Args&&... args) : FileBase(std::forward<Args>(args)...)
    {
    }

    int type() const noexcept override { return class_type(); }

    // 调用StreamBase多态的read函数
    length_type read(void* output, offset_type off, length_type len)
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        // 更新访问时间
        update_atime_helper();
        // 调用BlockBasedStream类的函数
        return this->m_stream->read(output, off, len);
    }

    void write(const void* input, offset_type off, length_type len)
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_mtime_helper();
        return this->m_stream->write(input, off, len);
    }

    length_type size() const noexcept THREAD_ANNOTATION_REQUIRES(*this) { return m_stream->size(); }

    void truncate(length_type new_size) THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_mtime_helper();
        return m_stream->resize(new_size);
    }
};

class Symlink : public FileBase
{
public:
    static int class_type() { return FileBase::SYMLINK; }

    template <class... Args>
    explicit Symlink(Args&&... args) : FileBase(std::forward<Args>(args)...)
    {
    }

    int type() const noexcept override { return class_type(); }

    // 取出文件中的path密文，解密后再返回
    std::string get() THREAD_ANNOTATION_REQUIRES(*this)
    {
        std::string result(m_stream->size(), 0);
        auto rc = m_stream->read(&result[0], 0, result.size());
        result.resize(rc);
        update_atime_helper();
        return result;
    }

    // 将path数据写入到文件中，明文加密后再写进去
    void set(const std::string& path) THREAD_ANNOTATION_REQUIRES(*this)
    {
        m_stream->write(path.data(), 0, path.size());
    }
};

class Directory : public FileBase
{
public:
    static const size_t MAX_FILENAME_LENGTH = 255;

public:
    static int class_type() { return FileBase::DIRECTORY; }

    template <class... Args>
    explicit Directory(Args&&... args) : FileBase(std::forward<Args>(args)...)
    {
    }

    int type() const noexcept override { return class_type(); }

public:
    typedef std::function<bool(const std::string&, const id_type&, int)> callback;

    // 根据name获取id和type
    bool get_entry(const std::string& name, id_type& id, int& type)
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        // 更新atime访问时间
        update_atime_helper();
        // 此处调用Directory子类BtreeDirectory中的方法
        // get_entry_impl()在Directory中为纯虚函数，说明传进来的对象应该是Directory多态的BtreeDirectory类型
        return get_entry_impl(name, id, type);
    }
    
    // 根据name、id、type增加一条记录到树中
    bool add_entry(const std::string& name, const id_type& id, int type)
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_mtime_helper();
        return add_entry_impl(name, id, type);
    }

    /**
     * Removes the entry while also report the info of said entry.
     * Returns false when the entry is not found.
     */
    bool remove_entry(const std::string& name, id_type& id, int& type)
        THREAD_ANNOTATION_REQUIRES(*this)
    {
        update_mtime_helper();
        return remove_entry_impl(name, id, type);
    }

    /**
     * When callback returns false, the iteration will be terminated
     */
    void iterate_over_entries(const callback& cb) THREAD_ANNOTATION_REQUIRES(*this)
    {
        // 更新访问时间
        update_atime_helper();
        // 调用iterate_over_entries_impl()函数来实现目录的遍历
        return iterate_over_entries_impl(cb);
    }

    virtual bool empty() THREAD_ANNOTATION_REQUIRES(*this) = 0;

protected:
    virtual bool get_entry_impl(const std::string& name, id_type& id, int& type) = 0;

    virtual bool add_entry_impl(const std::string& name, const id_type& id, int type) = 0;

    /**
     * Removes the entry while also report the info of said entry.
     * Returns false when the entry is not found.
     */
    virtual bool remove_entry_impl(const std::string& name, id_type& id, int& type) = 0;

    /**
     * When callback returns false, the iteration will be terminated
     */
    virtual void iterate_over_entries_impl(const callback& cb) = 0;
};

class SimpleDirectory : public Directory
{
private:
    std::unordered_map<std::string, std::pair<id_type, int>> m_table;
    bool m_dirty;

private:
    void initialize() THREAD_ANNOTATION_REQUIRES(*this);

public:
    template <class... Args>
    explicit SimpleDirectory(Args&&... args) : Directory(std::forward<Args>(args)...)
    {
        initialize();
    }

    bool get_entry_impl(const std::string& name, id_type& id, int& type) override;

    bool add_entry_impl(const std::string& name, const id_type& id, int type) override;

    bool remove_entry_impl(const std::string& name, id_type& id, int& type) override;

    void subflush() override THREAD_ANNOTATION_REQUIRES(*this);

    void iterate_over_entries_impl(const callback& cb) override
    {
        for (const auto& pair : m_table)
        {
            if (!cb(pair.first, pair.second.first, pair.second.second))
                break;
        }
    }

    bool empty() noexcept override { return m_table.empty(); }

    ~SimpleDirectory();
};

// FileLockGuard类
// 利用std::lock_guard<T>封装的，在构造的时候执行T.lock()，析构的时候执行T.unlock()
// 可能因为作者不需要自写的LockGuard那样上flock文件锁，所以重写写一个FileLockGuard类来用？？
class THREAD_ANNOTATION_SCOPED_CAPABILITY FileLockGuard
{
private:
    std::lock_guard<FileBase> m_lg;

public:
    // RegularFile和Directory等类继承FileBase，也具有lock等方法
    explicit FileLockGuard(FileBase& fb) THREAD_ANNOTATION_ACQUIRE(fb)
        // fb.cast_as<RegularFile>()相当于RegularFile *，线程安全注释这样写有什么作用？
        THREAD_ANNOTATION_ACQUIRE(fb.cast_as<RegularFile>())
            THREAD_ANNOTATION_ACQUIRE(fb.cast_as<Directory>())
                THREAD_ANNOTATION_ACQUIRE(fb.cast_as<Symlink>())
        : m_lg(fb)
    {
    }
    ~FileLockGuard() THREAD_ANNOTATION_RELEASE() {}
};

// 自旋锁：与互斥锁的区别是，在获取锁失败的时候不会使得线程阻塞而是一直自旋尝试获取锁，一直占有cpu
// 利用std::unique_lock实现自旋锁
class THREAD_ANNOTATION_SCOPED_CAPABILITY SpinFileLockGuard
{
private:
    std::unique_lock<FileBase> m_ul;

public:
    explicit SpinFileLockGuard(FileBase& fb) THREAD_ANNOTATION_ACQUIRE(fb)
        THREAD_ANNOTATION_ACQUIRE(fb.cast_as<RegularFile>())
            THREAD_ANNOTATION_ACQUIRE(fb.cast_as<Directory>())
                THREAD_ANNOTATION_ACQUIRE(fb.cast_as<Symlink>())
        : m_ul(fb, std::defer_lock)
    {
        for (int i = 0; i < 100; ++i)
        {
            if (m_ul.try_lock())
            {
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        throwVFSException(EBUSY);
    }
    ~SpinFileLockGuard() THREAD_ANNOTATION_RELEASE() {}
};

// 双重锁，同时上两个锁？？
class THREAD_ANNOTATION_SCOPED_CAPABILITY DoubleFileLockGuard
{
private:
    std::unique_lock<FileBase> m1, m2;

public:
    explicit DoubleFileLockGuard(FileBase& f1, FileBase& f2) THREAD_ANNOTATION_ACQUIRE(f1)
        THREAD_ANNOTATION_ACQUIRE(f1.cast_as<RegularFile>())
            THREAD_ANNOTATION_ACQUIRE(f1.cast_as<Directory>())
                THREAD_ANNOTATION_ACQUIRE(f1.cast_as<Symlink>()) THREAD_ANNOTATION_ACQUIRE(f2)
                    THREAD_ANNOTATION_ACQUIRE(f2.cast_as<RegularFile>())
                        THREAD_ANNOTATION_ACQUIRE(f2.cast_as<Directory>())
                            THREAD_ANNOTATION_ACQUIRE(f2.cast_as<Symlink>())
    {
        if (&f1 == &f2)
        {
            m1 = std::unique_lock<FileBase>{f1};
        }
        else
        {
            std::lock(f1, f2);
            m1 = {f1, std::adopt_lock};
            m2 = {f2, std::adopt_lock};
        }
    }
    ~DoubleFileLockGuard() THREAD_ANNOTATION_RELEASE() {}
};
}    // namespace securefs
