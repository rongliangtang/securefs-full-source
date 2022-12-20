#ifndef WIN32
#define _DARWIN_BETTER_REALPATH 1
#include "exceptions.h"
#include "lock_enabled.h"
#include "logger.h"
#include "platform.h"
#include "streams.h"

#include <algorithm>
#include <locale.h>
#include <vector>

#include <cxxabi.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <typeinfo>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/xattr.h>
#endif

/*unix平台用的函数*/

namespace securefs
{
class UnixFileStream final : public FileStream
{
private:
    int m_fd;

public:
    explicit UnixFileStream(int fd) : m_fd(fd)
    {
        if (fd < 0)
            throwVFSException(EBADF);
    }

    ~UnixFileStream() { this->close(); }

    void close() noexcept override
    {
        ::close(m_fd);
        m_fd = -1;
    }

    // 对文件进行上锁操作
    void lock(bool exclusive) override
    {
        // 若lock_flag为false则直接结束
        // lock_flag为原子类型，读写都是原子操作，为防止不同进程在执行这里的时候出现错乱
        if (!securefs::is_lock_enabled())
        {
            return;
        }
        // 根据exclusive的真值，来决定上LOCK_EX还是LOCK_SH
        // LOCK_EX表示互斥锁定，一个文件同时只有一个互斥锁定，常被用作写锁；LOCK_SH表示共享锁定，多个进程可同时对同一个文件作共享锁定，常被用作读共享锁。
        int rc = ::flock(m_fd, exclusive ? LOCK_EX : LOCK_SH);
        if (rc < 0)
        {
            THROW_POSIX_EXCEPTION(errno, "flock");
        }
    }

    // 对文件进行解锁
    void unlock() noexcept override
    {
        // 若lock_flag为false则直接结束
        if (!securefs::is_lock_enabled())
        {
            return;
        }
        // 解除文件锁定状态
        int rc = ::flock(m_fd, LOCK_UN);
        (void)rc;
    }

    // 同步文件数据，通过调用linux内核提供的库函数fsync(文件描述符)，这个函数会完成执行对应系统调用的所需步骤
    void fsync() override
    {
        // fsync(m_fd)的作用是将修改后的数据和文件描述符的属性持久化到存储设备中；
        int rc = ::fsync(m_fd);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fsync");
    }

    // 调用fstat，功能类似于fstatat
    void fstat(struct stat* out) const override
    {
        if (!out)
            throwVFSException(EFAULT);

        if (::fstat(m_fd, out) < 0)
            THROW_POSIX_EXCEPTION(errno, "fstat");
    }

    // 读取文件的数据，通过调用linux内核提供的库函数pread()实现
    length_type read(void* output, offset_type offset, length_type length) override
    {   
        // m_fd为类属性，OSService::open_file_stream()会返回并构造对象
        // pread(文件描述符, 输出, 长度, 偏移量)
        auto rc = ::pread(m_fd, output, length, offset);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "pread");
        return static_cast<length_type>(rc);
    }

    length_type sequential_read(void* output, length_type length) override
    {
        auto rc = ::read(m_fd, output, length);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "read");
        return static_cast<length_type>(rc);
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        auto rc = ::pwrite(m_fd, input, length, offset);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "pwrite");
        if (static_cast<length_type>(rc) != length)
            throwVFSException(EIO);
    }

    void sequential_write(const void* input, length_type length) override
    {
        auto rc = ::write(m_fd, input, length);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "write");
        if (static_cast<length_type>(rc) != length)
            throwVFSException(EIO);
    }

    void flush() override {}

    // 调整文件的大小，通过调用linux内核提供的库函数ftruncate()实现
    void resize(length_type new_length) override
    {
        // new_length更长的话，会用0填充
        auto rc = ::ftruncate(m_fd, new_length);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "truncate");
    }

    // 返回文件当前的大小
    length_type size() const override
    {
        struct stat st;
        this->fstat(&st);
        return static_cast<length_type>(st.st_size);
    }

    bool is_sparse() const noexcept override { return true; }

    void utimens(const struct fuse_timespec ts[2]) override
    {
        int rc = ::futimens(m_fd, ts);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "utimens");
    }

#ifdef __APPLE__

    void removexattr(const char* name) override
    {
        auto rc = ::fremovexattr(m_fd, name, 0);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fremovexattr");
    }

    ssize_t getxattr(const char* name, void* value, size_t size) override
    {
        ssize_t rc = ::fgetxattr(m_fd, name, value, size, 0, 0);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fgetxattr");
        return rc;
    }

    ssize_t listxattr(char* buffer, size_t size) override
    {
        auto rc = ::flistxattr(m_fd, buffer, size, 0);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "flistxattr");
        return rc;
    }

    void setxattr(const char* name, void* value, size_t size, int flags) override
    {
        auto rc = ::fsetxattr(m_fd, name, value, size, 0, flags);
        if (rc < 0)
            THROW_POSIX_EXCEPTION(errno, "fsetxattr");
    }
#endif
};

// unix系统中的目录遍历类
class UnixDirectoryTraverser : public DirectoryTraverser
{
private:
    DIR* m_dir;

public:
    explicit UnixDirectoryTraverser(StringRef path)
    {
        m_dir = ::opendir(path.c_str());
        if (!m_dir)
            THROW_POSIX_EXCEPTION(errno, "opendir " + path);
    }
    ~UnixDirectoryTraverser() { ::closedir(m_dir); }

    // 将目录流定位到下一个条目，并存入name和stat
    bool next(std::string* name, struct fuse_stat* st) override
    {
        errno = 0;
        // 返回一个结构体指针，并将目录流定位到下一个条目
        // https://pubs.opengroup.org/onlinepubs/7908799/xsh/dirent.h.html
        auto entry = ::readdir(m_dir);
        if (!entry)
        {
            if (errno)
                THROW_POSIX_EXCEPTION(errno, "readdir");
            return false;
        }
        // 如果传入了st
        if (st)
        {
            // 根据读取出的目录项的d_type文件类型来设置st_mode的文件类型
            switch (entry->d_type)
            {
            case DT_DIR:
                st->st_mode = S_IFDIR;
                break;
            case DT_LNK:
                st->st_mode = S_IFLNK;
                break;
            case DT_REG:
                st->st_mode = S_IFREG;
                break;
            default:
                st->st_mode = 0;
                break;
            }
        }
        // 如果传入了name
        if (name)
        {
            // 将name设置为目录项名
            *name = entry->d_name;
        }
        return true;
    }

    // reset position of directory stream to the beginning of a directory
    // 重置目录流的遍历位置，通过调用linux系统库的rewinddir来实现
    void rewind() override { ::rewinddir(m_dir); }
};

bool OSService::is_absolute(StringRef path) { return path.size() > 0 && path[0] == '/'; }

native_string_type OSService::concat_and_norm(StringRef base_dir, StringRef path)
{
    if (base_dir.empty() || is_absolute(path))
        return path.to_string();
    if (!is_absolute(base_dir))
    {
        throwInvalidArgumentException("base_dir must be absolute, but is " + base_dir);
    }
    if (base_dir.ends_with("/"))
    {
        return base_dir + path;
    }
    return base_dir + "/" + path;
}

OSService::OSService() { m_dir_fd = AT_FDCWD; }

OSService::~OSService()
{
    if (m_dir_fd >= 0)
        ::close(m_dir_fd);
}
// OSService类的构造函数，输入参数为StringRef path
// 获得挂载点的文件操作符
OSService::OSService(StringRef path)
{
    char buffer[PATH_MAX + 1] = {0};
    char* rc = ::realpath(path.c_str(), buffer);
    if (!rc)
        THROW_POSIX_EXCEPTION(errno, "realpath on " + path);
    m_dir_name.reserve(strlen(buffer) + 1);
    m_dir_name.assign(buffer);
    m_dir_name.push_back('/');

    int dir_fd = ::open(path.c_str(), O_RDONLY);
    if (dir_fd < 0)
        THROW_POSIX_EXCEPTION(errno, "Opening directory " + path);
    m_dir_fd = dir_fd;
}

// 返回指向FileStream类的shared_ptr，调用linux内核提供的库函数openat()
std::shared_ptr<FileStream>
OSService::open_file_stream(StringRef path, int flags, unsigned mode) const
{
    // openat(目录描述符, 接下去的路径？, flags, mode);
    // 通过设置flags实现不存在则会自动创建
    int fd = ::openat(m_dir_fd, path.c_str(), flags, mode);
    if (fd < 0)
        THROW_POSIX_EXCEPTION(
            errno, strprintf("Opening %s with flags %#o", norm_path(path).c_str(), flags));
    return std::make_shared<UnixFileStream>(fd);
}

// 删除一个文件，通过调用linux内核提供的库函数unlinkat()实现
void OSService::remove_file(StringRef path) const
{
    // unlinkat(目录描述符，路径,xx )删除文件，实际是把目录项(inode记录)删掉
    int rc = ::unlinkat(m_dir_fd, path.c_str(), 0);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "unlinking " + norm_path(path));
}

// 删除一个目录，通过调用linux内核提供的库函数unlinkat()实现
void OSService::remove_directory(StringRef path) const
{
    int rc = ::unlinkat(m_dir_fd, path.c_str(), AT_REMOVEDIR);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "removing directory " + norm_path(path));
}

void OSService::lock() const
{
    if (!securefs::is_lock_enabled())
    {
        return;
    }
    // 将data_dir这个目录锁住，别的进程不能对其进行操作这个时候
    int rc = ::flock(m_dir_fd, LOCK_NB | LOCK_EX);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno,
                              strprintf("Fail to obtain exclusive lock on %s", m_dir_name.c_str()));
}

// unix环境下的mkdir函数，调用了linux内核提供的库函数中提供的mkdirat
void OSService::mkdir(StringRef path, unsigned mode) const
{
    int rc = ::mkdirat(m_dir_fd, path.c_str(), mode);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno,
                              strprintf("Fail to create directory %s", norm_path(path).c_str()));
}

// 创建一个符号链接（用到了UNIX环境编程，自己写的时候要好好学下）
void OSService::symlink(StringRef to, StringRef from) const
{
    int rc = ::symlinkat(to.c_str(), m_dir_fd, from.c_str());
    if (rc < 0)
        THROW_POSIX_EXCEPTION(
            errno, strprintf("symlink to=%s and from=%s", to.c_str(), norm_path(from).c_str()));
}

void OSService::link(StringRef source, StringRef dest) const
{
    int rc = ::linkat(m_dir_fd, source.c_str(), m_dir_fd, dest.c_str(), 0);
    if (rc < 0)
    {
        THROW_POSIX_EXCEPTION(errno,
                              strprintf("link src=%s dest=%s", source.c_str(), dest.c_str()));
    }
}

// 返回文件系统的信息，存到fs_info中,fuse_statvfs就是statvfs结构体
// https://pubs.opengroup.org/onlinepubs/9699919799/basedefs/sys_statvfs.h.html
// 调用linux内核提供的库函数fstatvfs()实现
void OSService::statfs(struct fuse_statvfs* fs_info) const
{
    int rc = ::fstatvfs(m_dir_fd, fs_info);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "statvfs");
}

// 将文件重命名，通过调用linux内核提供的库函数rename()来实现
void OSService::rename(StringRef a, StringRef b) const
{
    int rc = ::renameat(m_dir_fd, a.c_str(), m_dir_fd, b.c_str());
    if (rc < 0)
        THROW_POSIX_EXCEPTION(
            errno, strprintf("Renaming from %s to %s", norm_path(a).c_str(), norm_path(b).c_str()));
}

// 获取文件的属性，通过调用linux内核提供的库函数fstatat()来实现，fuse_stat实际是stat结构体 
// https://docs.oracle.com/cd/E36784_01/html/E36872/fstatat-2.html
bool OSService::stat(StringRef path, struct fuse_stat* stat) const
{
    int rc = ::fstatat(m_dir_fd, path.c_str(), stat, AT_SYMLINK_NOFOLLOW);
    if (rc < 0)
    {
        if (errno == ENOENT)
            return false;
        THROW_POSIX_EXCEPTION(errno, strprintf("stating %s", norm_path(path).c_str()));
    }
    return true;
}

// 实现改变文件权限位
void OSService::chmod(StringRef path, fuse_mode_t mode) const
{
    int rc = ::fchmodat(m_dir_fd, path.c_str(), mode, AT_SYMLINK_NOFOLLOW);
    if (rc < 0 && errno == ENOTSUP)
        rc = ::fchmodat(m_dir_fd, path.c_str(), mode, 0);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno,
                              strprintf("chmod %s with mode=0%o", norm_path(path).c_str(), mode));
}

void OSService::chown(StringRef path, uid_t uid, gid_t gid) const
{
    int rc = ::fchownat(m_dir_fd, path.c_str(), uid, gid, AT_SYMLINK_NOFOLLOW);
    if (rc < 0 && errno == ENOTSUP)
        rc = ::fchownat(m_dir_fd, path.c_str(), uid, gid, 0);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno,
                              strprintf("chown %s with uid=%lld and gid=%lld",
                                        norm_path(path).c_str(),
                                        static_cast<long long>(uid),
                                        static_cast<long long>(gid)));
}

// 读取符号链接的目标，通过调用linux内核提供的库函数readlinkat函数实现
ssize_t OSService::readlink(StringRef path, char* output, size_t size) const
{
    ssize_t rc = ::readlinkat(m_dir_fd, path.c_str(), output, size);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(
            errno, strprintf("readlink %s with buffer size=%zu", norm_path(path).c_str(), size));
    return rc;
}

// 改变文件的访问和修改时间（纳秒级），通过调用linux内核提供的库函数utimensat函数实现
void OSService::utimens(StringRef path, const fuse_timespec* ts) const
{
    int rc = ::utimensat(m_dir_fd, path.c_str(), ts, AT_SYMLINK_NOFOLLOW);
    if (rc < 0)
        THROW_POSIX_EXCEPTION(errno, "utimensat");
}

// 创建一个UnixDirectoryTraverser类的unique_ptr，使用了多态技术
std::unique_ptr<DirectoryTraverser> OSService::create_traverser(StringRef dir) const
{
    return securefs::make_unique<UnixDirectoryTraverser>(norm_path(dir));
}

uint32_t OSService::getuid() noexcept { return ::getuid(); }
uint32_t OSService::getgid() noexcept { return ::getgid(); }

int64_t OSService::raise_fd_limit() noexcept
{
    struct rlimit rl;
    int rc = ::getrlimit(RLIMIT_NOFILE, &rl);
    if (rc < 0)
    {
        WARN_LOG("Failed to query limit of file descriptors. Error code: %d.", errno);
        return 1024;
    }

    if (rl.rlim_cur >= rl.rlim_max)
    {
        return rl.rlim_cur;
    }

    auto current_limit = rl.rlim_cur;
    rl.rlim_cur = rl.rlim_max;
    rc = ::setrlimit(RLIMIT_NOFILE, &rl);
    if (rc < 0)
    {
        WARN_LOG("Failed to set limit of file descriptors. Error code: %d.", errno);
        return current_limit;
    }
    return rl.rlim_cur;
}

void OSService::get_current_time(fuse_timespec& current_time)
{
    clock_gettime(CLOCK_REALTIME, &current_time);
}

// 列出相应路径的扩展属性
#ifdef __APPLE__
ssize_t OSService::listxattr(const char* path, char* buf, size_t size) const noexcept
{
    // ::listxattr表示调用xattr.h提供的函数
    auto rc = ::listxattr(norm_path(path).c_str(), buf, size, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

// 列出扩展属性所对应的值
// 实现OSService类中的getxattr函数
ssize_t
OSService::getxattr(const char* path, const char* name, void* buf, size_t size) const noexcept
{
    // ::表示调用全局函数，调用linux内核提供的库函数xattr.h中的getxattr函数
    auto rc = ::getxattr(norm_path(path).c_str(), name, buf, size, 0, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

// 设置扩展属性
int OSService::setxattr(
    const char* path, const char* name, void* buf, size_t size, int flags) const noexcept
{
    auto rc = ::setxattr(norm_path(path).c_str(), name, buf, size, 0, flags | XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}

int OSService::removexattr(const char* path, const char* name) const noexcept
{
    auto rc = ::removexattr(norm_path(path).c_str(), name, XATTR_NOFOLLOW);
    return rc < 0 ? -errno : rc;
}
#endif    // __APPLE__

// 读取一次输入的密码
void OSService::read_password_no_confirmation(const char* prompt,
                                              CryptoPP::AlignedSecByteBlock* output)
{
    byte buffer[4000];
    DEFER(CryptoPP::SecureWipeBuffer(buffer, array_length(buffer)));
    size_t bufsize = 0;

    struct termios old_tios, new_tios;
    if (::isatty(STDIN_FILENO))
    {
        if (::isatty(STDERR_FILENO))
        {
            fputs(prompt, stderr);
            fflush(stderr);
        }

        tcgetattr(STDIN_FILENO, &old_tios);
        new_tios = old_tios;
        new_tios.c_lflag &= ~(unsigned)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_tios);
    }
    while (1)
    {
        int c = getchar();
        if (c == '\r' || c == '\n' || c == EOF)
            break;
        if (bufsize < array_length(buffer))
        {
            buffer[bufsize] = static_cast<byte>(c);
            ++bufsize;
        }
        else
        {
            throw_runtime_error("Password exceeds 4000 characters");
        }
    }
    if (::isatty(STDIN_FILENO))
    {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_tios);
        putc('\n', stderr);
    }
    output->resize(bufsize);
    memcpy(output->data(), buffer, bufsize);
}

void OSService::get_current_time_in_tm(struct tm* tm, int* nanoseconds)
{
    timespec now;
    get_current_time(now);
    if (tm)
        gmtime_r(&now.tv_sec, tm);
    if (nanoseconds)
        *nanoseconds = static_cast<int>(now.tv_nsec);
}

// 读取密码，需要二次验证输入密码是否一致
void OSService::read_password_with_confirmation(const char* prompt,
                                                CryptoPP::AlignedSecByteBlock* output)
{
    // 第一次输入，读取密码到output中
    read_password_no_confirmation(prompt, output);
    // 若不是键盘输入，则结束函数
    // STDIN_FILENO表示标准输入（键盘输入），若为标准输入，则::isatty(STDIN_FILENO)返回1
    if (!::isatty(STDIN_FILENO) || !::isatty(STDERR_FILENO))
    {
        return;
    }
    // 第二次输入，读取密码到another中
    CryptoPP::AlignedSecByteBlock another;
    read_password_no_confirmation("Again: ", &another);
    // 判断两次输入密码的尺寸和数据是否一样
    if (output->size() != another.size()
        || memcmp(output->data(), another.data(), another.size()) != 0)
        throw_runtime_error("Password mismatch");
}

// These two overloads are used to distinguish the GNU and XSI version of strerror_r

// GNU
static std::string postprocess_strerror(const char* rc, const char* buffer, int code)
{
    if (rc)
        return rc;
    (void)buffer;
    return strprintf("Unknown POSIX error %d", code);
}

// XSI
static std::string postprocess_strerror(int rc, const char* buffer, int code)
{
    if (rc == 0)
        return buffer;
    return strprintf("Unknown POSIX error %d", code);
}

std::string OSService::stringify_system_error(int errcode)
{
    char buffer[4000];
    return postprocess_strerror(strerror_r(errcode, buffer, array_length(buffer)), buffer, errcode);
}

std::unique_ptr<ConsoleColourSetter> ConsoleColourSetter::create_setter(FILE* fp)
{
    if (!fp || !::isatty(::fileno(fp)))
        return {};
    return securefs::make_unique<POSIXColourSetter>(fp);
}

std::unique_ptr<const char, void (*)(const char*)> get_type_name(const std::exception& e) noexcept
{
    const char* name = typeid(e).name();
    const char* demangled = abi::__cxa_demangle(name, nullptr, nullptr, nullptr);
    if (demangled)
        return {demangled, [](const char* ptr) { free((void*)ptr); }};
    return {name, [](const char*) { /* no op */ }};
}

const char* PATH_SEPARATOR_STRING = "/";
const char PATH_SEPARATOR_CHAR = '/';

Mutex::Mutex() {}
Mutex::~Mutex() {}

void Mutex::lock() { m_std.lock(); }

void Mutex::unlock() noexcept
{
    try
    {
        m_std.unlock();
    }
    catch (const std::exception& e)
    {
        ERROR_LOG("std::mutex::unlock() throws %s: %s", get_type_name(e).get(), e.what());
    }
}
bool Mutex::try_lock() { return m_std.try_lock(); }

}    // namespace securefs
#endif
