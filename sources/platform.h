#pragma once

#include "exceptions.h"
#include "mystring.h"
#include "myutils.h"
#include "streams.h"
#include "thread_safety_annotations.hpp"

#include <functional>
#include <memory>
#include <mutex>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <vector>

#include <fuse.h>

#ifdef WIN32
#include <Windows.h>

typedef ptrdiff_t ssize_t;

#define __PRETTY_FUNCTION__ __FUNCTION__

#define O_RDONLY 0x0000   /* open for reading only */
#define O_WRONLY 0x0001   /* open for writing only */
#define O_RDWR 0x0002     /* open for reading and writing */
#define O_ACCMODE 0x0003  /* mask for above modes */
#define O_NONBLOCK 0x0004 /* no delay */
#define O_APPEND 0x0008   /* set append mode */
#define O_SHLOCK 0x0010   /* open with shared file lock */
#define O_EXLOCK 0x0020   /* open with exclusive file lock */
#define O_ASYNC 0x0040    /* signal pgrp when data ready */
#define O_FSYNC O_SYNC    /* source compatibility: do not use */
#define O_NOFOLLOW 0x0100 /* don't follow symlinks */
#define O_CREAT 0x0200    /* create if nonexistant */
#define O_TRUNC 0x0400    /* truncate to zero length */
#define O_EXCL 0x0800     /* error if already exists */

#define S_IFMT 0170000   /* type of file */
#define S_IFIFO 0010000  /* named pipe (fifo) */
#define S_IFCHR 0020000  /* character special */
#define S_IFDIR 0040000  /* directory */
#define S_IFBLK 0060000  /* block special */
#define S_IFREG 0100000  /* regular */
#define S_IFLNK 0120000  /* symbolic link */
#define S_IFSOCK 0140000 /* socket */

/* File mode */
/* Read, write, execute/search by owner */
#define S_IRWXU 0000700 /* [XSI] RWX mask for owner */
#define S_IRUSR 0000400 /* [XSI] R for owner */
#define S_IWUSR 0000200 /* [XSI] W for owner */
#define S_IXUSR 0000100 /* [XSI] X for owner */
/* Read, write, execute/search by group */
#define S_IRWXG 0000070 /* [XSI] RWX mask for group */
#define S_IRGRP 0000040 /* [XSI] R for group */
#define S_IWGRP 0000020 /* [XSI] W for group */
#define S_IXGRP 0000010 /* [XSI] X for group */
/* Read, write, execute/search by others */
#define S_IRWXO 0000007 /* [XSI] RWX mask for other */
#define S_IROTH 0000004 /* [XSI] R for other */
#define S_IWOTH 0000002 /* [XSI] W for other */
#define S_IXOTH 0000001 /* [XSI] X for other */

#define S_ISUID 0004000 /* [XSI] set user id on execution */
#define S_ISGID 0002000 /* [XSI] set group id on execution */
#define S_ISVTX 0001000 /* [XSI] directory restrcted delete */

#else

#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#define fuse_uid_t uid_t
#define fuse_gid_t gid_t
#define fuse_pid_t pid_t

#define fuse_dev_t dev_t
#define fuse_ino_t ino_t
#define fuse_mode_t mode_t
#define fuse_nlink_t nlink_t
#define fuse_off_t off_t

#define fuse_fsblkcnt_t fsblkcnt_t
#define fuse_fsfilcnt_t fsfilcnt_t
#define fuse_blksize_t blksize_t
#define fuse_blkcnt_t blkcnt_t

#define fuse_utimbuf utimbuf
#define fuse_timespec timespec

#define fuse_stat stat
#define fuse_statvfs statvfs
#define fuse_flock flock
#endif

namespace securefs
{
extern const char* PATH_SEPARATOR_STRING;
extern const char PATH_SEPARATOR_CHAR;

// 文件流类，继承自字节流基类，文件流类定义的都是纯虚函数，只能被继承且子孙类必须要有类实现，文件流类不能实例化
class FileStream : public StreamBase
{
public:
    virtual void fsync() = 0;
    virtual void utimens(const struct fuse_timespec ts[2]) = 0;
    virtual void fstat(struct fuse_stat*) const = 0;
    virtual void close() noexcept = 0;
    virtual ssize_t listxattr(char*, size_t);
    virtual ssize_t getxattr(const char*, void*, size_t);
    virtual void setxattr(const char*, void*, size_t, int);
    virtual void removexattr(const char*);
    virtual void lock(bool exclusive) = 0;
    virtual void unlock() noexcept = 0;
    virtual length_type sequential_read(void*, length_type) = 0;
    virtual void sequential_write(const void*, length_type) = 0;
};

class DirectoryTraverser
{
    DISABLE_COPY_MOVE(DirectoryTraverser)

public:
    DirectoryTraverser() {}
    virtual ~DirectoryTraverser();
    virtual bool next(std::string* name, struct fuse_stat* st) = 0;
    virtual void rewind() = 0;
};

#ifdef WIN32
typedef std::wstring native_string_type;
#else
typedef std::string native_string_type;
#endif

#ifdef WIN32
std::wstring widen_string(StringRef str);
std::string narrow_string(WideStringRef str);
// [[noreturn]]指？？？
[[noreturn]] void throw_windows_exception(const wchar_t* func_name);
void windows_init(void);
#endif

// os服务接口类（分为unix和window两个文件来实现），定义了一些路径操作、系统操作方法
// 这个类还没有读懂哦？
class OSService
{
private:
#if defined(WIN32)
    void* m_root_handle;
#else
    int m_dir_fd;   // path的文件描述符，构造函数OSService(StringRef path)会进行赋值
#endif
    std::string m_dir_name;

public:
    static bool is_absolute(StringRef path);
    static native_string_type concat_and_norm(StringRef base_dir, StringRef path);
    // 函数后面加const，表示这个函数不可以修改类属性
    native_string_type norm_path(StringRef path) const { return concat_and_norm(m_dir_name, path); }

public:
    OSService();
    explicit OSService(StringRef path);
    ~OSService();
    std::shared_ptr<FileStream> open_file_stream(StringRef path, int flags, unsigned mode) const;
    bool remove_file_nothrow(StringRef path) const noexcept;
    bool remove_directory_nothrow(StringRef path) const noexcept;
    void remove_file(StringRef path) const;
    void remove_directory(StringRef path) const;

    void rename(StringRef a, StringRef b) const;
    void lock() const;
    void ensure_directory(StringRef path, unsigned mode) const;
    void mkdir(StringRef path, unsigned mode) const;
    void statfs(struct fuse_statvfs*) const;
    void utimens(StringRef path, const fuse_timespec ts[2]) const;

    // Returns false when the path does not exist; throw exceptions on other errors
    // The ENOENT errors are too frequent so the API is redesigned
    bool stat(StringRef path, struct fuse_stat* stat) const;

    void link(StringRef source, StringRef dest) const;
    void chmod(StringRef path, fuse_mode_t mode) const;
    void chown(StringRef path, fuse_uid_t uid, fuse_gid_t gid) const;
    ssize_t readlink(StringRef path, char* output, size_t size) const;
    void symlink(StringRef source, StringRef dest) const;

    typedef std::function<void(StringRef, StringRef)> recursive_traverse_callback;
    void recursive_traverse(StringRef dir, const recursive_traverse_callback& callback) const;

    std::unique_ptr<DirectoryTraverser> create_traverser(StringRef dir) const;

// 如果是apple系统，则定义一些xattr操作函数
#ifdef __APPLE__
    // These APIs, unlike all others, report errors through negative error numbers as defined in
    // <errno.h>
    ssize_t listxattr(const char* path, char* buf, size_t size) const noexcept;
    ssize_t getxattr(const char* path, const char* name, void* buf, size_t size) const noexcept;
    int
    setxattr(const char* path, const char* name, void* buf, size_t size, int flags) const noexcept;
    int removexattr(const char* path, const char* name) const noexcept;
#endif
public:
    static uint32_t getuid() noexcept;
    static uint32_t getgid() noexcept;
    static int64_t raise_fd_limit() noexcept;

    static std::string temp_name(StringRef prefix, StringRef suffix);
    static const OSService& get_default();
    static void get_current_time(fuse_timespec& out);
    static void get_current_time_in_tm(struct tm* tm, int* nanoseconds);

    static void read_password_no_confirmation(const char* prompt,
                                              CryptoPP::AlignedSecByteBlock* output);
    static void read_password_with_confirmation(const char* prompt,
                                                CryptoPP::AlignedSecByteBlock* output);
    static std::string stringify_system_error(int errcode);
};

struct Colour
{
    enum Code
    {
        Default = 0,

        White,
        Red,
        Green,
        Blue,
        Cyan,
        Yellow,
        Grey,

        Bright = 0x10,

        BrightRed = Bright | Red,
        BrightGreen = Bright | Green,
        LightGrey = Bright | Grey,
        BrightWhite = Bright | White,

        // By intention
        FileName = LightGrey,
        Warning = Yellow,
        ResultError = BrightRed,
        ResultSuccess = BrightGreen,
        ResultExpectedFailure = Warning,

        Error = BrightRed,
        Success = Green,

        OriginalExpression = Cyan,
        ReconstructedExpression = Yellow,

        SecondaryText = LightGrey,
        Headers = White
    };
};

// ConsoleColourSetter类用于设置控制台输出颜色
// 在unix.cpp和win.cpp分别实现
class ConsoleColourSetter
{
public:
    DISABLE_COPY_MOVE(ConsoleColourSetter)

    explicit ConsoleColourSetter() {}
    virtual ~ConsoleColourSetter() {}
    virtual void use(Colour::Code colour) noexcept = 0;

    // Returns null if fp is not connected to console/tty
    static std::unique_ptr<ConsoleColourSetter> create_setter(FILE* fp);
};

// posix标准的控制台输出颜色设置器，win和linux都可用，win也遵守部分posix
class POSIXColourSetter final : public ConsoleColourSetter
{
public:
    explicit POSIXColourSetter(FILE* fp) : m_fp(fp) {}

    void use(Colour::Code _colourCode) noexcept override;

private:
    FILE* m_fp;
    void setColour(const char* _escapeCode) noexcept;
};

// 定义Mutex类，用来实现clang的线程安全分析
// THREAD_ANNOTATION_CAPABILITY("mutex")表示该类对象具有能力，可以看为锁，用来clang线程安全分析
class THREAD_ANNOTATION_CAPABILITY("mutex") Mutex
{
public:
    Mutex();
    ~Mutex();
    // 进行了定义，m_std.lock()，即锁定互斥，若互斥不可用则阻塞
    // THREAD_ANNOTATION_ACQUIRE()表示进入时才持有能力，退出后不释放
    void lock() THREAD_ANNOTATION_ACQUIRE();
    // 进行了定义，m_std.unlock()，即解锁互斥
    // THREAD_ANNOTATION_RELEASE()表示进入时已持有能力，退出前释放
    void unlock() noexcept THREAD_ANNOTATION_RELEASE();
    // 进行了定义，m_std.try_lock()，即尝试锁定互斥，若互斥不可用则返回
    // THREAD_ANNOTATION_TRY_ACQUIRE(true)表示试图获得给定的功能，并返回一个指示成功或失败的布尔值
    bool try_lock() THREAD_ANNOTATION_TRY_ACQUIRE(true);

private:
// 如果是windows，则要调用windows下的互斥信号量
#ifdef _WIN32
    // MSVC implementation of std::mutex is too slow.
    // So we reimplment it.
    CRITICAL_SECTION m_cs;
#else
    std::mutex m_std;
#endif
};

}    // namespace securefs
