#ifdef _WIN32
#include "lock_enabled.h"
#include "logger.h"
#include "platform.h"
#include "win_get_proc.h"

#include <winfsp/winfsp.h>

#include <cerrno>
#include <limits>
#include <memory>
#include <mutex>
#include <stdint.h>
#include <stdlib.h>
#include <sys/utime.h>
#include <time.h>
#include <typeinfo>

#include <VersionHelpers.h>
#include <Windows.h>
#include <io.h>
#include <sddl.h>
#include <strsafe.h>

/*windows的有关操作通过win32 api实现，这个库可以通过安装vs或可再发行程序包获得*/

/*windows平台用的函数*/

static void(WINAPI* best_get_time_func)(LPFILETIME) = nullptr;

// 将两个dword32位表示的64位无符号数，拼接成uint64_t表示的无符号数
static inline uint64_t convert_dword_pair(uint64_t low_part, uint64_t high_part)
{
    return low_part | (high_part << 32);
}

// 将FILETIME格式的时间转换为unix格式的时间
static void filetime_to_unix_time(const FILETIME* ft, struct fuse_timespec* out)
{
    long long ll = convert_dword_pair(ft->dwLowDateTime, ft->dwHighDateTime) - 116444736000000000LL;
    static const long long FACTOR = 10000000LL;
    out->tv_sec = ll / FACTOR;
    out->tv_nsec = (ll % FACTOR) * 100;
}

static FILETIME unix_time_to_filetime(const fuse_timespec* t)
{
    long long ll = t->tv_sec * 10000000LL + t->tv_nsec / 100LL + 116444736000000000LL;
    FILETIME res;
    res.dwLowDateTime = (DWORD)ll;
    res.dwHighDateTime = (DWORD)(ll >> 32);
    return res;
}

static const DWORD MAX_SINGLE_BLOCK = std::numeric_limits<DWORD>::max();

namespace securefs
{

// windows异常类，继承SystemException类
class WindowsException : public SystemException
{
private:
    // 这里传入的err一般是getlasterr()win32 api获得的，获得的错误码是winerror.h中的
    DWORD err;
    const wchar_t* funcname;
    std::wstring path1, path2;

public:
    explicit WindowsException(DWORD err,
                              const wchar_t* funcname,
                              std::wstring path1,
                              std::wstring path2)
        : err(err), funcname(funcname), path1(std::move(path1)), path2(std::move(path2))
    {
    }
    explicit WindowsException(DWORD err, const wchar_t* funcname, std::wstring path)
        : err(err), funcname(funcname), path1(std::move(path))
    {
    }
    explicit WindowsException(DWORD err, const wchar_t* funcname) : err(err), funcname(funcname) {}
    ~WindowsException() {}

    std::string message() const override
    {
        wchar_t system_buffer[2000];
        if (!FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM,
                            nullptr,
                            err,
                            0,
                            system_buffer,
                            array_length(system_buffer),
                            nullptr))
        {
            system_buffer[0] = 0;
        }

        // Strip any trailing CRLF
        for (ptrdiff_t i = wcslen(system_buffer) - 1; i >= 0; --i)
        {
            if (system_buffer[i] == L'\r' || system_buffer[i] == L'\n')
                system_buffer[i] = 0;
            else
                break;
        }

        std::vector<wchar_t> final_buffer(path1.size() + path2.size() + wcslen(system_buffer)
                                          + wcslen(funcname) + 100);
        if (!path1.empty() && !path2.empty())
        {
            StringCchPrintfW(final_buffer.data(),
                             final_buffer.size(),
                             L"error %lu %s (%s(path1=%s, path2=%s))",
                             err,
                             system_buffer,
                             funcname,
                             path1.c_str(),
                             path2.c_str());
        }
        else if (!path1.empty())
        {
            StringCchPrintfW(final_buffer.data(),
                             final_buffer.size(),
                             L"error %lu %s (%s(path=%s))",
                             err,
                             system_buffer,
                             funcname,
                             path1.c_str());
        }
        else
        {
            StringCchPrintfW(final_buffer.data(),
                             final_buffer.size(),
                             L"error %lu %s (%s)",
                             err,
                             system_buffer,
                             funcname);
        }
        return narrow_string(final_buffer.data());
    }
    // 返回err属性
    DWORD win32_code() const noexcept { return err; }

    // getlasterr()是win32 api，获得的错误码是winerror.h中的
    // 将winerror.h中错误码转换为errno.h错误码
    // 目的是让unix和win错误码保持一致
    int error_number() const noexcept override
    {
        static const int errorTable[] = {
            0,
            EINVAL,       /* ERROR_INVALID_FUNCTION	1 */
            ENOENT,       /* ERROR_FILE_NOT_FOUND		2 */
            ENOENT,       /* ERROR_PATH_NOT_FOUND		3 */
            EMFILE,       /* ERROR_TOO_MANY_OPEN_FILES	4 */
            EACCES,       /* ERROR_ACCESS_DENIED		5 */
            EBADF,        /* ERROR_INVALID_HANDLE		6 */
            ENOMEM,       /* ERROR_ARENA_TRASHED		7 */
            ENOMEM,       /* ERROR_NOT_ENOUGH_MEMORY	8 */
            ENOMEM,       /* ERROR_INVALID_BLOCK		9 */
            E2BIG,        /* ERROR_BAD_ENVIRONMENT	10 */
            ENOEXEC,      /* ERROR_BAD_FORMAT		11 */
            EACCES,       /* ERROR_INVALID_ACCESS		12 */
            EINVAL,       /* ERROR_INVALID_DATA		13 */
            EFAULT,       /* ERROR_OUT_OF_MEMORY		14 */
            ENOENT,       /* ERROR_INVALID_DRIVE		15 */
            EACCES,       /* ERROR_CURRENT_DIRECTORY	16 */
            EXDEV,        /* ERROR_NOT_SAME_DEVICE	17 */
            ENOENT,       /* ERROR_NO_MORE_FILES		18 */
            EROFS,        /* ERROR_WRITE_PROTECT		19 */
            ENXIO,        /* ERROR_BAD_UNIT		20 */
            EBUSY,        /* ERROR_NOT_READY		21 */
            EIO,          /* ERROR_BAD_COMMAND		22 */
            EIO,          /* ERROR_CRC			23 */
            EIO,          /* ERROR_BAD_LENGTH		24 */
            EIO,          /* ERROR_SEEK			25 */
            EIO,          /* ERROR_NOT_DOS_DISK		26 */
            ENXIO,        /* ERROR_SECTOR_NOT_FOUND	27 */
            EBUSY,        /* ERROR_OUT_OF_PAPER		28 */
            EIO,          /* ERROR_WRITE_FAULT		29 */
            EIO,          /* ERROR_READ_FAULT		30 */
            EIO,          /* ERROR_GEN_FAILURE		31 */
            EACCES,       /* ERROR_SHARING_VIOLATION	32 */
            EACCES,       /* ERROR_LOCK_VIOLATION		33 */
            ENXIO,        /* ERROR_WRONG_DISK		34 */
            ENFILE,       /* ERROR_FCB_UNAVAILABLE	35 */
            ENFILE,       /* ERROR_SHARING_BUFFER_EXCEEDED	36 */
            EINVAL,       /* 37 */
            EINVAL,       /* 38 */
            ENOSPC,       /* ERROR_HANDLE_DISK_FULL	39 */
            EINVAL,       /* 40 */
            EINVAL,       /* 41 */
            EINVAL,       /* 42 */
            EINVAL,       /* 43 */
            EINVAL,       /* 44 */
            EINVAL,       /* 45 */
            EINVAL,       /* 46 */
            EINVAL,       /* 47 */
            EINVAL,       /* 48 */
            EINVAL,       /* 49 */
            ENODEV,       /* ERROR_NOT_SUPPORTED		50 */
            EBUSY,        /* ERROR_REM_NOT_LIST		51 */
            EEXIST,       /* ERROR_DUP_NAME		52 */
            ENOENT,       /* ERROR_BAD_NETPATH		53 */
            EBUSY,        /* ERROR_NETWORK_BUSY		54 */
            ENODEV,       /* ERROR_DEV_NOT_EXIST		55 */
            EAGAIN,       /* ERROR_TOO_MANY_CMDS		56 */
            EIO,          /* ERROR_ADAP_HDW_ERR		57 */
            EIO,          /* ERROR_BAD_NET_RESP		58 */
            EIO,          /* ERROR_UNEXP_NET_ERR		59 */
            EINVAL,       /* ERROR_BAD_REM_ADAP		60 */
            EFBIG,        /* ERROR_PRINTQ_FULL		61 */
            ENOSPC,       /* ERROR_NO_SPOOL_SPACE		62 */
            ENOENT,       /* ERROR_PRINT_CANCELLED	63 */
            ENOENT,       /* ERROR_NETNAME_DELETED	64 */
            EACCES,       /* ERROR_NETWORK_ACCESS_DENIED	65 */
            ENODEV,       /* ERROR_BAD_DEV_TYPE		66 */
            ENOENT,       /* ERROR_BAD_NET_NAME		67 */
            ENFILE,       /* ERROR_TOO_MANY_NAMES		68 */
            EIO,          /* ERROR_TOO_MANY_SESS		69 */
            EAGAIN,       /* ERROR_SHARING_PAUSED		70 */
            EINVAL,       /* ERROR_REQ_NOT_ACCEP		71 */
            EAGAIN,       /* ERROR_REDIR_PAUSED		72 */
            EINVAL,       /* 73 */
            EINVAL,       /* 74 */
            EINVAL,       /* 75 */
            EINVAL,       /* 76 */
            EINVAL,       /* 77 */
            EINVAL,       /* 78 */
            EINVAL,       /* 79 */
            EEXIST,       /* ERROR_FILE_EXISTS		80 */
            EINVAL,       /* 81 */
            ENOSPC,       /* ERROR_CANNOT_MAKE		82 */
            EIO,          /* ERROR_FAIL_I24		83 */
            ENFILE,       /* ERROR_OUT_OF_STRUCTURES	84 */
            EEXIST,       /* ERROR_ALREADY_ASSIGNED	85 */
            EPERM,        /* ERROR_INVALID_PASSWORD	86 */
            EINVAL,       /* ERROR_INVALID_PARAMETER	87 */
            EIO,          /* ERROR_NET_WRITE_FAULT	88 */
            EAGAIN,       /* ERROR_NO_PROC_SLOTS		89 */
            EINVAL,       /* 90 */
            EINVAL,       /* 91 */
            EINVAL,       /* 92 */
            EINVAL,       /* 93 */
            EINVAL,       /* 94 */
            EINVAL,       /* 95 */
            EINVAL,       /* 96 */
            EINVAL,       /* 97 */
            EINVAL,       /* 98 */
            EINVAL,       /* 99 */
            EINVAL,       /* 100 */
            EINVAL,       /* 101 */
            EINVAL,       /* 102 */
            EINVAL,       /* 103 */
            EINVAL,       /* 104 */
            EINVAL,       /* 105 */
            EINVAL,       /* 106 */
            EXDEV,        /* ERROR_DISK_CHANGE		107 */
            EAGAIN,       /* ERROR_DRIVE_LOCKED		108 */
            EPIPE,        /* ERROR_BROKEN_PIPE		109 */
            ENOENT,       /* ERROR_OPEN_FAILED		110 */
            EINVAL,       /* ERROR_BUFFER_OVERFLOW	111 */
            ENOSPC,       /* ERROR_DISK_FULL		112 */
            EMFILE,       /* ERROR_NO_MORE_SEARCH_HANDLES	113 */
            EBADF,        /* ERROR_INVALID_TARGET_HANDLE	114 */
            EFAULT,       /* ERROR_PROTECTION_VIOLATION	115 */
            EINVAL,       /* 116 */
            EINVAL,       /* 117 */
            EINVAL,       /* 118 */
            EINVAL,       /* 119 */
            EINVAL,       /* 120 */
            EINVAL,       /* 121 */
            EINVAL,       /* 122 */
            ENOENT,       /* ERROR_INVALID_NAME		123 */
            EINVAL,       /* 124 */
            EINVAL,       /* 125 */
            EINVAL,       /* 126 */
            ESRCH,        /* ERROR_PROC_NOT_FOUND		127 */
            ECHILD,       /* ERROR_WAIT_NO_CHILDREN	128 */
            ECHILD,       /* ERROR_CHILD_NOT_COMPLETE	129 */
            EBADF,        /* ERROR_DIRECT_ACCESS_HANDLE	130 */
            EINVAL,       /* 131 */
            ESPIPE,       /* ERROR_SEEK_ON_DEVICE		132 */
            EINVAL,       /* 133 */
            EINVAL,       /* 134 */
            EINVAL,       /* 135 */
            EINVAL,       /* 136 */
            EINVAL,       /* 137 */
            EINVAL,       /* 138 */
            EINVAL,       /* 139 */
            EINVAL,       /* 140 */
            EINVAL,       /* 141 */
            EAGAIN,       /* ERROR_BUSY_DRIVE		142 */
            EINVAL,       /* 143 */
            EINVAL,       /* 144 */
            ENOTEMPTY,    /* ERROR_DIR_NOT_EMPTY		145 */
            EINVAL,       /* 146 */
            EINVAL,       /* 147 */
            EINVAL,       /* 148 */
            EINVAL,       /* 149 */
            EINVAL,       /* 150 */
            EINVAL,       /* 151 */
            EINVAL,       /* 152 */
            EINVAL,       /* 153 */
            EINVAL,       /* 154 */
            EINVAL,       /* 155 */
            EINVAL,       /* 156 */
            EINVAL,       /* 157 */
            EACCES,       /* ERROR_NOT_LOCKED		158 */
            EINVAL,       /* 159 */
            EINVAL,       /* 160 */
            ENOENT,       /* ERROR_BAD_PATHNAME	        161 */
            EINVAL,       /* 162 */
            EINVAL,       /* 163 */
            EINVAL,       /* 164 */
            EINVAL,       /* 165 */
            EINVAL,       /* 166 */
            EAGAIN,       /* ERROR_LOCK_FAILED		167 */
            EINVAL,       /* 168 */
            EINVAL,       /* 169 */
            EINVAL,       /* 170 */
            EINVAL,       /* 171 */
            EINVAL,       /* 172 */
            EINVAL,       /* 173 */
            EINVAL,       /* 174 */
            EINVAL,       /* 175 */
            EINVAL,       /* 176 */
            EINVAL,       /* 177 */
            EINVAL,       /* 178 */
            EINVAL,       /* 179 */
            EINVAL,       /* 180 */
            EINVAL,       /* 181 */
            EINVAL,       /* 182 */
            EEXIST,       /* ERROR_ALREADY_EXISTS		183 */
            ECHILD,       /* ERROR_NO_CHILD_PROCESS	184 */
            EINVAL,       /* 185 */
            EINVAL,       /* 186 */
            EINVAL,       /* 187 */
            EINVAL,       /* 188 */
            EINVAL,       /* 189 */
            EINVAL,       /* 190 */
            EINVAL,       /* 191 */
            EINVAL,       /* 192 */
            EINVAL,       /* 193 */
            EINVAL,       /* 194 */
            EINVAL,       /* 195 */
            EINVAL,       /* 196 */
            EINVAL,       /* 197 */
            EINVAL,       /* 198 */
            EINVAL,       /* 199 */
            EINVAL,       /* 200 */
            EINVAL,       /* 201 */
            EINVAL,       /* 202 */
            EINVAL,       /* 203 */
            EINVAL,       /* 204 */
            EINVAL,       /* 205 */
            ENAMETOOLONG, /* ERROR_FILENAME_EXCED_RANGE	206 */
            EINVAL,       /* 207 */
            EINVAL,       /* 208 */
            EINVAL,       /* 209 */
            EINVAL,       /* 210 */
            EINVAL,       /* 211 */
            EINVAL,       /* 212 */
            EINVAL,       /* 213 */
            EINVAL,       /* 214 */
            EINVAL,       /* 215 */
            EINVAL,       /* 216 */
            EINVAL,       /* 217 */
            EINVAL,       /* 218 */
            EINVAL,       /* 219 */
            EINVAL,       /* 220 */
            EINVAL,       /* 221 */
            EINVAL,       /* 222 */
            EINVAL,       /* 223 */
            EINVAL,       /* 224 */
            EINVAL,       /* 225 */
            EINVAL,       /* 226 */
            EINVAL,       /* 227 */
            EINVAL,       /* 228 */
            EINVAL,       /* 229 */
            EPIPE,        /* ERROR_BAD_PIPE		230 */
            EAGAIN,       /* ERROR_PIPE_BUSY		231 */
            EPIPE,        /* ERROR_NO_DATA		232 */
            EPIPE,        /* ERROR_PIPE_NOT_CONNECTED	233 */
            EINVAL,       /* 234 */
            EINVAL,       /* 235 */
            EINVAL,       /* 236 */
            EINVAL,       /* 237 */
            EINVAL,       /* 238 */
            EINVAL,       /* 239 */
            EINVAL,       /* 240 */
            EINVAL,       /* 241 */
            EINVAL,       /* 242 */
            EINVAL,       /* 243 */
            EINVAL,       /* 244 */
            EINVAL,       /* 245 */
            EINVAL,       /* 246 */
            EINVAL,       /* 247 */
            EINVAL,       /* 248 */
            EINVAL,       /* 249 */
            EINVAL,       /* 250 */
            EINVAL,       /* 251 */
            EINVAL,       /* 252 */
            EINVAL,       /* 253 */
            EINVAL,       /* 254 */
            EINVAL,       /* 255 */
            EINVAL,       /* 256 */
            EINVAL,       /* 257 */
            EINVAL,       /* 258 */
            EINVAL,       /* 259 */
            EINVAL,       /* 260 */
            EINVAL,       /* 261 */
            EINVAL,       /* 262 */
            EINVAL,       /* 263 */
            EINVAL,       /* 264 */
            EINVAL,       /* 265 */
            EINVAL,       /* 266 */
            ENOTDIR,      /* ERROR_DIRECTORY		267 */
        };
        // 根据err
        if (err >= 0 && err < array_length(errorTable))
            return errorTable[err];
        return EPERM;
    }
};

[[noreturn]] void throw_windows_exception(const wchar_t* funcname)
{
    DWORD err = GetLastError();
    throw WindowsException(err, funcname);
}

#define THROW_WINDOWS_EXCEPTION(err, exp)                                                          \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp);                                                         \
    } while (0)

#define THROW_WINDOWS_EXCEPTION_WITH_PATH(err, exp, path)                                          \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp, path);                                                   \
    } while (0)

#define THROW_WINDOWS_EXCEPTION_WITH_TWO_PATHS(err, exp, path1, path2)                             \
    do                                                                                             \
    {                                                                                              \
        DWORD code = err;                                                                          \
        throw WindowsException(code, exp, path1, path2);                                           \
    } while (0)

// 檢查調用宏，如果調用失敗抛出異常
#define CHECK_CALL(exp)                                                                            \
    if (!(exp))                                                                                    \
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"" #exp);

// 根據句柄獲取文件屬性，stat函數會用到
static void stat_file_handle(HANDLE hd, struct fuse_stat* st)
{
    memset(st, 0, sizeof(*st));
    BY_HANDLE_FILE_INFORMATION info;
    CHECK_CALL(GetFileInformationByHandle(hd, &info));
    filetime_to_unix_time(&info.ftLastAccessTime, &st->st_atim);
    filetime_to_unix_time(&info.ftLastWriteTime, &st->st_mtim);
    filetime_to_unix_time(&info.ftCreationTime, &st->st_birthtim);
    st->st_ctim = st->st_mtim;
    st->st_nlink = static_cast<fuse_nlink_t>(info.nNumberOfLinks);
    st->st_uid = securefs::OSService::getuid();
    st->st_gid = securefs::OSService::getgid();
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        st->st_mode = S_IFDIR | 0755;
    else
        st->st_mode = S_IFREG | 0755;
    st->st_dev = info.dwVolumeSerialNumber;
    st->st_ino = convert_dword_pair(info.nFileIndexLow, info.nFileIndexHigh);
    st->st_size = convert_dword_pair(info.nFileSizeLow, info.nFileSizeHigh);
    st->st_blksize = 4096;
    st->st_blocks = (st->st_size + 4095) / 4096 * (4096 / 512);
}

class WindowsFileStream final : public FileStream
{
private:
    HANDLE m_handle;

private:
    // 写数据（每次写的数据长度最多32位）
    void write32(const void* input, offset_type offset, DWORD length)
    {
        // ol表示offset，用两个dword表示64位
        OVERLAPPED ol;
        memset(&ol, 0, sizeof(ol));
        ol.Offset = static_cast<DWORD>(offset);
        ol.OffsetHigh = static_cast<DWORD>(offset >> 32);

        DWORD writelen;
        // 写失败会抛出异常
        CHECK_CALL(WriteFile(m_handle, input, length, &writelen, &ol));
        // 写的长度不对也会抛出异常
        if (writelen != length)
            throwVFSException(EIO);
    }

    void write32(const void* input, DWORD length)
    {
        DWORD writelen;
        CHECK_CALL(WriteFile(m_handle, input, length, &writelen, nullptr));
        if (writelen != length)
            throwVFSException(EIO);
    }

    // 读数据（每次读取的数据长度最多32位）
    length_type read32(void* output, offset_type offset, DWORD length)
    {
        // ol表示offset，用两个dword表示64位
        OVERLAPPED ol;
        memset(&ol, 0, sizeof(ol));
        ol.Offset = static_cast<DWORD>(offset);
        ol.OffsetHigh = static_cast<DWORD>(offset >> 32);

        DWORD readlen;
        if (!ReadFile(m_handle, output, length, &readlen, &ol))
        {
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF)
                return 0;
            THROW_WINDOWS_EXCEPTION(err, L"ReadFile");
        }
        return readlen;
    }

    length_type read32(void* output, DWORD length)
    {
        DWORD readlen;
        if (!ReadFile(m_handle, output, length, &readlen, nullptr))
        {
            DWORD err = GetLastError();
            if (err == ERROR_HANDLE_EOF)
                return 0;
            THROW_WINDOWS_EXCEPTION(err, L"ReadFile");
        }
        return readlen;
    }

public:
    // WindowsFileStream类的构造函数（打开or创建文件，获得文件描述符）
    explicit WindowsFileStream(WideStringRef path, int flags, unsigned mode)
        : m_handle(INVALID_HANDLE_VALUE)
    {
        DWORD access_flags = 0;
        // 因为fuse会使用到flag，会利用到下面这些标志，但是只有unix才有
        // 所以利用winfsp实现flag判断的时候，需要拿出unix有的这些标志来用，然后转换为windows api操作标志
        switch (flags & O_ACCMODE)
        {
        case O_RDONLY:
            access_flags = GENERIC_READ;
            break;
        case O_WRONLY:
            access_flags = GENERIC_WRITE;
            break;
        case O_RDWR:
            access_flags = GENERIC_READ | GENERIC_WRITE;
            break;
        default:
            throwVFSException(EINVAL);
        }

        DWORD create_flags = 0;
        if (flags & O_CREAT)
        {
            if (flags & O_EXCL)
                create_flags = CREATE_NEW;
            else if (flags & O_TRUNC)
                throwInvalidArgumentException(
                    "On Windows, O_TRUNC cannot be specified together with O_CREAT");
            else
                create_flags = OPEN_ALWAYS;
        }
        else if (flags & O_TRUNC)
        {
            create_flags = TRUNCATE_EXISTING;
        }
        else
        {
            create_flags = OPEN_EXISTING;
        }

        // 创建or打开文件，返回文件句柄
        m_handle = CreateFileW(path.c_str(),
                               access_flags,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr,
                               create_flags,
                               FILE_ATTRIBUTE_NORMAL,
                               nullptr);
        // 如果返回的文件句柄非法，抛出异常
        if (m_handle == INVALID_HANDLE_VALUE)
        {
            DWORD err = GetLastError();
            throw WindowsException(err, L"CreateFileW", path.to_string());
        }
    }

    ~WindowsFileStream() { CloseHandle(m_handle); }

    // 尝试对文件上锁（类似于flock，利用这个方法可以实现不同线程的同时安全操作）
    void lock(bool exclusive) override
    {
        if (!securefs::is_lock_enabled())
        {
            return;
        }
        OVERLAPPED o;
        memset(&o, 0, sizeof(o));
        CHECK_CALL(LockFileEx(m_handle,
                              exclusive ? LOCKFILE_EXCLUSIVE_LOCK : 0,
                              0,
                              std::numeric_limits<DWORD>::max(),
                              std::numeric_limits<DWORD>::max(),
                              &o));
    }

    // 尝试对文件解锁
    void unlock() noexcept override
    {
        if (!securefs::is_lock_enabled())
        {
            return;
        }
        OVERLAPPED o;
        memset(&o, 0, sizeof(o));
        (void)(UnlockFileEx(
            m_handle, 0, std::numeric_limits<DWORD>::max(), std::numeric_limits<DWORD>::max(), &o));
    }

    // 关闭文件，通过关闭句柄实现（句柄有点像文件描述符）
    void close() noexcept override
    {
        CloseHandle(m_handle);
        m_handle = INVALID_HANDLE_VALUE;
    }

    // 读数据（通过调用read32()实现）
    // typedef uint64_t length_type;
    // static const DWORD MAX_SINGLE_BLOCK = std::numeric_limits<DWORD>::max();
    length_type read(void* output, offset_type offset, length_type length) override
    {
        length_type total = 0;
        // MAX_SINGLE_BLOCK表示一次读取的最大数据
        while (length > MAX_SINGLE_BLOCK)
        {
            length_type readlen = read32(output, offset, MAX_SINGLE_BLOCK);
            if (readlen == 0)
                return total;
            length -= readlen;
            offset += readlen;
            output = static_cast<char*>(output) + readlen;
            total += readlen;
        }
        total += read32(output, offset, static_cast<DWORD>(length));
        return total;
    }

    length_type sequential_read(void* output, length_type length) override
    {
        length_type total = 0;
        while (length > MAX_SINGLE_BLOCK)
        {
            length_type readlen = read32(output, MAX_SINGLE_BLOCK);
            if (readlen == 0)
                return total;
            length -= readlen;
            output = static_cast<char*>(output) + readlen;
            total += readlen;
        }
        total += read32(output, static_cast<DWORD>(length));
        return total;
    }

    // 写数据（通过write32()实现）
    void write(const void* input, offset_type offset, length_type length) override
    {
        // 表示一次能写的最大长度
        while (length > MAX_SINGLE_BLOCK)
        {
            write32(input, offset, MAX_SINGLE_BLOCK);
            length -= MAX_SINGLE_BLOCK;
            offset += MAX_SINGLE_BLOCK;
            input = static_cast<const char*>(input) + MAX_SINGLE_BLOCK;
        }
        write32(input, offset, static_cast<DWORD>(length));
    }

    void sequential_write(const void* input, length_type length) override
    {
        while (length > MAX_SINGLE_BLOCK)
        {
            write32(input, MAX_SINGLE_BLOCK);
            length -= MAX_SINGLE_BLOCK;
            input = static_cast<const char*>(input) + MAX_SINGLE_BLOCK;
        }
        write32(input, static_cast<DWORD>(length));
    }

    length_type size() const override
    {
        _LARGE_INTEGER SIZE;
        CHECK_CALL(GetFileSizeEx(m_handle, &SIZE));
        return SIZE.QuadPart;
    }

    // windows不需要实现这个函数
    void flush() override {}

    void resize(length_type len) override
    {
        LARGE_INTEGER llen;
        llen.QuadPart = len;
        CHECK_CALL(SetFilePointerEx(m_handle, llen, nullptr, FILE_BEGIN));
        CHECK_CALL(SetEndOfFile(m_handle));
    }

    length_type optimal_block_size() const noexcept override { return 4096; }

    // 将文件的内容从缓存同步到磁盘上，低级I/O用
    void fsync() override { CHECK_CALL(FlushFileBuffers(m_handle)); }

    void utimens(const struct fuse_timespec ts[2]) override
    {
        FILETIME access_time, mod_time;
        if (!ts)
        {
            best_get_time_func(&access_time);
            mod_time = access_time;
        }
        else
        {
            access_time = unix_time_to_filetime(ts + 0);
            mod_time = unix_time_to_filetime(ts + 1);
        }
        CHECK_CALL(SetFileTime(m_handle, nullptr, &access_time, &mod_time));
    }
    // 獲取已打開文件的文件屬性，文件句柄已經指向文件，而不像OS類中指向數據目錄
    void fstat(struct fuse_stat* st) const override { stat_file_handle(m_handle, st); }
    bool is_sparse() const noexcept override { return true; }
};

OSService::OSService() : m_root_handle(INVALID_HANDLE_VALUE) {}

OSService::~OSService() { CloseHandle(m_root_handle); }

bool OSService::is_absolute(StringRef path)
{
    return path.empty() || path[0] == '/' || path[0] == '\\'
        || (path.size() >= 2 && path[1] == ':');
}

namespace
{
    const StringRef LONG_PATH_PREFIX = R"(\\?\)";

    bool is_canonical(StringRef path)
    {
        if (path.empty())
        {
            return true;
        }
        if (!path.starts_with(LONG_PATH_PREFIX))
            return false;
        size_t last_boundary = LONG_PATH_PREFIX.size();
        for (size_t i = last_boundary; i <= path.size(); ++i)
        {
            bool is_boundary = i >= path.size() || path[i] == '\\';
            if (!is_boundary)
            {
                continue;
            }
            if (i == last_boundary || i == last_boundary + 1)
            {
                return false;
            }
            if (i == last_boundary + 2 && path[last_boundary + 1] == '.')
            {
                return false;
            }
            if (i == last_boundary + 3 && path[last_boundary + 1] == '.'
                && path[last_boundary + 2] == '.')
            {
                return false;
            }
            last_boundary = i;
        }
        return true;
    }

    // Convert forward slashes to back slashes, and remove "." and ".." from path components
    void canonicalize(std::string& prepath)
    {
        for (char& c : prepath)
        {
            if (c == '/')
                c = '\\';
        }
        if (is_canonical(prepath))
        {
            return;
        }
        std::vector<std::string> components = split(prepath, '\\');
        std::vector<const std::string*> norm_components;
        norm_components.reserve(components.size());
        for (const std::string& name : components)
        {
            if (name.empty() || name == ".")
                continue;
            if (name == "..")
            {
                if (norm_components.size() > 0)
                    norm_components.pop_back();
                continue;
            }
            norm_components.push_back(&name);
        }
        bool is_already_universal = prepath.size() >= 2 && prepath[0] == '\\' && prepath[1] == '\\';

        prepath.clear();
        if (is_already_universal)
        {
            prepath.push_back('\\');
        }
        else
        {
            prepath.assign(("\\\\?"));
        }
        for (const std::string* name : norm_components)
        {
            prepath.push_back('\\');
            prepath.append(*name);
        }
    }
}    // namespace

native_string_type OSService::concat_and_norm(StringRef base_dir, StringRef path)
{
    if (base_dir.empty() || is_absolute(path))
    {
        return widen_string(path);
    }
    if (!is_absolute(base_dir))
    {
        throwInvalidArgumentException("base_dir must be an absolute path, yet we received "
                                      + base_dir);
    }
    std::string prepath;
    if (path == ".")
    {
        prepath = base_dir.to_string();
    }
    else
    {
        prepath.reserve(prepath.size() + 1 + path.size());
        prepath.append(base_dir.c_str(), base_dir.size());
        prepath.push_back('\\');
        prepath.append(path.data(), path.size());
    }
    canonicalize(prepath);
    return widen_string(prepath);
}

OSService::OSService(StringRef path)
{
    auto wide_path = widen_string(path);
    m_root_handle = CreateFileW(wide_path.c_str(),
                                GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS,
                                nullptr);
    if (m_root_handle == INVALID_HANDLE_VALUE)
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateFileW", wide_path);
    std::wstring fullname(33000, 0);
    DWORD size = GetFinalPathNameByHandleW(m_root_handle, &fullname[0], fullname.size(), 0);
    if (size <= 0)
    {
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"GetFinalPathNameByHandleW");
    }
    fullname.resize(size);
    m_dir_name = narrow_string(fullname);
}

std::shared_ptr<FileStream>
OSService::open_file_stream(StringRef path, int flags, unsigned mode) const
{
    return std::make_shared<WindowsFileStream>(norm_path(path), flags, mode);
}

// 删除文件
void OSService::remove_file(StringRef path) const
{
    CHECK_CALL(DeleteFileW(norm_path(path).c_str()));
}

// 删除目录
void OSService::remove_directory(StringRef path) const
{
    CHECK_CALL(RemoveDirectoryW(norm_path(path).c_str()));
}

void OSService::lock() const
{
    if (!securefs::is_lock_enabled())
    {
        return;
    }
    fprintf(stderr,
            "Warning: Windows does not support directory locking. "
            "Be careful not to mount the same data directory multiple times!\n");
}

// 创建目录
void OSService::mkdir(StringRef path, unsigned mode) const
{
    auto npath = norm_path(path);
    if (CreateDirectoryW(npath.c_str(), nullptr) == 0)
    {
        DWORD err = GetLastError();
        THROW_WINDOWS_EXCEPTION_WITH_PATH(err, L"CreateDirectory", npath);
    }
}

// 獲取文件系統的属性
void OSService::statfs(struct fuse_statvfs* fs_info) const
{
    // 將存放屬性的結構體中數據全部置0
    memset(fs_info, 0, sizeof(*fs_info));
    // ULARGE_INTEGER表示64位无符号整数值，實際上是一個結構體
    ULARGE_INTEGER FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes;
    // typedef unsigned long DWORD;
    DWORD namemax = 0;
    // CHECK_CALL宏用於判斷執行結果，失敗則抛出異常
    // GetDiskFreeSpaceExW()检索有关磁盘卷上可用空间量的信息，即总空间量、可用空间总量以及与调用线程关联的用户可用的可用空间总量。
    CHECK_CALL(GetDiskFreeSpaceExW(
        norm_path(".").c_str(), &FreeBytesAvailable, &TotalNumberOfBytes, &TotalNumberOfFreeBytes));
    // GetVolumeInformationByHandleW()检索与指定文件关联的文件系统和卷的相关信息。
    CHECK_CALL(GetVolumeInformationByHandleW(
        m_root_handle, nullptr, 0, nullptr, &namemax, nullptr, nullptr, 0));
    // 將獲取的文件系統信息放入結構體中
    auto maximum = static_cast<unsigned>(-1);
    fs_info->f_bsize = 4096;
    fs_info->f_frsize = fs_info->f_bsize;
    fs_info->f_bfree = TotalNumberOfFreeBytes.QuadPart / fs_info->f_bsize;
    fs_info->f_blocks = TotalNumberOfBytes.QuadPart / fs_info->f_bsize;
    fs_info->f_bavail = FreeBytesAvailable.QuadPart / fs_info->f_bsize;
    fs_info->f_files = maximum;
    fs_info->f_ffree = maximum;
    fs_info->f_favail = maximum;
    fs_info->f_namemax = namemax;
}

// 改变文件的访问和修改时间（纳秒级），利用 best_get_time_func() 实现
void OSService::utimens(StringRef path, const fuse_timespec ts[2]) const
{
    FILETIME atime, mtime;
    // 如果传入的ts不存在，调用windwos api获取
    if (!ts)
    {
        // best_get_time_func()是目前系统上能获取精度最准的函数
        best_get_time_func(&atime);
        mtime = atime;
    }
    // 如果传入的ts存在，unix time转化为FILETIME格式
    else
    {
        atime = unix_time_to_filetime(ts);
        mtime = unix_time_to_filetime(ts + 1);
    }
    auto npath = norm_path(path);
    // 利用CreateFileW()打开文件
    HANDLE hd = CreateFileW(npath.c_str(),
                            FILE_WRITE_ATTRIBUTES,
                            FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_FLAG_BACKUP_SEMANTICS,
                            nullptr);
    if (hd == INVALID_HANDLE_VALUE)
        THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"CreateFileW", npath);
    // 记得关闭句柄
    DEFER(CloseHandle(hd));
    // 设置文件的的时间
    CHECK_CALL(SetFileTime(hd, nullptr, &atime, &mtime));
}

// 獲取文件的屬性
bool OSService::stat(StringRef path, struct fuse_stat* stat) const
{
    // 如果路徑為根數據目錄，且跟數據目錄的句柄是合法的，那麽使用這個句柄就行
    // 這種情況經常發生
    if (path == "." && m_root_handle != INVALID_HANDLE_VALUE)
    {
        // Special case which occurs very frequently
        // 根據句柄獲取文件信息
        stat_file_handle(m_root_handle, stat);
        return true;
    }
    // 將相對路徑和數據目錄進行拼接
    auto npath = norm_path(path);
    // 创建或打开文件或 I/O 设备，返回文件句柄
    HANDLE handle = CreateFileW(npath.c_str(),
                                FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_FLAG_BACKUP_SEMANTICS,
                                nullptr);
    // 如果句柄非法，抛出異常
    if (handle == INVALID_HANDLE_VALUE)
    {
        DWORD err = GetLastError();
        if (err == ERROR_PATH_NOT_FOUND || err == ERROR_FILE_NOT_FOUND || err == ERROR_NOT_FOUND)
            return false;
        THROW_WINDOWS_EXCEPTION_WITH_PATH(err, L"CreateFileW", npath);
    }

    // 延遲執行，抛出異常
    DEFER(CloseHandle(handle));
    // 根據句柄獲取文件信息
    stat_file_handle(handle, stat);

    return true;
}

// 这几个系统调用，unix才有，所以win不进行重写
void OSService::link(StringRef source, StringRef dest) const { throwVFSException(ENOSYS); }
void OSService::chmod(StringRef path, fuse_mode_t mode) const { (void)0; }
void OSService::chown(StringRef, fuse_uid_t, fuse_gid_t) const { (void)0; }

ssize_t OSService::readlink(StringRef path, char* output, size_t size) const
{
    throwVFSException(ENOSYS);
}
void OSService::symlink(StringRef source, StringRef dest) const { throwVFSException(ENOSYS); }

// 重命名操作
void OSService::rename(StringRef a, StringRef b) const
{
    auto wa = norm_path(a);
    auto wb = norm_path(b);
    // 不用宏，是为了简化抛出异常的信息
    if (!MoveFileExW(wa.c_str(), wb.c_str(), MOVEFILE_REPLACE_EXISTING))
        THROW_WINDOWS_EXCEPTION_WITH_TWO_PATHS(GetLastError(), L"MoveFileExW", wa, wb);
}

int64_t OSService::raise_fd_limit() noexcept
{
    // The handle limit on Windows is high enough that no adjustments are necessary
    return std::numeric_limits<int32_t>::max();
}

// windows目錄遍歷類，基礎 DirectoryTraverser類
class WindowsDirectoryTraverser final : public DirectoryTraverser
{
private:
    // 目錄路徑
    std::wstring m_pattern;
    // 當前句柄對應文件的信息（結構體）
    WIN32_FIND_DATAW m_data;
    // 目錄中某個目錄項的句柄
    HANDLE m_handle;
    // 表示是否在目錄項中開頭
    bool m_is_initial;

public:
    // 構造函數
    explicit WindowsDirectoryTraverser(std::wstring pattern)
        : m_pattern(std::move(pattern)), m_handle(INVALID_HANDLE_VALUE), m_is_initial(false)
    {
        rewind();
    }

    ~WindowsDirectoryTraverser()
    {
        if (m_handle != INVALID_HANDLE_VALUE)
            FindClose(m_handle);
    }

    // 將目錄遍歷指針移到目錄項開頭
    void rewind() override
    {
        // 如果m_is_initial為true，表示已經在目錄項開頭
        if (m_is_initial)
            return;    // Already at the beginning
        // 如果句柄非法，關閉句柄對應的文件
        if (m_handle != INVALID_HANDLE_VALUE)
            FindClose(m_handle);
        // 將句柄指向目錄中第一個目錄項
        // FindFirstFileW()返回找到目錄中的第一个文件或目录的句柄和信息
        m_handle = FindFirstFileW(m_pattern.c_str(), &m_data);
        // 如果句柄非法，抛出異常
        if (m_handle == INVALID_HANDLE_VALUE)
        {
            THROW_WINDOWS_EXCEPTION_WITH_PATH(GetLastError(), L"FindFirstFileW", m_pattern);
        }
    }

    // 移動到下一個目錄下
    bool next(std::string* name, struct fuse_stat* st) override
    {
        // 如果在開頭，將開頭你好標志改爲false
        if (m_is_initial)
        {
            m_is_initial = false;
        }
        // 如果不是在开头，判断能不能找到下一个
        else
        {
            if (!FindNextFileW(m_handle, &m_data))
            {
                DWORD err = GetLastError();
                if (err == ERROR_NO_MORE_FILES)
                    return false;
                THROW_WINDOWS_EXCEPTION_WITH_PATH(err, L"FindNextFileW", m_pattern);
            }
        }

        // 将当前文件信息中的文件名转换为窄字符串，赋值给传入的name
        if (name)
            *name = narrow_string(m_data.cFileName);
        // 将当前文件信息中一些信息赋值给传入的st
        if (st)
        {
            // 在st或上相应目录or文件标志位
            if (m_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                st->st_mode = 0755 | S_IFDIR;
            else
                st->st_mode = 0755 | S_IFREG;
            // 将两个dword32位表示的64位无符号数，拼接成uint64_t表示的无符号数
            st->st_size = convert_dword_pair(m_data.nFileSizeLow, m_data.nFileSizeHigh);
            // 因为fuse中文件结构体是用unix格式的时间表示的，winfsp中实现的fuse也是
            // 所以需要将FILETIME格式的时间转换为unix格式的时间
            filetime_to_unix_time(&m_data.ftCreationTime, &st->st_birthtim);
            filetime_to_unix_time(&m_data.ftLastAccessTime, &st->st_atim);
            filetime_to_unix_time(&m_data.ftLastWriteTime, &st->st_mtim);
            st->st_ctim = st->st_mtim;
            st->st_nlink = 1;
            st->st_blksize = 4096;
            st->st_blocks = st->st_size / 512;
        }
        return true;
    }
};

std::unique_ptr<DirectoryTraverser> OSService::create_traverser(StringRef dir) const
{
    return securefs::make_unique<WindowsDirectoryTraverser>(norm_path(dir) + L"\\*");
}

uint32_t OSService::getuid() noexcept { return 0; }

uint32_t OSService::getgid() noexcept { return 0; }

void OSService::get_current_time(fuse_timespec& current_time)
{
    FILETIME ft;
    best_get_time_func(&ft);
    filetime_to_unix_time(&ft, &current_time);
}

void OSService::get_current_time_in_tm(struct tm* tm, int* ns)
{
    fuse_timespec spec;
    get_current_time(spec);
    time_t tts = spec.tv_sec;
    gmtime_s(tm, &tts);
    *ns = spec.tv_nsec;
}

void OSService::read_password_no_confirmation(const char* prompt,
                                              CryptoPP::AlignedSecByteBlock* output)
{
    byte buffer[4000];
    DEFER(CryptoPP::SecureWipeBuffer(buffer, array_length(buffer)));
    size_t bufsize = 0;

    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    DWORD old_mode, new_mode;
    if (GetConsoleMode(in, &old_mode))
    {
        // Success, guess we are reading from user input instead of a pipe
        fputs(prompt, stderr);
        fflush(stderr);

        new_mode = old_mode & ~(DWORD)ENABLE_ECHO_INPUT;
        SetConsoleMode(in, new_mode);
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

    if (SetConsoleMode(in, old_mode))
        putc('\n', stderr);
    output->resize(bufsize);
    memcpy(output->data(), buffer, bufsize);
}

void OSService::read_password_with_confirmation(const char* prompt,
                                                CryptoPP::AlignedSecByteBlock* output)
{
    CryptoPP::AlignedSecByteBlock another;
    read_password_no_confirmation(prompt, output);
    read_password_no_confirmation("Again: ", &another);
    if (output->size() != another.size()
        || memcmp(output->data(), another.data(), another.size()) != 0)
        throw_runtime_error("Password mismatch!");
}

std::string OSService::stringify_system_error(int errcode)
{
    char buffer[4000];
    strerror_s(buffer, array_length(buffer), errcode);
    return buffer;
}

std::wstring widen_string(StringRef str)
{
    if (str.empty())
    {
        return {};
    }
    if (str.size() >= std::numeric_limits<int>::max())
        throwInvalidArgumentException("String too long");
    int sz = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0);
    if (sz <= 0)
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"MultiByteToWideChar");
    std::wstring result(sz, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &result[0], sz);
    return result;
}

// 将宽字符数组转换为窄字符数组
// typedef BasicStringRef<wchar_t> WideStringRef;
std::string narrow_string(WideStringRef str)
{
    // 如果str为空，返回空
    if (str.empty())
    {
        return {};
    }
    // 如果str的size超过了int的限制，抛出异常
    if (str.size() >= std::numeric_limits<int>::max())
        throwInvalidArgumentException("String too long");
    // Windows提供的宽字符转窄字符函数，不具有通用性
    // 这里调用主要是看能不能转换
    int sz = WideCharToMultiByte(
        CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0, 0, 0);
    // 返回的结果<=0说明转换失败，抛出异常
    if (sz <= 0)
        THROW_WINDOWS_EXCEPTION(GetLastError(), L"WideCharToMultiByte");
    // 创建窄字符数组，进行转换
    std::string result(sz, 0);
    WideCharToMultiByte(
        CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &result[0], sz, 0, 0);
    return result;
}

namespace
{
    // 控制台测试结果
    struct ConsoleTestResult
    {
        bool is_console = false;
        HANDLE handle = INVALID_HANDLE_VALUE;
        DWORD mode = 0;
    };

    // 测试fp是不是控制台
    ConsoleTestResult test_console(FILE* fp)
    {
        // 不存在返回空
        if (!fp)
        {
            return {};
        }
        int fd = _fileno(fp);
        if (fd < 0)
        {
            return {};
        }
        // 获取与os有关的操作句柄
        auto h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
        // 非法返回空
        if (h == INVALID_HANDLE_VALUE)
        {
            return {};
        }
        ConsoleTestResult result;
        result.handle = h;
        // 根据os操作句柄，判断是否为控制台模式
        result.is_console = GetConsoleMode(h, &result.mode);
        return result;
    }
}    // namespace

std::unique_ptr<ConsoleColourSetter> ConsoleColourSetter::create_setter(FILE* fp)
{
    auto t = test_console(fp);
    if (!t.is_console)
        return {};
    if (!SetConsoleMode(t.handle, t.mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    {
        return {};
    }
    return securefs::make_unique<POSIXColourSetter>(fp);
}

std::unique_ptr<const char, void (*)(const char*)> get_type_name(const std::exception& e) noexcept
{
    return {typeid(e).name(), [](const char*) { /* no op */ }};
}

const char* PATH_SEPARATOR_STRING = "\\";
const char PATH_SEPARATOR_CHAR = '\\';

// windows环境下的一些初始化操作（设置控制台编码方式、缓冲区和获取时间函数等）
void windows_init(void)
{
    // 获取控制台输出的代码页（代码页即命令行编码方式）
    static auto original_cp = ::GetConsoleOutputCP();
    // 设置控制台的编码方式为UTF-8
    ::SetConsoleOutputCP(CP_UTF8);
    // 程序结束的时候，把控制台的编码方式设置回去
    atexit([]() { ::SetConsoleOutputCP(original_cp); });
    // 设置非法参数异常处理函数，这里写入空的匿名函数，即不做其他处理，会直接崩溃
    _set_invalid_parameter_handler(
        [](wchar_t const*, wchar_t const*, wchar_t const*, unsigned int, uintptr_t) {});

    // 如果stdout是控制台模式
    if (test_console(stdout).is_console)
    {
        // 设置stdout缓冲区大小，模式为每次从流中读入一行数据或向流中写入一行数据。
        // 在遇到换行符前或者缓冲区满前，都咱存在系统自动申请的buffer中，而不会写到真正的磁盘文件上。
        setvbuf(stdout, nullptr, _IOLBF, 65536);
    }
    // 如果stderr是控制台模式
    if (test_console(stderr).is_console)
    {
        setvbuf(stderr, nullptr, _IOLBF, 65536);
    }
    // 延迟加载winfsp的dll，若不成功则输出提示并结束程序
    // https://zhuanlan.zhihu.com/p/440971338
    if (::FspLoad(nullptr) != STATUS_SUCCESS)
    {
        fputs("SecureFS cannot load WinFsp. Please make sure you have WinFsp properly installed.\n",
              stderr);
        abort();
    }

    // dll是动态链接库，在内存中共用一份。不同于静态链接库，每个用到的程序在内存中都会单独有一份。
    // 获得当前程序已加载dll的句柄
    HMODULE hd = GetModuleHandleW(L"kernel32.dll");

    // decltype(best_get_time_func)表示自动推断best_get_time_func的类型，在前面定义好了
    // best_get_time_func为GetSystemTimePreciseAsFileTime函数
    // 为什么要从kernel32.dll中导出这个函数？通过头文件也可以，可能是为了兼容性？
    best_get_time_func
        = get_proc_address<decltype(best_get_time_func)>(hd, "GetSystemTimePreciseAsFileTime");
    // 从kernel32.dll中获取失败则设置为GetSystemTimeAsFileTime函数
    if (best_get_time_func == nullptr)
        best_get_time_func = &GetSystemTimeAsFileTime;
}

// win 类中的mutex通过临界区实现
Mutex::Mutex() { ::InitializeCriticalSectionAndSpinCount(&m_cs, 4000); }
Mutex::~Mutex() { ::DeleteCriticalSection(&m_cs); }

void Mutex::lock() { ::EnterCriticalSection(&m_cs); }

void Mutex::unlock() noexcept { ::LeaveCriticalSection(&m_cs); }

bool Mutex::try_lock() { return ::TryEnterCriticalSection(&m_cs); }
}    // namespace securefs

#endif
