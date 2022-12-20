#pragma once
#include "myutils.h"

#include <cerrno>
#include <exception>
#include <memory>
#include <stdint.h>
#include <string.h>
#include <string>
#include <utility>

/*
自定义异常，通过继承std::exception实现
*/


namespace securefs
{
// 异常基类，继承std::exception
class ExceptionBase : public std::exception
{
private:
    mutable std::string m_cached_msg;
    // Mutable fields are not thread safe in `const` functions.
    // But who accesses exception objects concurrently anyway?

protected:
    ExceptionBase();

public:
    ~ExceptionBase() override;
    virtual std::string message() const = 0;
    virtual int error_number() const noexcept { return EPERM; }
    const char* what() const noexcept override;
};

// 不可达到代码异常，继承ExceptionBase
class UnreachableCodeException final : public ExceptionBase
{
private:
    const char* m_func; // 函数名
    const char* m_file; // 文件名
    int m_line; // 行号

public:
    explicit UnreachableCodeException(const char* func, const char* file, int line)
        : m_func(func), m_file(file), m_line(line)
    {
    }

    std::string message() const override
    {
        return strprintf(
            "Unreachable code executed in function \"%s\" at %s:%d", m_func, m_file, m_line);
    }
};

// 宏定义UNREACHABLE()，调用该宏的时候，会构造相应的UnreachableCodeException对象
#define UNREACHABLE() throw securefs::UnreachableCodeException(__FUNCTION__, __FILE__, __LINE__)

// VFS异常，继承ExceptionBase
class VFSException final : public ExceptionBase
{
private:
    int m_errno;    // 错误码

public:
    explicit VFSException(int errc) : m_errno(errc) {}
    ~VFSException() override;

    int error_number() const noexcept override { return m_errno; }

    std::string message() const override;
};

// [[noreturn]]关键字表示当前函数不会返回，即在当前函数调用之后的函数或代码并不会被执行
[[noreturn]] void throwVFSException(int errc);

// 系统异常，继承ExceptionBase
class SystemException : public ExceptionBase
{
};

// POSIX异常，继承ExceptionBase
class POSIXException final : public SystemException
{
private:
    int m_errno;
    std::string m_msg;

public:
    explicit POSIXException(int errc, std::string msg) : m_errno(errc), m_msg(std::move(msg)) {}
    ~POSIXException() override;

    int error_number() const noexcept override { return m_errno; }

    std::string message() const override;
};

// THROW_POSIX_EXCEPTION宏定义
// This macro is needed because errno expands to a function, which has unspecified evaluation order
// with respect to other function calls, and those other function calls may modify errno, resulting
// in incorrect error reporting
#define THROW_POSIX_EXCEPTION(errc, msg)                                                           \
    do                                                                                             \
    {                                                                                              \
        int code = errc;                                                                           \
        ::securefs::throwPOSIXExceptionDoNotUseDirectly(code, msg);                                \
    } while (0)

[[noreturn]] void throwPOSIXExceptionDoNotUseDirectly(int err, std::string msg);

// 验证异常，继承ExceptionBase
class VerificationException : public ExceptionBase
{
};

// 非法格式异常，继承ExceptionBase
class InvalidFormatException : public ExceptionBase
{
};

// 非法参数异常，继承ExceptionBase
class InvalidArgumentException : public ExceptionBase
{
private:
    std::string m_msg;

public:
    explicit InvalidArgumentException(std::string why) { m_msg.swap(why); }
    ~InvalidArgumentException() override;

    std::string message() const override { return m_msg; }

    int error_number() const noexcept override { return EINVAL; }
};

// noreturn的抛出异常函数
[[noreturn]] void throwInvalidArgumentException(const char* why);
[[noreturn]] void throwInvalidArgumentException(std::string why);

// 元数据损坏异常，继承ExceptionBase
class CorruptedMetaDataException : public InvalidFormatException
{
private:
    id_type m_id;
    const char* m_reason;

public:
    explicit CorruptedMetaDataException(const id_type& id, const char* reason) : m_reason(reason)
    {
        memcpy(m_id.data(), id.data(), id.size());
    }

    std::string message() const override
    {
        return strprintf("Metadata for ID %s is corrupted (%s)",
                         hexify(m_id.data(), m_id.size()).c_str(),
                         m_reason);
    }
};

// 消息验证异常，继承ExceptionBase
class MessageVerificationException : public VerificationException
{
private:
    id_type m_id;
    offset_type m_off;

public:
    explicit MessageVerificationException(const id_type& id, offset_type off) : m_off(off)
    {
        memcpy(m_id.data(), id.data(), id.size());
    }

    std::string message() const override
    {
        return strprintf("Message for ID %s at offset %lld does not match the checksum",
                         hexify(m_id.data(), m_id.size()).c_str(),
                         (long long)m_off);
    }
};

// xattr验证异常，继承ExceptionBase
class XattrVerificationException : public VerificationException
{
private:
    id_type m_id;
    std::string m_name;

public:
    explicit XattrVerificationException(const id_type& id, std::string name)
    {
        memcpy(m_id.data(), id.data(), id.size());
        m_name.swap(name);
    }

    std::string message() const override
    {
        return strprintf("Extended attribute for ID %s and name \"%s\" has wrong checksum",
                         hexify(m_id.data(), m_id.size()).c_str(),
                         m_name.c_str());
    }
};

// lite消息验证异常，继承ExceptionBase
class LiteMessageVerificationException : public VerificationException
{
public:
    std::string message() const override { return "File content has invalid checksum"; }
};

// 流太长异常，继承ExceptionBase
class StreamTooLongException : public ExceptionBase
{
private:
    int64_t m_max_size;
    int64_t m_size;

public:
    explicit StreamTooLongException(int64_t max_size, int64_t size)
        : m_max_size(max_size), m_size(size)
    {
    }

    std::string message() const override
    {
        return strprintf("Operation on stream at point %lld, which exceeds its maximum size %lld",
                         (long long)m_size,
                         (long long)m_max_size);
    }
    int error_number() const noexcept override { return EFBIG; }
};

// 非法转换异常，继承ExceptionBase
class InvalidCastException final : public ExceptionBase
{
private:
    const char* from_name;
    const char* to_name;

public:
    explicit InvalidCastException(const char* from_name, const char* to_name)
        : from_name(from_name), to_name(to_name)
    {
    }

    std::string message() const override
    {
        return strprintf("Invalid cast from %s to %s", from_name, to_name);
    }
};

// 文件类型不一致异常异常，继承ExceptionBase
class FileTypeInconsistencyException : public ExceptionBase
{
public:
    std::string message() const override
    {
        return "A file object has inconsistent type. This indicates that a bug or corruption in "
               "the filesystem has happened.";
    }
};

// noreturn的一些抛出异常函数
[[noreturn]] void throwFileTypeInconsistencyException();

[[noreturn]] void throw_runtime_error(const char*);
[[noreturn]] void throw_runtime_error(const std::string&);

std::unique_ptr<const char, void (*)(const char*)> get_type_name(const std::exception& e) noexcept;
}    // namespace securefs
