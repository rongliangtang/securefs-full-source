#include "exceptions.h"
#include "logger.h"
#include "platform.h"

// ExceptionBase类的构造和析构都用默认
securefs::ExceptionBase::ExceptionBase() = default;

securefs::ExceptionBase::~ExceptionBase() = default;

// 抛出VFSException
void ::securefs::throwVFSException(int errc) { throw VFSException(errc); }

// 抛出InvalidArgumentException
void ::securefs::throwInvalidArgumentException(const char* why)
{
    throw InvalidArgumentException(why);
}

// 抛出InvalidArgumentException
void ::securefs::throwInvalidArgumentException(std::string why)
{
    throw InvalidArgumentException(std::move(why));
}

securefs::VFSException::~VFSException() = default;

securefs::POSIXException::~POSIXException() = default;

securefs::InvalidArgumentException::~InvalidArgumentException() = default;

// [[noreturn]]关键字只对其作用的函数或类有效
[[noreturn]] void securefs::throwFileTypeInconsistencyException()
{
    throw ::securefs::FileTypeInconsistencyException();
}

[[noreturn]] void securefs::throwPOSIXExceptionDoNotUseDirectly(int err, std::string msg)
{
    throw POSIXException(err, std::move(msg));
}

[[noreturn]] void securefs::throw_runtime_error(const char* msg) { throw std::runtime_error(msg); }

[[noreturn]] void securefs::throw_runtime_error(const std::string& msg)
{
    throw std::runtime_error(msg);
}

std::string securefs::VFSException::message() const
{
    return securefs::OSService::stringify_system_error(m_errno);
}

std::string securefs::POSIXException::message() const
{
    return strprintf(
        "%s (%s)", securefs::OSService::stringify_system_error(m_errno).c_str(), m_msg.c_str());
}

const char* ::securefs::ExceptionBase::what() const noexcept
{
    if (m_cached_msg.empty())
    {
        try
        {
            message().swap(m_cached_msg);
        }
        catch (...)
        {
            return "An exception occurred while formatting exception message";
        }
    }
    return m_cached_msg.c_str();
}
