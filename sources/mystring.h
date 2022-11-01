#pragma once

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stddef.h>
#include <string>
#include <vector>

typedef unsigned char byte;

namespace securefs
{
// 一个模版类，类名是BasicStringRef
// 作用是实现一个类似 T* 的数组，但是具备string那样所有功能的类，这样相比于string更具有灵活性（利用std::basic_string<CharT>实现）
// 编写这个类的目的是什么？？？std::basic_string<CharT>都有这些功能
template <class CharT>
class BasicStringRef
{
private:
    const CharT* m_buffer;
    size_t m_size;

public:
    BasicStringRef() : m_buffer(nullptr), m_size(0) {}
    BasicStringRef(const CharT* str) : m_buffer(str), m_size(std::char_traits<CharT>::length(str))
    {
    }
    // 通过这个构造函数，有隐式转换std::basic_string<CharT>到BasicStringRef<CharT>
    BasicStringRef(const std::basic_string<CharT>& str) : m_buffer(str.c_str()), m_size(str.size())
    {
    }
    const CharT* data() const noexcept { return m_buffer; }
    const CharT* c_str() const noexcept { return m_buffer; }
    size_t size() const noexcept { return m_size; }
    size_t length() const noexcept { return m_size; }
    CharT operator[](size_t i) const noexcept { return m_buffer[i]; }
    const CharT* begin() const noexcept { return data(); }
    const CharT* end() const noexcept { return data() + size(); }
    CharT front() const noexcept { return m_buffer[0]; }
    CharT back() const noexcept { return m_buffer[m_size - 1]; }
    bool empty() const noexcept { return size() == 0; }
    std::basic_string<CharT> to_string() const
    {
        return std::basic_string<CharT>(m_buffer, m_size);
    }
    bool starts_with(BasicStringRef<CharT> prefix) const noexcept
    {
        return size() >= prefix.size()
            && std::char_traits<CharT>::compare(data(), prefix.data(), prefix.size()) == 0;
    }
    bool ends_with(BasicStringRef<CharT> suffix) const noexcept
    {
        return size() >= suffix.size()
            && std::char_traits<CharT>::compare(
                   data() + size() - suffix.size(), suffix.data(), suffix.size())
            == 0;
    }
    std::basic_string<CharT> substr(size_t start, size_t count) const
    {
        return std::basic_string<CharT>(data() + start, std::min(size() - start, count));
    }
};

// 重载BasicStringRef类的符号操作，最后返回的都是std::basic_string<CharT>类型的数据
template <class CharT>
inline std::basic_string<CharT> operator+(BasicStringRef<CharT> a, BasicStringRef<CharT> b)
{
    std::basic_string<CharT> result;
    result.reserve(a.size() + b.size());
    result.insert(0, a.data(), a.size());
    result.insert(a.size(), b.data(), b.size());
    return result;
}

template <class CharT>
inline std::basic_string<CharT> operator+(const CharT* a, BasicStringRef<CharT> b)
{
    return BasicStringRef<CharT>(a) + b;
}

template <class CharT>
inline std::basic_string<CharT> operator+(BasicStringRef<CharT> a, const CharT* b)
{
    return a + BasicStringRef<CharT>(b);
}

template <class CharT>
inline std::basic_string<CharT> operator+(const std::basic_string<CharT>& a,
                                          BasicStringRef<CharT> b)
{
    return BasicStringRef<CharT>(a) + b;
}

template <class CharT>
inline std::basic_string<CharT> operator+(BasicStringRef<CharT> a,
                                          const std::basic_string<CharT>& b)
{
    return a + BasicStringRef<CharT>(b);
}

template <class CharT>
bool operator==(BasicStringRef<CharT> a, BasicStringRef<CharT> b)
{
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

template <class CharT>
bool operator!=(BasicStringRef<CharT> a, BasicStringRef<CharT> b)
{
    return !(a == b);
}

template <class CharT>
bool operator==(BasicStringRef<CharT> a, const char* b)
{
    return a == BasicStringRef<CharT>(b);
}

template <class CharT>
bool operator!=(BasicStringRef<CharT> a, const char* b)
{
    return a != BasicStringRef<CharT>(b);
}

typedef BasicStringRef<char> StringRef;
typedef BasicStringRef<wchar_t> WideStringRef;

std::string strprintf(const char* format, ...)
#ifndef _MSC_VER
    __attribute__((format(printf, 1, 2)))
#endif
    ;
std::string vstrprintf(const char* format, va_list args);

std::vector<std::string> split(StringRef str, char separator);

std::string hexify(const byte* data, size_t length);
void parse_hex(StringRef hex, byte* output, size_t len);

template <class ByteContainer>
inline std::string hexify(const ByteContainer& c)
{
    return hexify(c.data(), c.size());
}

void base32_encode(const byte* input, size_t size, std::string& output);
void base32_decode(const char* input, size_t size, std::string& output);

std::string escape_nonprintable(const char* str, size_t size);
std::string case_fold(StringRef str);

// ManagedCharPointer为char型的unique_ptr
// void (*)(const char*)表示删除器函数指针类型
using ManagedCharPointer = std::unique_ptr<const char, void (*)(const char*)>;
// transform函数返回一个类型
ManagedCharPointer transform(StringRef str, bool case_fold, bool nfc);

bool is_ascii(StringRef str);
}    // namespace securefs
