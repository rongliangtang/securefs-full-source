#pragma once
#ifdef _WIN32
#include <Windows.h>

namespace securefs
{
// 保存当前的编译器警告状态
#pragma warning(push)
// 消除4191警告
#pragma warning(disable : 4191)
// 模板函数
// 在HMODULE句柄 dll中获取name的函数地址指针
template <class FuncPointer>
inline FuncPointer get_proc_address(HMODULE h, const char* name) noexcept
{
    // 将地址转换为模板指定的类型
    return reinterpret_cast<FuncPointer>(::GetProcAddress(h, name));
}
// 恢复原先的警告状态
#pragma warning(pop)

}    // namespace securefs
#endif
