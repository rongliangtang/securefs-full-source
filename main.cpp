#include "commands.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"
#include <clocale>

#ifdef WIN32
// 如果是windows时(包括64位)
// wmain是unicode字符集环境下的console入口函数,
// 如果要编写符合 Unicode 编程模型的可移植代码，请使用 wmain 而不是 main。
// 因为在Windows中，内部是以utf-16来保存字符串的，windows中的底层api都是基于unicode实现，即utf-16。
// https://zhuanlan.zhihu.com/p/56306408
// 可以看到与main不同的是，传入参数的类型为wchar_t，占两个字节，即使utf-16的unicode。
int wmain(int argc, wchar_t** wargv)
{
    // windows环境下的一些初始化操作（设置控制台编码方式、缓冲区和获取时间函数等）
    ::securefs::windows_init();

    // 创建std::string类型的unique_ptr数组，用于存放函数参数列表
    auto str_argv = securefs::make_unique_array<std::string>(argc);
    // 将参数列表中的每个元素从将宽字符数组转换为窄字符数组
    for (int i = 0; i < argc; ++i)
        // 将宽字符数组转换为窄字符数组
        str_argv[i] = securefs::narrow_string(wargv[i]);
    // 创建char*类型的unique_ptr数组，用于存放函数参数列表
    // 多创建一个，最后一个置空指针，这里实际上没什么用
    auto argv = securefs::make_unique_array<const char*>(argc + 1);
    for (int i = 0; i < argc; ++i)
        argv[i] = str_argv[i].c_str();
    argv[argc] = nullptr;

    return securefs::commands_main(argc, argv.get());
}

#else
// 不是windows系统时
int main(int argc, char** argv) {

    return securefs::commands_main(argc, argv);
}
#endif
