#include "commands.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"
#include <clocale>

#ifdef WIN32
// 如果是windows时(包括64位)

int wmain(int argc, wchar_t** wargv)
{
    ::securefs::windows_init();
    auto str_argv = securefs::make_unique_array<std::string>(argc);
    for (int i = 0; i < argc; ++i)
        str_argv[i] = securefs::narrow_string(wargv[i]);
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
