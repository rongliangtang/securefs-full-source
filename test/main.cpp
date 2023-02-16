#define CATCH_CONFIG_RUNNER 1
#include "catch.hpp"
#include "platform.h"

int main(int argc, char** argv)
{
#ifdef WIN32
    // 初始化win下的环境，才能正常运行程序
    securefs::windows_init();
#endif
    // 创建tmp文件夹
    securefs::OSService::get_default().ensure_directory("tmp", 0755);
    // 自己提供main函数给catch（作用是？？）
    Catch::Session s;
    return s.run(argc, argv);
}
