#include "apple_xattr_workaround.h"

#ifdef __APPLE__

#include <errno.h>
#include <string.h>
#include <sys/xattr.h>

namespace securefs
{
// 当设置标签后，会打上com.apple.FinderInfo标志
// 注释什么的，打的是其他的标志
static const char APPLE_FINDER_INFO[] = "com.apple.FinderInfo";
// securefs设置xattr会将挂载点文件的"com.apple.FinderInfo"标志，在加密文件中换为"_securefs.FinderInfo"
static const char REPLACEMENT_FOR_FINDER_INFO[] = "_securefs.FinderInfo";
// 苹果系统有一个GateKeeper保护机制（自 OSX 10.5 加入）。从互联网上下载来的文件，会被自动打上com.apple.quarantine标志，翻译过来就是免疫隔离，系统根据这个附加属性对这个文件作出限制。
static const char APPLE_QUARANTINE[] = "com.apple.quarantine";

static_assert(sizeof(APPLE_FINDER_INFO) == sizeof(REPLACEMENT_FOR_FINDER_INFO),
              "The two \"FinderInfo\" attribute names must have the same size");

// 利用listxattr()系统调用后获得的扩展属性名称列表中的所有名称中的_securefs.FinderInfo替换成com.apple.FinderInfo
void transform_listxattr_result(char* buffer, size_t size)
{
    if (size < sizeof(APPLE_FINDER_INFO))
        return;

    for (size_t i = 0; i <= size - sizeof(APPLE_FINDER_INFO); ++i)
    {
        if (i > 0 && buffer[i - 1] != '\0')
        {
            continue;    // Not a string boundary.
        }
        // The terminating null must be compared too.
        if (memcmp(buffer + i, REPLACEMENT_FOR_FINDER_INFO, sizeof(REPLACEMENT_FOR_FINDER_INFO))
            == 0)
        {
            memcpy(buffer + i, APPLE_FINDER_INFO, sizeof(APPLE_FINDER_INFO));
        }
    }
}

// 通用预检查，用于getxattr和removexattr
// 检查是否已经由_securefs.FinderInfo替换成com.apple.FinderInfo
static int precheck_common(const char** name)
{
    // 如果*name == "com.apple.FinderInfo"，则返回1
    if (strcmp(*name, APPLE_FINDER_INFO) == 0)
    {
        *name = REPLACEMENT_FOR_FINDER_INFO;
        return 1;    // No early return.
    }
    // 如果*name == "_securefs.FinderInfo"，则返回Operation not permitted
    if (strcmp(*name, REPLACEMENT_FOR_FINDER_INFO) == 0)
    {
        return -EPERM;
    }
    // 其他情况返回1
    return 1;
}

// 预检查，用于getxattr
// 检查是否有com.apple.quarantine标志
// 检查是否已经由_securefs.FinderInfo替换成com.apple.FinderInfo
int precheck_getxattr(const char** name)
{
    // 如果*name == "com.apple.quarantine"，则返回Attribute not found
    if (strcmp(*name, APPLE_QUARANTINE) == 0)
    {
        return -ENOATTR;
    }
    // 通用检查
    return precheck_common(name);
}

// 预检查，用于setxattr
// 将com.apple.FinderInfo替换成_securefs.FinderInfo
int precheck_setxattr(const char** name, int* flags)
{
    // 如果*name == "com.apple.quarantine"，则返回0
    // 即不对该标志进行set写入
    // 伪造成功以绕过macOS上的“XXX已损坏”bug
    if (strcmp(*name, APPLE_QUARANTINE) == 0)
    {
        return 0;    // Fakes success of quarantine to work around "XXX is damaged" bug on macOS.
    }
    // 如果*name == "com.apple.FinderInfo"，将其替换为"_securefs.FinderInfo"并返回1
    if (strcmp(*name, APPLE_FINDER_INFO) == 0)
    {
        *name = REPLACEMENT_FOR_FINDER_INFO;
        *flags &= ~(unsigned)XATTR_NOSECURITY;
        return 1;    // No early return.
    }
    // 如果*name == "_securefs.FinderInfo"，则返回Operation not permitted
    if (strcmp(*name, REPLACEMENT_FOR_FINDER_INFO) == 0)
    {
        return -EPERM;
    }
    // 其他情况返回1
    return 1;
}

// 预检查，用于removexattr
// 检查是否已经由_securefs.FinderInfo替换成com.apple.FinderInfo
int precheck_removexattr(const char** name) { return precheck_common(name); }
}    // namespace securefs

#endif
