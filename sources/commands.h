#pragma once

#include "myutils.h"
#include "platform.h"

#include <cryptopp/secblock.h>
#include <string>

namespace securefs
{
int commands_main(int argc, const char* const* argv);

// 配置文件的结构体
struct FSConfig
{
    CryptoPP::AlignedSecByteBlock master_key;
    unsigned block_size;
    unsigned iv_size;
    unsigned version;
    unsigned max_padding = 0;
};

// 命令操作基类：用来实现命令操作的抽象类
class CommandBase
{
    // 禁止拷贝复制
    DISABLE_COPY_MOVE(CommandBase)

protected:
    // 创建返回shared_ptr指针的open_config_stream()函数，这里只声明了函数
    // shared_ptr指针能够记录多少个shared_ptr共同指向一个对象，从而消除显示的调用 delete，当引用计数变为零的时候就会将对象自动删除。
    // 一个静态成员函数只能访问它的参数、类的静态数据成员和全局变量
    static std::shared_ptr<FileStream> open_config_stream(const std::string& full_path, int flags);
    // 根据配置文件和password（或keyfile）来获得master_key等解密数据的key
    static FSConfig
    read_config(FileStream*, const void* password, size_t pass_len, StringRef maybe_key_file_path);
    // 写配置函数
    static void write_config(FileStream*,
                             StringRef maybe_key_file_path,
                             const std::string& pbdkf_algorithm,
                             const FSConfig&,
                             const void* password,
                             size_t pass_len,
                             unsigned rounds);

public:
    CommandBase() = default;
    // 纯虚析构，该类属于抽象类，无法实例化对象
    virtual ~CommandBase() = default;

    // 纯虚函数，子类必须要实现这个函数，否则也是抽象类
    virtual const char* long_name() const noexcept = 0;
    virtual char short_name() const noexcept = 0;
    virtual const char* help_message() const noexcept = 0;

    virtual void parse_cmdline(int argc, const char* const* argv) = 0;
    virtual int execute() = 0;
};
}    // namespace securefs
