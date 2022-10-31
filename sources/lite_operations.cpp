#include "lite_operations.h"
#include "apple_xattr_workaround.h"
#include "fuse_tracer.h"
#include "lite_fs.h"
#include "lite_stream.h"
#include "lock_guard.h"
#include "logger.h"
#include "myutils.h"
#include "operations.h"
#include "platform.h"

namespace securefs
{
namespace lite
{
    namespace
    {
        // BundledContext这个结构体里面放了MountOptions类的指针opt
        struct BundledContext
        {
            ::securefs::operations::MountOptions* opt;
        };

        // 返回一个FileSystem类指针对象
        FileSystem* get_local_filesystem()
        {
            // thread_local是c++11为线程安全引进的变量声明符，thread_local就是达到线程内独有的全局变量
            // thread_local修饰过的变量，变量的生存周期不再以程序为准，而是以线程生命周期，thread_local声明的变量存储在线程开始时分配，线程结束时销毁。
            // 在类的成员函数内定义了 thread_local 变量，则对于同一个线程内的该类的多个对象都会共享一个变量实例，并且只会在第一次执行这个成员函数时初始化这个变量实例
            // 当使用thread_local描述类成员变量时，必须是static的。传统的static类成员变量是所有对象共享，而static thread_local修饰的时候会变成在线程内共享，线程间不是共享的（对象可能来自同一线程，可能来自多个线程）
            // 具体还不是特别理解需要多学习c++线程方面的知识？？
            static thread_local optional<FileSystem> opt_fs;

            // local_opt_fs为opt_fs的引用，opt_fs为FileSystem类型的optional对象
            auto& local_opt_fs = opt_fs;
            // 在同一个线程中，若已经有local_opt_fs对象并实例化后则直接返回
            if (local_opt_fs)
                return &(*local_opt_fs);
            // fuse_context->private_data在init的时候将原来的private_data存在BundledContext*中了
            // 这里再进行一下强制转换，防止类型出现问题
            auto ctx = static_cast<BundledContext*>(fuse_get_context()->private_data);

            // 如果version不是4的话，报错（因为这个文件中的方法都是针对lite版本写得）
            if (ctx->opt->version.value() != 4)
                throwInvalidArgumentException("This function only supports filesystem format 4");

            // 获得master_key
            const auto& master_key = ctx->opt->master_key;
            // typedef PODArray<byte, KEY_LENGTH> key_type;
            key_type name_key, content_key, xattr_key, padding_key;
            // KEY_LENGTH = 32
            // 若master_key的size不是KEY_LENGTH三倍或四倍，则报错
            if (master_key.size() != 3 * KEY_LENGTH && master_key.size() != 4 * KEY_LENGTH)
                throwInvalidArgumentException("Master key has wrong length");

            // 将masterkey的0～KEY_LENGTH字节部分的数据拷贝到name_key中
            memcpy(name_key.data(), master_key.data(), KEY_LENGTH);
            // 将masterkey的KEY_LENGTH～2*KEY_LENGTH字节部分的数据拷贝到content_key中
            memcpy(content_key.data(), master_key.data() + KEY_LENGTH, KEY_LENGTH);
            // 将masterkey的2*KEY_LENGTH～3*KEY_LENGTH字节部分的数据拷贝到xattr_key中
            memcpy(xattr_key.data(), master_key.data() + 2 * KEY_LENGTH, KEY_LENGTH);

            // 判断key的随机性够不够
            warn_if_key_not_random(name_key, __FILE__, __LINE__);
            warn_if_key_not_random(content_key, __FILE__, __LINE__);
            warn_if_key_not_random(xattr_key, __FILE__, __LINE__);
            
            // max_padding_size在create的时候未设置数值则为0
            // 若master_key的size >= 4*KEY_LENGTH
            if (master_key.size() >= 4 * KEY_LENGTH)
            {
                // 则将masterkey的3*KEY_LENGTH～4*KEY_LENGTH字节部分的数据拷贝到padding_key中
                memcpy(padding_key.data(), master_key.data() + 3 * KEY_LENGTH, KEY_LENGTH);
            }
            // 若ctx->opt->max_padding_size > 0
            if (ctx->opt->max_padding_size > 0)
            {
                // 则判断padding_key的随机性够不够
                warn_if_key_not_random(padding_key, __FILE__, __LINE__);
            }

            // 输出与key信息有关的TRACE_LOG
            TRACE_LOG("\nname_key: %s\ncontent_key: %s\nxattr_key: %s\npadding_key: %s",
                      hexify(name_key).c_str(),
                      hexify(content_key).c_str(),
                      hexify(xattr_key).c_str(),
                      hexify(padding_key).c_str());

            // 执行FileSystem的构造函数
            local_opt_fs.emplace(ctx->opt->root,
                                 name_key,
                                 content_key,
                                 xattr_key,
                                 padding_key,
                                 ctx->opt->block_size.value(),
                                 ctx->opt->iv_size.value(),
                                 ctx->opt->max_padding_size,
                                 ctx->opt->flags.value());
            // &(*local_opt_fs)是什么鬼？？？
            return &(*local_opt_fs);
        }

        // 设置文件句柄（目录也是文件）
        // fuse_file_info结构体表示打开文件的信息
        // 传入的Base一般为其子类File或者Directory及其子类，然后再将其转为整数存在info->fh中
        // 后面我们再把infor->fh转回对象指针
        void set_file_handle(struct fuse_file_info* info, securefs::lite::Base* base)
        {
            // fh是文件句柄
            // 将base类转为uint64_t整数的文件句柄
            info->fh = reinterpret_cast<uintptr_t>(base);
        }

        // 获得文件句柄，转换成Base类指针并返回
        Base* get_base_handle(const struct fuse_file_info* info)
        {
            if (!info->fh)
            {
                throwVFSException(EFAULT);
            }
            // 将文件句柄整数转换为Base类指针
            return reinterpret_cast<Base*>(static_cast<uintptr_t>(info->fh));
        }

        // 获得文件句柄，返回File类指针
        File* get_handle_as_file_checked(const struct fuse_file_info* info)
        {
            // 将 Base指针 转为 File 指针
            // 这个函数中的info->fh原来就是用多态Base的File指针转的
            auto fp = get_base_handle(info)->as_file();
            if (!fp)
            {
                throwVFSException(EISDIR);
            }
            return fp;
        }

        // 获得文件句柄，返回Directory类指针
        Directory* get_handle_as_dir_checked(const struct fuse_file_info* info)
        {
            // 将 Base指针 转为 Directory 指针
            // 这个函数中的info->fh原来就是用多态Base的Directory指针转的
            auto fp = get_base_handle(info)->as_dir();
            if (!fp)
            {
                throwVFSException(ENOTDIR);
            }
            return fp;
        }

    }    // namespace
    
    // 初始化文件系统：返回的ctx中的opt是一个MountOptions对象，存放了要用的master_key等关键信息
    void* init(struct fuse_conn_info* fsinfo)
    {
        (void)fsinfo;
#ifdef FSP_FUSE_CAP_READDIR_PLUS
        fsinfo->want |= (fsinfo->capable & FSP_FUSE_CAP_READDIR_PLUS);
#endif
        // private_data实际是fuse_main()中传入的opt，在mount命令的时候就读取好了，已经赋好值了的，存放了master_key等关键信息
        void* args = fuse_get_context()->private_data;
        INFO_LOG("init");
        // 将fuse_get_context()->private_data转为MountOptions*，即BundledContext
        auto ctx = new BundledContext;
        ctx->opt = static_cast<operations::MountOptions*>(args);
        return ctx;
    }

    // 清除文件系统：释放指针
    void destroy(void*)
    {
        // 将fuse_get_context()->private_data转为BundledContext*，防止类型不对，并释放该指针
        delete static_cast<BundledContext*>(fuse_get_context()->private_data);
        INFO_LOG("destroy");
    }

    // 获得文件系统的属性：通过执行FileSystem对象中的statvfs()函数来实现
    int statfs(const char* path, struct fuse_statvfs* buf)
    {
        // C++中的匿名函数，类似于python的lambda函数，也就是在句中定义和声明的一个临时函数，仅在调用时才会创建函数对象，无需在头文件中声明。
        // [=]表示以值的形式捕获所有外部变量
        auto func = [=]()
        {
            if (!buf)
                return -EFAULT;
            auto filesystem = get_local_filesystem();
            filesystem->statvfs(buf);
            // Due to the Base32 encoding and the extra 16 bytes of synthesized IV
            // 因为name的Base32编码和额外16byte的IV，所以buf->f_namemax需要这样设置
            // 143
            buf->f_namemax = buf->f_namemax * 5 / 8 - 16;
            return 0;
        };
        // FuseTracer类的作用是？？猜测是跟踪函数调用，输出日志？？
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {buf}});
    }

    // 获得加密文件的属性：通过执行FileSystem对象中的stat()来实现
    // 输入的path是明文路径，将path对应的加密文件的属性存到st中
    int getattr(const char* path, struct fuse_stat* st)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            // 将密文文件的stat读出来，然后改其中的st_size为实际明文大小，这样挂载点显示才正确
            if (!filesystem->stat(path, st))
                return -ENOENT;

            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {st}});
    }

    // 获得打开的文件的属性
    int fgetattr(const char* path, struct fuse_stat* st, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto base = get_base_handle(info);
            auto file = base->as_file();
            // 判断是文件还是目录
            if (file)
            {
                LockGuard<File> lock_guard(*file, false);
                // 如果是文件，则调用File类的fstat()函数
                file->fstat(st);
                return 0;
            }
            auto dir = base->as_dir();
            if (dir)
            {
                auto filesystem = get_local_filesystem();
                // 如果是目录，则调用FileSystem类的stat()函数
                if (!filesystem->stat(dir->path(), st))
                    return -ENOENT;
                return 0;
            }
            throwInvalidArgumentException("Neither file nor dir");
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {st}, {info}});
    }

    // 打开一个目录，调用FileSystem类的opendir()函数
    // path为明文路径
    int opendir(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            // filesystem->opendir(path)返回LiteDirectory类型的对象unique_str
            auto traverser = filesystem->opendir(path);
            // 调用release会切断unique_ptr和它原来管理的对象的联系,并返回对象的指针
            set_file_handle(info, traverser.release());
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 释放一个目录，通过释放指针实现
    int releasedir(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            delete get_base_handle(info);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 读取目录
    // buff存放目录entry
    int readdir(const char* path,
                void* buf,
                fuse_fill_dir_t filler,
                fuse_off_t off,
                struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fs = get_local_filesystem();
            auto traverser = get_handle_as_dir_checked(info);
            if (!traverser)
                return -EFAULT;
            // rewind需要上锁，这里通过lock_guard的构造和析构来上锁解锁
            LockGuard<Directory> lock_guard(*traverser);
            // traverser从文件描述符转换过来，实际是Base类多态的LiteDirectory
            traverser->rewind();
            // name用来获取明文路径
            std::string name;
            // fuse_stat结构体（stat在目录中实际是没用的，因为目录不显示大小，文件才显示大小，而需要读取文件属性的时候是会调用stat系统调用，与readdir这里无法）
            // https://www.cnblogs.com/yaowen/p/4801541.html
            struct fuse_stat stbuf;
            memset(&stbuf, 0, sizeof(stbuf));

            // 调用LiteDirectory->next
            while (traverser->next(&name, &stbuf))
            {
// 如果不是windows系统，即为unix，会包含"."和".."，跳过就行
#ifndef _WIN32
                if (name == "." || name == "..")
                {
                    continue;
                }
#endif
                int rc =
                    // When random padding is enabled, we cannot obtain accurate size information
                    // 当开启了random padding功能，不能获取准确的信息，则不传入stat
                    // filler()的作用是在readdir()返回的buf中中添加一个条目
                    fs->has_padding() && (stbuf.st_mode & S_IFMT) == S_IFREG
                    ? filler(buf, name.c_str(), nullptr, 0)
                    // 如果是文件，则&stbuf文件属性要传入
                    : filler(buf, name.c_str(), &stbuf, 0);
                if (rc != 0)
                    return -abs(rc);
            }
            return 0;
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {buf}, {(const void*)filler}, {&off}, {info}});
    }

    // 创建一个文件，利用FileSystem对象中的open()函数实现
    int create(const char* path, fuse_mode_t mode, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            AutoClosedFile file = filesystem->open(path, O_RDWR | O_CREAT | O_EXCL, mode);
            set_file_handle(info, file.release());
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}, {info}});
    }

    // 打开一个文件，通过调用FileSystem对象的open()实现
    // 将对象转为句柄存在info中，后面的操作通过info中的句柄来取得对象
    // fuse_file_info是每个open挂载点文件都会有的一个结构体
    // 通过读取对应的底层文件来创建一个File对象，然后将该对象设置为info中的句柄，这样read等方法可以直接通过info句柄来找到对象，不需要每次执行重新去创建对象，这样执行效率更高！
    int open(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 每次执行fuse api，都要先执行get_local_filesystem()来获得FileSystem对象，里面存放了key和配置信息等
            // 后面的操作要用到该对象
            // 似乎用了优化，线程里面创建过这个对象就不会再创建？？线程这边要好好看看，很有作用！！
            auto filesystem = get_local_filesystem();
            // file为File类，里面存放了UnixFileStream(加密文件的句柄)、key等
            AutoClosedFile file = filesystem->open(path, info->flags, 0644);
            // 将打开文件获得的对象转为句柄存在info中，后面的操作再通过info中的句柄来取得对象，很nice的操作！
            set_file_handle(info, file.release());
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 释放打开的文件，通过释放指针实现
    int release(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            delete get_base_handle(info);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 从打开的文件中读取size大小的数据，通过File对象的read()实现，数据存到buf中
    // 注意read()实现的函数调用关系，这里有点复杂
    // path是明文路径，在这里实际没有用到，是通过open后获得的UnixFileStream对象中的fd来访问密文
    int
    read(const char* path, char* buf, size_t size, fuse_off_t offset, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 获得File对象（info->fh转Base*转File*）
            // 之前在open()中获得对象后，再转为文件句柄存在info中，这里将句柄再转回对象
            // 注意fp这个File对象指针里面存放很多有效信息！
            auto fp = get_handle_as_file_checked(info);
            // 进行线程保护，通过锁实现，读的时候不能进行写，阻塞写，防止出错
            // 会利用flock库函数对文件上共享锁，多个线程可以同时读（这里说的多个线程可以是同一进程中，也可以是不同进程中，因为os调度的单位是线程，进行只是系统资源分配单位）
            LockGuard<File> lock_guard(*fp, false);
            // 返回读取到的字节数
            return static_cast<int>(fp->read(buf, offset, size));
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {(const void*)buf}, {&size}, {&offset}, {info}});
    }

    // 写数据到打开的文件中，通过File对象的write()实现，将buf中size大的数据写入
    // 注意write()实现的函数调用关系，这里有点复杂
    // path是明文路径，在这里实际没有用到，是通过open后获得的UnixFileStream对象中的fd来访问密文
    int write(const char* path,
              const char* buf,
              size_t size,
              fuse_off_t offset,
              struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 获得File对象指针
            auto fp = get_handle_as_file_checked(info);
            // 进行线程保护，通过锁实现（创建的时候上锁，析构的时候解锁，满足下面write函数执行的要求，退出这个匿名函数的时候会执行析构）
            // 会利用flock库函数对文件上独占锁，只能有一个线程在写
            LockGuard<File> lock_guard(*fp, true);
            // 进行写操作（执行该函数是要上锁解锁的，Required()）
            fp->write(buf, offset, size);
            // 返回写的大小
            return static_cast<int>(size);
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {(const void*)buf}, {&size}, {&offset}, {info}});
    }

    // 可能刷新缓存数据，通过调用File对象中的flush()实现
    // 作用不太理解
    // lite版本中没有实现这个功能
    int flush(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fp = get_handle_as_file_checked(info);
            LockGuard<File> lock_guard(*fp, true);
            fp->flush();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 改变（截断）打开文件的大小为len，通过调用File对象中的resize()实现
    int ftruncate(const char* path, fuse_off_t len, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fp = get_handle_as_file_checked(info);
            LockGuard<File> lock_guard(*fp, true);
            fp->resize(len);\
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&len}, {info}});
    }

    // 删除一个文件，通过调用FileSystem对象的unlink()实现
    // path为明文路径
    int unlink(const char* path)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->unlink(path);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}});
    }

    // 创建一个目录，通过调用FileSystem对象的mkdir()实现
    int mkdir(const char* path, fuse_mode_t mode)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->mkdir(path, mode);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}});
    }

    // 删除一个目录，通过调用FileSystem对象的rmdir()实现
    int rmdir(const char* path)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->rmdir(path);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}});
    }

    /* UNIX系统下特有 */
    // 改变文件的权限位，通过调用FileSystem对象的chmod()实现
    int chmod(const char* path, fuse_mode_t mode)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->chmod(path, mode);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}});
    }

    /* UNIX系统下特有 */
    // 改变文件的owner和group，通过调用FileSystem对象的chown()实现
    int chown(const char* path, fuse_uid_t uid, fuse_gid_t gid)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->chown(path, uid, gid);
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&uid}, {&gid}});
    }

    /* UNIX系统下特有 */
    // 创建一个符号链接，通过调用FileSystem对象的symlink()实现
    int symlink(const char* to, const char* from)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->symlink(to, from);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{to}, {from}});
    }

    /* UNIX系统下特有 */
    // 创建一个硬链接，通过调用FileSystem对象的link()实现
    int link(const char* src, const char* dest)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->link(src, dest);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{src}, {dest}});
    }

    /* UNIX系统下特有 */
    // 读取符号链接的目标，通过调用FileSystem对象的readlink()实现
    int readlink(const char* path, char* buf, size_t size)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            (void)filesystem->readlink(path, buf, size);
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {(const void*)buf}, {&size}});
    }

    // 将一个文件重命名，通过调用FileSystem对象的rename()实现
    int rename(const char* from, const char* to)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->rename(from, to);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{from}, {to}});
    }

    // 将修改后的数据和文件描述符的属性持久化到存储设备中，通过File类的fsync()实现
    // 若datasync非0，则只同步文件内容，而不同步元数据
    int fsync(const char* path, int datasync, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto fp = get_handle_as_file_checked(info);
            LockGuard<File> lock_guard(*fp, true);
            fp->fsync();
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&datasync}, {info}});
    }

    // 改变文件的大小（截断），通过FileSystem类的open()和resize()实现
    int truncate(const char* path, fuse_off_t len)
    {
        auto func = [=]()
        {
            if (len < 0)
                return -EINVAL;
            auto filesystem = get_local_filesystem();

            AutoClosedFile fp = filesystem->open(path, O_RDWR, 0644);
            LockGuard<File> lock_guard(*fp, true);
            fp->resize(static_cast<size_t>(len));
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&len}});
    }

    // 改变文件的访问和修改时间（纳秒级），通过FileSystem类的utimens()实现
    int utimens(const char* path, const struct fuse_timespec ts[2])
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            filesystem->utimens(path, ts);
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {ts}, {ts ? ts + 1 : ts}});
    }

// apple设备才实现的fuse api
#ifdef __APPLE__
    int listxattr(const char* path, char* list, size_t size)
    {
        auto func = [=]()
        {
            auto filesystem = get_local_filesystem();
            int rc = static_cast<int>(filesystem->listxattr(path, list, size));
            transform_listxattr_result(list, size);
            return rc;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {(const void*)list}, {&size}});
    }

    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position)
    {
        auto func = [&]()
        {
            if (position != 0)
                return -EINVAL;
            int rc = precheck_getxattr(&name);
            if (rc <= 0)
                return rc;

            auto filesystem = get_local_filesystem();
            rc = static_cast<int>(filesystem->getxattr(path, name, value, size));
            return rc;
        };
        return FuseTracer::traced_call(
            func,
            FULL_FUNCTION_NAME,
            __LINE__,
            {{path}, {name}, {(const void*)value}, {&size}, {&position}});
    }

    int setxattr(const char* path,
                 const char* name,
                 const char* value,
                 size_t size,
                 int flags,
                 uint32_t position)
    {
        auto func = [&]()
        {
            if (position != 0)
                return -EINVAL;
            int rc = precheck_setxattr(&name, &flags);
            if (rc <= 0)
                return rc;
            if (!value || size == 0)
                return 0;

            auto filesystem = get_local_filesystem();
            rc = filesystem->setxattr(path, name, const_cast<char*>(value), size, flags);
            return rc;
        };
        return FuseTracer::traced_call(
            func,
            FULL_FUNCTION_NAME,
            __LINE__,
            {{path}, {name}, {(const void*)value}, {&size}, {&flags}, {&position}});
    }
    int removexattr(const char* path, const char* name)
    {
        auto func = [&]()
        {
            int rc = precheck_removexattr(&name);
            if (rc <= 0)
                return rc;
            auto filesystem = get_local_filesystem();
            rc = filesystem->removexattr(path, name);
            return rc;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {name}});
    }
#endif

    // init_fuse_operations函数的作用是初始化fuse_operation，这里用的是high_level
    void init_fuse_operations(struct fuse_operations* opt, bool xattr)
    {
        // 将opt对象在内存中置0
        memset(opt, 0, sizeof(*opt));
        
        // 对于读写等操作不需要计算路径
        opt->flag_nopath = true;
        // 对于读写等操作可以接受空path
        opt->flag_nullpath_ok = true;

        // 初始化文件系统（返回值会在private_data of fuse_context传递给所有的文件操作，并作为一个参数传给destory()函数）
        opt->init = &::securefs::lite::init;
        // 清除文件系统（在文件系统退出的时候调用）
        opt->destroy = &::securefs::lite::destroy;
        // 获得文件系统的属性
        opt->statfs = &::securefs::lite::statfs;
        // 获得文件的属性
        opt->getattr = &::securefs::lite::getattr;
        // 获得打开的文件的属性
        opt->fgetattr = &::securefs::lite::fgetattr;
        // 打开一个目录
        opt->opendir = &::securefs::lite::opendir;
        // 释放一个目录
        opt->releasedir = &::securefs::lite::releasedir;
        // 从打开的目录里面读取数据
        opt->readdir = &::securefs::lite::readdir;
        // 创建并打开一个文件
        opt->create = &::securefs::lite::create;
        // 打开文件
        opt->open = &::securefs::lite::open;
        // 释放打开的文件
        opt->release = &::securefs::lite::release;
        // 从打开的文件中读取数据
        opt->read = &::securefs::lite::read;
        // 写数据到打开的文件中
        opt->write = &::securefs::lite::write;
        // 可能刷新缓存数据（在每次close文件后会调用，具体作用？？）
        opt->flush = &::securefs::lite::flush;
        // 改变文件的大小
        opt->truncate = &::securefs::lite::truncate;
        // 改变打开的文件的大小
        opt->ftruncate = &::securefs::lite::ftruncate;
        // 删除一个文件
        opt->unlink = &::securefs::lite::unlink;
        // 创建一个目录
        opt->mkdir = &::securefs::lite::mkdir;
        // 删除一个目录
        opt->rmdir = &::securefs::lite::rmdir;
// 如果不是windows系统，对下面函数进行实现
#ifndef _WIN32
        // 改变文件的权限位
        opt->chmod = &::securefs::lite::chmod;
        // 改变文件的owner和group
        opt->chown = &::securefs::lite::chown;
        // 创建一个符号链接
        //（符号链接即保存路径或相对路径，可以跨文件系统，原理是建立了一个新的inode，并记录了指向源文件的路径，是一个真实的文件并占有很小的磁盘空间）
        opt->symlink = &::securefs::lite::symlink;
        // 创建一个硬链接
        //（硬链接即对应同一个inode，和原文件有相同大小却不占空间）
        opt->link = &::securefs::lite::link;
        // 读取符号链接的目标
        opt->readlink = &::securefs::lite::readlink;
#endif
        // 将一个文件重命名
        opt->rename = &::securefs::lite::rename;
        // 同步文件的内容（如果datasync参数非零，那么应该只刷新用户数据，而不是元数据）
        opt->fsync = &::securefs::lite::fsync;
        // 改变文件的访问和修改时间（纳秒级）
        opt->utimens = &::securefs::lite::utimens;

        // 如果禁用xattr则返回，否在下面进行xattr的实现（只有apple设备有xattr）
        if (!xattr)
            return;

#ifdef __APPLE__
        // 列出扩展属性
        opt->listxattr = &::securefs::lite::listxattr;
        // 得到扩展属性
        opt->getxattr = &::securefs::lite::getxattr;
        // 设置扩展属性
        opt->setxattr = &::securefs::lite::setxattr;
        //
        opt->removexattr = &::securefs::lite::removexattr;
#endif
    }
}    // namespace lite
}    // namespace securefs
