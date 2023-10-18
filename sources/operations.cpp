#include "operations.h"
#include "apple_xattr_workaround.h"
#include "constants.h"
#include "crypto.h"
#include "fuse_tracer.h"
#include "platform.h"

#include <algorithm>
#include <chrono>
#include <mutex>
#include <stdio.h>
#include <string.h>
#include <string>
#include <typeinfo>
#include <utility>

#ifdef __APPLE__
#include <sys/xattr.h>
#endif

namespace securefs
{
namespace operations
{
    // .lock文件只在挂载后创建，取消挂载的时候删除
    // 表示这个文件夹有进程在用，不能删除？？具体根据后面代码来理解吧
    const char* LOCK_FILENAME = ".securefs.lock";

    // MountOptions这个结构体的构造和析构
    MountOptions::MountOptions() {}
    MountOptions::~MountOptions() {}

    // FileSystemContext结构体的构造函数，通过MountOptions来进行构造
    // ：后的内容为结构体初始化
    FileSystemContext::FileSystemContext(const MountOptions& opt)
        : table(opt.version.value(),
                opt.root,
                from_cryptopp_key(opt.master_key),
                opt.flags.value(),
                opt.block_size.value(),
                opt.iv_size.value(),
                opt.max_padding_size)
        , root(opt.root)
        , root_id() //root_id初始化为data全0的PODarray
        , flags(opt.flags.value())
        , lock_stream(opt.lock_stream)
    {
        // FileSystemContext对象仅在full format中用，lite中用的是FileSystem
        if (opt.version.value() > 3)
            throwInvalidArgumentException("This context object only works with format 1,2,3");
        block_size = opt.block_size.value();
    }

    // 一个securefs进程只有一个FileSystemContext对象
    // FileSystemContext对象的析构函数，将打开的.securefs.lock文件关闭，并删除对应的文件
    FileSystemContext::~FileSystemContext()
    {
        if (!lock_stream)
        {
            return;
        }
        lock_stream->close();
        root->remove_file_nothrow(LOCK_FILENAME);
    }
}    // namespace operations
}    // namespace securefs

// using 声明将FileSystemContext类的成员引入到当前命名空间或块作用域中，优先调用该类中成员
using securefs::operations::FileSystemContext;

namespace securefs
{
namespace internal
{
    // 返回FileSystemContext类指针，将fuse_context->private_data转换为
    // fuse_context->private_data中实际为一个MountOption结构体，进行强制转换会指向FileSystemContext对应的构造函数
    inline FileSystemContext* get_fs(struct fuse_context* ctx)
    {
        return static_cast<FileSystemContext*>(ctx->private_data);
    }

    // 定义AutoClosedFileBase的别名FileGuard
    // AutoClosedFileBase这个类的作用是建立table和filebase的对应关系，注意多态
    typedef AutoClosedFileBase FileGuard;

    // 获取文件所在目录的FileGuard，里面存了table和FileBase
    FileGuard open_base_dir(FileSystemContext* fs, const char* path, std::string& last_component)
    {
        // 将传进来的path进行标准化后，进行划分
        std::vector<std::string> components = split(
            transform(path, fs->flags & kOptionCaseFoldFileName, fs->flags & kOptionNFCFileName)
                .get(),
            '/');

        // 指执行对应的构造函数，result（表，根目录文件流BtreeDirectory对象），返回一个FileGuard类型
        FileGuard result(&fs->table, fs->table.open_as(fs->root_id, FileBase::DIRECTORY));
        // 如果path为空，即为根目录，则直接返回result
        if (components.empty())
        {
            last_component = std::string();
            return result;
        }
        
        // 获取文件所在目录的FileGuard，遍历调用对象方法，因为根据前一目录的BtreeDirectory对象才能找到下一目录
        id_type id;
        int type;
        // 遍历path中的每个component（最后一个文件名不遍历）
        for (size_t i = 0; i + 1 < components.size(); ++i)
        {
            // FileGuard中重载了*运算符，FileBase& operator*() noexcept { return *m_fb; }
            // 返回FileBase类属性，实际为BtreeDirectory对象
            auto& dir = *result;
            {
                // 在当前{}这个作用域内进行c++互斥锁
                FileLockGuard lg(dir);
                // 根据components[i]获取id和type，获取成功返回true
                bool exists = dir.cast_as<Directory>()->get_entry(components[i], id, type);
                if (!exists)
                    throwVFSException(ENOENT);
                if (type != FileBase::DIRECTORY)
                    throwVFSException(ENOTDIR);
            }
            // result中的m_fb指向新打开的文件所在目录
            result.reset(fs->table.open_as(id, type));
        }
        // 获得last_component，即文件名
        last_component = components.back();
        return result;
    }

    // 打开path对象的文件，返回FileGuard
    FileGuard open_all(FileSystemContext* fs, const char* path)
    {
        std::string last_component;
        // 经过open_base_dir()后last_component为文件名
        auto auto_closed_file = open_base_dir(fs, path, last_component);
        // 如果last_component为空的话，说明打开的是目录，此时直接返回就行
        if (last_component.empty())
            return auto_closed_file;
        // last_component不为空的话，
        id_type id;
        int type;
        {
            // dir实际为BtreeDirectory对象
            auto& dir = *auto_closed_file;
            FileLockGuard file_lock_guard(dir);
            // 根据文件名，获取文件的id和type
            bool exists = dir.cast_as<Directory>()->get_entry(last_component, id, type);
            if (!exists)
                throwVFSException(ENOENT);
        }
        // auto_closed_file中的m_fb指向新打开的文件所在目录，m_ft在操作的过程中没有变
        auto_closed_file.reset(fs->table.open_as(id, type));
        return auto_closed_file;
    }

    // Specialization of `open_all` since `VFSException(ENOENT)` occurs too frequently
    // 特殊的open_all()函数，把auto_closed_file作为函数的引用参数传入
    bool open_all(FileSystemContext* fs, const char* path, FileGuard& auto_closed_file)
    {
        std::string last_component;
        auto_closed_file = open_base_dir(fs, path, last_component);
        if (last_component.empty())
            return true;
        id_type id;
        int type;
        {
            auto& dir = *auto_closed_file;
            FileLockGuard file_lock_guard(dir);
            bool exists = dir.cast_as<Directory>()->get_entry(last_component, id, type);
            if (!exists)
            {
                return false;
            }
        }
        auto_closed_file.reset(fs->table.open_as(id, type));
        return true;
    }

    // 创建文件（目录、文件、链接）
    FileGuard create(FileSystemContext* fs,
                     const char* path,
                     int type,
                     uint32_t mode,
                     uint32_t uid,
                     uint32_t gid)
    {
        // 打开文件所在目录
        std::string last_component;
        auto dir = open_base_dir(fs, path, last_component);
        // 随机生成一个id
        id_type id;
        generate_random(id.data(), id.size());

        // 根据type和id，创建一个FileGuard
        FileGuard result(&fs->table, fs->table.create_as(id, type));

        // 初始化FileGuard中的m_fb，用互斥锁保护操作，用一个{}限制锁的作用域是很妙呀
        {
            auto& fp = *result;
            FileLockGuard file_lock_guard(fp);
            fp.initialize_empty(mode, uid, gid);
        }

        // 往文件所在的BtreeDirectory中加入一个记录
        try
        {
            auto& dirfp = *dir;
            FileLockGuard file_lock_guard(dirfp);
            bool success = dirfp.cast_as<Directory>()->add_entry(last_component, id, type);
            if (!success)
                throwVFSException(EEXIST);
        }
        catch (...)
        {
            auto& fp = *result;
            FileLockGuard file_lock_guard(fp);
            fp.unlink();
            throw;
        }
        return result;
    }

    // 根据id和type来删除一个文件
    void remove(FileSystemContext* fs, const id_type& id, int type)
    {
        try
        {
            FileGuard to_be_removed(&fs->table, fs->table.open_as(id, type));
            auto& fp = *to_be_removed;
            FileLockGuard file_lock_guard(fp);
            fp.unlink();
        }
        catch (...)
        {
            // Errors in unlinking the actual underlying file can be ignored
            // They will not affect the apparent filesystem operations
        }
    }

    // 根据path来删除一个文件（目录）
    void remove(FileSystemContext* fs, const char* path)
    {
        // 获取文件的id和type
        std::string last_component;
        auto dir_guard = open_base_dir(fs, path, last_component);
        auto dir = dir_guard.get_as<Directory>();
        if (last_component.empty())
            throwVFSException(EPERM);
        id_type id;
        int type;

        {
            FileLockGuard file_lock_guard(*dir);
            if (!dir->get_entry(last_component, id, type))
                throwVFSException(ENOENT);
        }

        // 
        FileGuard inner_guard = open_as(fs->table, id, type);
        auto inner_fb = inner_guard.get();
        // 双重锁的作用是用来保护删除一个非空目录的？？
        DoubleFileLockGuard double_file_lock_guard(*dir, *inner_fb);
        if (inner_fb->type() == FileBase::DIRECTORY && !static_cast<Directory*>(inner_fb)->empty())
        {
            std::string contents;
            static_cast<Directory*>(inner_fb)->iterate_over_entries(
                [&contents](const std::string& str, const id_type&, int) -> bool
                {
                    contents.push_back('\n');
                    contents += str;
                    return true;
                });
            WARN_LOG("Trying to remove a non-empty directory \"%s\" with contents: %s",
                     path,
                     contents.c_str());
            throwVFSException(ENOTEMPTY);
        }
        dir->remove_entry(last_component, id, type);
        inner_fb->unlink();
    }

    // 判断是不是开启只读功能，输入fuse上下文对象，通过取出fuse上下文对象中的private->data，转成文件系统上下文对象，再调用SharedFiletableImpl的方法
    inline bool is_readonly(struct fuse_context* ctx) { return get_fs(ctx)->table.is_readonly(); }
}    // namespace internal

namespace operations
{
    // 这里的define没太看懂？
#define COMMON_PROLOGUE                                                                            \
    auto ctx = fuse_get_context();                                                                 \
    auto fs = internal::get_fs(ctx);                                                               \
    (void)fs;                                                                                      \
    OPT_TRACE_WITH_PATH;

    // 初始化函数：返回值会放到fuse_get_context()->private_data中
    // 将FileSystemContext对象放到private_data中，整个进程只有一个将FileSystemContext对象
    // lite中的将FileSystem对象在每个线程都有，这两者的区别和作用是？？？
    void* init(struct fuse_conn_info* fsinfo)
    {
        // 将fsinfo强制转换为void类型，init里面默认写的
        (void)fsinfo;
        // fuse_get_context()->private_data本来放的就是MountOptions*，里面有master_key、root等重要信息
        // 取出fuse_get_context()->private_data，转换回MountOptions*
        auto args = static_cast<MountOptions*>(fuse_get_context()->private_data);
        auto fs = new FileSystemContext(*args);
        TRACE_LOG("%s", __FUNCTION__);
        return fs;
    }

    // 清除文件系统：释放指针
    void destroy(void* data)
    {
        auto fs = static_cast<FileSystemContext*>(data);
        TRACE_LOG("%s", __FUNCTION__);
        delete fs;
    }

    // 获得文件系统的属性
    // ShardedFileTableImpl.statvfs()->FileTableImpl.statvfs()->OSService.statvfs()
    int statfs(const char* path, struct fuse_statvfs* fs_info)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            fs->table.statfs(fs_info);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {fs_info}});
    }

    // 获得未打开文件的属性
    // 输入的path是明文路径，将path对应的加密文件的属性存到st中
    int getattr(const char* path, struct fuse_stat* st)
    {
        auto func = [=]()
        {
            // 创建文件系统上下文对象，里面包括了table、root等重要属性
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            if (!st)
                return -EINVAL;

            // 创建FileGuard对象
            internal::FileGuard auto_closed_file(nullptr, nullptr);
            if (!internal::open_all(fs, path, auto_closed_file))
                return -ENOENT;
            auto& fp = *auto_closed_file;
            // 上锁
            FileLockGuard file_lock_guard(fp);
            // 调用FileBase类的stat函数
            fp.stat(st);
            // 设置st中的id，通过OSService中方法获取
            st->st_uid = OSService::getuid();
            st->st_gid = OSService::getgid();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {st}});
    }

    // 获得已打开文件的属性
    int fgetattr(const char* path, struct fuse_stat* st, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 将info->fh转回FileBase*多态对象
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            if (!fb)
                return -EFAULT;
            // 上锁
            FileLockGuard file_lock_guard(*fb);
            // 调用FileBase类的stat函数
            fb->stat(st);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {st}, {info}});
    }

    // 打开一个目录，调用FileSystem类的opendir()函数
    // path为明文路径
    int opendir(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 调用open_all(fs, path)获得FileGuard对象，有table和filebase多态属性
            auto auto_closed_file = internal::open_all(fs, path);
            // 如果不是目录的话，返回错误码
            if (auto_closed_file->type() != FileBase::DIRECTORY)
                return -ENOTDIR;
            // 将auto_closed_file对象强制转换为uintptr_t类型，存到info->fh中
            // uintptr_t 类型用来存放指针地址。它们提供了一种可移植且安全的方法声明指针，而且和系统中使用的指针长度相同，对于把指针转化成整数形式来说很有用。
            // auto_closed_file.release()将成员fb置空，返回fb（为什么这样写呀？？）
            info->fh = reinterpret_cast<uintptr_t>(auto_closed_file.release());

            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 释放一个目录，通过释放指针实现
    int releasedir(const char* path, struct fuse_file_info* info)
    {
        // 通过调用release实现，目录也是文件
        return ::securefs::operations::release(path, info);
    }

    // 读取目录
    // buff存放当前目录的目录项entry
    int readdir(const char* path,
                void* buffer,
                fuse_fill_dir_t filler,
                fuse_off_t off,
                struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            auto ctx = fuse_get_context();
            // 创建文件系统上下文对象，里面包括了table、root等重要属性
            auto fs = internal::get_fs(ctx);
            // 判断是不是开启padding功能
            bool has_padding = fs->table.has_padding();
            // 将info->fh转回FileBase*多态
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            // fb为空则返回错误码
            if (!fb)
                return -EFAULT;
            // fb类型不是目录也返回错误码
            if (fb->type() != FileBase::DIRECTORY)
                return -ENOTDIR;

            // 初始全为0的一个st
            struct fuse_stat st;
            memset(&st, 0, sizeof(st));

            // 上锁
            FileLockGuard file_lock_guard(*fb);
            // 后面学windows编程的时候再看有关windows代码
#ifdef _WIN32
            // We have to fill in "." and ".." entries ourselves due to WinFsp limitations.
            fb->stat(&st);
            filler(buffer, ".", &st, 0);
            filler(buffer, "..", nullptr, 0);
#endif
            // 匿名函数
            auto actions = [&st, filler, buffer, has_padding](
                               const std::string& name, const id_type&, int type) -> bool
            {
                // 设置st中mode，通过type来设置mode
                st.st_mode = FileBase::mode_for_type(type);
                // 加入一条目录项
                bool success = filler(buffer,
                                      name.c_str(),
                                      // When random padding is enabled, we cannot obtain accurate
                                      // size information
                                      has_padding && type == FileBase::REGULAR_FILE ? nullptr : &st,
                                      0)
                    == 0;
                if (!success)
                {
                    WARN_LOG("Filling directory buffer failed");
                }
                // 返回这条加入是否成功
                return success;
            };
            // 将多态子类转换为父类类型
            // iterate_over_entries(actions)当callback返回false时，迭代将被终止
            // 迭代遍历这里的过程回复杂一点，需要好好捋一下
            // （通过回调函数实现，为什么要这样写呀？处理类似事件的时候，可以灵活使用不同的方法，简化代码量）
            fb->cast_as<Directory>()->iterate_over_entries(actions);
            return 0;
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {buffer}, {(const void*)filler}, {&off}, {info}});
    }

    // 创建一个文件（非目录）
    int create(const char* path, fuse_mode_t mode, struct fuse_file_info* info)
    {
        auto func = [&]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 初始化mode
            mode &= ~static_cast<uint32_t>(S_IFMT);
            mode |= S_IFREG;

            // 如果开启只读功能的话，返回错误码，不能创建文件
            if (internal::is_readonly(ctx))
                return -EROFS;
            // 创建 auto_closed_file
            auto auto_closed_file
                = internal::create(fs, path, FileBase::REGULAR_FILE, mode, ctx->uid, ctx->gid);
            // auto_closed_file->返回m_fb，通过其cast_as转化为原本类型RegularFile
            auto_closed_file->cast_as<RegularFile>();
            // 将auto_closed_file对象存在info->fh中，以便后面读写获取操作
            info->fh = reinterpret_cast<uintptr_t>(auto_closed_file.release());

            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}, {info}});
    }

    // 打开一个文件
    int open(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 获取flags，通过&，可以取出相应的标志（info->flag的值为打开文件的方式？）
            int rdwr = info->flags & O_RDWR;
            int wronly = info->flags & O_WRONLY;
            int append = info->flags & O_APPEND;
            // 判断flags是不是与写有关
            int require_write = wronly | append | rdwr;

            // 如果与写有关但是开启了只读功能，起了冲突，返回错误码
            if (require_write && internal::is_readonly(ctx))
                return -EROFS;
            // 打开path对象的文件，返回FileGuard
            auto auto_closed_file = internal::open_all(fs, path);
            // 将auto_closed_file中的m_fb从FileBase多态转换为本来的RegularFile
            // 注意auto_closed_file的->运算符重载了的
            RegularFile* file = auto_closed_file->cast_as<RegularFile>();
            // 取出O_TRUNC这个flags，如果有的话就要调用truncate函数
            // https://blog.csdn.net/shengnan89/article/details/124313839
            if (info->flags & O_TRUNC)
            {
                FileLockGuard file_lock_guard(*file);
                file->truncate(0);
            }
            // 将auto_closed_file对象存在info->fh中
            info->fh = reinterpret_cast<uintptr_t>(auto_closed_file.release());

            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 释放打开的文件，通过释放指针实现(释放目录也通过调用这个函数实现)
    int release(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 获得文件系统上下文对象
            auto ctx = fuse_get_context();
            // 获得文件流对象
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            // 如果文件流对象为空，返回错误码
            if (!fb)
                return -EINVAL;
            // 释放前，刷新到磁盘上
            {
                // 锁的作用域在当前{}中
                FileLockGuard file_lock_guard(*fb);
                fb->flush();
            }
            // 创建并初始化FileGuard对象
            internal::FileGuard auto_closed_file(&internal::get_fs(ctx)->table, fb);
            // 调用AutoClosedFileBase中的reset函数将m_fb设置为空指针
            // 析构的时候会删除指针，所以这里不释放，只指向空？
            auto_closed_file.reset(nullptr);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 从打开的文件中读取len大小的数据，偏移量是off，数据存到buf中
    // path是明文路径，在这里实际没有用到，是通过open后获得的FileBase多态对象中的fd来访问密文，从info->fh取出
    int
    read(const char* path, char* buffer, size_t len, fuse_off_t off, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 从info->fh取出FileBase多态对象
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            // 如果fb为空，则返回错误码
            if (!fb)
                return -EFAULT;
            // 上锁
            FileLockGuard file_lock_guard(*fb);
            // 注意read()实现的函数调用关系，这里有点复杂
            // 将fb这个FileBase多态转换为本来的RegularFile类型
            // 将多态父类转子类的目的是因为调用父类的非虚函数不会用到多态
            // read -> RegularFile.read -> BlockBasedStream.read -> BlockBasedStream.read_block -> CryptStream.read_block -> UnixFileStream.read-> ::pread
            // 注意lite和full格式的AESGCMCryptStream类是不同的，分开文件写的
            // FileBase父类中有meta文件加密解密对象、数据文件加密解密对象
            return static_cast<int>(fb->cast_as<RegularFile>()->read(buffer, off, len));
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {(const void*)buffer}, {&len}, {&off}, {info}});
    }

    // 写数据到打开的文件中
    // 注意write()实现的函数调用关系，这里有点复杂
    // path是明文路径，在这里实际没有用到，是通过open后获得的FileBase多态对象来访问密文
    int write(const char* path,
              const char* buffer,
              size_t len,
              fuse_off_t off,
              struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 将info->fh转回FileBase类多态对象
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            // 为空则返回错误码
            if (!fb)
                return -EFAULT;
            // 上锁
            FileLockGuard file_lock_guard(*fb);
            // 进行写操作
            // write -> RegularFile.write -> BlockBasedStream.write -> BlockBasedStream.unchecked_write(resize) -> BlockBasedStream.read_then_write_block -> CryptStream.write_block(encrypt) -> UnixFileStream.write-> ::pwrite
            fb->cast_as<RegularFile>()->write(buffer, off, len);
            // 返回成功写入的长度
            return static_cast<int>(len);
        };
        return FuseTracer::traced_call(func,
                                       FULL_FUNCTION_NAME,
                                       __LINE__,
                                       {{path}, {(const void*)buffer}, {&len}, {&off}, {info}});
    }
    
    // 将内存RAM中的数据write到对应的文件中（因为full format中利用了RAM来缓存，实现类似cpu cache的功能）
    // 可能还在内存脏页中，os会在合适的时候写入到磁盘中
    // 通过调用继承FileBase下来的flush()实现
    // lite版本中没有实现这个功能，full中实现了并用到了
    int flush(const char* path, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 将info->fh转回FileBase类多态对象
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            // 为空则返回错误码
            if (!fb)
                return -EFAULT;
            // 上锁
            FileLockGuard file_lock_guard(*fb);
            // 调用继承FileBase下来的flush()
            fb->cast_as<RegularFile>()->flush();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {info}});
    }

    // 改变（截断）未打开文件的大小为len，通过调用RegularFile对象中的truncate()实现
    int truncate(const char* path, fuse_off_t size)
    {
        auto func = [=]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 打开path对象的文件，返回FileGuard
            auto auto_closed_file = internal::open_all(fs, path);
            // 取出auto_closed_file中的m_fb
            auto& fp = *auto_closed_file;
            // 上锁
            FileLockGuard file_lock_guard(fp);
            // truncate -> RegularFile.truncate -> BlockBasedStream.resize -> BlockBasedStream.unchecked_resize -> 利用read_block和write_block实现
            fp.cast_as<RegularFile>()->truncate(size);
            // 调用FileBase::flush()
            fp.flush();

            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&size}});
    }

    // 改变（截断）已打开文件的大小为len，通过调用RegularFile对象中的truncate()实现
    int ftruncate(const char* path, fuse_off_t size, struct fuse_file_info* info)
    {
        auto func = [=]()
        {
            // 将info->fh转回FileBase类多态对象
            auto fb = reinterpret_cast<FileBase*>(info->fh);
            // 为空则返回错误码
            if (!fb)
                return -EFAULT;
            // 上锁
            FileLockGuard file_lock_guard(*fb);
            // 与上面函数实现原理一样
            fb->cast_as<RegularFile>()->truncate(size);
            // 调用FileBase::flush()
            fb->flush();

            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&size}, {info}});
    }

    // 删除一个文件
    // path为明文路径
    int unlink(const char* path)
    {
        auto func = [=]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 如果开启只读功能，则返回错误码
            if (internal::is_readonly(ctx))
                return -EROFS;
            // 调用这个文件开头写好的remove函数
            internal::remove(fs, path);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}});
    }

    // 创建一个目录，通过调用FileSystem对象的mkdir()实现
    int mkdir(const char* path, fuse_mode_t mode)
    {
        auto func = [&]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);

            // mode初始化为dir对应的值
            mode &= ~static_cast<uint32_t>(S_IFMT);
            mode |= S_IFDIR;

            // 如果开启只读功能，则返回错误码
            if (internal::is_readonly(ctx))
                return -EROFS;
            // 调用这个文件开头写好的create函数
            auto auto_closed_file
                = internal::create(fs, path, FileBase::DIRECTORY, mode, ctx->uid, ctx->gid);
            // 将auto_closed_file中的m_fb转换为Directory类型
            auto_closed_file->cast_as<Directory>();
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&mode}});
    }

    // 删除一个目录，通过上面写的unlink函数
    int rmdir(const char* path) { return ::securefs::operations::unlink(path); }

    /* UNIX系统下特有 */
    // 改变文件的权限位，通过调用FileSystem对象的chmod()实现
    int chmod(const char* path, fuse_mode_t mode)
    {
        auto func = [&]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 打开文件，返回FileGuard对象
            auto auto_closed_file = internal::open_all(fs, path);
            // fp = auto_closed_file.m_fb
            auto& fp = *auto_closed_file;
            // 上锁
            FileLockGuard file_lock_guard(fp);
            // 设置fp的mode，实际是设置fp的属性m_flags[0]
            auto original_mode = fp.get_mode();
            mode &= 0777;
            mode |= original_mode & S_IFMT;
            fp.set_mode(mode);
            // 调用FileBase::flush()
            fp.flush();
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
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 打开文件，返回FileGuard对象
            auto auto_closed_file = internal::open_all(fs, path);
            // fp = auto_closed_file.m_fb
            auto& fp = *auto_closed_file;

            // 上锁
            FileLockGuard file_lock_guard(fp);

            // 设置fp的uid和gid，实际是设置fp的属性m_flags[1]和m_flags[2]
            fp.set_uid(uid);
            fp.set_gid(gid);
            // 因为设置好后的对象是在内存RAM中的，所以需要调用FileBase::flush()
            fp.flush();

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
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);

            // 如果开启了只读功能，返回错误码
            if (internal::is_readonly(ctx))
                return -EROFS;
            // 创建from路径对应的文件，注意类型是 FileBase::SYMLINK，返回FileGuard对象
            auto auto_closed_file
                = internal::create(fs, from, FileBase::SYMLINK, S_IFLNK | 0755, ctx->uid, ctx->gid);
            // fp = auto_closed_file.m_fb
            auto& fp = *auto_closed_file;
            // 上锁
            FileLockGuard file_lock_guard(fp);
            // 将fp从FileBase父类转换到Symlink子类，目的是防止调用到FileBase的非虚函数
            // 调用Symlink.set()，将to明文路径加密后写入到文件中
            fp.cast_as<Symlink>()->set(to);

            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{to}, {from}});
    }

    /* UNIX系统下特有 */
    // 读取符号链接的目标，通过调用FileSystem对象的readlink()实现
    int readlink(const char* path, char* buf, size_t size)
    {
        // 如果要求读取的size为0，返回错误码
        if (size == 0)
            return -EINVAL;
        // 匿名函数
        auto func = [=]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 打开符号链接文件，返回FileGuard对象
            auto auto_closed_file = internal::open_all(fs, path);
            // fp = auto_closed_file.m_fb
            auto& fp = *auto_closed_file;
            // 上锁
            FileLockGuard file_lock_guard(fp);
            // 将fp从FileBase父类转换到Symlink子类，目的是防止调用到FileBase的非虚函数
            // 调用Symlink.get()，将符号链接文件中密文路径解密后存到buffer中
            auto destination = fp.cast_as<Symlink>()->get();
            memset(buf, 0, size);
            memcpy(buf, destination.data(), std::min(destination.size(), size - 1));
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {(const void*)buf}, {&size}});
    }

    // 将一个文件重命名（与rename系统调用功能一样）
    // src和dst是路径名
    // 原理是将对应文件中记录的filename进行更改，id是不变的
    // 如果存在和目的名一样的文件且类型一致，则会覆盖掉这个文件
    // 但是实际测试中不会这样覆盖，os还上了一层保护？？
    int rename(const char* src, const char* dst)
    {
        auto func = [=]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // src_filename为源文件名，不是路径
            // dst_filename为目的文件名，不是路径
            std::string src_filename, dst_filename;
            // 返回对应的FileGuard对象，注意type为DIRECTORY，但是m_fb为BtreeDirectory对象
            auto src_dir_guard = internal::open_base_dir(fs, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(fs, dst, dst_filename);
            // 向上转换
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();
            
            // 双重锁
            DoubleFileLockGuard double_file_lock_guard(*src_dir, *dst_dir);

            // 获取对应文件的id和type
            id_type src_id, dst_id;
            int src_type, dst_type;
            // 如果原名文件找不到，返回错误码
            if (!src_dir->get_entry(src_filename, src_id, src_type))
                return -ENOENT;
            // 判断目的名在该目录下是否有存在对应的文件
            bool dst_exists = (dst_dir->get_entry(dst_filename, dst_id, dst_type));

            // 如果存在目的名在该目录下对应的文件
            if (dst_exists)
            {
                // 如果源文件id和目的文件id一样，退出函数（因为目的名和原名一样）
                if (src_id == dst_id)
                    return 0;
                // 如果源文件不是目录，但是目的名在该目录下有对应的目录文件，返回错误码
                if (src_type != FileBase::DIRECTORY && dst_type == FileBase::DIRECTORY)
                    return -EISDIR;
                // 原文件类型和目的名存在对应文件的类型不一样，返回错误码
                if (src_type != dst_type)
                    return -EINVAL;
                // 如果原文件类型和目的名存在对应文件的类型一样，把对应文件名的记录删掉
                dst_dir->remove_entry(dst_filename, dst_id, dst_type);
            }
            // 删掉原名文件记录
            src_dir->remove_entry(src_filename, src_id, src_type);
            // 在该目录下加上一个目的文件名的记录
            dst_dir->add_entry(dst_filename, src_id, src_type);
            
            // 如果原文件类型和目的名存在对应文件的类型一样，把对应文件名的文件删掉
            if (dst_exists)
                internal::remove(fs, dst_id, dst_type);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{src}, {dst}});
    }

    /* UNIX系统下特有 */
    // 创建一个硬链接
    int link(const char* src, const char* dst)
    {
        auto func = [=]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // src_filename为源文件名，不是路径
            // dst_filename为目的文件名，不是路径
            std::string src_filename, dst_filename;
            // 返回对应的FileGuard对象，注意type为DIRECTORY，但是m_fb为BtreeDirectory对象
            auto src_dir_guard = internal::open_base_dir(fs, src, src_filename);
            auto dst_dir_guard = internal::open_base_dir(fs, dst, dst_filename);
            // 向上转换
            auto src_dir = src_dir_guard.get_as<Directory>();
            auto dst_dir = dst_dir_guard.get_as<Directory>();
            
            // 获取对应文件的id和type
            id_type src_id, dst_id;
            int src_type, dst_type;

            // 双重锁
            DoubleFileLockGuard double_file_lock_guard(*src_dir, *dst_dir);

            bool src_exists = src_dir->get_entry(src_filename, src_id, src_type);
            // 如果原名文件不存在，返回错误码
            if (!src_exists)
                return -ENOENT;
            
            bool dst_exists = dst_dir->get_entry(dst_filename, dst_id, dst_type);
            // 如果目的名文件存在，返回错误码
            if (dst_exists)
                return -EEXIST;

            // 获取table
            auto&& table = internal::get_fs(ctx)->table;

            // 对文件上锁
            internal::FileGuard guard(&table, table.open_as(src_id, src_type));

            if (guard->type() != FileBase::REGULAR_FILE)
                return -EPERM;

            auto& fp = *guard;
            // 自旋锁？？
            SpinFileLockGuard sflg(fp);
            // 给文件流的nlink+1，文件流有点像inode了，nlink这个有点像inode里面的属性
            fp.set_nlink(fp.get_nlink() + 1);
            // 目的名目录下加一条对应的记录，filename用自己的，id和type用src的
            dst_dir->add_entry(dst_filename, src_id, src_type);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{src}, {dst}});
    }

    // 将修改后的数据和文件描述符的属性持久化到存储设备中，通过File类的fsync()实现
    // 因为就算调用了write函数，数据可能也还是在内存的脏页中，并未真正写入到磁盘中
    // 调用fsync可以将脏页写入到磁盘中
    int fsync(const char* path, int dataysnc, struct fuse_file_info* fi)
    {
        auto func = [=]()
        {
            // 将info->fh转回FileBase类多态对象
            auto fb = reinterpret_cast<FileBase*>(fi->fh);
            // fb不存在，则返回错误码
            if (!fb)
                return -EFAULT;
            // 上锁
            FileLockGuard file_lock_guard(*fb);
            // 调用flunsh和fsunc
            fb->flush();
            fb->fsync();
            return 0;
        };
        return FuseTracer::traced_call(
            func, FULL_FUNCTION_NAME, __LINE__, {{path}, {&dataysnc}, {fi}});
    }

    // 将目录数据强制写入到磁盘中，通过调用上面这个函数
    int fsyncdir(const char* path, int isdatasync, struct fuse_file_info* fi)
    {
        return ::securefs::operations::fsync(path, isdatasync, fi);
    }

    // 改变文件的访问和修改时间（纳秒级）
    int utimens(const char* path, const struct fuse_timespec ts[2])
    {
        auto func = [=]()
        {
            // 获取文件系统上下文对象
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            // 打开文件，返回FileGuard对象
            auto auto_closed_file = internal::open_all(fs, path);
            // fp = auto_closed_file.m_fb
            auto& fp = *auto_closed_file;
            // 上锁
            FileLockGuard file_lock_guard(fp);
            // 调用FileBase::utimens
            fp.utimens(ts);
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
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            int rc = -1;
            {
                FileLockGuard file_lock_guard(fp);
                rc = static_cast<int>(fp.listxattr(list, size));
            }
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
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            if (position != 0)
                return -EINVAL;
            int rc = precheck_getxattr(&name);
            if (rc <= 0)
                return rc;

            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            return static_cast<int>(fp.getxattr(name, value, size));
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
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            if (position != 0)
                return -EINVAL;
            int rc = precheck_setxattr(&name, &flags);
            if (rc <= 0)
                return rc;

            flags &= XATTR_CREATE | XATTR_REPLACE;

            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            fp.setxattr(name, value, size, flags);
            return 0;
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
            auto ctx = fuse_get_context();
            auto fs = internal::get_fs(ctx);
            int rc = precheck_removexattr(&name);
            if (rc <= 0)
                return rc;

            auto auto_closed_file = internal::open_all(fs, path);
            auto& fp = *auto_closed_file;
            FileLockGuard file_lock_guard(fp);
            fp.removexattr(name);
            return 0;
        };
        return FuseTracer::traced_call(func, FULL_FUNCTION_NAME, __LINE__, {{path}, {name}});
    }
#endif

    // 这个函数的作用是将fuse.h定义的函数给实现了，定义自己文件系统里面的操作方法
    void init_fuse_operations(struct fuse_operations* opt, bool xattr)
    {
        memset(opt, 0, sizeof(*opt));

        opt->flag_nopath = true;
        opt->flag_nullpath_ok = true;
        opt->flag_utime_omit_ok = true;

        opt->getattr = &securefs::operations::getattr;
        opt->fgetattr = &securefs::operations::fgetattr;
        opt->init = &securefs::operations::init;
        opt->destroy = &securefs::operations::destroy;
        opt->opendir = &securefs::operations::opendir;
        opt->releasedir = &securefs::operations::releasedir;
        opt->readdir = &securefs::operations::readdir;
        opt->create = &securefs::operations::create;
        opt->open = &securefs::operations::open;
        opt->read = &securefs::operations::read;
        opt->write = &securefs::operations::write;
        opt->truncate = &securefs::operations::truncate;
        opt->unlink = &securefs::operations::unlink;
        opt->mkdir = &securefs::operations::mkdir;
        opt->rmdir = &securefs::operations::rmdir;
        opt->release = &securefs::operations::release;
        opt->ftruncate = &securefs::operations::ftruncate;
        opt->flush = &securefs::operations::flush;
#ifndef _WIN32
        opt->chmod = &securefs::operations::chmod;
        opt->chown = &securefs::operations::chown;
        opt->symlink = &securefs::operations::symlink;
        opt->link = &securefs::operations::link;
        opt->readlink = &securefs::operations::readlink;
#endif
        opt->rename = &securefs::operations::rename;
        opt->fsync = &securefs::operations::fsync;
        opt->fsyncdir = &securefs::operations::fsyncdir;
        opt->utimens = &securefs::operations::utimens;
        opt->statfs = &securefs::operations::statfs;

        if (!xattr)
            return;
#ifdef __APPLE__
        opt->listxattr = &securefs::operations::listxattr;
        opt->getxattr = &securefs::operations::getxattr;
        opt->setxattr = &securefs::operations::setxattr;
        opt->removexattr = &securefs::operations::removexattr;
#endif
    }
}    // namespace operations
}    // namespace securefs
