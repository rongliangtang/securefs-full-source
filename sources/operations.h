#pragma once

#include "file_table.h"
#include "logger.h"
#include "myutils.h"

#include <fuse.h>

namespace securefs
{
class FileStream;

namespace operations
{
    // 声明局部常量LOCK_FILENAME来自于其他翻译单元
    // 在operations.cpp文件中定义了const char* LOCK_FILENAME = ".securefs.lock";
    extern const char* LOCK_FILENAME;
    // MountOptions这个结构体存放来securefs挂载所需要用到的一些参数，与fuse的mount要区分开哦
    struct MountOptions
    {
        // optional这个模版类有点复杂，暂时按照c++17的optional去理解
        // optional这个模版类创建的对象可以有值也可以没值，没值的时候为空
        optional<int> version;
        // 定义一个OSService类型的shared_ptr
        // root对象用来进行一下os操作（通过c/c++提供的api实现，并进行了相关的封装来满足编程的需要）
        std::shared_ptr<const OSService> root;
        // 定义master_key，byte类型的block，对齐
        CryptoPP::AlignedSecByteBlock master_key;
        optional<uint32_t> flags;
        optional<unsigned> block_size;
        optional<unsigned> iv_size;
        unsigned max_padding_size = 0;
        std::shared_ptr<FileStream> lock_stream;

        // 结构体的构造函数，也就是初始化
        MountOptions();
        ~MountOptions();
    };

    // FileSystemContext文件系统上下文包含securefs文件系统的信息（根目录OSService、用户id、flag等信息）
    // full format中的FileSystemContext和lite的FileSystem用法不一样
    // FileSystemContext在full format仅有，与lite format中的FileSystem不同，不包含fuse api重写的实现方法
    // c++中的struct可以当作类来使用，而c中不可以，c++保留这个的原因是为了让c++能编译出一起c写的代码
    struct FileSystemContext
    {
    private:
        // 将key从CryptoPP::AlignedSecByteBlock类型中取出放入到key_type（即PODArray<byte, KEY_LENGTH>）
        static key_type from_cryptopp_key(const CryptoPP::AlignedSecByteBlock& key)
        {
            if (key.size() != KEY_LENGTH)
                throwInvalidArgumentException("Invalid key length");
            // key_type为POD array，这样做的目的是为了能够用memcpy()这种c库中的函数
            key_type result;
            // 将CryptoPP::AlignedSecByteBlock类型中的data放入到result中，前者本来也为byte
            memcpy(result.data(), key.data(), key.size());
            return result;
        }

    public:
        // ShardedFileTableImpl为分片的文件表实现类，操作密文文件主要是通过FileTable来实现
        ShardedFileTableImpl table;
        // OSService类型的shared_ptr，里面存了数据根目录的文件描述符
        std::shared_ptr<const OSService> root;
        // 数据根目录的id
        id_type root_id;
        // unsigned int（int隐含）
        // 明文数据块大小
        unsigned block_size;
        // #define fuse_uid_t uid_t
        // 用户id（文件的拥有者都是用用户id来表示的）
        optional<fuse_uid_t> uid_override;
        // #define fuse_gid_t gid_t
        // 组id
        optional<fuse_gid_t> gid_override;
        // 标志位，用来判断是否开启某些操作（StoreTime、CaseFoldFileName等）
        uint32_t flags;
        // .lock文件流
        std::shared_ptr<FileStream> lock_stream;

        // lite format中FileSystem对象的构造是将MountOptions opt的参数取出来，一个个构造
        // full format中FileSystemContext对象的构造直接传入MountOptions opt
        explicit FileSystemContext(const MountOptions& opt);

        ~FileSystemContext();
    };

    void init_fuse_operations(struct fuse_operations* opt, bool xattr);

    int statfs(const char*, struct fuse_statvfs*);

    void* init(struct fuse_conn_info*);

    void destroy(void* ptr);

    int getattr(const char*, struct fuse_stat*);

    int fgetattr(const char*, struct fuse_stat*, struct fuse_file_info*);

    int opendir(const char*, struct fuse_file_info*);

    int releasedir(const char*, struct fuse_file_info*);

    int readdir(const char*, void*, fuse_fill_dir_t, fuse_off_t, struct fuse_file_info*);

    int create(const char*, fuse_mode_t, struct fuse_file_info*);

    int open(const char*, struct fuse_file_info*);

    int release(const char*, struct fuse_file_info*);

    int read(const char*, char*, size_t, fuse_off_t, struct fuse_file_info*);

    int write(const char*, const char*, size_t, fuse_off_t, struct fuse_file_info*);

    int flush(const char*, struct fuse_file_info*);

    int truncate(const char*, fuse_off_t);

    int ftruncate(const char*, fuse_off_t, struct fuse_file_info*);

    int unlink(const char*);

    int mkdir(const char*, fuse_mode_t);

    int rmdir(const char*);

    int chmod(const char*, fuse_mode_t);

    int chown(const char* path, fuse_uid_t uid, fuse_gid_t gid);

    int symlink(const char* to, const char* from);

    int readlink(const char* path, char* buf, size_t size);

    int rename(const char*, const char*);

    int link(const char*, const char*);

    int fsync(const char* path, int isdatasync, struct fuse_file_info* fi);

    int fsyncdir(const char* path, int isdatasync, struct fuse_file_info* fi);

    int utimens(const char* path, const struct fuse_timespec ts[2]);

#ifdef __APPLE__
    int listxattr(const char* path, char* list, size_t size);
    int getxattr(const char* path, const char* name, char* value, size_t size, uint32_t position);

    int setxattr(const char* path,
                 const char* name,
                 const char* value,
                 size_t size,
                 int flags,
                 uint32_t position);
    int removexattr(const char* path, const char* name);
#endif
}    // namespace operations
}    // namespace securefs
