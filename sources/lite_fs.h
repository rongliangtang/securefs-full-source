#pragma once

#include "crypto.h"
#include "lite_stream.h"
#include "lock_guard.h"
#include "mystring.h"
#include "myutils.h"
#include "platform.h"
#include "thread_safety_annotations.hpp"

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/secblock.h>

namespace securefs
{
namespace lite
{
    class File;
    class Directory;

    // Base类：
    class Base
    {
    public:
        Base() {}
        virtual ~Base() = 0;
        virtual File* as_file() noexcept { return nullptr; }
        virtual Directory* as_dir() noexcept { return nullptr; }
    };

    // Directory类，继承Base类和DirectoryTraverser类：实现对目录的操作
    // THREAD_ANNOTATION_CAPABILITY("mutex")表示这个类对象具有能力，可以看为锁，用来clang线程安全分析
    class THREAD_ANNOTATION_CAPABILITY("mutex") Directory : public Base, public DirectoryTraverser
    {
    private:
        // 自己的Mutex类，再次封装是为了可以用clang线程安全分析
        securefs::Mutex m_lock;

    public:
        // lock和unlock是有capability类的常规操作，不懂看platform.h中Mutex类注释
        void lock() THREAD_ANNOTATION_ACQUIRE() { m_lock.lock(); }
        void unlock() noexcept THREAD_ANNOTATION_RELEASE() { m_lock.unlock(); }
        Directory* as_dir() noexcept { return this; }

        // Obtains the (virtual) path of the directory.
        // 获取明文路径
        virtual StringRef path() const = 0;

        // Redeclare the methods in `DirectoryTraverser` to add thread safe annotations.
        // 定位到下一个目录项
        // THREAD_ANNOTATION_REQUIRES表示调用该函数前需要上锁，结束后需要释放锁
        // 通过锁将这个函数变为多线程互斥访问的，防止线程干扰，导致出错（为什么需要互斥呀？？可能会有多个线程进行操作？？）
        virtual bool next(std::string* name, struct fuse_stat* st) THREAD_ANNOTATION_REQUIRES(*this)
            = 0;
        // 定位移到起点，重新开始
        // 通过锁将这个函数变为多线程互斥访问的，防止线程干扰，导致出错
        virtual void rewind() THREAD_ANNOTATION_REQUIRES(*this) = 0;
    };

    // 实现对文件的操作
    // final用来修饰类，让该类不能被继承；若用在函数中表示final终止派生，使派生类不需要重写该虚函数。
    // THREAD_ANNOTATION_CAPABILITY("mutex")表示该类拥有能力，可以当作锁来用
    class THREAD_ANNOTATION_CAPABILITY("mutex") File final : public Base
    {
        DISABLE_COPY_MOVE(File)

    private:
        securefs::optional<lite::AESGCMCryptStream>
            m_crypt_stream THREAD_ANNOTATION_GUARDED_BY(*this);
        std::shared_ptr<securefs::FileStream> m_file_stream THREAD_ANNOTATION_GUARDED_BY(*this);
        securefs::Mutex m_lock;

    public:
        // 模版构造函数
        template <typename... Args>
        // m_file_stream这个shared_ptr指向file_stream
        File(std::shared_ptr<securefs::FileStream> file_stream, Args&&... args)
            : m_file_stream(file_stream)
        {
            LockGuard<FileStream> lock_guard(*m_file_stream, true);
            m_crypt_stream.emplace(file_stream, std::forward<Args>(args)...);
        }

        ~File();

        length_type size() const THREAD_ANNOTATION_REQUIRES(*this)
        {
            return m_crypt_stream->size();
        }
        // 调用AESGCMCryptStream对象的flush()
        void flush() THREAD_ANNOTATION_REQUIRES(*this) { m_crypt_stream->flush(); }
        bool is_sparse() const noexcept THREAD_ANNOTATION_REQUIRES(*this)
        {
            return m_crypt_stream->is_sparse();
        }
        // 改变文件大小，通过调用AESGCMCryptStream对象的resize()
        void resize(length_type len) THREAD_ANNOTATION_REQUIRES(*this)
        {
            m_crypt_stream->resize(len);
        }
        // 通过调用AESGCMCryptStream对象的read()实现
        length_type read(void* output, offset_type off, length_type len)
            THREAD_ANNOTATION_REQUIRES(*this)
        {
            // m_crypt_stream为File对象的属性
            // 用到了继承
            // m_crypt_stream是AESGCMCryptStream对象
            // 但是read()是BlockBasedStream类的
            return m_crypt_stream->read(output, off, len);
        }
        // 通过调用AESGCMCryptStream对象的write()实现
        void write(const void* input, offset_type off, length_type len)
            THREAD_ANNOTATION_REQUIRES(*this)
        {
            // 用到了继承
            // m_crypt_stream是AESGCMCryptStream对象
            // 但是write()是BlockBasedStream类的
            return m_crypt_stream->write(input, off, len);
        }
        void fstat(struct fuse_stat* stat) THREAD_ANNOTATION_REQUIRES(*this);
        // 同步文件内容，通过FileStream的fsync()实现
        void fsync() THREAD_ANNOTATION_REQUIRES(*this) { m_file_stream->fsync(); }
        void utimens(const fuse_timespec ts[2]) THREAD_ANNOTATION_REQUIRES(*this)
        {
            m_file_stream->utimens(ts);
        }
        // 该类对象具有能力，可以当作锁用
        void lock(bool exclusive = true) THREAD_ANNOTATION_ACQUIRE()
        {
            // 上锁
            m_lock.lock();
            try
            {
                // m_file_stream实际为UnixFileStream(WindowsFileStream)类，执行文件的上锁操作，互斥锁
                m_file_stream->lock(exclusive);
            }
            // catch 语句指定省略号 (...) 而非类型，则 catch 程序块将处理每种类型的异常。
            catch (...)
            {
                // 对文件上锁失败，则对该类对象解锁
                m_lock.unlock();
                // 没有操作数的 throw 表达式将重新引发当前正在处理的异常。
                throw;
            }
        }
        // 该类对象具有能力，可以当作锁用
        void unlock() noexcept THREAD_ANNOTATION_RELEASE()
        {
            // m_file_stream实际为UnixFileStream(WindowsFileStream)类，执行文件的解锁操作
            m_file_stream->unlock();
            m_lock.unlock();
        }
        File* as_file() noexcept override { return this; }
    };

    class FileSystem;

    // TODO:AutoClosedFile为File类型的unique_ptr，表示自动关闭的文件，因为智能指针的原因吗
    typedef std::unique_ptr<File> AutoClosedFile;

    std::string encrypt_path(AES_SIV& encryptor, StringRef path);
    std::string decrypt_path(AES_SIV& decryptor, StringRef path);

    class InvalidFilenameException : public VerificationException
    {
    private:
        std::string m_filename;

    public:
        explicit InvalidFilenameException(std::string filename) : m_filename(filename) {}
        ~InvalidFilenameException();

        std::string message() const override;
        int error_number() const noexcept override { return EINVAL; }
    };

    // 文件系统类：实现文件系统和挂载点之间的各种操作
    class FileSystem
    {
        // 禁止拷贝复制，
        DISABLE_COPY_MOVE(FileSystem)

    private:
        // 文件名加密（解密）器
        AES_SIV m_name_encryptor;
        // 文本加密的key
        key_type m_content_key;
        // xattr的加密器，用AES-GCM算法
        CryptoPP::GCM<CryptoPP::AES>::Encryption m_xattr_enc;
        // xattr的解密器，用AES-GCM算法
        CryptoPP::GCM<CryptoPP::AES>::Decryption m_xattr_dec;
        // padding加密器，用AES-ECB算法，什么作用？
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption m_padding_aes;
        // m_root为可以执行OSService类的shared_ptr
        std::shared_ptr<const securefs::OSService> m_root;
        // 这些size的作用是加密算法用的
        unsigned m_block_size, m_iv_size, m_max_padding_size;
        // securefs的flags，判断securefs是不是StoreTime、NoAuthentication等
        unsigned m_flags;

    private:
        // 将path（文件的完全路径还是名字？？）进行加密
        // preserve_leading_slash表示是否保存path前面的/
        std::string translate_path(StringRef path, bool preserve_leading_slash);

    public:
        // FileSystem对象的构造函数
        FileSystem(std::shared_ptr<const securefs::OSService> root,
                   const key_type& name_key,
                   const key_type& content_key,
                   const key_type& xattr_key,
                   const key_type& padding_key,
                   unsigned block_size,
                   unsigned iv_size,
                   unsigned max_padding_size,
                   unsigned flags);

        ~FileSystem();

        AutoClosedFile open(StringRef path, int flags, fuse_mode_t mode);
        bool stat(StringRef path, struct fuse_stat* buf);
        void mkdir(StringRef path, fuse_mode_t mode);
        void rmdir(StringRef path);
        void chmod(StringRef path, fuse_mode_t mode);
        void chown(StringRef path, fuse_uid_t uid, fuse_gid_t gid);
        void rename(StringRef from, StringRef to);
        void unlink(StringRef path);
        void symlink(StringRef to, StringRef from);
        void link(StringRef src, StringRef dest);
        size_t readlink(StringRef path, char* buf, size_t size);
        void utimens(StringRef path, const fuse_timespec tm[2]);
        // 获取文件系统的信息，与普通的文件系统信息的结构一样
        void statvfs(struct fuse_statvfs* buf);
        std::unique_ptr<Directory> opendir(StringRef path);

        bool has_padding() const noexcept { return m_max_padding_size > 0; }

#ifdef __APPLE__
        // These APIs, unlike all others, report errors through negative error numbers as defined in
        // <errno.h>
        ssize_t listxattr(const char* path, char* buf, size_t size) noexcept
        {
            return m_root->listxattr(translate_path(path, false).c_str(), buf, size);
        }
        ssize_t getxattr(const char* path, const char* name, void* buf, size_t size) noexcept;
        int
        setxattr(const char* path, const char* name, void* buf, size_t size, int flags) noexcept;
        int removexattr(const char* path, const char* name) noexcept
        {
            return m_root->removexattr(translate_path(path, false).c_str(), name);
        }
#endif
    };
}    // namespace lite
}    // namespace securefs