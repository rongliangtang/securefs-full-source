#include "lite_fs.h"
#include "constants.h"
#include "lock_guard.h"
#include "logger.h"

#include <cryptopp/base32.h>

#include <cerrno>
#include <mutex>

namespace securefs
{
namespace lite
{

    File::~File() {}

    void File::fstat(struct fuse_stat* stat)
    {
        m_file_stream->fstat(stat);
        // 将文件的大小调整为真实的大小，即加密后的大小，单位byte
        stat->st_size = AESGCMCryptStream::calculate_real_size(
            stat->st_size, m_crypt_stream->get_block_size(), m_crypt_stream->get_iv_size());
    }

    // 构造函数：进行相关对象的构造和设置
    FileSystem::FileSystem(std::shared_ptr<const securefs::OSService> root,
                           const key_type& name_key,
                           const key_type& content_key,
                           const key_type& xattr_key,
                           const key_type& padding_key,
                           unsigned block_size,
                           unsigned iv_size,
                           unsigned max_padding_size,
                           unsigned flags)
        : m_name_encryptor(name_key.data(), name_key.size())
        , m_content_key(content_key)
        , m_padding_aes(padding_key.data(), padding_key.size())
        , m_root(std::move(root))
        , m_block_size(block_size)
        , m_iv_size(iv_size)
        , m_max_padding_size(max_padding_size)
        , m_flags(flags)
    {
        byte null_iv[12] = {0};
        m_xattr_enc.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
        m_xattr_dec.SetKeyWithIV(xattr_key.data(), xattr_key.size(), null_iv, sizeof(null_iv));
    }

    FileSystem::~FileSystem() {}

    InvalidFilenameException::~InvalidFilenameException() {}
    std::string InvalidFilenameException::message() const
    {
        return strprintf("Invalid filename \"%s\"", m_filename.c_str());
    }

    // 进行明文路径的加密，来获取密文路径
    // 使用AES_SIV算法
    std::string encrypt_path(AES_SIV& encryptor, StringRef path)
    {
        byte buffer[2032];
        // 存放加密后的结果
        std::string result;
        // 由于添加了IV和base32编码，底层文件名比虚拟文件名长。因此，挂载的文件系统中的最大文件名长度总是比其底层文件系统短。
        // reserve()是为容器预留空间，即为当前容器设定一个空间分配的阈值，但是并不会为容器直接allocate具体的空间，具体空间的分配是在创建对象时候进行分配得，超过了阀值会重新分配
        // 根据path获取enc_path的长度，不对啊，iv没有加上去呀！！！reserve后的是容量下限，实际容量可以大于该值
        result.reserve((path.size() * 8 + 4) / 5);
        // last_nonseparator_index表示上一个非分隔符/的坐标，即上一个/的后一个坐标
        size_t last_nonseparator_index = 0;
        std::string encoded_part;

        // 处理整个path
        for (size_t i = 0; i <= path.size(); ++i)
        {
            // 处理分隔符中的一块内容（也就是一个文件or目录的名称）
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;
                    // 这一块内容的字节数 > 2000，则抛出异常
                    if (slice_size > 2000)
                        throwVFSException(ENAMETOOLONG);
                    // encrypt_and_authenticate(const void* plaintext,size_t text_len,const void* additional_data,size_t additional_len,void* ciphertext,void* siv)
                    // buffer[IV_SIZE:]存的是密文，buffer[0:IV_SIZE]存的是iv
                    encryptor.encrypt_and_authenticate(
                        slice, slice_size, nullptr, 0, buffer + AES_SIV::IV_SIZE, buffer);
                    // 将得到的buffer，大小是slice_size + IV_SIZE，进行base32编码
                    base32_encode(buffer, slice_size + AES_SIV::IV_SIZE, encoded_part);
                    // 将这一块的内容加入到result中
                    result.append(encoded_part);
                }
                // i < path.size()时，放入/
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }

    // 进行路径的解密，解密的流程没有太看懂？？输入密文就可以解密？？
    // 使用AES_SIV算法
    std::string decrypt_path(AES_SIV& decryptor, StringRef path)
    {
        byte string_buffer[2032];
        std::string result, decoded_part;
        result.reserve(path.size() * 5 / 8 + 10);
        size_t last_nonseparator_index = 0;

        for (size_t i = 0; i <= path.size(); ++i)
        {
            if (i >= path.size() || path[i] == '/')
            {
                if (i > last_nonseparator_index)
                {
                    const char* slice = path.data() + last_nonseparator_index;
                    size_t slice_size = i - last_nonseparator_index;

                    base32_decode(slice, slice_size, decoded_part);
                    if (decoded_part.size() >= sizeof(string_buffer))
                        throwVFSException(ENAMETOOLONG);

                    // decrypt_and_verify(const void* ciphertext,size_t text_len,const void* additional_data,size_t additional_len,void* plaintext,const void* siv)
                    bool success
                        = decryptor.decrypt_and_verify(&decoded_part[AES_SIV::IV_SIZE],
                                                       decoded_part.size() - AES_SIV::IV_SIZE,
                                                       nullptr,
                                                       0,
                                                       string_buffer,
                                                       &decoded_part[0]);
                    if (!success)
                        throw InvalidFilenameException(path.to_string());
                    result.append((const char*)string_buffer,
                                  decoded_part.size() - AES_SIV::IV_SIZE);
                }
                if (i < path.size())
                    result.push_back('/');
                last_nonseparator_index = i + 1;
            }
        }
        return result;
    }

    // 将path进行加密，返回加密结果（一样的输入会有一样的加密结果）
    std::string FileSystem::translate_path(StringRef path, bool preserve_leading_slash)
    {
        // 如果path为空则直接返回空
        if (path.empty())
        {
            return {};
        }
        // 如果path == '/'则根据preserve_leading_slash来判断返回'/'还是'.'
        else if (path.size() == 1 && path[0] == '/')
        {
            if (preserve_leading_slash)
            {
                return "/";
            }
            else
            {
                return ".";
            }
        }
        // 其他
        else
        {
            // 返回加密后的结果str
            // transform()的作用是将字符串按 文件名规范化模式 进行转换，返回char型的unique_ptr
            std::string str = lite::encrypt_path(
                m_name_encryptor,
                transform(path, m_flags & kOptionCaseFoldFileName, m_flags & kOptionNFCFileName)
                    .get());
            // 如果preserve_leading_slash==false且str[0]=='/'，则将str[0]'/'删掉
            if (!preserve_leading_slash && !str.empty() && str[0] == '/')
            {
                str.erase(str.begin());
            }
            // Translate path /._git note.txt into Z32H5XQJVP3VBWJZGC85SPIVTN95DAH2XDY4GQC9CSZWXV4P
            TRACE_LOG("Translate path %s into %s", path.c_str(), str.c_str());
            return str;
        }
    }

    // 这里用到的线程安全编程技术需要好好琢磨琢磨
    // 打开文件，返回AutoClosedFile类对象，通过OSService类中的open_file_stream()实现
    AutoClosedFile FileSystem::open(StringRef path, int flags, fuse_mode_t mode)
    {
        if (flags & O_APPEND)
        {
            flags &= ~((unsigned)O_APPEND);
            // Clear append flags. Workaround for FUSE bug.
            // See https://github.com/netheril96/securefs/issues/58.
        }

        // Files cannot be opened write-only because the header must be read in order to derive the
        // session key
        if ((flags & O_ACCMODE) == O_WRONLY)
        {
            flags = (flags & ~O_ACCMODE) | O_RDWR;
        }
        if ((flags & O_CREAT))
        {
            mode |= S_IRUSR;
        }
        // 打开文件流，输入path加密后的结果
        // 读取的应该是用户空间文件系统中的加密数据
        // file_stream为FileStream类型的shared_ptr，实际是UnixFileStream（有属性fd），用到了多态
        // 打开的实际为加密文件，获取加密文件的句柄存在UnixFileStream类对象中
        auto file_stream = m_root->open_file_stream(translate_path(path, false), flags, mode);
        // 创建AutoClosedFile类（File类）的对象fp，并进行构造
        // 注意file_stream对象为UnixFileStream类型，里面存了fd，赋值给File对象中的m_file_stream属性
        // File对象中的m_crtpt_stream属性用所有的参来构造
        AutoClosedFile fp(new File(file_stream,
                                   m_content_key,
                                   m_block_size,
                                   m_iv_size,
                                   (m_flags & kOptionNoAuthentication) == 0,
                                   m_max_padding_size,
                                   &m_padding_aes));
        if (flags & O_TRUNC)
        {
            LockGuard<File> lock_guard(*fp, true);
            fp->resize(0);
        }

        // 返回AutoClosedFile类的对象fp，里面包含了文件流
        return fp;
    }

    // 获取文件的信息，输入的是明文路径，通过调用OSService类的stat()实现
    // fuse_stat
    bool FileSystem::stat(StringRef path, struct fuse_stat* buf)
    {
        // 获得加密文件的文件属性
        auto enc_path = translate_path(path, false);
        if (!m_root->stat(enc_path, buf))
            return false;
        if (buf->st_size <= 0)
            return true;
        // 判断文件的类型，S_IFMT为掩码
        switch (buf->st_mode & S_IFMT)
        {
        // 如果文件是符号链接（将符号链接的大小改为明文路径的大小）
        case S_IFLNK:
        {
            // This is a workaround for Interix symbolic links on NTFS volumes
            // (https://github.com/netheril96/securefs/issues/43).

            // 'buf->st_size' is the expected link size, but on NTFS volumes the link starts with
            // 'IntxLNK\1' followed by the UTF-16 encoded target.
            std::string buffer(buf->st_size, '\0');
            ssize_t link_size = m_root->readlink(enc_path, &buffer[0], buffer.size());
            if (link_size != buf->st_size && link_size != (buf->st_size - 8) / 2)
                throwVFSException(EIO);

            // Resize to actual size
            buffer.resize(static_cast<size_t>(link_size));

            auto resolved = decrypt_path(m_name_encryptor, buffer);
            buf->st_size = resolved.size();
            break;
        }
        // 如果文件是目录，直接结束，不做处理，因为目录不需要显示大小的bro
        case S_IFDIR:
            break;
        // 如果文件是常规文件
        case S_IFREG:
            // 若加密文件的大小>0（其实肯定是>0的，因为必有16byte的header）
            if (buf->st_size > 0)
            {
                // 没有开启padding功能的话
                if (m_max_padding_size <= 0)
                {
                    // 计算明文文件的实际大小
                    buf->st_size = AESGCMCryptStream::calculate_real_size(
                        buf->st_size, m_block_size, m_iv_size);
                }
                // 开启了padding功能的话（需要打开加密文件来计算明文文件的实际大小，这是为什么这个功能开销大的原因）
                // 知道m_max_padding_size的话不是可以单独写个函数来算？不需要打开文件
                else
                {
                    try
                    {
                        // 只读方式打开加密文件
                        auto fs = m_root->open_file_stream(enc_path, O_RDONLY, 0);
                        // 创建AESGCMCryptStream类对象
                        AESGCMCryptStream stream(std::move(fs),
                                                 m_content_key,
                                                 m_block_size,
                                                 m_iv_size,
                                                 (m_flags & kOptionNoAuthentication) == 0,
                                                 m_max_padding_size,
                                                 &m_padding_aes);
                        // 用过AESGCMCryptStream类对象的size()方法获得明文文件的实际大小
                        buf->st_size = stream.size();
                    }
                    catch (const std::exception& e)
                    {
                        ERROR_LOG("Encountered exception %s when opening file %s for read: %s",
                                  get_type_name(e).get(),
                                  path.c_str(),
                                  e.what());
                    }
                }
            }
            break;
        default:
            throwVFSException(ENOTSUP);
        }
        return true;
    }

    // 创建目录，通过调用OSService类的mkdir实现
    void FileSystem::mkdir(StringRef path, fuse_mode_t mode)
    {
        // 创建一个加密后的文件夹
        m_root->mkdir(translate_path(path, false), mode);
    }

    // 删除目录，通过调用OSService类的remove_directory实现
    void FileSystem::rmdir(StringRef path)
    {
        // 删除加密后的目录
        m_root->remove_directory(translate_path(path, false));
    }

    // 将文件重命名，通过调用OSService类的rename实现
    void FileSystem::rename(StringRef from, StringRef to)
    {
        // 挂载点重命名后，底层文件系统进行加密后的重命名
        m_root->rename(translate_path(from, false), translate_path(to, false));
    }

    // 改变文件权限位，通过调用OSService类的chmod实现
    void FileSystem::chmod(StringRef path, fuse_mode_t mode)
    {
        if (!(mode & S_IRUSR))
        {
            WARN_LOG("Change the mode of file %s to 0%o which denies user read access. "
                     "Mysterious bugs will occur.",
                     path.c_str(),
                     static_cast<unsigned>(mode));
        }
        // 对加密后的文件进行权限位的更改
        m_root->chmod(translate_path(path, false), mode);
    }

    // 改变文件的owner和group，通过调用OSService类的chown实现
    void FileSystem::chown(StringRef path, fuse_uid_t uid, fuse_gid_t gid)
    {
        // 对加密后的文件进行权限位的更改
        m_root->chown(translate_path(path, false), uid, gid);
    }

    // 读取符号链接的目标，通过调用OSService类的readlink实现
    // buf为明文结果
    size_t FileSystem::readlink(StringRef path, char* buf, size_t size)
    {
        if (size <= 0)
            return size;

        auto max_size = size / 5 * 8 + 32;
        auto underbuf = securefs::make_unique_array<char>(max_size);
        memset(underbuf.get(), 0, max_size);
        // 读取符号链接加密后的文件数据
        m_root->readlink(translate_path(path, false), underbuf.get(), max_size - 1);
        // 对读取后加密后的目标进行解密
        std::string resolved = decrypt_path(m_name_encryptor, underbuf.get());
        // 取得目标的正确大小
        size_t copy_size = std::min(resolved.size(), size - 1);
        // 将目标明文路径放到buf中
        memcpy(buf, resolved.data(), copy_size);
        buf[copy_size] = '\0';
        return copy_size;
    }

    // 创建一个符号链接,通过调用OSService类的symlink实现
    void FileSystem::symlink(StringRef to, StringRef from)
    {
        // eto为加密后的目的，efrom为加密后的源
        auto eto = translate_path(to, true), efrom = translate_path(from, false);
        // 对加密后的文件进行符号链接
        m_root->symlink(eto, efrom);
    }

    // 改变文件的访问和修改时间（纳秒级）,通过调用OSService类的utimens实现
    void FileSystem::utimens(StringRef path, const fuse_timespec* ts)
    {
        // fuse中这个api获取到的是挂载点path，所以这里对底层文件系统中的加密文件进行设置
        m_root->utimens(translate_path(path, false), ts);
    }

    // 删除文件，通过调用OSService类的remove_file(加密后路径)实现
    void FileSystem::unlink(StringRef path) { m_root->remove_file(translate_path(path, false)); }

    // 创建一个硬链接，通过调用OSService类的link实现
    void FileSystem::link(StringRef src, StringRef dest)
    {
        // 对加密后的文件进行硬链接
        m_root->link(translate_path(src, false), translate_path(dest, false));
    }

    // statvfs通过调用OSService类中的statfs()函数实现
    void FileSystem::statvfs(struct fuse_statvfs* buf) { m_root->statfs(buf); }

    // lite format中用的目录类，继承Directory类
    // 实现
    class THREAD_ANNOTATION_CAPABILITY("mutex") LiteDirectory final : public Directory
    {
    private:
        // 明文路径（挂载点是以自己为根目录来表示路径的）
        std::string m_path;
        // 底层文件系统遍历对象
        std::unique_ptr<DirectoryTraverser>
            m_underlying_traverser THREAD_ANNOTATION_GUARDED_BY(*this);
        // name加密/解密器
        AES_SIV m_name_encryptor THREAD_ANNOTATION_GUARDED_BY(*this);
        // block_size，iv_size
        unsigned m_block_size, m_iv_size;

    public:
        // 构造函数
        explicit LiteDirectory(std::string path,
                               std::unique_ptr<DirectoryTraverser> underlying_traverser,
                               const AES_SIV& name_encryptor,
                               unsigned block_size,
                               unsigned iv_size)
            : m_path(std::move(path))
            , m_underlying_traverser(std::move(underlying_traverser))
            , m_name_encryptor(name_encryptor)
            , m_block_size(block_size)
            , m_iv_size(iv_size)
        {
        }

        // 返回明文路径
        StringRef path() const override { return m_path; }

        // 目录项回到起点
        void rewind() override THREAD_ANNOTATION_REQUIRES(*this)
        {
            // 调用UnixDirectoryTraverser->rewind
            // m_underlying_traverser是DirectoryTraverser类的多态UnixDirectoryTraverser
            m_underlying_traverser->rewind();
        }

        // 下一个目录项
        // name用来获取明文路径
        bool next(std::string* name, struct fuse_stat* stbuf) override
            THREAD_ANNOTATION_REQUIRES(*this)
        {
            std::string under_name, decoded_bytes;

            while (1)
            {
                // 调用UnixDirectoryTraverser->next
                // under_name用来获取密文目录项名
                // 找不到了返回false
                if (!m_underlying_traverser->next(&under_name, stbuf))
                    return false;
                // 如果没有传入name参数，直接返回true
                if (!name)
                    return true;

                if (under_name.empty())
                    continue;
                // 如果找到"."和".."，直接赋值给name，结束运行
                if (under_name == "." || under_name == "..")
                {
                    if (name)
                        name->swap(under_name);
                    return true;
                }
                // 之后如果底层文件系统中目录项名的第一个为"."，说明这个目录项是隐藏文件(.securefs.json)，跳过处理
                if (under_name[0] == '.')
                    continue;
                
                // 用try catch来捕获错误
                try
                {
                    // 进行解码，再解密加密文件名
                    base32_decode(under_name.data(), under_name.size(), decoded_bytes);
                    // 如果解码后的size <= AES_SIV::IV_SIZE，说明加密文件名太短了，直接跳过处理（与AES-SIV的原理有关）
                    if (decoded_bytes.size() <= AES_SIV::IV_SIZE)
                    {
                        WARN_LOG("Skipping too small encrypted filename %s", under_name.c_str());
                        continue;
                    }
                    // 将name初始化为decoded_bytes.size() - AES_SIV::IV_SIZE个'\0'
                    name->assign(decoded_bytes.size() - AES_SIV::IV_SIZE, '\0');
                    // 解密并验证
                    /*
                    bool AES_SIV::decrypt_and_verify(const void* ciphertext,
                                 size_t text_len,
                                 const void* additional_data,
                                 size_t additional_len,
                                 void* plaintext,
                                 const void* siv)
                    */
                    bool success
                        = m_name_encryptor.decrypt_and_verify(&decoded_bytes[AES_SIV::IV_SIZE],
                                                              name->size(),
                                                              nullptr,
                                                              0,
                                                              &(*name)[0],
                                                              &decoded_bytes[0]);
                    if (!success)
                    {
                        WARN_LOG("Skipping filename %s (decrypted to %s) since it fails "
                                 "authentication check",
                                 under_name.c_str(),
                                 name->c_str());
                        continue;
                    }
                    // 设置stat中明文文件大小
                    // 实际的执行过程中，在这里传入的stbuf->st_size=0，所以最后设置的stbuf->st_size=0
                    if (stbuf)
                        stbuf->st_size = AESGCMCryptStream::calculate_real_size(
                            stbuf->st_size, m_block_size, m_iv_size);
                }
                catch (const std::exception& e)
                {
                    WARN_LOG("Skipping filename %s due to exception in decoding: %s",
                             under_name.c_str(),
                             e.what());
                    continue;
                }
                return true;
            }
        }
    };

    // 打开一个目录，返回一个LiteDirectory类的unique_ptr，使用了多态技术
    // 输入的path是明文路径
    // m_root->create_traverser(translate_path(path, false))创建的目录遍历是相对加密目录而言
    std::unique_ptr<Directory> FileSystem::opendir(StringRef path)
    {
        if (path.empty())
            throwVFSException(EINVAL);
        return securefs::make_unique<LiteDirectory>(
            path.to_string(),
            // 创建加密底层文件系统的traverser对象
            m_root->create_traverser(translate_path(path, false)),
            this->m_name_encryptor,
            m_block_size,
            m_iv_size);
    }

    Base::~Base() {}

// 实现apple中的xattr功能，暂时跳过
#ifdef __APPLE__
    ssize_t
    FileSystem::getxattr(const char* path, const char* name, void* buf, size_t size) noexcept
    {
        auto iv_size = m_iv_size;
        auto mac_size = AESGCMCryptStream::get_mac_size();
        if (!buf)
        {
            auto rc = m_root->getxattr(translate_path(path, false).c_str(), name, nullptr, 0);
            if (rc < 0)
            {
                return rc;
            }
            if (rc <= iv_size + mac_size)
            {
                return 0;
            }
            return rc - iv_size - mac_size;
        }

        try
        {
            auto underbuf = securefs::make_unique_array<byte>(size + iv_size + mac_size);
            ssize_t readlen = m_root->getxattr(translate_path(path, false).c_str(),
                                               name,
                                               underbuf.get(),
                                               size + iv_size + mac_size);
            if (readlen <= 0)
                return readlen;
            if (readlen <= iv_size + mac_size)
                return -EIO;
            bool success
                = m_xattr_dec.DecryptAndVerify(static_cast<byte*>(buf),
                                               underbuf.get() + readlen - mac_size,
                                               mac_size,
                                               underbuf.get(),
                                               static_cast<int>(iv_size),
                                               nullptr,
                                               0,
                                               underbuf.get() + iv_size,
                                               static_cast<size_t>(readlen) - iv_size - mac_size);
            if (!success)
            {
                ERROR_LOG("Encrypted extended attribute for file %s and name %s fails "
                          "ciphertext integrity check",
                          path,
                          name);
                return -EIO;
            }
            return readlen - iv_size - mac_size;
        }
        catch (const std::exception& e)
        {
            ERROR_LOG("Error decrypting extended attribute for file %s and name %s (%s)",
                      path,
                      name,
                      e.what());
            return -EIO;
        }
    }

    int FileSystem::setxattr(
        const char* path, const char* name, void* buf, size_t size, int flags) noexcept
    {
        try
        {
            auto iv_size = m_iv_size;
            auto mac_size = AESGCMCryptStream::get_mac_size();
            auto underbuf = securefs::make_unique_array<byte>(size + iv_size + mac_size);
            generate_random(underbuf.get(), iv_size);
            m_xattr_enc.EncryptAndAuthenticate(underbuf.get() + iv_size,
                                               underbuf.get() + iv_size + size,
                                               mac_size,
                                               underbuf.get(),
                                               static_cast<int>(iv_size),
                                               nullptr,
                                               0,
                                               static_cast<const byte*>(buf),
                                               size);
            return m_root->setxattr(translate_path(path, false).c_str(),
                                    name,
                                    underbuf.get(),
                                    size + iv_size + mac_size,
                                    flags);
        }
        catch (const std::exception& e)
        {
            ERROR_LOG("Error encrypting extended attribute for file %s and name %s (%s)",
                      path,
                      name,
                      e.what());
            return -EIO;
        }
    }

#endif
}    // namespace lite
}    // namespace securefs
