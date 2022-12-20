#include "file_table.h"
#include "btree_dir.h"
#include "exceptions.h"
#include "lock_guard.h"
#include "logger.h"
#include "myutils.h"
#include "platform.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <queue>
#include <string.h>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// 对file_table.h里面的函数进行定义

namespace securefs
{

// 定义一个pair里面存了两个FileStream类的shared_ptr
typedef std::pair<std::shared_ptr<FileStream>, std::shared_ptr<FileStream>> FileStreamPtrPair;

// 虚类，实现在子类FileTableIOVersion1和FileTableIOVersion2中
// 作用是根据id实现对加密文件的操作（打开、删除、创建），不同version的操作方法略有不同，所以写了两个version
class FileTableIO
{
    // 禁止拷贝移动
    DISABLE_COPY_MOVE(FileTableIO)

public:
    explicit FileTableIO() = default;
    virtual ~FileTableIO() = default;

    virtual FileStreamPtrPair open(const id_type& id) = 0;
    virtual FileStreamPtrPair create(const id_type& id) = 0;
    virtual void unlink(const id_type& id) noexcept = 0;
};

// FileTableIOVersion1在version1中用
class FileTableIOVersion1 : public FileTableIO
{
private:
    // OSService类，里面存了数据目录的文件描述符，然后根据此我们可以利用挂载点路径来操作电脑上的密文路径
    std::shared_ptr<const OSService> m_root;
    // 是否只读
    bool m_readonly;

    // 一级目录的字节数、二级目录的字节数
    static const size_t FIRST_LEVEL = 1, SECOND_LEVEL = 5;

    // 根据id计算出文件的一级目录和二级目录，及数据文件名和元数据文件名
    // 一级目录1个字节，二级目录5个字节
    static void calculate_paths(const securefs::id_type& id,
                                std::string& first_level_dir,
                                std::string& second_level_dir,
                                std::string& full_filename,
                                std::string& meta_filename)
    {
        // 一级目录路径：取出第1个字节进行16进制化，得到2个16进制表示
        first_level_dir = securefs::hexify(id.data(), FIRST_LEVEL);
        // 二级目录路径：取出第2到第6个字节进行16进制化，得到10个16进制表示
        second_level_dir
            = first_level_dir + '/' + securefs::hexify(id.data() + FIRST_LEVEL, SECOND_LEVEL);
        // 数据文件路径
        full_filename = second_level_dir + '/'
            + securefs::hexify(id.data() + FIRST_LEVEL + SECOND_LEVEL,
                               id.size() - FIRST_LEVEL - SECOND_LEVEL);
        // 元信息文件路径，数据文件路径后面加个meta后缀就ok
        meta_filename = full_filename + ".meta";
    }

public:
    // 构造函数
    explicit FileTableIOVersion1(std::shared_ptr<const OSService> root, bool readonly)
        : m_root(std::move(root)), m_readonly(readonly)
    {
    }

    // 根据id来打开数据文件和元数据文件，返回pair，里面放了两个FileStream类的shared_ptr
    FileStreamPtrPair open(const id_type& id) override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);

        // 设置open的flag
        int open_flags = m_readonly ? O_RDONLY : O_RDWR;
        return std::make_pair(m_root->open_file_stream(filename, open_flags, 0),
                              m_root->open_file_stream(metaname, open_flags, 0));
    }

    // 根据id来创建数据文件和元数据文件，返回pair，里面放了两个FileStream类的shared_ptr
    FileStreamPtrPair create(const id_type& id) override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
        // 创建一级目录，权限位为0755
        // first_level_dir.c_str()返回string类型的首字符地址char*，因为StringRef类的构造函数输入是char*
        m_root->ensure_directory(first_level_dir.c_str(), 0755);
        // 创建二级目录，权限位为0755
        m_root->ensure_directory(second_level_dir.c_str(), 0755);
        // 进行创建
        int open_flags = O_RDWR | O_CREAT | O_EXCL;
        return std::make_pair(m_root->open_file_stream(filename, open_flags, 0644),
                              m_root->open_file_stream(metaname, open_flags, 0644));
    }

    // 根据id删除文件
    void unlink(const id_type& id) noexcept override
    {
        std::string first_level_dir, second_level_dir, filename, metaname;
        calculate_paths(id, first_level_dir, second_level_dir, filename, metaname);
        // 我发现这里的实现都是OSService类方法根据系统调用OSService类方法
        m_root->remove_file_nothrow(filename);
        m_root->remove_file_nothrow(metaname);
        m_root->remove_directory_nothrow(second_level_dir);
        m_root->remove_directory_nothrow(second_level_dir);
    }
};

// FileTableIOVersion2在version2、3中用
class FileTableIOVersion2 : public FileTableIO
{
private:
    // OSService类，里面存了数据目录的文件描述符，然后根据此我们可以利用挂载点路径来操作电脑上的密文路径
    std::shared_ptr<const OSService> m_root;
    // 是否只读
    bool m_readonly;

   // 根据id计算出文件的一级目录和二级目录，及数据文件名和元数据文件名
   // 一级目录1个字节，二级目录31个字节
   static void calculate_paths(const securefs::id_type& id,
                                std::string& dir,
                                std::string& full_filename,
                                std::string& meta_filename)
    {
        dir = securefs::hexify(id.data(), 1);
        full_filename = dir + '/' + securefs::hexify(id.data() + 1, id.size() - 1);
        meta_filename = full_filename + ".meta";
    }

public:
    // 构造函数
    explicit FileTableIOVersion2(std::shared_ptr<const OSService> root, bool readonly)
        : m_root(std::move(root)), m_readonly(readonly)
    {
    }

    // 根据id计算出文件的一级目录和二级目录，及数据文件名和元数据文件名
    FileStreamPtrPair open(const id_type& id) override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);

        int open_flags = m_readonly ? O_RDONLY : O_RDWR;
        return std::make_pair(m_root->open_file_stream(filename, open_flags, 0),
                              m_root->open_file_stream(metaname, open_flags, 0));
    }

    // 根据id来创建数据文件和元数据文件，返回pair，里面放了两个FileStream类的shared_ptr
    FileStreamPtrPair create(const id_type& id) override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);
        m_root->ensure_directory(dir, 0755);
        int open_flags = O_RDWR | O_CREAT | O_EXCL;
        return std::make_pair(m_root->open_file_stream(filename, open_flags, 0644),
                              m_root->open_file_stream(metaname, open_flags, 0644));
    }

    // 根据id删除文件
    void unlink(const id_type& id) noexcept override
    {
        std::string dir, filename, metaname;
        calculate_paths(id, dir, filename, metaname);
        m_root->remove_file_nothrow(filename);
        m_root->remove_file_nothrow(metaname);
        m_root->remove_directory_nothrow(dir);
    }
};

// FileTableImpl类的构造函数
FileTableImpl::FileTableImpl(int version,
                             std::shared_ptr<const OSService> root,
                             const key_type& master_key,
                             uint32_t flags,
                             unsigned block_size,
                             unsigned iv_size,
                             unsigned max_padding_size)
    : m_flags(flags)
    , m_block_size(block_size)
    , m_iv_size(iv_size)
    , m_max_padding_size(max_padding_size)
    , m_root(root)
{
    memcpy(m_master_key.data(), master_key.data(), master_key.size());
    // 根据version来确定对文件表的操作方法
    switch (version)
    {
    case 1:
        // 智能指针中的reset会令智能指针p中存放指针q，即p指向q的空间，而且会释放原来的空间。
        m_fio.reset(new FileTableIOVersion1(root, is_readonly()));
        break;
    case 2:
    case 3:
        m_fio.reset(new FileTableIOVersion2(root, is_readonly()));
        break;
    default:
        throwInvalidArgumentException("Unknown version");
    }
}

// 析构函数：将m_files缓存中文件数据刷新到磁盘上
FileTableImpl::~FileTableImpl()
{
    for (auto&& pair : m_files)
        finalize(pair.second);
}

// 根据id，优先从m_files缓存中找，找不到则打开数据文件和元数据文件，返回一个FileBase类的多态type指针
FileBase* FileTableImpl::open_as(const id_type& id, int type)
{
    LockGuard<Mutex> lg(m_lock);
    // 如果能从m_files缓存中找到
    // unordered_map.find返回键值对
    auto it = m_files.find(id);
    if (it != m_files.end())
    {
        // Remove the marking that this id is closed
        // 从m_files缓存中找到了的话，则将这个id从已经关闭id中删除
        auto closed_id_iter = std::find(m_closed_ids.begin(), m_closed_ids.end(), id);
        if (closed_id_iter != m_closed_ids.end())
            m_closed_ids.erase(closed_id_iter);

        // 如果FileBase的tyep不等于传入的type，则从m_files删除对应键值对（说明从m_files缓存表中找出的有错，需要将其从表中删除）
        // 否则增加文件流的引用数量，并返回对象（非智能指针）
        if (it->second->type() != type)
            m_files.erase(it);
        else
        {
            it->second->incref();
            return it->second.get();
        }
    }

    // 如果在m_files缓存中找不到，只能自己从加密文件中读了，并且将其加入到m_files缓存中
    // 数据文件的描述符、元信息文件的描述符
    std::shared_ptr<FileStream> data_fd, meta_fd;
    // 将open的元组返回值分别赋值到对应变量上
    std::tie(data_fd, meta_fd) = m_fio->open(id);
    // 根据type来执行对应的构造函数，返回一个unique_str
    auto fb = btree_make_file_from_type(type,
                                        data_fd,
                                        meta_fd,
                                        m_master_key,
                                        id,
                                        is_auth_enabled(),
                                        m_block_size,
                                        m_iv_size,
                                        m_max_padding_size,
                                        is_time_stored());
    // 设置文件流的引用数量为1
    fb->setref(1);
    auto result = fb.get();
    m_files.emplace(id, std::move(fb));
    return result;
}

// 创建id对应的文件流并返回指针
FileBase* FileTableImpl::create_as(const id_type& id, int type)
{
    // 若只读则抛出异常
    if (is_readonly())
        throwVFSException(EROFS);

    // 上c++互斥锁
    LockGuard<Mutex> lg(m_lock);
    // 如果从m_files缓存表中找得到id，则抛出异常“已存在”
    // map.end()表示找不到，为最后一个元素的后一个位置
    if (m_files.find(id) != m_files.end())
        throwVFSException(EEXIST);

    // 创建数据文件流和元数据文件流
    std::shared_ptr<FileStream> data_fd, meta_fd;
    // m_fio为FileTableIO类的多态，std::unique_ptr<FileTableIO>
    // 作用是根据id来打开、创建、删除数据文件和元文件
    // std::tie 可用于解包 std::pair
    // data_fd为FileStream类的shared_ptr，表示数据文件流，实际为UnixFileStream或WindowsFileStream，里面存放了其文件描述符
    std::tie(data_fd, meta_fd) = m_fio->create(id);
    // btree_make_file_from_type函数根据type创建对应的对象，该对象为FileBase类的多态
    auto fb = btree_make_file_from_type(type,
                                        data_fd,
                                        meta_fd,
                                        m_master_key,
                                        id,
                                        is_auth_enabled(),
                                        m_block_size,
                                        m_iv_size,
                                        m_max_padding_size,
                                        is_time_stored());
    // 设置这个对象的引用数量为1，因为刚创建并打开
    fb->setref(1);
    // unique_ptr中get()，返回指向被管理对象的指针
    // result为普通指针，fb并为释放。也就相当于指针result和智能指针fb共同管理一个对象，所以就*result做的一切，都会反应到bar指向的对象上。
    // 当智能指针释放的时候，对象也会释放
    auto result = fb.get();
    // m_files是unordered_map，里面存放了每个文件的<id,FileBase>
    // emplace函数放入一个键值对
    // std:move(fb)使fb释放指针
    m_files.emplace(id, std::move(fb));
    // 返回指向被管理对象的指针
    return result;
}

// 关闭文件
void FileTableImpl::close(FileBase* fb)
{
    if (!fb)
        throwVFSException(EFAULT);

    LockGuard<Mutex> lg(m_lock);
    // 从m_files缓存表中找文件记录
    auto iter = m_files.find(fb->get_id());
    // 找不到的话报错，因为关闭打开的文件，文件肯定是有记录在m_files缓存表中的
    if (iter == m_files.end() || iter->second.get() != fb)
        throwInvalidArgumentException("ID does not match the table");

    // 如果文件流的引用数量<=0，说明文件已经关闭了，报错
    if (fb->getref() <= 0)
        throwInvalidArgumentException("Closing an closed file");

    // 如果文件-1后==0，说明可以关闭
    if (fb->decref() <= 0)
    {
        // 执行文件流的终处理函数
        finalize(iter->second);
        // 如果该文件流对象存在
        // 将文件的id加入到已关闭id集合中，并判断要不要清理m_files缓存表中的已关闭文件缓存
        if (iter->second)
        {
            // This means the file is not deleted
            // The handle shall remain in the cache
            m_closed_ids.push_back(iter->second->get_id());
            gc();
        }
        // 如果该文件流对象不存在（什么时候会不存在？）
        // 从缓存表中删除该文件对应的记录
        else
        {
            m_files.erase(iter);
        }
    }
}

// 从fileTable中删除某些文件记录（每次删除的数量最多是8个）
void FileTableImpl::eject()
{
    // 删除的数量最多是8个
    auto num_eject = std::min<size_t>(NUM_EJECT, m_closed_ids.size());
    // 从fileTable中进行删除
    for (size_t i = 0; i < num_eject; ++i)
    {
        m_files.erase(m_closed_ids[i]);
        TRACE_LOG("Evicting file with ID=%s from cache", hexify(m_closed_ids[i]).c_str());
    }
    // 从m_closed_ids中去除已经从fileTable中删除的id
    m_closed_ids.erase(m_closed_ids.begin(), m_closed_ids.begin() + num_eject);
}

// 对传进来的文件流fb做最终处理
void FileTableImpl::finalize(std::unique_ptr<FileBase>& fb)
{
    // 如果fb为空，直接返回
    if (!fb)
        return;

    // 如果fb对应的文件，link数量<=0，则fb->is_unlinked()返回true
    // 如果为true则通过FileTableIO对象多态的方法，删除id对应的密文文件夹
    if (fb->is_unlinked())
    {
        id_type id = fb->get_id();
        fb.reset();
        m_fio->unlink(id);
    }
    // 如果为false，说明该文件link>0，执行flunsh操作，将数据刷新到磁盘上
    else
    {
        LockGuard<FileBase> lg(*fb);
        fb->flush();
    }
}

// m_closed_ids的数量大于MAX_NUM_CLOSED时执行eject函数，将已关闭文件的缓存从m_files缓存表中删除
// 目的是防止已经关闭文件的缓存在缓存表中过多
// 每次关闭文件的时候，会执行这个函数
void FileTableImpl::gc()
{
    if (m_closed_ids.size() >= MAX_NUM_CLOSED)
        eject();
}

FileTable::~FileTable() {}

// ShardedFileTableImpl构造函数：主要是初始化m_shards
ShardedFileTableImpl::ShardedFileTableImpl(int version,
                                           std::shared_ptr<const OSService> root,
                                           const key_type& master_key,
                                           uint32_t flags,
                                           unsigned block_size,
                                           unsigned iv_size,
                                           unsigned max_padding_size)
{
    // 如果没有env_shards的话num_shards = 4
    unsigned num_shards = 4;
    // SECUREFS_NUM_FILE_TABLE_SHARDS怎么就在环境变量中了呀？？？
    // 如果有env_shards的话num_shards = env_shards
    const char* env_shards = std::getenv("SECUREFS_NUM_FILE_TABLE_SHARDS");
    if (env_shards)
    {
        num_shards = std::max(2ul, std::strtoul(env_shards, nullptr, 0));
    }
    TRACE_LOG("Use %u shards of FileTableImpls.", num_shards);

    // 将m_shards的大小调整至num_shards
    m_shards.resize(num_shards);
    // 遍历m_shards，对里面的每个FileTableImpl进行初始化
    for (unsigned i = 0; i < num_shards; ++i)
    {
        m_shards[i].reset(new FileTableImpl(
            version, root, master_key, flags, block_size, iv_size, max_padding_size));
    }
}

// ShardedFileTableImpl的析构函数
ShardedFileTableImpl::~ShardedFileTableImpl() {}

// 打开密文文件，通过调用id对应的FileTableImpl对象
FileBase* ShardedFileTableImpl::open_as(const id_type& id, int type)
{
    return get_shard_by_id(id)->open_as(id, type);
}

// 创建密文文件流对象，通过调用id对应的FileTableImpl对象
FileBase* ShardedFileTableImpl::create_as(const id_type& id, int type)
{
    // 调用FileTableImpl类中的create_as
    return get_shard_by_id(id)->create_as(id, type);
}

// 关闭密文文件流，通过调用id对应的FileTableImpl对象
void ShardedFileTableImpl::close(FileBase* fb)
{
    if (!fb)
    {
        return;
    }
    get_shard_by_id(fb->get_id())->close(fb);
}

// 返回一个FileTableImpl类指针，根据id从m_shards数组中取出对象（id与FileTableImpl对象有对应关系）
FileTableImpl* ShardedFileTableImpl::get_shard_by_id(const id_type& id) noexcept
{
    // id与FileTableImpl对象的对应关系如下，id前4个字节表示的无符号数对m_shards.size()进行取余
    return m_shards[static_cast<size_t>(id.data()[0]) % m_shards.size()].get();
}
}    // namespace securefs
