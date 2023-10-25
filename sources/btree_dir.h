#pragma once
#include "files.h"
#include "myutils.h"

#include <memory>
#include <stdio.h>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

namespace securefs
{
// -1表示非法空闲节点号
const uint32_t INVALID_PAGE = -1;
// b树的最大深度
const int BTREE_MAX_DEPTH = 32;
// b树的最大记录数量（14阶b树）
const int BTREE_MAX_NUM_ENTRIES = 13;

// static_assert关键字利用判断式，帮助我们在编译的时候发现错误
// 如果b树的一个节点占用内存超过一个block则编译报错，why？计算公式不太理解
static_assert(BTREE_MAX_NUM_ENTRIES * (Directory::MAX_FILENAME_LENGTH + 1 + ID_LENGTH + 4)
                      + (BTREE_MAX_NUM_ENTRIES + 1) * 4 + 4 + 4
                  <= BLOCK_SIZE,
              "A btree node may not fit in a single block");

// 目录损坏异常，继承自VerificationException
class CorruptedDirectoryException : public VerificationException
{
public:
    std::string message() const override { return "Directory corrupted"; }
};

// Dir记录类（即节点中的关键字）
class DirEntry
{
public:
    // 文件名
    std::string filename;
    // 文件对应的id
    id_type id;
    // 文件类型
    uint32_t type;

    // 比较两个DirEntry的文件名是否相等，通过调用下面这个compare函数实现
    int compare(const DirEntry& other) const { return filename.compare(other.filename); }
    // 比较文件名是否相等
    int compare(const std::string& name) const { return filename.compare(name); }
    // 重载比较运算符
    bool operator<(const DirEntry& other) const { return compare(other) < 0; }
    bool operator==(const DirEntry& other) const { return compare(other) == 0; }
    bool operator<(const std::string& other) const { return compare(other) < 0; }
    bool operator==(const std::string& other) const { return compare(other) == 0; }
};

// b树的节点类
class BtreeNode
{
private:
    // 无符号32位整数类型的父节点号、自己节点号
    uint32_t m_parent_num, m_num;
    // 孩子节点号vector
    std::vector<uint32_t> m_child_indices;
    // 自己节点所带的记录
    std::vector<DirEntry> m_entries;
    // 是否脏节点
    bool m_dirty;

public:
    // 构造函数
    explicit BtreeNode(uint32_t parent, uint32_t num)
        : m_parent_num(parent), m_num(num), m_dirty(false)
    {
    }
    // 拷贝构造函数
    BtreeNode(BtreeNode&& other) noexcept
        : m_parent_num(other.m_parent_num)
        , m_num(other.m_num)
        , m_child_indices(std::move(other.m_child_indices))
        , m_entries(std::move(other.m_entries))
        , m_dirty(false)
    {
        std::swap(m_dirty, other.m_dirty);
        other.m_num = INVALID_PAGE;
    }

    // 重载等号操作符
    BtreeNode& operator=(BtreeNode&& other) noexcept
    {
        if (this == &other)
            return *this;
        // std::swap(a,b)会交换a,b的值
        std::swap(m_child_indices, other.m_child_indices);
        std::swap(m_entries, other.m_entries);
        std::swap(m_dirty, other.m_dirty);
        std::swap(m_num, other.m_num);
        std::swap(m_parent_num, other.m_parent_num);
        return *this;
    }

    // 获得当前节点号
    uint32_t page_number() const { return m_num; }
    // 获得父节点号
    uint32_t parent_page_number() const { return m_parent_num; }
    // 获得父节点号，把节点置脏
    uint32_t& mutable_parent_page_number()
    {
        m_dirty = true;
        return m_parent_num;
    }
    // 判断是不是叶结点
    bool is_leaf() const
    {
        // 如果没有孩子节点就是叶节点
        if (m_child_indices.empty())
            return true;
        // 如果有孩子节点就不是叶节点，注意孩子节点的数量=自己节点中关键字的数量+1
        if (m_child_indices.size() == m_entries.size() + 1)
            return false;
        throw CorruptedDirectoryException();
    }

    // 判断当前节点是否脏
    bool is_dirty() const { return m_dirty; }
    // 设置当前节点不脏
    void clear_dirty() { m_dirty = false; }

    // 编写一个返回常量的方法和一个返回非常量同时置脏的方法，是因为返回非常量后容易修改，所以最好置脏
    // 获取当前节点中的记录，返回值是常量
    const std::vector<DirEntry>& entries() const noexcept { return m_entries; }
    // 获取孩子节点号，返回值是常量
    const std::vector<uint32_t>& children() const noexcept { return m_child_indices; }
    // 获取获取当前节点中的记录，同时节点置脏（此时获取后，会进行节点更改操作，所以置脏）
    std::vector<DirEntry>& mutable_entries() noexcept
    {
        m_dirty = true;
        return m_entries;
    }
    // 获取孩子节点号，同时节点置脏（此时获取后，会进行节点更改操作，所以置脏）
    std::vector<uint32_t>& mutable_children() noexcept
    {
        m_dirty = true;
        return m_child_indices;
    }
    // 从buffer中取出当前节点的信息
    bool from_buffer(const byte* buffer, size_t size);
    // 将当前节点的信息写到buffer中
    void to_buffer(byte* buffer, size_t size) const;
};

// b树目录类，继承Directory
class BtreeDirectory : public Directory
{
private:
    // 定义别名
    typedef BtreeNode Node; // 一个节点
    typedef DirEntry Entry; // 一个节点中的一条记录
    class FreePage; //空闲的节点

private:
    // unordered_map容器，里面存放了节点号及其对应的节点对象，存放在内存中（实现缓存节点功能，加快节点访问速度）
    std::unordered_map<uint32_t, std::unique_ptr<Node>> m_node_cache;

private:
    // 根据节点号从文件中读取出节点的信息存放到节点中
    bool read_node(uint32_t, Node&) THREAD_ANNOTATION_REQUIRES(*this);
    // 从空闲节点中读取出当前节点附近空闲的节点？？？还不确定
    void read_free_page(uint32_t, FreePage&) THREAD_ANNOTATION_REQUIRES(*this);
    // 将节点信息写入到节点号对应的block中
    void write_node(uint32_t, const Node&) THREAD_ANNOTATION_REQUIRES(*this);
    // 将当前空闲节点附近空闲的节点写入到当前节点中对应的block中
    void write_free_page(uint32_t, const FreePage&) THREAD_ANNOTATION_REQUIRES(*this);
    // 回收块（节点）
    void deallocate_page(uint32_t) THREAD_ANNOTATION_REQUIRES(*this);
    // 分配空闲块给节点，返回空闲块号
    uint32_t allocate_page() THREAD_ANNOTATION_REQUIRES(*this);

    // 检索节点（从m_node_cache检索，若不在则创建并放入m_node_cache中）
    Node* retrieve_node(uint32_t parent_num, uint32_t num) THREAD_ANNOTATION_REQUIRES(*this);
    // 检索节点（仅从m_node_cache检索）
    Node* retrieve_existing_node(uint32_t num) THREAD_ANNOTATION_REQUIRES(*this);
    // 删除节点（根据节点号，调用deallocate_page回收块函数实现）
    void del_node(Node*) THREAD_ANNOTATION_REQUIRES(*this);
    // 获取根结点（从m_flags[4]中取出）
    Node* get_root_node() THREAD_ANNOTATION_REQUIRES(*this);
    // 刷新m_node_cache中的数据到文件中，根据每个结点的脏位去决定是否刷新
    void flush_cache() THREAD_ANNOTATION_REQUIRES(*this);
    // 将m_node_cache清空
    void clear_cache() THREAD_ANNOTATION_REQUIRES(*this);
    
    // 调整节点n在m_node_cache中的孩子节点的父节点号为parent
    void adjust_children_in_cache(BtreeNode* n, uint32_t parent) THREAD_ANNOTATION_REQUIRES(*this);
    // 调整节点n在m_node_cache中的孩子节点的父节点号当前节点n的节点号，通过调用上面这个函数实现
    void adjust_children_in_cache(BtreeNode* n) THREAD_ANNOTATION_REQUIRES(*this)
    {
        adjust_children_in_cache(n, n->page_number());
    }
    // 调整操作
    void rotate(BtreeNode* left, BtreeNode* right, Entry& separator)
        THREAD_ANNOTATION_REQUIRES(*this);
    // 合并操作
    void merge(BtreeNode* left, BtreeNode* right, BtreeNode* parent, ptrdiff_t entry_index)
        THREAD_ANNOTATION_REQUIRES(*this);

    // 在b树中通过文件名查找结点
    std::tuple<Node*, ptrdiff_t, bool> find_node(const std::string& name)
        THREAD_ANNOTATION_REQUIRES(*this);
    // 查找节点的兄弟（左边or右边）
    std::pair<ptrdiff_t, BtreeNode*> find_sibling(const BtreeNode* parent, const BtreeNode* child)
        THREAD_ANNOTATION_REQUIRES(*this);

    // 插入并调整平衡函数（递归调用的过程有点不太理解？？）
    void insert_and_balance(Node*, Entry, uint32_t additional_child, int depth)
        THREAD_ANNOTATION_REQUIRES(*this);
    // ？？
    Node* replace_with_sub_entry(Node*, ptrdiff_t index, int depth)
        THREAD_ANNOTATION_REQUIRES(*this);
    // 调整平衡函数（递归调用的过程有点不太理解？？）
    void balance_up(Node*, int depth) THREAD_ANNOTATION_REQUIRES(*this);

    // 判断某个子树是否合法
    bool validate_node(const Node* n, int depth) THREAD_ANNOTATION_REQUIRES(*this);
    // 打印出关系节点图
    void write_dot_graph(const Node*, FILE*) THREAD_ANNOTATION_REQUIRES(*this);

    // 遍历B树（模版类）
    template <class Callback>
    void recursive_iterate(const Node* n, const Callback& cb, int depth)
        THREAD_ANNOTATION_REQUIRES(*this);
    // 遍历B树（模版类），将遍历过的节点置脏（重新构建B树函数调用，所以需要将节点置脏）
    template <class Callback>
    void mutable_recursive_iterate(Node* n, const Callback& cb, int depth)
        THREAD_ANNOTATION_REQUIRES(*this);

protected:
    void subflush() override THREAD_ANNOTATION_REQUIRES(*this);

public:
    template <class... Args>
    explicit BtreeDirectory(Args&&... args) : Directory(std::forward<Args>(args)...)
    {
    }
    ~BtreeDirectory() override;

protected:
    bool get_entry_impl(const std::string& name, id_type& id, int& type) override
        THREAD_ANNOTATION_REQUIRES(*this);
    bool add_entry_impl(const std::string& name, const id_type& id, int type) override
        THREAD_ANNOTATION_REQUIRES(*this);
    bool remove_entry_impl(const std::string& name, id_type& id, int& type) override
        THREAD_ANNOTATION_REQUIRES(*this);
    // 遍历目录项，调用遍历B树函数实现（读取文件中数据，不需要将节点置脏）
    void iterate_over_entries_impl(const callback&) override THREAD_ANNOTATION_REQUIRES(*this);

public:
    virtual bool empty() override THREAD_ANNOTATION_REQUIRES(*this);
    void rebuild() THREAD_ANNOTATION_REQUIRES(*this);

public:
    bool validate_free_list() THREAD_ANNOTATION_REQUIRES(*this);
    bool validate_btree_structure() THREAD_ANNOTATION_REQUIRES(*this);
    void to_dot_graph(const char* filename) THREAD_ANNOTATION_REQUIRES(*this);
};

// 根据type来创建对应的对象
template <class... Args>
inline std::unique_ptr<FileBase> btree_make_file_from_type(int type, Args&&... args)
{
    switch (type)
    {
    case FileBase::REGULAR_FILE:
        return securefs::make_unique<RegularFile>(std::forward<Args>(args)...);
    case FileBase::SYMLINK:
        return securefs::make_unique<Symlink>(std::forward<Args>(args)...);
    // 注意DIRECTORY类型创建的对象为BtreeDirectory类型
    case FileBase::DIRECTORY:
        return securefs::make_unique<BtreeDirectory>(std::forward<Args>(args)...);
    case FileBase::BASE:
        return securefs::make_unique<FileBase>(std::forward<Args>(args)...);
    default:
        break;
    }
    throwInvalidArgumentException("Unrecognized file type");
}
}    // namespace securefs
