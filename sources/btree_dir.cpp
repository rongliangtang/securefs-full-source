#include "btree_dir.h"

#include <algorithm>
#include <assert.h>
#include <deque>
#include <iterator>
#include <stdio.h>
#include <type_traits>
#include <utility>
#include <vector>

static void dir_check(bool condition)
{
    if (!condition)
        throw securefs::CorruptedDirectoryException();
}

namespace securefs
{

class NotBTreeNodeException : public CorruptedDirectoryException
{
public:
};

template <class T>
static const byte* read_and_forward(const byte* buffer, const byte* end, T& value)
{
    static_assert(std::is_trivially_copyable<T>::value, "value must be trivially copyable");
    dir_check(buffer + sizeof(value) <= end);
    memcpy(&value, buffer, sizeof(value));
    return buffer + sizeof(value);
}

template <class T, size_t size>
static const byte* read_and_forward(const byte* buffer, const byte* end, PODArray<T, size>& value)
{
    dir_check(buffer + size <= end);
    memcpy(value.data(), buffer, size);
    return buffer + size;
}

template <class T>
static byte* write_and_forward(const T& value, byte* buffer, const byte* end)
{
    static_assert(std::is_trivially_copyable<T>::value, "value must be trivially copyable");
    dir_check(buffer + sizeof(value) <= end);
    memcpy(buffer, &value, sizeof(value));
    return buffer + sizeof(value);
}

template <class T, size_t size>
static byte* write_and_forward(const PODArray<T, size>& value, byte* buffer, const byte* end)
{
    dir_check(buffer + size <= end);
    memcpy(buffer, value.data(), sizeof(value));
    return buffer + size;
}

template <class T>
static T read_little_endian_and_forward(const byte** buffer, const byte* end)
{
    dir_check(*buffer + sizeof(T) <= end);
    auto v = from_little_endian<T>(*buffer);
    *buffer += sizeof(T);
    return v;
}

// 模版函数
// 将value转为小端存储，写入到buffer中，返回结束位置
template <class T>
static byte* write_little_endian_and_forward(const T& value, byte* buffer, const byte* end)
{
    dir_check(buffer + sizeof(T) <= end);
    // 将value按字节转换为小端存储，存储在buffer中
    to_little_endian(value, buffer);
    return buffer + sizeof(T);
}

// 模版函数
// 将c1从index位置划分为c1、c2两部分
template <class Container>
static void slice(Container& c1, Container& c2, size_t index)
{
    typedef std::move_iterator<typename Container::iterator> iterator;
    c2.assign(iterator(c1.begin() + index), iterator(c1.end()));
    c1.erase(c1.begin() + index, c1.end());
}

// 模版函数
// 将c2容器内的元素移动到c1末尾，而非复制
template <class Container>
static void steal(Container& c1, Container& c2)
{
    typedef std::move_iterator<typename Container::iterator> iterator;
    c1.insert(c1.end(), iterator(c2.begin()), iterator(c2.end()));
}

// 模版函数
// 将c2容器内的元素复制到c1中（注意c2为常量）
template <class Container>
static void steal(Container& c1, const Container& c2)
{
    c1.insert(c1.end(), c2.begin(), c2.end());
}

template <class Container>
static typename Container::iterator get_iter(Container& c, ptrdiff_t index)
{
    return std::next(c.begin(), index);
}

template <class Container>
static typename Container::const_iterator get_iter(const Container& c, ptrdiff_t index)
{
    return std::next(c.begin(), index);
}

template <class Container>
static void erase(Container& c, ptrdiff_t index)
{
    dir_check(index >= 0 && static_cast<size_t>(index) < c.size());
    c.erase(get_iter(c, index));
}

// 模版函数
// 插入元素到容器的某个位置（value是右值引用，这个有点不太清楚）
template <class Container, class T>
static void insert(Container& c, ptrdiff_t index, T&& value)
{
    // 检查index的范围是否合法
    dir_check(index >= 0 && static_cast<size_t>(index) <= c.size());
    // 进行插入操作
    c.insert(get_iter(c, index), std::forward<T>(value));
}

// 空闲的节点
class BtreeDirectory::FreePage
{
public:
    uint32_t next = 0;
    uint32_t prev = 0;
};

// 从block中读取出当前节点附近空闲的节点？？？还不确定
void BtreeDirectory::read_free_page(uint32_t num, FreePage& fp)
{
    byte buffer[BLOCK_SIZE];
    dir_check(m_stream->read(buffer, num * BLOCK_SIZE, BLOCK_SIZE) == BLOCK_SIZE);
    // buffer里面的数据用小端存储的方式存着，这里取出并转换为对应的值（以字节为单位操作）
    if (from_little_endian<uint32_t>(buffer) != 0)
        throw CorruptedDirectoryException();
    // 每一个block的依次花四个字节存储：节点号、前一个空闲节点号、下一个空闲节点号
    fp.next = from_little_endian<uint32_t>(buffer + sizeof(uint32_t));
    fp.prev = from_little_endian<uint32_t>(buffer + sizeof(uint32_t) * 2);
}

// 将当前节点附近空闲的节点写入到block中？？？还不确定
void BtreeDirectory::write_free_page(uint32_t num, const FreePage& fp)
{
    byte buffer[BLOCK_SIZE] = {};
    // 将下一个空闲节点号存放在block的4-8个字节处
    to_little_endian(fp.next, buffer + sizeof(uint32_t));
    // 将前一个空闲节点号存放在block的8-12个字节处
    to_little_endian(fp.prev, buffer + sizeof(uint32_t) * 2);
    // 把block写入到文件中
    m_stream->write(buffer, BLOCK_SIZE * num, BLOCK_SIZE);
}

// 分配空闲块给节点，即分配空闲块（页即block）
// 空闲块号为其block在文件中的位置
// 分配空闲节点即先判断当前有无空闲节点，无则从文件中开辟一个block出来
uint32_t BtreeDirectory::allocate_page()
{
    // 获取起始空闲页
    auto pg = get_start_free_page();
    // 如果起始空闲页是非法的
    if (pg == INVALID_PAGE)
    {
        // 计算页号，即为文件中的下一个空闲block
        auto result = static_cast<uint32_t>(m_stream->size() / BLOCK_SIZE);
        // resize文件大小
        m_stream->resize(m_stream->size() + BLOCK_SIZE);
        return result;
    }
    // 根据空闲页号读取空闲页附近空闲节点
    FreePage fp;
    read_free_page(pg, fp);
    // 空闲页数量减1
    set_num_free_page(get_num_free_page() - 1);
    // 设置起始空闲页为当前空闲页的下一个
    set_start_free_page(fp.next);
    // 下一个空闲页不是非法页
    if (fp.next != INVALID_PAGE)
    {
        // 读取处下一个空闲页的附近空闲节点，并将其的前一个置于非法
        read_free_page(fp.next, fp);
        fp.prev = INVALID_PAGE;
        // 将下一个空闲节点附近的空闲节点，写入到下一个空闲节点中
        write_free_page(get_start_free_page(), fp);
    }
    // 返回空闲节点号
    return pg;
}

// 回收节点
// 输入的参数num为空闲节点号
void BtreeDirectory::deallocate_page(uint32_t num)
{
    // 如果节点为文件的最后一个block，则进行resize，将这个block回收
    if (num * BLOCK_SIZE == this->m_stream->size())
    {
        this->m_stream->resize((num - 1) * BLOCK_SIZE);
        return;    // Special case where the stream can be shrinked
    }

    // Otherwise add the page to free list
    // 否则的话把这个块加入到空闲块链表头中
    FreePage fp;
    fp.prev = INVALID_PAGE;
    fp.next = get_start_free_page();
    write_free_page(num, fp);

    // 将当前空闲块的prev设置为num
    auto start = get_start_free_page();
    if (start != INVALID_PAGE)
    {
        read_free_page(start, fp);
        fp.prev = num;
        write_free_page(start, fp);
    }
    // 设置起始空闲块为num
    set_start_free_page(num);
    // 空闲块的数量+1
    set_num_free_page(get_num_free_page() + 1);
}

bool BtreeNode::from_buffer(const byte* buffer, size_t size)
{
    const byte* end_of_buffer = buffer + size;

    auto flag = read_little_endian_and_forward<uint32_t>(&buffer, end_of_buffer);
    if (flag == 0)
        return false;
    auto child_num = read_little_endian_and_forward<uint16_t>(&buffer, end_of_buffer);
    auto entry_num = read_little_endian_and_forward<uint16_t>(&buffer, end_of_buffer);

    for (uint16_t i = 0; i < child_num; ++i)
    {
        m_child_indices.push_back(read_little_endian_and_forward<uint32_t>(&buffer, end_of_buffer));
    }
    for (uint16_t i = 0; i < entry_num; ++i)
    {
        DirEntry e;
        std::array<char, Directory::MAX_FILENAME_LENGTH + 1> filename;
        buffer = read_and_forward(buffer, end_of_buffer, filename);
        buffer = read_and_forward(buffer, end_of_buffer, e.id);
        buffer = read_and_forward(buffer, end_of_buffer, e.type);
        filename.back() = 0;
        e.filename = filename.data();
        m_entries.push_back(std::move(e));
    }
    return true;
}

// 将节点的信息写入到buffer中
void BtreeNode::to_buffer(byte* buffer, size_t size) const
{
    // end_of_buffer为buffer的结束位置
    const byte* end_of_buffer = buffer + size;
    // 将四个字节（内容为1）以小端存储的方式写入到buffer中，buffer进行相应的偏移
    buffer = write_little_endian_and_forward(static_cast<uint32_t>(1), buffer, end_of_buffer);
    // 继续写入两个字节（内容为孩子节点的数量）
    buffer = write_little_endian_and_forward(
        static_cast<uint16_t>(m_child_indices.size()), buffer, end_of_buffer);
    // 继续写入两个字节（自己节点中的记录数量）
    buffer = write_little_endian_and_forward(
        static_cast<uint16_t>(m_entries.size()), buffer, end_of_buffer);

    // 每次写入四个字节，将孩子节点号写进去
    for (uint32_t index : m_child_indices)
    {
        buffer = write_little_endian_and_forward(index, buffer, end_of_buffer);
    }

    // 写入自己节点中的每一条记录
    for (auto&& e : m_entries)
    {
        // 如果一条记录中的文件名大小 > MAX_FILENAME_LENGTH，则抛出异常
        if (e.filename.size() > Directory::MAX_FILENAME_LENGTH)
            throwVFSException(ENAMETOOLONG);
        // 创建一个MAX_FILENAME_LENGTH + 1大小的char数组（因为最后有\0所以+1）
        std::array<char, Directory::MAX_FILENAME_LENGTH + 1> filename;
        // 用0填满这个数组
        filename.fill(0);
        // 将一条记录中的文件名放入到数组中
        std::copy(e.filename.begin(), e.filename.end(), filename.begin());
        // 把这个数组(filename)写入到buffer中
        buffer = write_and_forward(filename, buffer, end_of_buffer);
        // 把id写入到buffer中
        buffer = write_and_forward(e.id, buffer, end_of_buffer);
        //把type写入到buff中
        buffer = write_and_forward(e.type, buffer, end_of_buffer);
    }
}

BtreeDirectory::~BtreeDirectory()
{
    try
    {
        flush_cache();
    }
    catch (...)
    {
    }
}

// 刷新m_node_cache中的数据到文件中，根据每个结点的脏位去决定是否刷新该记录
void BtreeDirectory::flush_cache()
{
    // 根据m_node_cache中每个结点的脏位，将内存中的数据刷新到文件上
    for (auto&& pair : m_node_cache)
    {
        auto&& n = *pair.second;
        if (n.is_dirty())
        {
            // 把节点信息接入到节点号对应的block中
            write_node(n.page_number(), n);
            // 复位脏位
            n.clear_dirty();
        }
    }
    // 如果m_node_cache中记录超过8，则清除，防止占用内存过大
    if (m_node_cache.size() > 8)
        m_node_cache.clear();
}

// 判断某个子树是否合法
bool BtreeDirectory::validate_node(const BtreeNode* n, int depth)
{
    // 判断深度是否合法
    if (depth > BTREE_MAX_DEPTH)
        return false;
    // 判断是否有序合法
    if (!std::is_sorted(n->entries().begin(), n->entries().end()))
        return false;
    // 判断记录数量是否合法（感觉这里有错，阶数到底是多少呀？？）
    if (n->parent_page_number() != INVALID_PAGE
        && (n->entries().size() < BTREE_MAX_NUM_ENTRIES / 2
            || n->entries().size() > BTREE_MAX_NUM_ENTRIES))
        return false;
    // 判断其孩子是否合法
    if (!n->is_leaf())
    {
        for (size_t i = 0, size = n->entries().size(); i < size; ++i)
        {
            const Entry& e = n->entries()[i];
            const Node* lchild = retrieve_node(n->page_number(), n->children()[i]);
            const Node* rchild = retrieve_node(n->page_number(), n->children()[i + 1]);
            validate_node(lchild, depth + 1);
            validate_node(rchild, depth + 1);
            if (e < lchild->entries().back() || rchild->entries().front() < e)
                return false;
        }
    }
    return true;
}

// 将m_node_cache清空
void BtreeDirectory::clear_cache() { m_node_cache.clear(); }

// 检索节点（从m_node_cache检索）
BtreeNode* BtreeDirectory::retrieve_existing_node(uint32_t num)
{
    auto iter = m_node_cache.find(num);
    if (iter == m_node_cache.end())
        return nullptr;
    return iter->second.get();
}

// 检索节点（从m_node_cache检索，若不在则创建并放入m_node_cache中）
BtreeDirectory::Node* BtreeDirectory::retrieve_node(uint32_t parent_num, uint32_t num)
{
    // 从m_node_cache中找出num对应的键值对
    auto iter = m_node_cache.find(num);
    // 如果找到了的话
    if (iter != m_node_cache.end())
    {
        // n为Node的普通指针
        auto n = iter->second.get();
        // num对应节点的父节点号合法且正确，则返回node的普通指针
        dir_check(parent_num == INVALID_PAGE || parent_num == n->parent_page_number());
        return n;
    }
    // 如果在m_node_cache总没有找到num对应的键值对
    auto n = make_unique<Node>(parent_num, num);
    // 根据节点号从文件中读取出节点的信息存放在节点中
    read_node(num, *n);
    auto result = n.get();
    // 在m_node_cache中放入键值对
    m_node_cache.emplace(num, std::move(n));
    // 返回node的普通指针
    return result;
}

// ？？
void BtreeDirectory::subflush()
{
    // 若空闲块>5并且空闲块占2/3以上是需要
    if (get_num_free_page() > 5
        && get_num_free_page() > this->m_stream->size() / (BLOCK_SIZE * 3 / 2))
        rebuild();
    flush_cache();
}

// 在b树中查找节点（通过文件名）
std::tuple<BtreeNode*, ptrdiff_t, bool> BtreeDirectory::find_node(const std::string& name)
{
    // 先获取根结点
    BtreeNode* n = get_root_node();
    // 如果根结点为空，返回（空指针，0，false）
    if (!n)
        return std::make_tuple(nullptr, 0, false);
    // 从上往下一层层遍历
    for (int i = 0; i < BTREE_MAX_DEPTH; ++i)
    {
        // 从数组的begin位置到end-1位置二分查找第一个大于或等于num的数字，找到返回该数字的地址，不存在则返回end。通过返回的地址减去起始地址begin,得到找到数字在数组中的下标。
        auto iter = std::lower_bound(n->entries().begin(), n->entries().end(), name);
        // 如果name刚好等于找到结点的filename，则返回（父节点，节点的下标，true）
        if (iter != n->entries().end() && name == iter->filename)
            return std::make_tuple(n, iter - n->entries().begin(), true);
        // 如果n是叶子结点的话，则返回（父节点，没用的下标，false）
        if (n->is_leaf())
            return std::make_tuple(n, iter - n->entries().begin(), false);
        // n不是叶子结点的话，往下一层找结点
        n = retrieve_node(n->page_number(), n->children().at(iter - n->entries().begin()));
    }
    throw CorruptedDirectoryException();    // A loop is present in the "tree" structure
}

// 获取根结点（从m_flags[4]中取出）
BtreeNode* BtreeDirectory::get_root_node()
{
    auto pg = get_root_page();
    if (pg == INVALID_PAGE)
        return nullptr;
    // 检索节点（从m_node_cache检索，若不在则创建并放入m_node_cache中）
    // 注意根结点的父结点号为-1
    return retrieve_node(INVALID_PAGE, pg);
}

// 根据name获取到对应的id和type
bool BtreeDirectory::get_entry_impl(const std::string& name, id_type& id, int& type)
{
    if (name.size() > MAX_FILENAME_LENGTH)
        throwVFSException(ENAMETOOLONG);

    BtreeNode* node;
    ptrdiff_t entry_index;
    bool is_equal;
    std::tie(node, entry_index, is_equal) = find_node(name);

    if (!is_equal || !node)
        return false;
    const Entry& e = node->entries().at(entry_index);
    if (name == e.filename)
    {
        id = e.id;
        type = e.type;
        return true;
    }
    return false;
}

// 根据节点号从（文件中？）读取出节点的信息存放到节点中
// 每个节点按节点号的顺序存放在文件中？？
bool BtreeDirectory::read_node(uint32_t num, BtreeDirectory::Node& n)
{
    if (num == INVALID_PAGE)
        throw CorruptedDirectoryException();
    byte buffer[BLOCK_SIZE];
    // dir_check根据返回值判断目录有没有损坏，即b树有没有损坏
    dir_check(m_stream->read(buffer, num * BLOCK_SIZE, BLOCK_SIZE) == BLOCK_SIZE);
    return n.from_buffer(buffer, array_length(buffer));
}

// 将节点信息写入到节点号对应的block中
void BtreeDirectory::write_node(uint32_t num, const BtreeDirectory::Node& n)
{
    if (num == INVALID_PAGE)
        throw CorruptedDirectoryException();
    byte buffer[BLOCK_SIZE];
    // 把节点信息写入到buffer中
    n.to_buffer(buffer, array_length(buffer));
    // 讲buffer写入到节点号对应的block中
    m_stream->write(buffer, num * BLOCK_SIZE, BLOCK_SIZE);
}

// 增加一条记录到树中
bool BtreeDirectory::add_entry_impl(const std::string& name, const id_type& id, int type)
{
    if (name.size() > MAX_FILENAME_LENGTH)
        throwVFSException(ENAMETOOLONG);

    BtreeNode* node;
    bool is_equal;
    std::tie(node, std::ignore, is_equal) = find_node(name);

    if (is_equal)
    {
        return false;
    }

    if (!node)
    {
        set_root_page(allocate_page());
        node = get_root_node();
        node->mutable_entries().emplace_back(Entry{name, id, static_cast<uint32_t>(type)});
        return true;
    }
    insert_and_balance(node, Entry{name, id, static_cast<uint32_t>(type)}, INVALID_PAGE, 0);
    return true;
}

// 调整节点n在m_node_cache中的孩子节点的父节点号为parent
void BtreeDirectory::adjust_children_in_cache(BtreeNode* n, uint32_t parent)
{
    // 遍历当前节点的每一个孩子节点
    for (uint32_t c : n->children())
    {
        // 尝试从m_node_cache中取出孩子节点
        auto child = retrieve_existing_node(c);
        // 如果从m_node_cache中取出成功，将孩子节点的父节点号设置为parent
        if (child)
            child->mutable_parent_page_number() = parent;
    }
}

// 插入并调整平衡函数（从根结点开始操作还是？？）
// This function assumes that every parent node of n is already in the cache
// 这个函数假设n的所有父节点都已经在缓存中
void BtreeDirectory::insert_and_balance(BtreeNode* n, Entry e, uint32_t additional_child, int depth)
{
    // 检查深度有没有超过限制
    dir_check(depth < BTREE_MAX_DEPTH);
    // 根据e往下找一层
    auto iter = std::lower_bound(n->mutable_entries().begin(), n->mutable_entries().end(), e);
    // 如果插入的结点号合法且n不是叶子结点
    if (additional_child != INVALID_PAGE && !n->is_leaf())
        // 插入结点到合适的位置中
        insert(n->mutable_children(), iter - n->entries().begin() + 1, additional_child);
    // 将记录插入到结点n合适的位置中
    insert(n->mutable_entries(), iter - n->entries().begin(), std::move(e));

    // 如果n结点的记录超过限制，则要进行分裂操作
    if (n->entries().size() > BTREE_MAX_NUM_ENTRIES)
    {
        // 创建一个兄弟结点
        Node* sibling = retrieve_node(n->parent_page_number(), allocate_page());
        // 计算n结点记录的中间位置
        auto middle_index = n->entries().size() / 2 - 1;
        // 取出n结点记录的中间位置的记录
        e = std::move(n->mutable_entries()[middle_index]);
        // 如果n结点不是叶子结点
        if (!n->is_leaf())
        {
            // 在middle_index + 1位置将n的孩子节点划分为两部分
            slice(n->mutable_children(), sibling->mutable_children(), middle_index + 1);
            // 调整节点sibling在m_node_cache中的孩子节点的父节点号当前节点n的节点号
            adjust_children_in_cache(sibling);
        }
        // 在middle_index + 1位置将n的记录节点划分为两部分
        slice(n->mutable_entries(), sibling->mutable_entries(), middle_index + 1);
        // 弹出n的最后一条记录，因为我们已经取出到e中了
        n->mutable_entries().pop_back();
        // 如果n是根结点，则进行建立新根结点操作
        if (n->parent_page_number() == INVALID_PAGE)
        {
            // 分配一个新的空闲块给节点
            auto new_root_page = allocate_page();
            // 创建根结点
            Node* root = retrieve_node(INVALID_PAGE, new_root_page);
            // 将两部分的节点号连到新根节点上
            root->mutable_children().push_back(n->page_number());
            root->mutable_children().push_back(sibling->page_number());
            // 放入e记录
            root->mutable_entries().push_back(std::move(e));
            // 设置根节点号
            set_root_page(new_root_page);
            // 设置n和sibling节点的父节点号为新根节点
            n->mutable_parent_page_number() = new_root_page;
            sibling->mutable_parent_page_number() = new_root_page;
        }
        // 否则从下往上递归调用插入平衡函数
        else
        {
            insert_and_balance(retrieve_existing_node(n->parent_page_number()),
                               std::move(e),
                               sibling->page_number(),
                               depth + 1);
        }
    }
}

// ？？
BtreeNode* BtreeDirectory::replace_with_sub_entry(BtreeNode* n, ptrdiff_t index, int depth)
{
    dir_check(depth < BTREE_MAX_DEPTH);
    if (n->is_leaf())
    {
        erase(n->mutable_entries(), index);
        return n;
    }
    else
    {
        Node* lchild = retrieve_node(n->page_number(), n->children().at(index));
        while (!lchild->is_leaf())
            lchild = retrieve_node(lchild->page_number(), lchild->children().back());
        n->mutable_entries().at(index) = std::move(lchild->mutable_entries().back());
        lchild->mutable_entries().pop_back();
        return lchild;
    }
}

// 删除节点（根据节点号，调用deallocate_page回收块函数实现）
void BtreeDirectory::del_node(BtreeNode* n)
{
    if (!n)
        return;
    // 调用回收块函数
    deallocate_page(n->page_number());
    // 将node的记录从m_node_cache中擦除
    m_node_cache.erase(n->page_number());
}

// 找到node节点的左边or右边节点
std::pair<ptrdiff_t, BtreeNode*> BtreeDirectory::find_sibling(const BtreeNode* parent,
                                                              const BtreeNode* node)
{
    // 检查参数是否正确
    dir_check(parent->page_number() == node->parent_page_number());
    // 获取父节点的孩子节点们的引用
    const auto& child_indices = parent->children();
    // 找自己在孩子节点们中的位置
    auto iter = std::find(child_indices.begin(), child_indices.end(), node->page_number());
    auto index = iter - child_indices.begin();
    dir_check(iter != child_indices.end());

    // 如果自己是孩子节点中的最右边那个，则返回自己左边节点的下标和节点指针
    if (iter + 1 == child_indices.end())
        return std::make_pair(
            index - 1, retrieve_node(parent->page_number(), parent->children().at(index - 1)));

    // 否则返回自己右边的节点下标和其指针
    return std::make_pair(index,
                          retrieve_node(parent->page_number(), parent->children().at(index + 1)));
}

// 调整操作（作用是啥？？？）
// 左节点、separator、右节点合并，取出中间节点做新的separator，并对左右节点记录和孩子节点做调整
void BtreeDirectory::rotate(BtreeNode* left, BtreeNode* right, Entry& separator)
{
    
    std::vector<Entry> temp_entries;
    // reserve为vector预留capacity，超过会按这个函数再次分配
    temp_entries.reserve(left->entries().size() + right->entries().size() + 1);

    // move_iterator 迭代器适配器，又可简称为移动迭代器，其可以实现以移动而非复制的方式，将某个区域空间中的元素移动至另一个指定的空间。
    // https://blog.csdn.net/qq_37529913/article/details/119859888
    typedef std::move_iterator<decltype(temp_entries.begin())> entry_move_iterator;

    // 将左节点的记录移动到temp_entries中
    steal(temp_entries, left->mutable_entries());
    // 将separator移动到temp_entries中
    temp_entries.push_back(std::move(separator));
    // 将右节点的记录移动到temp_entries中
    steal(temp_entries, right->mutable_entries());

    // 计算temp_entries中间位置的下标
    auto middle = temp_entries.size() / 2;
    // 将temp_entries中间位置的记录移动到separator中
    separator = std::move(temp_entries.at(middle));
    // 将temp_entries中间位置左边的记录移动到左节点记录中（同时左节点会置脏）
    left->mutable_entries().assign(entry_move_iterator(temp_entries.begin()),
                                   entry_move_iterator(temp_entries.begin() + middle));
    // 将temp_entries中间位置右边的记录移动到右节点记录中
    right->mutable_entries().assign(entry_move_iterator(temp_entries.begin() + middle + 1),
                                    entry_move_iterator(temp_entries.end()));

    // 如果左右节点都有孩子节点
    if (!left->children().empty() && !right->children().empty())
    {
        
        std::vector<uint32_t> temp_children;
        temp_children.reserve(left->children().size() + right->children().size());
        // 将左节点的孩子节点移动到temp_children中
        steal(temp_children, left->children());
        // 将右节点的孩子节点移动到temp_children中
        steal(temp_children, right->children());
        
        // 多拿一个孩子节点给做节点（因为上面做的分配就是左节点会多一个记录）
        left->mutable_children().assign(temp_children.begin(), temp_children.begin() + middle + 1);
        // 少拿一个孩子节点给做节点
        right->mutable_children().assign(temp_children.begin() + middle + 1, temp_children.end());
        // 调整节点在m_node_cache中的孩子节点的父节点号当前节点n的节点号
        adjust_children_in_cache(left);
        adjust_children_in_cache(right);
    }
}

// 合并操作（结合balance_up函数就很好理解啦）
// entry_index来自find_sibling(parent, n)，为n的兄弟姐妹下标
void BtreeDirectory::merge(BtreeNode* left,
                           BtreeNode* right,
                           BtreeNode* parent,
                           ptrdiff_t entry_index)
{
    // 将parent的下标为entry_index的记录移动到左节点中
    left->mutable_entries().push_back(std::move(parent->mutable_entries().at(entry_index)));
    erase(parent->mutable_entries(), entry_index);
    // 将右边节点擦除
    parent->mutable_children().erase(std::find(parent->mutable_children().begin(),
                                               parent->mutable_children().end(),
                                               right->page_number()));
    // 将右节点的记录移动到左节点末尾
    steal(left->mutable_entries(), right->mutable_entries());
    // 调整节点在m_node_cache中的孩子节点的父节点号当前节点n的节点号
    this->adjust_children_in_cache(right, left->page_number());
    // 将右节点的孩子节点移动左节点中
    steal(left->mutable_children(), right->mutable_children());
    // 删除节点
    this->del_node(right);
}

// 平衡b树操作（这是一个递归函数）
// 什么时候用，怎么用？？
// This funciton assumes that every parent node is in the cache
// 这个函数假设每个父节点都在缓存中
void BtreeDirectory::balance_up(BtreeNode* n, int depth)
{
    // 检查depth是不是超过限制了
    dir_check(depth < BTREE_MAX_DEPTH);

    // 如果n是根结点并且n没有记录，但有孩子节点
    if (n->parent_page_number() == INVALID_PAGE && n->entries().empty() && !n->children().empty())
    {
        // 这种情况孩子节点只能有一个
        dir_check(n->children().size() == 1);
        // 调整节点n在m_node_cache中的孩子节点的父节点号为INVALID_PAGE，即将其子节点升级为根结点
        adjust_children_in_cache(n, INVALID_PAGE);
        // 设置根结点号为这个孩子节点号
        set_root_page(n->children().front());
        // 删除没有记录的根结点
        del_node(n);
        // 结束运行
        return;
    }
    // 如果n是根结点 或 n的记录数>=BTREE_MAX_NUM_ENTRIES / 2，则直接return
    // why？？什么原理
    if (n->parent_page_number() == INVALID_PAGE || n->entries().size() >= BTREE_MAX_NUM_ENTRIES / 2)
        return;

    // 获取父节点指针（仅从m_node_cache检索）
    Node* parent = retrieve_existing_node(n->parent_page_number());
    dir_check(parent != nullptr);

    // 找到n节点的兄弟（左边或右边）的下标和指针
    ptrdiff_t entry_index;
    BtreeNode* sibling;
    std::tie(entry_index, sibling) = find_sibling(parent, n);

    // 如果节点n的记录数量和其兄弟的记录数和 < BTREE_MAX_NUM_ENTRIES
    // 注意在merge操作会从父节点搞一条记录下来，所以这里用<而不是<=
    if (n->entries().size() + sibling->entries().size() < BTREE_MAX_NUM_ENTRIES)
    {
        if (n->entries().back() < sibling->entries().front())
            merge(n, sibling, parent, entry_index);
        else
            merge(sibling, n, parent, entry_index);
    }
    // >的话，则进行rotate操作
    else
    {
        if (n->entries().back() < sibling->entries().front())
            rotate(n, sibling, parent->mutable_entries().at(entry_index));
        else
            rotate(sibling, n, parent->mutable_entries().at(entry_index));
    }

    // 从下往上去操作平衡
    balance_up(parent, depth + 1);
}

// 删除b树中的一条记录
bool BtreeDirectory::remove_entry_impl(const std::string& name, id_type& id, int& type)
{
    if (name.size() > MAX_FILENAME_LENGTH)
        throwVFSException(ENAMETOOLONG);

    BtreeNode* node;
    ptrdiff_t entry_index;
    bool is_equal;
    std::tie(node, entry_index, is_equal) = find_node(name);

    if (!is_equal || !node)
        return false;
    const Entry& e = node->entries().at(entry_index);

    id = e.id;
    type = e.type;
    auto leaf_node = replace_with_sub_entry(node, entry_index, 0);
    // 删除后需要从该节点开始调整平衡？？
    balance_up(leaf_node, 0);
    return true;
}

// 验证空闲块链表有没有损坏
bool BtreeDirectory::validate_free_list()
{
    auto pg = get_start_free_page();
    uint32_t prev = INVALID_PAGE;
    FreePage fp;
    for (size_t i = 0; i < get_num_free_page(); ++i)
    {
        read_free_page(pg, fp);
        if (fp.prev != prev)
            return false;
        prev = pg;
        pg = fp.next;
    }
    return pg == INVALID_PAGE;
}

// 严重b树合不合法（通过validate_node(root, 0)实现）
bool BtreeDirectory::validate_btree_structure()
{
    Node* root = get_root_node();
    if (root)
        return validate_node(root, 0);
    return true;
}

// 将树的结构写到某个文件中
void BtreeDirectory::to_dot_graph(const char* filename)
{
    auto root = get_root_node();
    if (!root)
        return;
    FILE* fp = fopen(filename, "w");
    if (!fp)
        throwVFSException(errno);
    fputs("digraph Btree{\nrankdir=BT;\n", fp);
    write_dot_graph(root, fp);
    fputs("\n}\n", fp);
    if (feof(fp))
    {
        int saved_errno = errno;
        fclose(fp);    // Calling this will modify `errno`.
        throw VFSException(saved_errno);
    }
    fclose(fp);
}

static std::string to_string(const std::vector<DirEntry>& entries)
{
    std::string result;
    for (auto&& e : entries)
    {
        result += e.filename;
        result += '\n';
    }
    return result;
}

// ？？写节点关系图
void BtreeDirectory::write_dot_graph(const BtreeNode* n, FILE* fp)
{
    if (n->parent_page_number() != INVALID_PAGE)
        fprintf(fp,
                "    node%u -> node%u [style=dotted];\n",
                n->page_number(),
                n->parent_page_number());
    fprintf(fp,
            "node%u [label=\"node%u:\n\n%s\"];\n",
            n->page_number(),
            n->page_number(),
            to_string(n->entries()).c_str());
    for (uint32_t c : n->children())
        fprintf(fp, "    node%u -> node%u;\n", c, n->page_number());
    for (uint32_t c : n->children())
        write_dot_graph(retrieve_node(n->page_number(), c), fp);
}

// 回调遍历（递归）直至n->children()为空
template <class Callback>
void BtreeDirectory::recursive_iterate(const BtreeNode* n, const Callback& cb, int depth)
{
    dir_check(depth < BTREE_MAX_DEPTH);
    for (const Entry& e : n->entries())
        cb(e.filename, e.id, e.type);
    for (uint32_t c : n->children())
        recursive_iterate(retrieve_node(n->page_number(), c), cb, depth + 1);
}

// ？？
template <class Callback>
void BtreeDirectory::mutable_recursive_iterate(BtreeNode* n, const Callback& cb, int depth)
{
    dir_check(depth < BTREE_MAX_DEPTH);
    for (Entry& e : n->mutable_entries())
        cb(std::move(e));
    for (uint32_t c : n->children())
        mutable_recursive_iterate(retrieve_node(n->page_number(), c), cb, depth + 1);
}

// 实现目录项遍历函数，通过调用回调函数
void BtreeDirectory::iterate_over_entries_impl(const BtreeDirectory::callback& cb)
{
    auto root = get_root_node();
    if (root)
        //
        recursive_iterate(root, cb, 0);
}

// ？？
void BtreeDirectory::rebuild()
{
    auto root = get_root_node();
    if (!root)
        return;

    std::vector<DirEntry> entries;
    entries.reserve(this->m_stream->size() / BLOCK_SIZE * BTREE_MAX_NUM_ENTRIES);
    mutable_recursive_iterate(
        root, [&](DirEntry&& e) { entries.push_back(std::move(e)); }, 0);
    clear_cache();    // root is invalid after this line
    m_stream->resize(0);
    set_num_free_page(0);
    set_start_free_page(INVALID_PAGE);
    set_root_page(INVALID_PAGE);
    for (DirEntry& e : entries)
        add_entry(e.filename, e.id, e.type);
}

// 判断是不是空树
bool BtreeDirectory::empty()
{
    auto root = get_root_node();
    return root == nullptr || root->entries().empty();
}
}    // namespace securefs
