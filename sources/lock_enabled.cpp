#include "lock_enabled.h"
#include <atomic>
// C++11提供原子库<atomic>，原子库中定义的数据类型，对这些类型的所有操作都是原子的
// 对原子类型的访问，最主要的就是读和写，但原子库提供的对应原子操作是load()与store(val)
// 原子操作：顾名思义就是不可分割的操作，该操作只存在未开始和已完成两种状态，不存在中间状态

namespace securefs
{
// 定义bool原子类型，默认值为true
static std::atomic_bool lock_flag{true};
// 获取bool原子类型的值，load()为原子操作
bool is_lock_enabled() { return lock_flag.load(); }
// 设置bool原子类型的值，store()为原子操作
void set_lock_enabled(bool value) { return lock_flag.store(value); }
}    // namespace securefs
