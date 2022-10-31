#pragma once
#include "thread_safety_annotations.hpp"

// lock_guard模版类在c++11中mutex头文件中有提供，自己重写的原因是为了能够利用clang进行线程安全分析
// 实现线程保护功能，通过锁来实现
// 模版类，这个模版类定义的对象在创建的时候会上锁，销毁的时候释放

namespace securefs
{
// 注意传入的类Lockable要有lock函数的哦
template <class Lockable>
// THREAD_ANNOTATION_SCOPED_CAPABILITY实现RAII-style锁的类的一个属性，其功能在构造函数中获得，在析构函数中释放
class THREAD_ANNOTATION_SCOPED_CAPABILITY LockGuard
{
private:
    Lockable* m_lock;

public:
    // THREAD_ANNOTATION_ACQUIRE(lock)表示函数进入时才持有lock，退出不持有
    // lock.lock(exclusive);
    explicit LockGuard(Lockable& lock, bool exclusive) THREAD_ANNOTATION_ACQUIRE(lock)
        : m_lock(&lock)
    {
        lock.lock(exclusive);
    }
    // THREAD_ANNOTATION_ACQUIRE(lock)表示函数进入时才持有lock，退出不持有
    // lock.lock();
    explicit LockGuard(Lockable& lock) THREAD_ANNOTATION_ACQUIRE(lock) : m_lock(&lock)
    {
        lock.lock();
    }
    // THREAD_ANNOTATION_RELEASE()表示函数退出前释放lock
    ~LockGuard() THREAD_ANNOTATION_RELEASE() { m_lock->unlock(); }
    // 禁止拷贝
    LockGuard(LockGuard&&) = delete;
    LockGuard(const LockGuard&) = delete;
    LockGuard& operator=(LockGuard&&) = delete;
    LockGuard& operator=(const LockGuard&) = delete;
};
}    // namespace securefs
