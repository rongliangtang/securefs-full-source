#pragma once
// Enable thread safety attributes only with clang.
// The attributes can be safely erased when compiling with other compilers.
// 只使用clang来启用线程安全属性。
// 在使用其他编译器编译时，可以安全地擦除属性。
#if defined(__clang__) && (!defined(SWIG))
// __atrribute__ 是一个编译器指令，它指定声明的特征，允许更多的错误检查和高级优化。
// 这个文件将用于线程安全的一些注解用__atrribute__进行define
// 参考资料：
// https://clang.llvm.org/docs/ThreadSafetyAnalysis.html
// https://blog.csdn.net/qq_32648921/article/details/109114887
// https://blog.csdn.net/zxpoiu/article/details/115963687
#define THREAD_ANNOTATION_ATTRIBUTE__(x) __attribute__((x))
#else
#define THREAD_ANNOTATION_ATTRIBUTE__(x)    // no-op
#endif

#define THREAD_ANNOTATION_CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE__(capability(x))

#define THREAD_ANNOTATION_SCOPED_CAPABILITY THREAD_ANNOTATION_ATTRIBUTE__(scoped_lockable)

#define THREAD_ANNOTATION_GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE__(guarded_by(x))

#define THREAD_ANNOTATION_PT_GUARDED_BY(x) THREAD_ANNOTATION_ATTRIBUTE__(pt_guarded_by(x))

#define THREAD_ANNOTATION_ACQUIRED_BEFORE(...)                                                     \
    THREAD_ANNOTATION_ATTRIBUTE__(acquired_before(__VA_ARGS__))

#define THREAD_ANNOTATION_ACQUIRED_AFTER(...)                                                      \
    THREAD_ANNOTATION_ATTRIBUTE__(acquired_after(__VA_ARGS__))

#define THREAD_ANNOTATION_REQUIRES(...)                                                            \
    THREAD_ANNOTATION_ATTRIBUTE__(requires_capability(__VA_ARGS__))

#define THREAD_ANNOTATION_REQUIRES_SHARED(...)                                                     \
    THREAD_ANNOTATION_ATTRIBUTE__(requires_shared_capability(__VA_ARGS__))

#define THREAD_ANNOTATION_ACQUIRE(...)                                                             \
    THREAD_ANNOTATION_ATTRIBUTE__(acquire_capability(__VA_ARGS__))

#define THREAD_ANNOTATION_ACQUIRE_SHARED(...)                                                      \
    THREAD_ANNOTATION_ATTRIBUTE__(acquire_shared_capability(__VA_ARGS__))

#define THREAD_ANNOTATION_RELEASE(...)                                                             \
    THREAD_ANNOTATION_ATTRIBUTE__(release_capability(__VA_ARGS__))

#define THREAD_ANNOTATION_RELEASE_SHARED(...)                                                      \
    THREAD_ANNOTATION_ATTRIBUTE__(release_shared_capability(__VA_ARGS__))

#define THREAD_ANNOTATION_TRY_ACQUIRE(...)                                                         \
    THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_capability(__VA_ARGS__))

#define THREAD_ANNOTATION_TRY_ACQUIRE_SHARED(...)                                                  \
    THREAD_ANNOTATION_ATTRIBUTE__(try_acquire_shared_capability(__VA_ARGS__))

#define THREAD_ANNOTATION_EXCLUDES(...) THREAD_ANNOTATION_ATTRIBUTE__(locks_excluded(__VA_ARGS__))

#define THREAD_ANNOTATION_ASSERT_CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE__(assert_capability(x))

#define THREAD_ANNOTATION_ASSERT_SHARED_CAPABILITY(x)                                              \
    THREAD_ANNOTATION_ATTRIBUTE__(assert_shared_capability(x))

#define THREAD_ANNOTATION_RETURN_CAPABILITY(x) THREAD_ANNOTATION_ATTRIBUTE__(lock_returned(x))

#define THREAD_ANNOTATION_NO_THREAD_SAFETY_ANALYSIS                                                \
    THREAD_ANNOTATION_ATTRIBUTE__(no_thread_safety_analysis)
