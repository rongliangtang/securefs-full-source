#include "fuse_tracer.h"

#include <cctype>
#include <ctime>

namespace securefs
{
// 注意命名空间嵌套 
namespace details
{
    namespace
    {

        template <typename StatClass>
        // decltype则可以从一个变量或表达式中得到类型，auto是从值得到类型
        // 在 C++11 中，可以结合使用尾随返回类型上的 decltype 类型说明符和 auto 关键字来声明其返回类型依赖于其模板参数类型的模板函数。
        auto get_atim_helper(const StatClass* st, int) -> decltype(&st->st_atim)
        {
            return &st->st_atim;
        }

        template <typename StatClass>
        auto get_atim_helper(const StatClass* st, double) -> decltype(&st->st_atimespec)
        {
            return &st->st_atimespec;
        }

        template <typename StatClass>
        const struct fuse_timespec* get_atim_helper(const StatClass*, ...)
        {
            return nullptr;
        }

        template <typename StatClass>
        auto get_mtim_helper(const StatClass* st, int) -> decltype(&st->st_mtim)
        {
            return &st->st_mtim;
        }

        template <typename StatClass>
        auto get_mtim_helper(const StatClass* st, double) -> decltype(&st->st_mtimespec)
        {
            return &st->st_mtimespec;
        }

        template <typename StatClass>
        const struct fuse_timespec* get_mtim_helper(const StatClass*, ...)
        {
            return nullptr;
        }

        template <typename StatClass>
        auto get_ctim_helper(const StatClass* st, int) -> decltype(&st->st_ctim)
        {
            return &st->st_ctim;
        }

        template <typename StatClass>
        auto get_ctim_helper(const StatClass* st, double) -> decltype(&st->st_ctimespec)
        {
            return &st->st_ctimespec;
        }

        template <typename StatClass>
        const struct fuse_timespec* get_ctim_helper(const StatClass*, ...)
        {
            return nullptr;
        }

        template <typename StatClass>
        auto get_birthtim_helper(const StatClass* st, int) -> decltype(&st->st_birthtim)
        {
            return &st->st_birthtim;
        }

        template <typename StatClass>
        auto get_birthtim_helper(const StatClass* st, double) -> decltype(&st->st_birthtimespec)
        {
            return &st->st_birthtimespec;
        }

        template <typename StatClass>
        const struct fuse_timespec* get_birthtim_helper(const StatClass*, ...)
        {
            return nullptr;
        }

        // 根据v的不同的类型，输出v到fp文件流中
        void print(FILE* fp, const int* v) { fprintf(fp, "%d", *v); }
        void print(FILE* fp, const unsigned* v) { fprintf(fp, "%u", *v); }
        void print(FILE* fp, const long* v) { fprintf(fp, "%ld", *v); }
        void print(FILE* fp, const unsigned long* v) { fprintf(fp, "%lu", *v); }
        void print(FILE* fp, const long long* v) { fprintf(fp, "%lld", *v); }
        void print(FILE* fp, const unsigned long long* v) { fprintf(fp, "%llu", *v); }

        // 输出fuse的时间信息
        void print(FILE* fp, const struct fuse_timespec* v)
        {
            std::tm tm;
#ifdef _WIN32
            if (gmtime_s(&tm, &v->tv_sec))
                return;
#else
            if (!gmtime_r(&v->tv_sec, &tm))
                return;
#endif
            char buffer[256] = {};
            std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
            fprintf(fp, "%s.%09d UTC", buffer, static_cast<int>(v->tv_nsec));
        }

        void print(FILE* fp, const char* v)
        {
            fputc('\"', fp);
            while (*v)
            {
                int ch = *v;
                switch (ch)
                {
                case '\"':
                    fputs("\\\"", fp);
                    break;
                case '\'':
                    fputs("\\\'", fp);
                    break;
                case '\\':
                    fputs("\\\\", fp);
                    break;
                case '\a':
                    fputs("\\a", fp);
                    break;
                case '\b':
                    fputs("\\b", fp);
                    break;
                case '\n':
                    fputs("\\n", fp);
                    break;
                case '\t':
                    fputs("\\t", fp);
                    break;
                case '\f':
                    fputs("\\f", fp);
                    break;
                default:
                    if (ch > 0 && std::iscntrl(ch))
                        fprintf(fp, "\\x%02x", ch);
                    else
                        fputc(ch, fp);
                }
                ++v;
            }
            fputc('\"', fp);
        }

        // 输出文件的信息
        void print(FILE* fp, const struct fuse_stat* v)
        {
            fprintf(fp,
                    "{st_size=%lld, st_mode=%#o, st_nlink=%lld, st_uid=%lld, st_gid=%lld, "
                    "st_blksize=%lld, st_blocks=%lld",
                    static_cast<long long>(v->st_size),
                    static_cast<unsigned>(v->st_mode),
                    static_cast<long long>(v->st_nlink),
                    static_cast<long long>(v->st_uid),
                    static_cast<long long>(v->st_gid),
                    static_cast<long long>(v->st_blksize),
                    static_cast<long long>(v->st_blocks));

            auto atim = get_atim_helper(v, 0);
            if (atim)
            {
                fputs(", st_atim=", fp);
                ::securefs::details::print(fp, atim);
            }
            auto mtim = get_mtim_helper(v, 0);
            if (mtim)
            {
                fputs(", st_mtim=", fp);
                ::securefs::details::print(fp, mtim);
            }
            auto ctim = get_ctim_helper(v, 0);
            if (ctim)
            {
                fputs(", st_ctim=", fp);
                ::securefs::details::print(fp, ctim);
            }
            auto birthtim = get_birthtim_helper(v, 0);
            if (birthtim)
            {
                fputs(", st_birthtim=", fp);
                ::securefs::details::print(fp, birthtim);
            }
            fputc('}', fp);
        }

        // 输出文件信息
        void print(FILE* fp, const struct fuse_file_info* v)
        {
            fprintf(fp, "{fh=0x%p, flags=%#o}", (const void*)(v->fh), v->flags);
        }

        // 输出文件系统的信息
        void print(FILE* fp, const struct fuse_statvfs* v)
        {
            fprintf(fp,
                    "{f_bsize=%lld, f_frsize=%lld, f_blocks=%lld, f_bfree=%lld, f_bavail=%lld, "
                    "f_files=%lld, f_ffree=%lld, f_favail=%lld, f_fsid=%lld, f_flag=%lld, "
                    "f_namemax=%lld}",
                    static_cast<long long>(v->f_bsize),
                    static_cast<long long>(v->f_frsize),
                    static_cast<long long>(v->f_blocks),
                    static_cast<long long>(v->f_bfree),
                    static_cast<long long>(v->f_bavail),
                    static_cast<long long>(v->f_files),
                    static_cast<long long>(v->f_ffree),
                    static_cast<long long>(v->f_favail),
                    static_cast<long long>(v->f_fsid),
                    static_cast<long long>(v->f_flag),
                    static_cast<long long>(v->f_namemax));
        }
    }    // namespace
}    // namespace details

// 单个arg的输出
void FuseTracer::print(FILE* fp, const WrappedFuseArg& arg)
{
    // arg.value不存在，则输出空，结束运行
    if (!arg.value)
    {
        fputs("null", fp);
        return;
    }

    // define宏定义，直接替换代码
    // 若存在且arg的type_index,输出对应类型的信息
#define SECUREFS_DISPATCH(type)                                                                    \
    else if (arg.type_index == std::type_index(typeid(type)))                                      \
    {                                                                                              \
        ::securefs::details::print(fp, static_cast<const type*>(arg.value));                       \
    }

    // 根据arg的value的类型，执行对应的代码
    // 下面会进行宏定义的替换，这种写法很节省自己编写的代码量！
    if (0)
    {
    }
    SECUREFS_DISPATCH(char)
    SECUREFS_DISPATCH(struct fuse_stat)
    SECUREFS_DISPATCH(int)
    SECUREFS_DISPATCH(unsigned)
    SECUREFS_DISPATCH(long)
    SECUREFS_DISPATCH(unsigned long)
    SECUREFS_DISPATCH(long long)
    SECUREFS_DISPATCH(unsigned long long)
    SECUREFS_DISPATCH(struct fuse_file_info)
    SECUREFS_DISPATCH(struct fuse_statvfs)
    SECUREFS_DISPATCH(struct fuse_timespec)
    else { fprintf(fp, "0x%p", arg.value); }
#undef SECUREFS_DISPATCH    //撤销define，让对应的宏定义失效
}

// 多个arg的输出，通过循环调用print(fp, args[i])实现
void FuseTracer::print(FILE* fp, const WrappedFuseArg* args, size_t arg_size)
{
    fputc('(', fp);
    for (size_t i = 0; i < arg_size; ++i)
    {
        if (i)
        {
            fputs(", ", fp);
        }
        print(fp, args[i]);
    }
    fputc(')', fp);
}

// 输出函数的信息
void FuseTracer::print_function_starts(
    Logger* logger, const char* funcsig, int lineno, const WrappedFuseArg* args, size_t arg_size)
{
    // 如果logger->get_level() <= LoggingLevel::kLogTrace则执行
    if (logger && logger->get_level() <= LoggingLevel::kLogTrace)
    {
        // 输出前半部分log：[Trace] [0x70000d09a000] [2022-10-26 11:23:29.111629000 UTC] [int securefs::lite::getattr(const char *, struct stat *):154]
        logger->prelog(LoggingLevel::kLogTrace, funcsig, lineno);
        // 后处理，加入换行符并刷新
        DEFER(logger->postlog(LoggingLevel::kLogTrace));
        // 输出后半部分内容，通过调用print(logger->m_fp, args, arg_size)实现
        fputs("Function starts with arguments ", logger->m_fp);
        print(logger->m_fp, args, arg_size);
    }
}

// 输出函数的信息和返回值
void FuseTracer::print_function_returns(Logger* logger,
                                        const char* funcsig,
                                        int lineno,
                                        const WrappedFuseArg* args,
                                        size_t arg_size,
                                        long long rc)
{
    if (logger && logger->get_level() <= LoggingLevel::kLogTrace)
    {
        logger->prelog(LoggingLevel::kLogTrace, funcsig, lineno);
        DEFER(logger->postlog(LoggingLevel::kLogTrace));

        fputs("Function ends with arguments ", logger->m_fp);
        print(logger->m_fp, args, arg_size);
        fprintf(logger->m_fp, " and return code %lld", rc);
    }
}

// 输出函数执行失败的信息和异常信息
void FuseTracer::print_function_exception(Logger* logger,
                                          const char* funcsig,
                                          int lineno,
                                          const WrappedFuseArg* args,
                                          size_t arg_size,
                                          const std::exception& e,
                                          int rc)
{
    if (logger && logger->get_level() <= LoggingLevel::kLogError)
    {
        logger->prelog(LoggingLevel::kLogError, funcsig, lineno);
        DEFER(logger->postlog(LoggingLevel::kLogError));

        fputs("Function fails with arguments ", logger->m_fp);
        print(logger->m_fp, args, arg_size);
        fprintf(logger->m_fp,
                " with return code %d because it encounters exception %s: %s",
                rc,
                get_type_name(e).get(),
                e.what());
    }
}

}    // namespace securefs
