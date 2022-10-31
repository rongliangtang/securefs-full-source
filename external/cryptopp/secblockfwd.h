// secblockfwd.h - written and placed in the public domain by Jeffrey Walton

/// \file secblockfwd.h
/// \brief Forward declarations for SecBlock
/// \details secblock.h and misc.h have a circular dependency. secblockfwd.h
///  allows the library to sidestep the circular dependency, and reference
///  SecBlock classes without the full implementation.
/// \since Crypto++ 8.3

#ifndef CRYPTOPP_SECBLOCKFWD_H
#define CRYPTOPP_SECBLOCKFWD_H

#include "config.h"

NAMESPACE_BEGIN(CryptoPP)

template <class T, class A>
class SecBlock;

template <class T, bool A>
class AllocatorWithCleanup;

// 将一个模版用typedef重命名
// 定义SecByteBlock，byte类型的block，不对齐
typedef SecBlock<byte, AllocatorWithCleanup<byte, false> > SecByteBlock;
// 定义SecWordBlock，word类型的block，不对齐
typedef SecBlock<word, AllocatorWithCleanup<word, false> > SecWordBlock;
// 定义AlignedSecByteBlock，byte类型的block，对齐
// AllocatorWithCleanup的作用是通过清理来分配一块内存
typedef SecBlock<byte, AllocatorWithCleanup<byte,  true> > AlignedSecByteBlock;

NAMESPACE_END

#endif  // CRYPTOPP_SECBLOCKFWD_H
