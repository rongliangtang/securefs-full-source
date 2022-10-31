#pragma once

// 定义一下securefs要用到的常量
namespace securefs
{
    // 0x表示16进制
const unsigned kOptionNoAuthentication = 0x1, kOptionReadOnly = 0x2, kOptionStoreTime = 0x4,
               kOptionCaseFoldFileName = 0x8, kOptionNFCFileName = 0x10;
}
