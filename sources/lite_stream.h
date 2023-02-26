#pragma once

#include "streams.h"

#include <cryptopp/aes.h>
#include <cryptopp/sm4.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rng.h>
#include <cryptopp/secblock.h>

namespace securefs
{
namespace lite
{
    class CorruptedStreamException : public ExceptionBase
    {
    public:
        std::string message() const override;
    };

    // AESGCMCryptStream为AES-GCM算法的加密处理类，继承自BlockBasedStream类别
    // 以block为单位处理，block为fuse文件系统的块大小？？
    class AESGCMCryptStream : public BlockBasedStream
    {
    private:
        // 将AES改为SM4
        // 定义加密器
        CryptoPP::GCM<CryptoPP::SM4>::Encryption m_encryptor;
        // 定义解密器
        CryptoPP::GCM<CryptoPP::SM4>::Decryption m_decryptor;
        // m_stream是加密后的文件数据流
        std::shared_ptr<StreamBase> m_stream;
        // m_buffer是读取的某块的数据
        // m_auxiliary存放附加消息（4byte block_number + padingg_size byte）
        std::unique_ptr<byte[]> m_buffer, m_auxiliary;
        // m_iv_size默认为12
        // m_padding_size默认为0
        unsigned m_iv_size, m_padding_size;
        // (m_flags & kOptionNoAuthentication) == 0
        // m_check表示是否开启不需要完整性检验，但是mount中的insecure参数实际是没有开启的
        // 所以m_check恒为1
        bool m_check;

    public:
        // 返回block_size，默认是4096
        length_type get_block_size() const noexcept { return m_block_size; }

        // 返回iv_size，默认是12
        length_type get_iv_size() const noexcept { return m_iv_size; }

        // 返回mac_size = 16
        static constexpr unsigned get_mac_size() noexcept { return 16; }

        // 返回id_size = 16
        static constexpr length_type get_id_size() noexcept { return 16; }

        // 返回header_size = id_size + padding_size
        length_type get_header_size() const noexcept { return get_id_size() + get_padding_size(); }

        // 返回underlying_block_size = block_size + iv_size + mac_size
        length_type get_underlying_block_size() const noexcept
        {
            return get_block_size() + get_iv_size() + get_mac_size();
        }

        // 返回padding_size，默认为0
        unsigned get_padding_size() const noexcept { return m_padding_size; }

    protected:
        // read_block(块号，输出)，返回读取到的有效数据大小(<=block_size)
        // 读取加密文件流中的某个块，并进行解密到output中
        length_type read_block(offset_type block_number, void* output) override;

        // write_block(块号，输入，输入大小(<=block_size))
        // 将输入加密后写入到加密文件流中
        void write_block(offset_type block_number, const void* input, length_type size) override;

        // 调整加密文件数据流中的逻辑大小，块大小变了的时候用？？？
        // lite版本中好像没有用到哦？
        void adjust_logical_size(length_type length) override;

    public:
        // 构造函数，explicit要求显示调用，避免隐式自动调用
        explicit AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                                   const key_type& master_key,
                                   unsigned block_size = 4096,
                                   unsigned iv_size = 12,
                                   bool check = true,
                                   unsigned max_padding_size = 0,
                                   CryptoPP::ECB_Mode<CryptoPP::SM4>::Encryption* padding_aes
                                   = nullptr);

        ~AESGCMCryptStream();

        // 返回有效数据总和
        virtual length_type size() const override;

        // 重写Base类的flush()，实际没用，是为了防止AESGCMCryptStream变为虚类
        virtual void flush() override;

        // 判断文件是否为稀疏文件，有一些算法对稀疏文件需要特殊处理，默认为false
        virtual bool is_sparse() const noexcept override;

        // Calculates the size of `AESGCMCryptStream` based on its underlying stream size. This only
        // works when padding is not enabled.
        static length_type calculate_real_size(length_type underlying_size,
                                               length_type block_size,
                                               length_type iv_size) noexcept;
    };
}    // namespace lite
}    // namespace securefs
