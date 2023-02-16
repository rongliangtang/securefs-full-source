#include "lite_stream.h"
#include "crypto.h"
#include "logger.h"

#include <cryptopp/aes.h>
#include <cryptopp/integer.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

namespace securefs
{
namespace lite
{
    namespace
    {
        const offset_type MAX_BLOCKS = (1ULL << 31) - 1;
        unsigned compute_padding(unsigned max_padding,
                                 CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption* padding_aes,
                                 const byte* id,
                                 size_t id_size)
        {
            if (!max_padding || !padding_aes)
            {
                return 0;
            }
            CryptoPP::FixedSizeAlignedSecBlock<byte, 16> transformed;
            padding_aes->ProcessData(transformed.data(), id, id_size);
            CryptoPP::Integer integer(transformed.data(),
                                      transformed.size(),
                                      CryptoPP::Integer::UNSIGNED,
                                      CryptoPP::BIG_ENDIAN_ORDER);
            return static_cast<unsigned>(integer.Modulo(max_padding + 1));
        }
    }    // namespace
    std::string CorruptedStreamException::message() const { return "Stream is corrupted"; }

    /*
    AESGCMCryptStream stream(std::move(fs),
                             m_content_key,
                             m_block_size,
                             m_iv_size,
                             (m_flags & kOptionNoAuthentication) == 0,
                             m_max_padding_size,
                             &m_padding_aes);
    */
    AESGCMCryptStream::AESGCMCryptStream(std::shared_ptr<StreamBase> stream,
                                         const key_type& master_key,
                                         unsigned block_size,
                                         unsigned iv_size,
                                         bool check,
                                         unsigned max_padding_size,
                                         CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption* padding_aes)
        : BlockBasedStream(block_size)
        , m_stream(std::move(stream))
        , m_iv_size(iv_size)
        , m_padding_size(0)
        , m_check(check)
    {
        if (m_iv_size < 12 || m_iv_size > 32)
            throwInvalidArgumentException("IV size too small or too large");
        if (!m_stream)
            throwInvalidArgumentException("Null stream");
        if (block_size < 32)
            throwInvalidArgumentException("Block size too small");

        warn_if_key_not_random(master_key, __FILE__, __LINE__);

        // get_id_size(){ return 16; }
        CryptoPP::FixedSizeAlignedSecBlock<byte, get_id_size()> id, session_key;
        // id.data()从m_stream文件加密数据流中读取
        // rc为从m_stream读取的id.size()个字节数据？？
        // m_stream实际为StreamBase多态的UnixSteamFile类型
        // 调用UnixFileStream中的read()
        auto rc = m_stream->read(id.data(), 0, id.size());
        // 当rc为0的时候，随机生成并写入到m_stream文件加密流中
        // 没有打开过的明文文件，会走这一步
        if (rc == 0)
        {
            // 随机生成id.data()
            generate_random(id.data(), id.size());
            // 调用UnixFileStream中的write()
            m_stream->write(id.data(), 0, id.size());
            m_padding_size = compute_padding(max_padding_size, padding_aes, id.data(), id.size());
            m_auxiliary.reset(new byte[sizeof(std::uint32_t) + m_padding_size]);
            if (m_padding_size)
            {
                generate_random(m_auxiliary.get(), sizeof(std::uint32_t) + m_padding_size);
                m_stream->write(
                    m_auxiliary.get() + sizeof(std::uint32_t), id.size(), m_padding_size);
            }
        }
        else if (rc != id.size())
        {
            throwInvalidArgumentException("Underlying stream has invalid ID size");
        }
        else
        {
            m_padding_size = compute_padding(max_padding_size, padding_aes, id.data(), id.size());
            m_auxiliary.reset(new byte[sizeof(std::uint32_t) + m_padding_size]);
            if (m_padding_size
                && m_stream->read(
                       m_auxiliary.get() + sizeof(std::uint32_t), id.size(), m_padding_size)
                    != m_padding_size)
                throwInvalidArgumentException("Invalid padding in the underlying file");
        }

        if (max_padding_size > 0)
        {
            TRACE_LOG("Stream padded with %u bytes", m_padding_size);
        }

        // master_key实际为m_content_key，这里设置为AES-ECB的共享密钥
        CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption ecenc(master_key.data(), master_key.size());
        // ProcessData(byte *outString, const byte *inString, size_t length)
        // session_key.data()为id.data()加密后的结果
        ecenc.ProcessData(session_key.data(), id.data(), id.size());

        m_buffer.reset(new byte[get_underlying_block_size()]);

        // The null iv is only a placeholder; it will replaced during encryption and decryption
        const byte null_iv[12] = {0};
        // SetKeyWithIV(const byte *key, size_t length, const byte *iv, size_t ivLength)
        // m_encryptor的key为session_key.data()
        // m_encryptor的IV暂时为null，具体使用的时候会设置IV
        m_encryptor.SetKeyWithIV(
            session_key.data(), session_key.size(), null_iv, array_length(null_iv));
        m_decryptor.SetKeyWithIV(
            session_key.data(), session_key.size(), null_iv, array_length(null_iv));
    }

    AESGCMCryptStream::~AESGCMCryptStream() {}

    // 调用streamBase的flush()，然后调用UnixFileStream或WindowsFileStream中的方法
    void AESGCMCryptStream::flush() { m_stream->flush(); }

    bool AESGCMCryptStream::is_sparse() const noexcept { return m_stream->is_sparse(); }

    // 读一块的数据，将读到的密文解密到output中
    // UnixFileStream对象fd对应的文件是加密文件
    // 以块为单位进行操作，读出加密后的数据并解密
    length_type AESGCMCryptStream::read_block(offset_type block_number, void* output)
    {
        if (block_number > MAX_BLOCKS)
            throw StreamTooLongException(MAX_BLOCKS * get_block_size(),
                                         block_number * get_block_size());

        // rc为读取到的字节数(最大就是 数据大小(<=block_size) + iv_size + mac_size)
        // m_stream是加密后的数据流
        // get_header_size() = get_id_size() + get_padding_size()
        // get_underlying_block_size() = get_block_size() + get_iv_size() + get_mac_size()
        // m_stream是加密后的数据流
        // 读取get_header_size() + get_underlying_block_size() * block_number后get_underlying_block_size()字节的数据到m_buffer中
        
        // 读出来的rc<=get_underlying_block_size()
        // m_buffer中存放存加密文件中读取的一块underlying_block，包括了block、iv、mac
        
        // 因为m_stream是StreamBase类多态的UnixFileStream对象，所以这里会调用UnixFileStream中的read()
        length_type rc
            = m_stream->read(m_buffer.get(),
                             get_header_size() + get_underlying_block_size() * block_number,
                             get_underlying_block_size());
        if (rc <= get_mac_size() + get_iv_size())
            return 0;

        if (rc > get_underlying_block_size())
            throwInvalidArgumentException("Invalid read");

        // 实际返回的outsize为密文数据大小
        auto out_size = rc - get_iv_size() - get_mac_size();

        if (is_all_zeros(m_buffer.get(), rc))
        {
            memset(output, 0, get_block_size());
            return out_size;
        }

        // block_number块号,是AES-GCM的附加消息
        to_little_endian(static_cast<std::uint32_t>(block_number), m_auxiliary.get());

        // 将underlying_block进行解密，output存放解密后的数据
        // DecryptAndVerify(byte *message, const byte *mac, size_t macLength, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *ciphertext, size_t ciphertextLength)
        // m_buffer.get()中的前get_iv_size()个字节数据是IV,所以这里的密文数据跳过了IV
        bool success = m_decryptor.DecryptAndVerify(static_cast<byte*>(output),
                                                    m_buffer.get() + rc - get_mac_size(),
                                                    get_mac_size(),
                                                    m_buffer.get(),
                                                    static_cast<int>(get_iv_size()),
                                                    m_auxiliary.get(),
                                                    sizeof(std::uint32_t) + m_padding_size,
                                                    m_buffer.get() + get_iv_size(),
                                                    out_size);

        if (m_check && !success)
            throw LiteMessageVerificationException();

        return out_size;
    }

    // 必须要先read后write，因为read后才知道数据写在哪里
    // 写一块的数据，将明文加密后写入
    // input是明文
    // UnixFileStream对象fd对应的文件是加密文件
    void
    AESGCMCryptStream::write_block(offset_type block_number, const void* input, length_type size)
    {
        // 若block_number > MAX_BLOCKS，说明文件已经达到最大了
        // 因为NIST建议单个密钥不能用于AES-GCM的2^32 IVs以上。由于这个原因，文件大小被限制为2^31 - 1块(默认块大小为4KiB，最大文件大小约为8TiB)
        if (block_number > MAX_BLOCKS)
            throw StreamTooLongException(MAX_BLOCKS * get_block_size(),
                                         block_number * get_block_size());

        // 通过block_number，获得在加密文件中的offset
        auto underlying_offset = block_number * get_underlying_block_size() + get_header_size();
        // 计算应该在加密文件中写入的数据大小
        auto underlying_size = size + get_iv_size() + get_mac_size();

        // 如果input中都是0，则写入0
        if (is_all_zeros(input, size))
        {
            memset(m_buffer.get(), 0, underlying_size);
            m_stream->write(m_buffer.get(), underlying_offset, underlying_size);
            return;
        }

        // block_number块号,是AES-GCM的附加消息
        // 将block_number转为std::uint32_t类型
        // 这里为啥要用小端存储？？
        to_little_endian(static_cast<std::uint32_t>(block_number), m_auxiliary.get());

        // 如果iv都为0，则需要随机生成一个iv
        do
        {
            generate_random(m_buffer.get(), get_iv_size());
        } while (is_all_zeros(m_buffer.get(), get_iv_size()));

        // 将明文数据进行加密
        // EncryptAndAuthenticate(byte *ciphertext, byte *mac, size_t macSize, const byte *iv, int ivLength, const byte *header, size_t headerLength, const byte *message, size_t messageLength)
        m_encryptor.EncryptAndAuthenticate(m_buffer.get() + get_iv_size(),
                                           m_buffer.get() + get_iv_size() + size,
                                           get_mac_size(),
                                           m_buffer.get(),
                                           static_cast<int>(get_iv_size()),
                                           m_auxiliary.get(),
                                           sizeof(std::uint32_t) + m_padding_size,
                                           static_cast<const byte*>(input),
                                           size);
        // 把加密后获得的underlying_block写入加密文件中
        // 调用UnixFileStream中的write()
        m_stream->write(m_buffer.get(), underlying_offset, underlying_size);
    }

    // 返回有效数据大小（所有block的和），调用calculate_real_size()
    length_type AESGCMCryptStream::size() const
    {
        // UnixFileStream类中的size()
        auto underlying_size = m_stream->size();    // 整个加密后的文件的大小
        // 如果加密后的文件大小 <= get_header_size()，则直接返回有效数据大小为0
        // 否则计算有效数据大小
        return underlying_size <= get_header_size()
            ? 0
            : calculate_real_size(underlying_size - m_padding_size, m_block_size, m_iv_size);
    }

    // 调整加密文件的大小
    void AESGCMCryptStream::adjust_logical_size(length_type length)
    {
        // 得到有效数据新块数，即underlying_block块数
        auto new_blocks = length / get_block_size();
        // 最后一块的residue大小
        auto residue = length % get_block_size();
        // 调用UnixFileStream类中的resize()
        m_stream->resize(get_header_size() + new_blocks * get_underlying_block_size()
                         + (residue > 0 ? residue + get_iv_size() + get_mac_size() : 0));
    }

    // 计算有效数据大小（所有block的和）
    // calculate_real_size(加密后文件总大小，有效块大小，iv大小)
    length_type AESGCMCryptStream::calculate_real_size(length_type underlying_size,
                                                       length_type block_size,
                                                       length_type iv_size) noexcept
    {
        auto id_size = get_id_size();
        auto underlying_block_size = block_size + iv_size + get_mac_size();
        if (underlying_size <= id_size)
            return 0;
        underlying_size -= id_size;
        auto num_blocks = underlying_size / underlying_block_size;
        auto residue = underlying_size % underlying_block_size;
        return num_blocks * block_size
            + (residue > (iv_size + get_mac_size()) ? residue - iv_size - get_mac_size() : 0);
    }
}    // namespace lite
}    // namespace securefs
