#include "streams.h"
#include "crypto.h"

#include <algorithm>
#include <array>
#include <assert.h>
#include <memory>
#include <stdint.h>
#include <string.h>
#include <utility>

#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rng.h>
#include <cryptopp/salsa.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>

namespace securefs
{
namespace internal
{
    class InvalidHMACStreamException : public InvalidFormatException
    {
    private:
        id_type m_id;
        std::string m_msg;

    public:
        explicit InvalidHMACStreamException(const id_type& id, std::string msg)
        {
            memcpy(m_id.data(), id.data(), id.size());
            m_msg.swap(msg);
        }

        std::string message() const override { return m_msg; }
    };

    class HMACStream final : public StreamBase
    {
    private:
        //  m_key未发生作用啊？？？
        key_type m_key;
        id_type m_id;
        std::shared_ptr<StreamBase> m_stream;
        bool is_dirty;

        typedef CryptoPP::HMAC<CryptoPP::SHA256> hmac_calculator_type;

        static const size_t hmac_length = hmac_calculator_type::DIGESTSIZE;

    private:
        const id_type& id() const noexcept { return m_id; }
        const key_type& key() const noexcept { return m_key; }

        void run_mac(CryptoPP::MessageAuthenticationCode& calculator)
        {
            calculator.Update(id().data(), id().size());
            std::array<byte, 4096> buffer;
            offset_type off = hmac_length;
            while (true)
            {
                auto rc = m_stream->read(buffer.data(), off, buffer.size());
                if (rc == 0)
                    break;
                calculator.Update(buffer.data(), rc);
                off += rc;
            }
        }

    public:
        explicit HMACStream(const key_type& key_,
                            const id_type& id_,
                            std::shared_ptr<StreamBase> stream,
                            bool check = true)
            : m_key(key_), m_id(id_), m_stream(std::move(stream)), is_dirty(false)
        {
            if (!m_stream)
                throwVFSException(EFAULT);
            if (check)
            {
                std::array<byte, hmac_length> hmac;
                auto rc = m_stream->read(hmac.data(), 0, hmac.size());
                if (rc == 0)
                    return;
                if (rc != hmac_length)
                    throw InvalidHMACStreamException(
                        id(), "The header field for stream is not of enough length");
                hmac_calculator_type calculator;
                calculator.SetKey(key().data(), key().size());
                run_mac(calculator);
                if (!calculator.Verify(hmac.data()))
                    throw InvalidHMACStreamException(id(), "HMAC mismatch");
            }
        }

        ~HMACStream()
        {
            try
            {
                flush();
            }
            catch (...)
            {
                // ignore
            }
        }

        void flush() override
        {
            if (!is_dirty)
                return;
            hmac_calculator_type calculator;
            calculator.SetKey(key().data(), key().size());
            run_mac(calculator);
            std::array<byte, hmac_length> hmac;
            calculator.Final(hmac.data());
            m_stream->write(hmac.data(), 0, hmac.size());
            m_stream->flush();
            is_dirty = false;
        }

        length_type size() const override
        {
            auto sz = m_stream->size();
            if (sz < hmac_length)
                return 0;
            return sz - hmac_length;
        }

        length_type read(void* output, offset_type off, length_type len) override
        {
            return m_stream->read(output, off + hmac_length, len);
        }

        void write(const void* input, offset_type off, length_type len) override
        {
            m_stream->write(input, off + hmac_length, len);
            is_dirty = true;
        }

        void resize(length_type len) override
        {
            m_stream->resize(len + hmac_length);
            is_dirty = true;
        }

        bool is_sparse() const noexcept override { return m_stream->is_sparse(); }
    };
}    // namespace internal

std::shared_ptr<StreamBase> make_stream_hmac(const key_type& key_,
                                             const id_type& id_,
                                             std::shared_ptr<StreamBase> stream,
                                             bool check)
{
    return std::make_shared<internal::HMACStream>(key_, id_, std::move(stream), check);
}

// full format中会用到
// 读取对应块号的block密文并解密到output中
length_type CryptStream::read_block(offset_type block_number, void* output)
{
    // m_stream是StreamBase类的shared_ptr
    // 读取后的output是密文
    // 调用unixFileStream类中的read()函数
    auto rc = m_stream->read(output, block_number * m_block_size, m_block_size);
    if (rc == 0)
        return 0;
    // 进行密文数据的解密，根据block_number找到底层的IV和mac来进行解密
    // 调用streams.cpp中的AESGCMCryptStream类中的方法
    // 注意liteformat中调用的是lite_stream.h中的AESGCMCryptStream
    decrypt(block_number, output, output, rc);
    return rc;
}

// output会存放解密后的数据
// 利用c的read和memcpy实现
length_type BlockBasedStream::read_block(offset_type block_number,
                                         void* output,
                                         offset_type begin,
                                         offset_type end)
{
    // 断言，检测假设是否成立
    // 判断begin和end是否在1个block_size内
    assert(begin <= m_block_size && end <= m_block_size);

    // 当begin和end刚好为1个block时，直接读取这个块就行，调用对应函数
    // lite format
    /* 
    因为m_crypt_stream为AESGCMCryptStream类型（故以后调用同名同参都是优先调用该类型中的）；m_crypt_stream->read通过继承调用BlockBasedStream中的read（因为AESGCMCryptStream类型中无read实现）；
    因为参数原因read调用BlockBasedStream中的read_block（本类找没有四个参的read_block，再找BlockBasedStream）；read_block调用AESGCMCryptStream中的read_block（虽然有同名，但是优先调用AESGCMCryptStream类型中的）
    */
    // read_block调用AESGCMCryptStream中的read_block（虽然有同名，但是优先调用AESGCMCryptStream类型中的）
    
    // full format
    // 调用CryptStream类的read_block()函数
    if (begin == 0 && end == m_block_size)
        return read_block(block_number, output);

    // 如果begin >= end，说明读完了或出错了，返回0
    if (begin >= end)
        return 0;

    // buffer为m_block_size大小的AlignedSecByteBlock类型，byte类型的对齐块
    CryptoPP::AlignedSecByteBlock buffer(m_block_size);
    // 读取对应一个块的数据到buffer.data()中，后面再将其中begin到end的数据复制到output中
    auto rc = read_block(block_number, buffer.data());
    if (rc <= begin)
        return 0;
    end = std::min<offset_type>(end, rc);
    memcpy(output, buffer.data() + begin, end - begin);
    return end - begin;
}

void CryptStream::write_block(offset_type block_number, const void* input, length_type length)
{
    assert(length <= m_block_size);
    auto buffer = make_unique_array<byte>(length);
    encrypt(block_number, input, buffer.get(), length);
    m_stream->write(buffer.get(), block_number * m_block_size, length);
}

// 读取block_number对应块中的数据，然后将input写入到这个块的begin到end位置
void BlockBasedStream::read_then_write_block(offset_type block_number,
                                             const void* input,
                                             offset_type begin,
                                             offset_type end)
{
    // 断言，若begin和end不小于m_block_size则会报错
    assert(begin <= m_block_size && end <= m_block_size);

    // 当begin和end刚好为1个block的时
    if (begin == 0 && end == m_block_size)
        // AESGCMCryptStream::write_block(块号，写入数据，写入数据大小)
        return write_block(block_number, input, m_block_size);
    // begin>end，有错结束
    if (begin >= end)
        return;

    // 当begin和end不刚好为1个block的时
    // 将最后一块的数据读出来，再将input在相应位置替换
    // 将替换后的结果写回
    CryptoPP::AlignedSecByteBlock buffer(m_block_size);
    auto rc = read_block(block_number, buffer.data());
    // 在这里进行cp，然后write_block只对一块进行操作，os内核也是这样做的
    memcpy(buffer.data() + begin, input, end - begin);
    // AESGCMCryptStream::write_block(块号，写入数据，写入数据大小)
    // 用max的原因是，有时候最后一块不是满的
    write_block(block_number, buffer.data(), std::max<length_type>(rc, end));
}

// 返回读取到的字节数量，读取length长度的数据存到output中
// 按块操作
length_type BlockBasedStream::read(void* output, offset_type offset, length_type length)
{
    length_type total = 0;

    // 使用while处理的原因是，每次最多只能读一个block大小，而length有可能大于1个block，需要多次读取
    while (length > 0)
    {
        // 计算块号
        auto block_num = offset / m_block_size;
        auto start_of_block = block_num * m_block_size;
        auto begin = offset - start_of_block;
        // 每次不能读超过1个block的大小
        // begin和end都是相对1个block而言，都是小于等于m_block_size
        auto end = std::min<offset_type>(m_block_size, offset + length - start_of_block);
        // 按块读
        // read_block(块号, 输出, 读起点, 读终点);
        // 这里调用的read_block()是BlockBasedStream中的，因为AESGCMCrypyStream中没有实现四个参数的read_block()，所以顺着继承关系往上找
        // lite format用的是lite_stream.h中的AESGCMStream类
        // full format同上，用到是Stream.cpp中的AESGCMStream类
        auto rc = read_block(block_num, output, begin, end);
        // total为当前读取到的总字节数
        total += rc;
        // 如果 rc 会小于 end-begin 说明读完或者出错了，直接返回total
        if (rc < end - begin)
            return total;
        // output偏移到下次存入数据的位置
        output = static_cast<byte*>(output) + rc;
        // 计算下次起始偏移量
        offset += rc;
        // 剩余需要读取的length
        length -= rc;
    }

    return total;
}

// 写入input中的size大小数据
void BlockBasedStream::write(const void* input, offset_type offset, length_type length)
{
    // 如果length <= 0，则直接结束
    if (length <= 0)
    {
        return;
    }
    // 计算文件当前有效数据的大小（通过加密后文件大小来求出）
    // AESGCMCryptStream::size()
    auto current_size = this->size();
    // 若偏移量>当前有效数据大小，则需要将明文数据大小进行调整（多出部分置0），密文也随之调整
    if (offset > current_size)
        unchecked_resize(current_size, offset);

    // 进行写
    unchecked_write(input, offset, length);
}

// 将input中length长的数据从offset位置开始写
void BlockBasedStream::unchecked_write(const void* input, offset_type offset, length_type length)
{
    // 用while实现length大于1个block的写操作
    while (length > 0)
    {
        // 计算写入数据起点所在的块号
        auto block_num = offset / m_block_size;
        // 该块的起始位置（相对整个明文文件）
        auto start_of_block = block_num * m_block_size;
        // 写入数据起点在这个块中的位置
        auto begin = offset - start_of_block;
        // 写入数据终点不能超过这个块
        auto end = std::min<offset_type>(m_block_size, offset + length - start_of_block);
        // 进行写入
        read_then_write_block(block_num, input, begin, end);
        // 计算这次写入的数据大小
        auto rc = end - begin;
        // 下次待写数据的起点
        input = static_cast<const byte*>(input) + rc;
        // 下次写的offset
        offset += rc;
        // 剩余需要写的length
        length -= rc;
    }
}

// 将offset到finish这部分区域用0填充，考虑到到了跨块的情况
void BlockBasedStream::zero_fill(offset_type offset, offset_type finish)
{
    auto zeros = make_unique_array<byte>(m_block_size);
    memset(zeros.get(), 0, m_block_size);
    while (offset < finish)
    {
        auto block_num = offset / m_block_size;
        auto start_of_block = block_num * m_block_size;
        auto begin = offset - start_of_block;
        auto end = std::min<offset_type>(m_block_size, finish - start_of_block);
        read_then_write_block(block_num, zeros.get(), begin, end);
        auto rc = end - begin;
        offset += rc;
    }
}

// 通过调用下面一行的unchecked_resize()实现resize
void BlockBasedStream::resize(length_type new_size) { unchecked_resize(size(), new_size); }

// 将明文文件的大小从current_size调整到new_size，最后密文文件也要做相应的修改
void BlockBasedStream::unchecked_resize(length_type current_size, length_type new_size)
{
    // 当new_size == current_size，结束运行
    if (new_size == current_size)
        return;
    // 当new_size < current_size
    else if (new_size < current_size)
    {
        // 最后一块block里面的数据大小
        auto residue = new_size % m_block_size;
        // 计算出块数
        auto block_num = new_size / m_block_size;
        // 如果最后一块block里面的数据大小不为block_size，则将最后一块里residue外的数据置0
        if (residue > 0)
        {
            // 创建一个m_block_size大小的AlignedSecByteBlock类型对象，里面data都为0
            CryptoPP::AlignedSecByteBlock buffer(m_block_size);
            memset(buffer.data(), 0, buffer.size());
            // 将最后一块的数据存到buffer.data()中
            (void)read_block(block_num, buffer.data());
            // 将buffer.data()中的residue数据写入到文件中
            write_block(block_num, buffer.data(), residue);
        }
    }
    // 当new_size > current_size，则用current_size到new_size这部分区域0填充
    else
    {
        // 原来的块数
        auto old_block_num = current_size / m_block_size;
        // 新的块数
        auto new_block_num = new_size / m_block_size;
        if (!is_sparse() || old_block_num == new_block_num)
            zero_fill(current_size, new_size);
        else
        {
            zero_fill(current_size, old_block_num * m_block_size + m_block_size);
        }
    }
    
    // 将加密后文件的大小根据新的有效数据new_size进行调整
    // 调用AESGCMCryptStream::adjust_logical_size
    adjust_logical_size(new_size);
}

namespace internal
{
    // lite中也有一个AESGCMCryptStream类
    class AESGCMCryptStream final : public CryptStream, public HeaderBase
    {
    public:
        int get_iv_size() const noexcept { return m_iv_size; }

        unsigned get_mac_size() const noexcept { return 16; }

        unsigned get_meta_size() const noexcept { return get_iv_size() + get_mac_size(); }

        unsigned get_header_size() const noexcept { return m_header_size; }

        unsigned get_encrypted_header_size() const noexcept
        {
            return get_header_size() + get_iv_size() + get_mac_size();
        }

        static const int64_t max_block_number = 1 << 30;

    private:
        CryptoPP::GCM<CryptoPP::AES>::Encryption m_enc;
        CryptoPP::GCM<CryptoPP::AES>::Decryption m_dec;
        HMACStream m_metastream;
        id_type m_id;
        unsigned m_iv_size, m_header_size;
        bool m_check;

    private:
        length_type meta_position_for_iv(offset_type block_num) const noexcept
        {
            return get_encrypted_header_size() + get_meta_size() * (block_num);
        }

        void check_block_number(offset_type block_number)
        {
            if (block_number > max_block_number)
                throw StreamTooLongException(max_block_number * this->m_block_size,
                                             block_number * this->m_block_size);
        }

        const id_type& id() const noexcept { return m_id; }

    public:
        explicit AESGCMCryptStream(std::shared_ptr<StreamBase> data_stream,
                                   std::shared_ptr<StreamBase> meta_stream,
                                   const key_type& data_key,
                                   const key_type& meta_key,
                                   const id_type& id_,
                                   bool check,
                                   unsigned block_size,
                                   unsigned iv_size,
                                   unsigned header_size)
            : CryptStream(data_stream, block_size)
            , m_metastream(meta_key, id_, meta_stream, check)
            , m_id(id_)
            , m_iv_size(iv_size)
            , m_header_size(header_size)
            , m_check(check)
        {
            const byte null_iv[12] = {};
            m_enc.SetKeyWithIV(data_key.data(), data_key.size(), null_iv, array_length(null_iv));
            m_dec.SetKeyWithIV(data_key.data(), data_key.size(), null_iv, array_length(null_iv));
            warn_if_key_not_random(data_key, __FILE__, __LINE__);
            warn_if_key_not_random(meta_key, __FILE__, __LINE__);
        }

    protected:
        void encrypt(offset_type block_number,
                     const void* input,
                     void* output,
                     length_type length) override
        {
            if (length == 0)
                return;
            check_block_number(block_number);

            auto buffer = make_unique_array<byte>(get_meta_size());
            byte* iv = buffer.get();
            byte* mac = iv + get_iv_size();

            do
            {
                generate_random(iv, get_iv_size());
            } while (is_all_zeros(iv, get_iv_size()));    // Null IVs are markers for sparse blocks
            m_enc.EncryptAndAuthenticate(static_cast<byte*>(output),
                                         mac,
                                         get_mac_size(),
                                         iv,
                                         get_iv_size(),
                                         id().data(),
                                         id().size(),
                                         static_cast<const byte*>(input),
                                         length);
            auto pos = meta_position_for_iv(block_number);
            m_metastream.write(buffer.get(), pos, get_meta_size());
        }

        // 对底层文件系统中的加密块进行解密，根据block_numer找到底层文件系统中的IV和Mac，在对input进行解密
        void decrypt(offset_type block_number,
                     const void* input,
                     void* output,
                     length_type length) override
        {
            if (length == 0)
                return;
            check_block_number(block_number);

            auto buffer = make_unique_array<byte>(get_meta_size());
            auto pos = meta_position_for_iv(block_number);
            if (m_metastream.read(buffer.get(), pos, get_meta_size()) != get_meta_size())
                throw CorruptedMetaDataException(id(), "MAC/IV not found");

            const byte* iv = buffer.get();
            byte* mac = buffer.get() + get_iv_size();

            if (is_all_zeros(buffer.get(), get_meta_size()) && is_all_zeros(input, length))
            {
                memset(output, 0, length);
                return;
            }
            bool success = m_dec.DecryptAndVerify(static_cast<byte*>(output),
                                                  mac,
                                                  get_mac_size(),
                                                  iv,
                                                  get_iv_size(),
                                                  id().data(),
                                                  id().size(),
                                                  static_cast<const byte*>(input),
                                                  length);
            if (m_check && !success)
                throw MessageVerificationException(id(), block_number * m_block_size);
        }

        void adjust_logical_size(length_type length) override
        {
            CryptStream::adjust_logical_size(length);
            auto block_num = (length + this->m_block_size - 1) / this->m_block_size;
            m_metastream.resize(meta_position_for_iv(block_num));
        }

    public:
        bool is_sparse() const noexcept override
        {
            return m_stream->is_sparse() && m_metastream.is_sparse();
        }

        void flush() override
        {
            CryptStream::flush();
            m_metastream.flush();
        }

    private:
        length_type unchecked_read_header(void* output)
        {
            auto buffer = make_unique_array<byte>(get_encrypted_header_size());
            auto rc = m_metastream.read(buffer.get(), 0, get_encrypted_header_size());
            if (rc == 0)
                return 0;
            if (rc != get_encrypted_header_size())
                throw CorruptedMetaDataException(id(), "Not enough header field");

            byte* iv = buffer.get();
            byte* mac = iv + get_iv_size();
            byte* ciphertext = mac + get_mac_size();
            m_dec.DecryptAndVerify(static_cast<byte*>(output),
                                   mac,
                                   get_mac_size(),
                                   iv,
                                   get_iv_size(),
                                   id().data(),
                                   id().size(),
                                   ciphertext,
                                   get_header_size());
            return get_header_size();
        }

        void unchecked_write_header(const void* input)
        {
            auto buffer = make_unique_array<byte>(get_encrypted_header_size());
            byte* iv = buffer.get();
            byte* mac = iv + get_iv_size();
            byte* ciphertext = mac + get_mac_size();
            generate_random(iv, get_iv_size());

            m_enc.EncryptAndAuthenticate(ciphertext,
                                         mac,
                                         get_mac_size(),
                                         iv,
                                         get_iv_size(),
                                         id().data(),
                                         id().size(),
                                         static_cast<const byte*>(input),
                                         get_header_size());
            m_metastream.write(buffer.get(), 0, get_encrypted_header_size());
        }

    public:
        bool read_header(void* output, length_type length) override
        {
            if (length > get_header_size())
                throwInvalidArgumentException("Header too long");
            if (length == get_header_size())
                return unchecked_read_header(output) == length;

            CryptoPP::AlignedSecByteBlock buffer(get_header_size());
            auto rc = unchecked_read_header(buffer.data());
            memcpy(output, buffer.data(), std::min(length, rc));
            return rc != 0;
        }

        length_type max_header_length() const noexcept override { return get_header_size(); }

        void write_header(const void* input, length_type length) override
        {
            if (length > get_header_size())
                throwInvalidArgumentException("Header too long");

            if (length == get_header_size())
                return unchecked_write_header(input);

            CryptoPP::AlignedSecByteBlock buffer(get_header_size());
            memcpy(buffer.data(), input, length);
            memset(buffer.data() + length, 0, buffer.size() - length);
            unchecked_write_header(buffer.data());
        }

        void flush_header() override { m_metastream.flush(); }
    };
}    // namespace internal

std::pair<std::shared_ptr<CryptStream>, std::shared_ptr<HeaderBase>>
make_cryptstream_aes_gcm(std::shared_ptr<StreamBase> data_stream,
                         std::shared_ptr<StreamBase> meta_stream,
                         const key_type& data_key,
                         const key_type& meta_key,
                         const id_type& id_,
                         bool check,
                         unsigned block_size,
                         unsigned iv_size,
                         unsigned header_size)
{
    // 返回的是多态，实际为internal::AESGCMCryptStream类
    auto stream = std::make_shared<internal::AESGCMCryptStream>(std::move(data_stream),
                                                                std::move(meta_stream),
                                                                data_key,
                                                                meta_key,
                                                                id_,
                                                                check,
                                                                block_size,
                                                                iv_size,
                                                                header_size);
    return {stream, stream};
}

PaddedStream::PaddedStream(std::shared_ptr<StreamBase> delegate, unsigned padding_size)
    : m_delegate(std::move(delegate)), m_padding_size(padding_size)
{
    if (m_delegate->size() < padding_size)
    {
        auto buffer = make_unique_array<byte>(padding_size);
        generate_random(buffer.get(), padding_size);
        m_delegate->write(buffer.get(), 0, padding_size);
    }
}

PaddedStream::~PaddedStream() {}
}    // namespace securefs
