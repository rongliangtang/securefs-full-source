#pragma once
#include "exceptions.h"
#include "myutils.h"

#include <memory>
#include <utility>

namespace securefs
{

/**
 * Base classes for byte streams.
 **/
// 字节流基类，文件流操作接口预先定义的抽象模型，便于代码的维护以及扩展
// 基类的函数需要定义为虚函数（这样子类可以实现或不实现这个函数），也可定义为纯虚函数（这样子类必须实现这个函数。）
class StreamBase
{
public:
    StreamBase() {}
    virtual ~StreamBase() {}
    DISABLE_COPY_MOVE(StreamBase)

    /**
     * Returns the number of bytes actually read into the buffer `output`.
     * Always read in full unless beyond the end, i.e., offset + length > size.
     **/
    // 读函数返回output缓冲区的字节数，读到满为止
    // length_type是long long64位整数，typedef定义不能对类型名进行扩展
    virtual length_type read(void* output, offset_type offset, length_type length) = 0;

    /**
     * Write must always succeed as a whole or throw an exception otherwise.
     * If the offset is beyond the end of the stream, the gap should be filled with zeros.
     **/
    // 写函数，如果offset超过了流的末端，间隙用0填充？？啥意思
    virtual void write(const void* input, offset_type offset, length_type length) = 0;

    virtual length_type size() const = 0;

    virtual void flush() = 0;

    /**
     * Similar to ftruncate().
     * Discard extra data when shrinking, zero-fill when extending.
     **/
    // 改变文件大小，收缩时丢弃额外数据，扩张时用0填充
    virtual void resize(length_type) = 0;

    /**
     * Sparse streams can be extended with zeros in constant time.
     * Some algorithms may be specialized on sparse streams.
     */
    // 判断文件是否为稀疏文件，有一些算法对稀疏文件需要特殊处理
    virtual bool is_sparse() const noexcept { return false; }

    /**
     * Certain streams are more efficient when reads and writes are aligned to blocks
     */
    // 返回最优的block大小，当读写按block进行时，某些流的效率更高
    virtual length_type optimal_block_size() const noexcept { return 1; }
};

/**
 * Interface that supports a fixed size buffer to store headers for files
 */
class HeaderBase
{
public:
    HeaderBase() {}
    virtual ~HeaderBase() {}
    DISABLE_COPY_MOVE(HeaderBase)

    virtual length_type max_header_length() const noexcept = 0;

    /**
     * Returns: true if read in full, false if no header is present.
     * Never reads in part.
     */
    virtual bool read_header(void* output, length_type length) = 0;

    /**
     * Always write in full.
     */
    virtual void write_header(const void* input, length_type length) = 0;
    virtual void flush_header() = 0;
};

std::shared_ptr<StreamBase> make_stream_hmac(const key_type& key_,
                                             const id_type& id_,
                                             std::shared_ptr<StreamBase> stream,
                                             bool check);

// BlockBasedStream块处理基类，
class BlockBasedStream : public StreamBase
{
protected:
    length_type m_block_size;

protected:
    virtual length_type read_block(offset_type block_number, void* output) = 0;
    virtual void write_block(offset_type block_number, const void* input, length_type length) = 0;
    virtual void adjust_logical_size(length_type length) = 0;

private:
    length_type
    read_block(offset_type block_number, void* output, offset_type begin, offset_type end);
    void read_then_write_block(offset_type block_number,
                               const void* input,
                               offset_type begin,
                               offset_type end);

    void unchecked_write(const void* input, offset_type offset, length_type length);
    void zero_fill(offset_type offset, length_type length);
    void unchecked_resize(length_type current_size, length_type new_size);

public:
    BlockBasedStream(length_type block_size) : m_block_size(block_size) {}
    ~BlockBasedStream() {}

    length_type read(void* output, offset_type offset, length_type length) override;
    void write(const void* input, offset_type offset, length_type length) override;
    void resize(length_type new_length) override;
    length_type optimal_block_size() const noexcept override { return m_block_size; }
};

/**
 * Base classes for streams that encrypt and decrypt data transparently
 * The transformation is done in blocks,
 * and must always output data of the same length as input.
 *
 * Subclasses should use additional storage, such as another stream, to store IVs and MACs.
 *
 * The CryptStream supports sparse streams if the subclass can tell whether all zero block
 * are ciphertext or sparse parts of the underlying stream.
 */
// full format用到的加密解密类，lite format用的是AESGCMCryptStream类
class CryptStream : public BlockBasedStream
{
protected:
    // 文件流，FileStream继承StreamBase的
    std::shared_ptr<StreamBase> m_stream;

    // Both encrypt/decrypt should not change the length of the block.
    // input/output may alias.
    virtual void
    encrypt(offset_type block_number, const void* input, void* output, length_type length)
        = 0;

    virtual void
    decrypt(offset_type block_number, const void* input, void* output, length_type length)
        = 0;

    void adjust_logical_size(length_type length) override { m_stream->resize(length); }

private:
    length_type read_block(offset_type block_number, void* output) override;
    void write_block(offset_type block_number, const void* input, length_type length) override;

public:
    // 构造函数
    explicit CryptStream(std::shared_ptr<StreamBase> stream, length_type block_size)
        : BlockBasedStream(block_size), m_stream(std::move(stream))
    {
        if (!m_stream)
            throwVFSException(EFAULT);
        if (m_block_size < 1)
            throwInvalidArgumentException("Too small block size");
    }

    void flush() override { m_stream->flush(); }
    length_type size() const override { return m_stream->size(); }
};

/**
 * AESGCMCryptStream is both a CryptStream and a HeaderBase.
 *
 * Returns a pair because the client does not need to know whether the two interfaces are
 * implemented by the same class.
 */
std::pair<std::shared_ptr<CryptStream>, std::shared_ptr<HeaderBase>>
make_cryptstream_aes_gcm(std::shared_ptr<StreamBase> data_stream,
                         std::shared_ptr<StreamBase> meta_stream,
                         const key_type& data_key,
                         const key_type& meta_key,
                         const id_type& id_,
                         bool check,
                         unsigned block_size,
                         unsigned iv_size,
                         unsigned header_size = 32);

// 实现padding功能的类
// padding类中的m_delegate属性指向AESGCMCryptStream对象，故可以利用其调用其的read和write等方法
// 实现原理就是空掉前面m_padding_size哥字节的数据不写，此时里面的数据为脏数据
class PaddedStream final : public StreamBase
{
public:
    explicit PaddedStream(std::shared_ptr<StreamBase> delegate, unsigned padding_size);
    ~PaddedStream();

    length_type read(void* output, offset_type offset, length_type length) override
    {
        return m_delegate->read(output, offset + m_padding_size, length);
    }

    void write(const void* input, offset_type offset, length_type length) override
    {
        return m_delegate->write(input, offset + m_padding_size, length);
    }

    length_type size() const override
    {
        auto dsize = m_delegate->size();
        return dsize > m_padding_size ? dsize - m_padding_size : 0;
    }

    void flush() override { return m_delegate->flush(); }

    void resize(length_type size) override { return m_delegate->resize(size + m_padding_size); }

    bool is_sparse() const noexcept override { return m_delegate->is_sparse(); }

    length_type optimal_block_size() const noexcept override
    {
        return m_delegate->optimal_block_size();
    }

    unsigned padding_size() const noexcept { return m_padding_size; }

private:
    std::shared_ptr<StreamBase> m_delegate;
    unsigned m_padding_size;
};
}    // namespace securefs
