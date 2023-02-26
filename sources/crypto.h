#pragma once

#include <cryptopp/aes.h>
#include <cryptopp/sm4.h>
#include <cryptopp/cmac.h>
#include <cryptopp/modes.h>

#include <stddef.h>
#include <stdint.h>

// AES_SIV是作者自己实现的，参考了https://tools.ietf.org/html/rfc5297

namespace securefs
{
// Implementation of AES-SIV according to https://tools.ietf.org/html/rfc5297
class AES_SIV
{
private:
    // 在这里直接将AES改为SM4可以正确运行，key为32byte，不需要改为16byte
    // 答上：因为32byte的key，划分为了两半，分别作为下面两个算法的密钥
    // TODO: 待了解AES_SIV的原理，和Cryptopp泛型模版的实现原理
    CryptoPP::CMAC<CryptoPP::SM4> m_cmac;
    CryptoPP::CTR_Mode<CryptoPP::SM4>::Encryption m_ctr;

public:
    static constexpr size_t IV_SIZE = 16;

public:
    // AES_SIV对象的初始化与一个key有关
    explicit AES_SIV(const void* key, size_t size);
    ~AES_SIV();

    void s2v(const void* plaintext,
             size_t text_len,
             const void* additional_data,
             size_t additional_len,
             void* iv);

    // 创建对象进行key构造，输入明文就可以加密
    void encrypt_and_authenticate(const void* plaintext,
                                  size_t text_len,
                                  const void* additional_data,
                                  size_t additional_len,
                                  void* ciphertext,
                                  void* siv);
    // 创建对象进行key构造，输入密文就可以解密
    bool decrypt_and_verify(const void* ciphertext,
                            size_t text_len,
                            const void* additional_data,
                            size_t additional_len,
                            void* plaintext,
                            const void* siv);
};

void hmac_sha256_calculate(const void* message,
                           size_t msg_len,
                           const void* key,
                           size_t key_len,
                           void* mac,
                           size_t mac_len);

bool hmac_sha256_verify(const void* message,
                        size_t msg_len,
                        const void* key,
                        size_t key_len,
                        const void* mac,
                        size_t mac_len);

// HMAC based key derivation function (https://tools.ietf.org/html/rfc5869)
// This one is not implemented by Crypto++, so we implement it ourselves
void hkdf(const void* key,
          size_t key_len,
          const void* salt,
          size_t salt_len,
          const void* info,
          size_t info_len,
          void* output,
          size_t out_len);

unsigned int pbkdf_hmac_sha256(const void* password,
                               size_t pass_len,
                               const void* salt,
                               size_t salt_len,
                               unsigned int min_iterations,
                               double min_seconds,
                               void* derived,
                               size_t derive_len);

unsigned int hkdf_with_sm3(const void* password,
                           size_t pass_len,
                           const void* salt,
                           size_t salt_len,
                           void* derived,
                           size_t derive_len);

void generate_random(void* buffer, size_t size);
}    // namespace securefs
