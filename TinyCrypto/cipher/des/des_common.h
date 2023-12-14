/**
 * FIPS 46-3: Data Encryption Standard (DES)
 */
#ifndef _TINY_CRYPTO_CIPHER_DES_COMMON_H
#define _TINY_CRYPTO_CIPHER_DES_COMMON_H

#include <stdint.h>
#include <stddef.h>

#define DES_BLOCK_SIZE   8
#define DES_USER_KEY_LEN 8

namespace tc {

typedef struct DesCommonCTX
{
    uint64_t round_key[16];
} DesCommonCTX;

void des_common_enc_key_init(DesCommonCTX* ctx, const uint8_t user_key[8]);

void des_common_dec_key_init(DesCommonCTX* ctx, const uint8_t user_key[8]);

void des_common_enc_block(const DesCommonCTX* ctx,
                          uint8_t             ciphertext[8],
                          const uint8_t       plaintext[8]);

void des_common_dec_block(const DesCommonCTX* ctx,
                          uint8_t             plaintext[8],
                          const uint8_t       ciphertext[8]);

void des_common_enc_blocks(const DesCommonCTX* ctx,
                           uint8_t*            ciphertext,
                           const uint8_t*      plaintext,
                           size_t              block_num);

void des_common_dec_blocks(const DesCommonCTX* ctx,
                           uint8_t*            plaintext,
                           const uint8_t*      ciphertext,
                           size_t              block_num);

}; // namespace tc

#endif