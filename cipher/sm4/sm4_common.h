#ifndef _TINY_CRYPTO_CIPHER_SM4_COMMON_H
#define _TINY_CRYPTO_CIPHER_SM4_COMMON_H

#include <stdint.h>
#include <stddef.h>

#define SM4_BLOCK_SIZE   16
#define SM4_USER_KEY_LEN 16

namespace tc {

typedef struct Sm4CommonCTX
{
    uint32_t round_key[32];
} Sm4CommonCTX;

void sm4_common_enc_key_init(Sm4CommonCTX *ctx, const uint8_t user_key[16]);

void sm4_common_dec_key_init(Sm4CommonCTX *ctx, const uint8_t user_key[16]);

void sm4_common_enc_block(const Sm4CommonCTX *ctx,
                          uint8_t             ciphertext[16],
                          const uint8_t       plaintext[16]);

void sm4_common_dec_block(const Sm4CommonCTX *ctx,
                          uint8_t             plaintext[16],
                          const uint8_t       ciphertext[16]);

void sm4_common_enc_blocks(const Sm4CommonCTX *ctx,
                           uint8_t            *ciphertext,
                           const uint8_t      *plaintext,
                           size_t              block_num);

void sm4_common_dec_blocks(const Sm4CommonCTX *ctx,
                           uint8_t            *plaintext,
                           const uint8_t      *ciphertext,
                           size_t              block_num);

}; // namespace tc

#endif