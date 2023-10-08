/**
 * Lang H, Zhang L, Wu W L. Fast software implementation of SM4[J]. Journal of
 * University of Chinese Academy of Sciences, 2018, 35(2): 180-187.
 *
 */
#ifndef _TINY_CRYPTO_CIPHER_SM4_LUT_H
#define _TINY_CRYPTO_CIPHER_SM4_LUT_H

#include <stdint.h>
#include <stddef.h>

#define SM4_BLOCK_SIZE   16
#define SM4_USER_KEY_LEN 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Sm4LutCTX
{
    uint32_t round_key[32];
} Sm4LutCTX;

void sm4_lut_enc_key_init(Sm4LutCTX* ctx, const uint8_t user_key[16]);

void sm4_lut_dec_key_init(Sm4LutCTX* ctx, const uint8_t user_key[16]);

void sm4_lut_enc_block(const Sm4LutCTX* ctx,
                       uint8_t          ciphertext[16],
                       const uint8_t    plaintext[16]);

void sm4_lut_dec_block(const Sm4LutCTX* ctx,
                       uint8_t          plaintext[16],
                       const uint8_t    ciphertext[16]);

void sm4_lut_enc_block_x4(const Sm4LutCTX* ctx,
                          uint8_t          ciphertext[64],
                          const uint8_t    plaintext[64]);

void sm4_lut_dec_block_x4(const Sm4LutCTX* ctx,
                          uint8_t          plaintext[64],
                          const uint8_t    ciphertext[64]);

void sm4_lut_enc_blocks(const Sm4LutCTX* ctx,
                        uint8_t*         ciphertext,
                        const uint8_t*   plaintext,
                        size_t           block_num);

void sm4_lut_dec_blocks(const Sm4LutCTX* ctx,
                        uint8_t*         plaintext,
                        const uint8_t*   ciphertext,
                        size_t           block_num);

#ifdef __cplusplus
}
#endif

#endif