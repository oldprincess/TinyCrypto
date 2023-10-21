/**
 * WU W L, ZHANG L, ZHENG Y F, LI L C. The block cipher uBlock[J]. Journal of
 * Cryptologic Research, 2019, 6(6): 690–703.
 *
 * https://sfjs.cacrnet.org.cn/site/term/list_73_1.html
 */
#ifndef _TINY_CRYPTO_CIPHER_UBLOCK_STANDARD_H
#define _TINY_CRYPTO_CIPHER_UBLOCK_STANDARD_H

#include <stdint.h>
#include <stddef.h>

#define UBLOCK128128_BLOCK_SIZE   16
#define UBLOCK128128_USER_KEY_LEN 16

#define UBLOCK128256_BLOCK_SIZE   16
#define UBLOCK128256_USER_KEY_LEN 32

#define UBLOCK256256_BLOCK_SIZE   32
#define UBLOCK256256_USER_KEY_LEN 32

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct UBlockStandardCTX
{
    union SubKey
    {
        uint8_t sub_key128128[17][32]; // ublock<blk=128><key=128>
        uint8_t sub_key128256[25][32]; // ublock<blk=128><key=256>
        uint8_t sub_key256256[25][64]; // ublock<blk=256><key=256>
    } m;
} UBlockStandardCTX;

// ****************************************
// ********** uBlock 128/128 **************
// ****************************************

void ublock128128_standard_enc_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[16]);

void ublock128128_standard_dec_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[16]);

void ublock128128_standard_enc_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  ciphertext[16],
                                     const uint8_t            plaintext[16]);

void ublock128128_standard_dec_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  plaintext[16],
                                     const uint8_t            ciphertext[16]);

void ublock128128_standard_enc_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *ciphertext,
                                      const uint8_t           *plaintext,
                                      size_t                   block_num);

void ublock128128_standard_dec_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *plaintext,
                                      const uint8_t           *ciphertext,
                                      size_t                   block_num);

// ****************************************
// ********** uBlock 128/256 **************
// ****************************************

void ublock128256_standard_enc_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[32]);

void ublock128256_standard_dec_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[32]);

void ublock128256_standard_enc_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  ciphertext[16],
                                     const uint8_t            plaintext[16]);

void ublock128256_standard_dec_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  plaintext[16],
                                     const uint8_t            ciphertext[16]);

void ublock128256_standard_enc_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *ciphertext,
                                      const uint8_t           *plaintext,
                                      size_t                   block_num);

void ublock128256_standard_dec_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *plaintext,
                                      const uint8_t           *ciphertext,
                                      size_t                   block_num);

// ****************************************
// ********** uBlock 256/256 **************
// ****************************************

void ublock256256_standard_enc_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[32]);

void ublock256256_standard_dec_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[32]);

void ublock256256_standard_enc_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  ciphertext[32],
                                     const uint8_t            plaintext[32]);

void ublock256256_standard_dec_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  plaintext[32],
                                     const uint8_t            ciphertext[32]);

void ublock256256_standard_enc_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *ciphertext,
                                      const uint8_t           *plaintext,
                                      size_t                   block_num);

void ublock256256_standard_dec_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *plaintext,
                                      const uint8_t           *ciphertext,
                                      size_t                   block_num);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif