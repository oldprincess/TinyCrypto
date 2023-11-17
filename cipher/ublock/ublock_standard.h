/*
The MIT License (MIT)

Copyright (c) 2023 oldprincess, https://github.com/oldprincess/TinyCrypto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*
WU W L, ZHANG L, ZHENG Y F, LI L C. The block cipher uBlock[J]. Journal of
Cryptologic Research, 2019, 6(6): 690-703.
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

namespace tc {

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

/**
 * @brief           uBlock128/128 key schedule (encryption)
 * @param ctx       uBlock128/128 standard encryption context
 * @param user_key  16-byte secret key
 */
void ublock128128_standard_enc_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[16]);

/**
 * @brief           uBlock128/128 key schedule (decryption)
 * @param ctx       uBlock128/128 standard decryption context
 * @param user_key  16-byte secret key
 */
void ublock128128_standard_dec_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[16]);

/**
 * @brief               uBlock128/128 block encryption
 * @param ctx           uBlock128/128 standard encryption context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void ublock128128_standard_enc_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  ciphertext[16],
                                     const uint8_t            plaintext[16]);

/**
 * @brief               uBlock128/128 block decryption
 * @param ctx           uBlock128/128 standard decryption context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void ublock128128_standard_dec_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  plaintext[16],
                                     const uint8_t            ciphertext[16]);

/**
 * @brief               uBlock128/128 block encryption, crypt in ECB mode
 * @param ctx           uBlock128/128 standard encryption context
 * @param ciphertext    output blocks, length of 16 x block_num bytes
 * @param plaintext     input blocks, length of 16 x block_num bytes
 * @param block_num     block num
 */
void ublock128128_standard_enc_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *ciphertext,
                                      const uint8_t           *plaintext,
                                      size_t                   block_num);

/**
 * @brief               uBlock128/128 block decryption, crypt in ECB mode
 * @param ctx           uBlock128/128 standard decryption context
 * @param plaintext     output blocks, length of 16 x block_num bytes
 * @param ciphertext    input blocks, length of 16 x block_num bytes
 * @param block_num     block num
 */
void ublock128128_standard_dec_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *plaintext,
                                      const uint8_t           *ciphertext,
                                      size_t                   block_num);

// ****************************************
// ********** uBlock 128/256 **************
// ****************************************

/**
 * @brief           uBlock128/256 key schedule (encryption)
 * @param ctx       uBlock128/256 standard encryption context
 * @param user_key  32-byte secret key
 */
void ublock128256_standard_enc_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[32]);

/**
 * @brief           uBlock128/256 key schedule (decryption)
 * @param ctx       uBlock128/256 standard decryption context
 * @param user_key  32-byte secret key
 */
void ublock128256_standard_dec_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[32]);

/**
 * @brief               uBlock128/256 block encryption
 * @param ctx           uBlock128/256 standard encryption context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void ublock128256_standard_enc_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  ciphertext[16],
                                     const uint8_t            plaintext[16]);

/**
 * @brief               uBlock128/256 block decryption
 * @param ctx           uBlock128/256 standard decryption context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void ublock128256_standard_dec_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  plaintext[16],
                                     const uint8_t            ciphertext[16]);

/**
 * @brief               uBlock128/256 block encryption, crypt in ECB mode
 * @param ctx           uBlock128/256 standard encryption context
 * @param ciphertext    output blocks, length of 16 x block_num bytes
 * @param plaintext     input blocks, length of 16 x block_num bytes
 * @param block_num     block num
 */
void ublock128256_standard_enc_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *ciphertext,
                                      const uint8_t           *plaintext,
                                      size_t                   block_num);

/**
 * @brief               uBlock128/256 block decryption, crypt in ECB mode
 * @param ctx           uBlock128/256 standard decryption context
 * @param plaintext     output blocks, length of 16 x block_num bytes
 * @param ciphertext    input blocks, length of 16 x block_num bytes
 * @param block_num     block num
 */
void ublock128256_standard_dec_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *plaintext,
                                      const uint8_t           *ciphertext,
                                      size_t                   block_num);

// ****************************************
// ********** uBlock 256/256 **************
// ****************************************

/**
 * @brief           uBlock256/256 key schedule (encryption)
 * @param ctx       uBlock1256/256 standard encryption context
 * @param user_key  32-byte secret key
 */
void ublock256256_standard_enc_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[32]);

/**
 * @brief           uBlock256/256 key schedule (decryption)
 * @param ctx       uBlock1256/256 standard decryption context
 * @param user_key  32-byte secret key
 */
void ublock256256_standard_dec_key_init(UBlockStandardCTX *ctx,
                                        const uint8_t      user_key[32]);

/**
 * @brief               uBlock256/256 block encryption
 * @param ctx           uBlock256/256 standard encryption context
 * @param ciphertext    32-byte output block
 * @param plaintext     32-byte input block
 */
void ublock256256_standard_enc_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  ciphertext[32],
                                     const uint8_t            plaintext[32]);

/**
 * @brief               uBlock256/256 block decryption
 * @param ctx           uBlock256/256 standard decryption context
 * @param plaintext     32-byte output block
 * @param ciphertext    32-byte input block
 */
void ublock256256_standard_dec_block(const UBlockStandardCTX *ctx,
                                     uint8_t                  plaintext[32],
                                     const uint8_t            ciphertext[32]);

/**
 * @brief               uBlock256/256 block encryption, crypt in ECB mode
 * @param ctx           uBlock256/256 standard encryption context
 * @param ciphertext    output blocks, length of 32 x block_num bytes
 * @param plaintext     input blocks, length of 32 x block_num bytes
 * @param block_num     block num
 */
void ublock256256_standard_enc_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *ciphertext,
                                      const uint8_t           *plaintext,
                                      size_t                   block_num);

/**
 * @brief               uBlock256/256 block decryption, crypt in ECB mode
 * @param ctx           uBlock256/256 standard decryption context
 * @param plaintext     output blocks, length of 32 x block_num bytes
 * @param ciphertext    input blocks, length of 32 x block_num bytes
 * @param block_num     block num
 */
void ublock256256_standard_dec_blocks(const UBlockStandardCTX *ctx,
                                      uint8_t                 *plaintext,
                                      const uint8_t           *ciphertext,
                                      size_t                   block_num);

}; // namespace tc

#endif