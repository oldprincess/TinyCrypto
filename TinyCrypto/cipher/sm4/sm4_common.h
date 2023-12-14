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
GB/T 32907-2016 Information security technology—SM4 block cipher algorthm
*/
#ifndef _TINY_CRYPTO_CIPHER_SM4_COMMON_H
#define _TINY_CRYPTO_CIPHER_SM4_COMMON_H

#include <stdint.h>
#include <stddef.h>

#define SM4_BLOCK_SIZE   16
#define SM4_USER_KEY_LEN 16

namespace tc {

/**
 * @brief SM4 cipher context of commom implementation
 */
typedef struct Sm4CommonCTX
{
    uint32_t round_key[32]; // 32x32-bit round key
} Sm4CommonCTX;

/**
 * @brief           SM4 key schedule (encryption)
 * @param ctx       SM4 common encryption context
 * @param user_key  16-byte secret key
 */
void sm4_common_enc_key_init(Sm4CommonCTX *ctx, const uint8_t user_key[16]);

/**
 * @brief           SM4 key schedule (decryption)
 * @param ctx       SM4 common decryption context
 * @param user_key  16-byte secret key
 */
void sm4_common_dec_key_init(Sm4CommonCTX *ctx, const uint8_t user_key[16]);

/**
 * @brief               SM4 block encryption
 * @param ctx           SM4 common encryption context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void sm4_common_enc_block(const Sm4CommonCTX *ctx,
                          uint8_t             ciphertext[16],
                          const uint8_t       plaintext[16]);

/**
 * @brief               SM4 block decryption
 * @param ctx           SM4 common decryption context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void sm4_common_dec_block(const Sm4CommonCTX *ctx,
                          uint8_t             plaintext[16],
                          const uint8_t       ciphertext[16]);

/**
 * @brief               SM4 block encryption, crypt in ECB mode
 * @param ctx           SM4 common encryption context
 * @param ciphertext    output blocks, length of 16 x block_num bytes
 * @param plaintext     input blocks, length of 16 x block_num bytes
 * @param block_num     block num
 */
void sm4_common_enc_blocks(const Sm4CommonCTX *ctx,
                           uint8_t            *ciphertext,
                           const uint8_t      *plaintext,
                           size_t              block_num);

/**
 * @brief               SM4 block decryption, crypt in ECB mode
 * @param ctx           SM4 common decryption context
 * @param plaintext     output blocks, length of 16 x block_num bytes
 * @param ciphertext    input blocks, length of 16 x block_num bytes
 * @param block_num     block num
 */
void sm4_common_dec_blocks(const Sm4CommonCTX *ctx,
                           uint8_t            *plaintext,
                           const uint8_t      *ciphertext,
                           size_t              block_num);

}; // namespace tc

#endif