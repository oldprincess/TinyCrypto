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

namespace tc {

typedef struct Sm4LutCTX
{
    uint32_t round_key[32];
} Sm4LutCTX;

/**
 * @brief               SM4 key schedule (encryption)
 * @param ctx           SM4 Lut Encryption Context
 * @param user_key      16-byte secret key
 */
void sm4_lut_enc_key_init(Sm4LutCTX* ctx, const uint8_t user_key[16]);

/**
 * @brief               SM4 key schedule (decryption)
 * @param ctx           SM4 Lut Decryption Context
 * @param user_key      16-byte secret key
 */
void sm4_lut_dec_key_init(Sm4LutCTX* ctx, const uint8_t user_key[16]);

/**
 * @brief               SM4 block encryption
 * @param ctx           SM4 Lut Encryption Context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void sm4_lut_enc_block(const Sm4LutCTX* ctx,
                       uint8_t          ciphertext[16],
                       const uint8_t    plaintext[16]);

/**
 * @brief               SM4 block decryption
 * @param ctx           SM4 Lut Decryption Context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void sm4_lut_dec_block(const Sm4LutCTX* ctx,
                       uint8_t          plaintext[16],
                       const uint8_t    ciphertext[16]);

/**
 * @brief               SM4 block encryption, crypt in ECB mode, 4 parallel
 * @param ctx           SM4 Lut encryption context
 * @param ciphertext    output blocks, length of 16 x 4 bytes
 * @param plaintext     input blocks, length of 16 x 4 bytes
 */
void sm4_lut_enc_block_x4(const Sm4LutCTX* ctx,
                          uint8_t          ciphertext[64],
                          const uint8_t    plaintext[64]);

/**
 * @brief               SM4 block decryption, crypt in ECB mode, 4 parallel
 * @param ctx           SM4 Lut decryption context
 * @param plaintext     output blocks, length of 16 x 4 bytes
 * @param ciphertext    input blocks, length of 16 x 4 bytes
 */
void sm4_lut_dec_block_x4(const Sm4LutCTX* ctx,
                          uint8_t          plaintext[64],
                          const uint8_t    ciphertext[64]);

/**
 * @brief               SM4 block encryption, crypt in ECB mode
 * @param ctx           SM4 Lut encryption context
 * @param ciphertext    output blocks, length of 16 x block_num bytes
 * @param plaintext     input blocks, length of 16 x block_num bytes
 * @param block_num     block num
 */
void sm4_lut_enc_blocks(const Sm4LutCTX* ctx,
                        uint8_t*         ciphertext,
                        const uint8_t*   plaintext,
                        size_t           block_num);

/**
 * @brief               SM4 block decryption, crypt in ECB mode
 * @param ctx           SM4 Lut decryption context
 * @param plaintext     output blocks, length of 16 x block_num bytes
 * @param ciphertext    input blocks, length of 16 x block_num bytes
 * @param block_num     block num
 */
void sm4_lut_dec_blocks(const Sm4LutCTX* ctx,
                        uint8_t*         plaintext,
                        const uint8_t*   ciphertext,
                        size_t           block_num);

}; // namespace tc

#endif