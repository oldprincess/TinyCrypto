/**
 * FIPS 197. Advanced Encryption Standard (AES)
 *
 * Partial reference: MIT License, Copyright (c) 2023 Jubal Mordecai Velasco,
 * @cite https://github.com/mrdcvlsc/AES/blob/main/AES.hpp
 *
 * Intel Intrinsics Guide.
 * https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html
 */
#ifndef _TINY_CRYPTO_CIPHER_AES_AESNI_H
#define _TINY_CRYPTO_CIPHER_AES_AESNI_H

#include <stdint.h>
#include <stddef.h>

#define AES128_BLOCK_SIZE   16
#define AES192_BLOCK_SIZE   16
#define AES256_BLOCK_SIZE   16
#define AES128_USER_KEY_LEN 16
#define AES192_USER_KEY_LEN 24
#define AES256_USER_KEY_LEN 32

namespace tc {

// ****************************************
// ************* AES 128 ******************
// ****************************************

typedef struct Aes128AesniCTX
{
    uint8_t round_key[11][16];
} Aes128AesniCTX;

/**
 * @brief               AES-128 key schedule (encryption)
 * @param ctx           AES-128 Aesni Encryption Context
 * @param user_key      16-byte secret key
 */
void aes128_aesni_enc_key_init(Aes128AesniCTX* ctx, const uint8_t user_key[16]);

/**
 * @brief               AES-128 key schedule (decryption)
 * @param ctx           AES-128 Aesni Decryption Context
 * @param user_key      16-byte secret key
 */
void aes128_aesni_dec_key_init(Aes128AesniCTX* ctx, const uint8_t user_key[16]);

/**
 * @brief               AES-128 block encryption
 * @param ctx           AES-128 Aesni Encryption Context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void aes128_aesni_enc_block(const Aes128AesniCTX* ctx,
                            uint8_t               ciphertext[16],
                            const uint8_t         plaintext[16]);

/**
 * @brief               AES-128 block decryption
 * @param ctx           AES-128 Aesni Decryption Context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void aes128_aesni_dec_block(const Aes128AesniCTX* ctx,
                            uint8_t               plaintext[16],
                            const uint8_t         ciphertext[16]);

void aes128_aesni_enc_blocks(const Aes128AesniCTX* ctx,
                             uint8_t*              ciphertext,
                             const uint8_t*        plaintext,
                             size_t                block_num);

void aes128_aesni_dec_blocks(const Aes128AesniCTX* ctx,
                             uint8_t*              plaintext,
                             const uint8_t*        ciphertext,
                             size_t                block_num);

// ****************************************
// ************* AES 192 ******************
// ****************************************

typedef struct Aes192AesniCTX
{
    uint8_t round_key[13][16];
} Aes192AesniCTX;

/**
 * @brief               AES-192 key schedule (encryption)
 * @param ctx           AES-192 Aesni Encryption Context
 * @param user_key      24-byte secret key
 */
void aes192_aesni_enc_key_init(Aes192AesniCTX* ctx, const uint8_t user_key[24]);

/**
 * @brief               AES-192 key schedule (decryption)
 * @param ctx           AES-192 Aesni Decryption Context
 * @param user_key      24-byte secret key
 */
void aes192_aesni_dec_key_init(Aes192AesniCTX* ctx, const uint8_t user_key[24]);

/**
 * @brief               AES-192 block encryption
 * @param ctx           AES-192 Aesni Encryption Context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void aes192_aesni_enc_block(const Aes192AesniCTX* ctx,
                            uint8_t               ciphertext[16],
                            const uint8_t         plaintext[16]);

/**
 * @brief               AES-192 block decryption
 * @param ctx           AES-192 Aesni Decryption Context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void aes192_aesni_dec_block(const Aes192AesniCTX* ctx,
                            uint8_t               plaintext[16],
                            const uint8_t         ciphertext[16]);

void aes192_aesni_enc_blocks(const Aes192AesniCTX* ctx,
                             uint8_t*              ciphertext,
                             const uint8_t*        plaintext,
                             size_t                block_num);

void aes192_aesni_dec_blocks(const Aes192AesniCTX* ctx,
                             uint8_t*              plaintext,
                             const uint8_t*        ciphertext,
                             size_t                block_num);

// ****************************************
// ************* AES 256 ******************
// ****************************************

typedef struct Aes256AesniCTX
{
    uint8_t round_key[15][16];
} Aes256AesniCTX;

/**
 * @brief               AES-256 key schedule (encryption)
 * @param ctx           AES-256 Aesni Encryption Context
 * @param user_key      32-byte secret key
 */
void aes256_aesni_enc_key_init(Aes256AesniCTX* ctx, const uint8_t user_key[32]);

/**
 * @brief               AES-256 key schedule (decryption)
 * @param ctx           AES-256 Aesni Decryption Context
 * @param user_key      32-byte secret key
 */
void aes256_aesni_dec_key_init(Aes256AesniCTX* ctx, const uint8_t user_key[32]);

/**
 * @brief               AES-256 block encryption
 * @param ctx           AES-256 Aesni Encryption Context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void aes256_aesni_enc_block(const Aes256AesniCTX* ctx,
                            uint8_t               ciphertext[16],
                            const uint8_t         plaintext[16]);

/**
 * @brief               AES-256 block decryption
 * @param ctx           AES-256 Aesni Decryption Context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void aes256_aesni_dec_block(const Aes256AesniCTX* ctx,
                            uint8_t               plaintext[16],
                            const uint8_t         ciphertext[16]);

void aes256_aesni_enc_blocks(const Aes256AesniCTX* ctx,
                             uint8_t*              ciphertext,
                             const uint8_t*        plaintext,
                             size_t                block_num);

void aes256_aesni_dec_blocks(const Aes256AesniCTX* ctx,
                             uint8_t*              plaintext,
                             const uint8_t*        ciphertext,
                             size_t                block_num);

}; // namespace tc

#endif