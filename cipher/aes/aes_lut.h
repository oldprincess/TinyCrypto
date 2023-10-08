/**
 * FIPS 197. Advanced Encryption Standard (AES)
 *
 * J.Daemen, V.Rijmen. The Design of Rijndael[M]. Berlin: Springer, 2020: 53-63.
 */
#ifndef _TINY_CRYPTO_CIPHER_AES_LUT_H
#define _TINY_CRYPTO_CIPHER_AES_LUT_H

#include <stdint.h>
#include <stddef.h>

#define AES128_BLOCK_SIZE   16
#define AES192_BLOCK_SIZE   16
#define AES256_BLOCK_SIZE   16
#define AES128_USER_KEY_LEN 16
#define AES192_USER_KEY_LEN 24
#define AES256_USER_KEY_LEN 32

#ifdef __cplusplus
extern "C" {
#endif

// ****************************************
// ************* AES 128 ******************
// ****************************************

typedef struct Aes128LutCTX
{
    uint32_t round_key[44];
} Aes128LutCTX;

/**
 * @brief               AES-128 key schedule (encryption)
 * @param ctx           AES-128 Lut Encryption Context
 * @param user_key      16-byte secret key
 */
void aes128_lut_enc_key_init(Aes128LutCTX* ctx, const uint8_t user_key[16]);

/**
 * @brief               AES-128 key schedule (decryption)
 * @param ctx           AES-128 Lut Decryption Context
 * @param user_key      16-byte secret key
 */
void aes128_lut_dec_key_init(Aes128LutCTX* ctx, const uint8_t user_key[16]);

/**
 * @brief               AES-128 block encryption
 * @param ctx           AES-128 Lut Encryption Context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void aes128_lut_enc_block(const Aes128LutCTX* ctx,
                          uint8_t             ciphertext[16],
                          const uint8_t       plaintext[16]);

/**
 * @brief               AES-128 block decryption
 * @param ctx           AES-128 Lut Decryption Context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void aes128_lut_dec_block(const Aes128LutCTX* ctx,
                          uint8_t             plaintext[16],
                          const uint8_t       ciphertext[16]);

void aes128_lut_enc_blocks(const Aes128LutCTX* ctx,
                           uint8_t*            ciphertext,
                           const uint8_t*      plaintext,
                           size_t              block_num);

void aes128_lut_dec_blocks(const Aes128LutCTX* ctx,
                           uint8_t*            plaintext,
                           const uint8_t*      ciphertext,
                           size_t              block_num);

// ****************************************
// ************* AES 192 ******************
// ****************************************

typedef struct Aes192LutCTX
{
    uint32_t round_key[52];
} Aes192LutCTX;

/**
 * @brief               AES-192 key schedule (encryption)
 * @param ctx           AES-192 Lut Encryption Context
 * @param user_key      24-byte secret key
 */
void aes192_lut_enc_key_init(Aes192LutCTX* ctx, const uint8_t user_key[24]);

/**
 * @brief               AES-192 key schedule (decryption)
 * @param ctx           AES-192 Lut Decryption Context
 * @param user_key      24-byte secret key
 */
void aes192_lut_dec_key_init(Aes192LutCTX* ctx, const uint8_t user_key[24]);

/**
 * @brief               AES-192 block encryption
 * @param ctx           AES-192 Lut Encryption Context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void aes192_lut_enc_block(const Aes192LutCTX* ctx,
                          uint8_t             ciphertext[16],
                          const uint8_t       plaintext[16]);

/**
 * @brief               AES-192 block decryption
 * @param ctx           AES-192 Lut Decryption Context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void aes192_lut_dec_block(const Aes192LutCTX* ctx,
                          uint8_t             plaintext[16],
                          const uint8_t       ciphertext[16]);

void aes192_lut_enc_blocks(const Aes192LutCTX* ctx,
                           uint8_t*            ciphertext,
                           const uint8_t*      plaintext,
                           size_t              block_num);

void aes192_lut_dec_blocks(const Aes192LutCTX* ctx,
                           uint8_t*            plaintext,
                           const uint8_t*      ciphertext,
                           size_t              block_num);

// ****************************************
// ************* AES 256 ******************
// ****************************************

typedef struct Aes256LutCTX
{
    uint32_t round_key[60];
} Aes256LutCTX;

/**
 * @brief               AES-256 key schedule (encryption)
 * @param ctx           AES-256 Lut Encryption Context
 * @param user_key      32-byte secret key
 */
void aes256_lut_enc_key_init(Aes256LutCTX* ctx, const uint8_t user_key[32]);

/**
 * @brief               AES-256 key schedule (decryption)
 * @param ctx           AES-256 Lut Decryption Context
 * @param user_key      32-byte secret key
 */
void aes256_lut_dec_key_init(Aes256LutCTX* ctx, const uint8_t user_key[32]);

/**
 * @brief               AES-256 block encryption
 * @param ctx           AES-256 Lut Encryption Context
 * @param ciphertext    16-byte output block
 * @param plaintext     16-byte input block
 */
void aes256_lut_enc_block(const Aes256LutCTX* ctx,
                          uint8_t             ciphertext[16],
                          const uint8_t       plaintext[16]);

/**
 * @brief               AES-256 block decryption
 * @param ctx           AES-256 Lut Decryption Context
 * @param plaintext     16-byte output block
 * @param ciphertext    16-byte input block
 */
void aes256_lut_dec_block(const Aes256LutCTX* ctx,
                          uint8_t             plaintext[16],
                          const uint8_t       ciphertext[16]);

void aes256_lut_enc_blocks(const Aes256LutCTX* ctx,
                           uint8_t*            ciphertext,
                           const uint8_t*      plaintext,
                           size_t              block_num);

void aes256_lut_dec_blocks(const Aes256LutCTX* ctx,
                           uint8_t*            plaintext,
                           const uint8_t*      ciphertext,
                           size_t              block_num);

#ifdef __cplusplus
}
#endif

#endif