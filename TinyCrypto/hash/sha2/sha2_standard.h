/**
 * US Secure Hash Algorithms(SHA and SHA-based HMAC and HKDF)
 * https://www.rfc-editor.org/rfc/rfc6234
 */
#ifndef _TINY_CRYPTO_HASH_SHA2_STANDARD_H
#define _TINY_CRYPTO_HASH_SHA2_STANDARD_H

#include <stdint.h>
#include <stddef.h>

#define SHA224_BLOCK_SIZE  64
#define SHA256_BLOCK_SIZE  64
#define SHA384_BLOCK_SIZE  128
#define SHA512_BLOCK_SIZE  128
#define SHA224_DIGEST_SIZE 28
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64

namespace tc {

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// *********** SHA224/256 CIPHER FUNCTION ***********
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

typedef struct Sha224256StandardCTX
{
    uint32_t state[8];
    uint64_t data_bits;

    uint8_t buf[64];
    size_t  buf_size;
} Sha224256StandardCTX;

// ****************************************
// ************** SHA224 ******************
// ****************************************

typedef Sha224256StandardCTX Sha224StandardCTX;

void sha224_standard_init(Sha224StandardCTX* ctx);

void sha224_standard_reset(Sha224StandardCTX* ctx);

int sha224_standard_update(Sha224StandardCTX* ctx,
                           const uint8_t*     in,
                           size_t             inl);

void sha224_standard_final(Sha224StandardCTX* ctx, uint8_t digest[28]);

// ****************************************
// ************** SHA256 ******************
// ****************************************

typedef Sha224256StandardCTX Sha256StandardCTX;

void sha256_standard_init(Sha256StandardCTX* ctx);

void sha256_standard_reset(Sha256StandardCTX* ctx);

int sha256_standard_update(Sha256StandardCTX* ctx,
                           const uint8_t*     in,
                           size_t             inl);

void sha256_standard_final(Sha256StandardCTX* ctx, uint8_t digest[32]);

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// *********** SHA384/512 CIPHER FUNCTION ***********
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

typedef struct Sha384512StandardCTX
{
    uint64_t state[8];
    uint64_t data_bits_h, data_bits_l;

    uint8_t buf[128];
    size_t  buf_size;
} Sha384512StandardCTX;

// ****************************************
// ************** SHA384 ******************
// ****************************************

typedef Sha384512StandardCTX Sha384StandardCTX;

void sha384_standard_init(Sha384StandardCTX* ctx);

void sha384_standard_reset(Sha384StandardCTX* ctx);

int sha384_standard_update(Sha384StandardCTX* ctx,
                           const uint8_t*     in,
                           size_t             inl);

void sha384_standard_final(Sha384StandardCTX* ctx, uint8_t digest[48]);

// ****************************************
// ************** SHA512 ******************
// ****************************************

typedef Sha384512StandardCTX Sha512StandardCTX;

void sha512_standard_init(Sha512StandardCTX* ctx);

void sha512_standard_reset(Sha512StandardCTX* ctx);

int sha512_standard_update(Sha512StandardCTX* ctx,
                           const uint8_t*     in,
                           size_t             inl);

void sha512_standard_final(Sha512StandardCTX* ctx, uint8_t digest[64]);

}; // namespace tc

#endif