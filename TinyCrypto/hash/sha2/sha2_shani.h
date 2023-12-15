/**
 * US Secure Hash Algorithms(SHA and SHA-based HMAC and HKDF)
 * https://www.rfc-editor.org/rfc/rfc6234
 */
#ifndef _TINY_CRYPTO_HASH_SHA2_SHANI_H
#define _TINY_CRYPTO_HASH_SHA2_SHANI_H

#include <stdint.h>
#include <stddef.h>

#define SHA224_BLOCK_SIZE  64
#define SHA256_BLOCK_SIZE  64
#define SHA224_DIGEST_SIZE 28
#define SHA256_DIGEST_SIZE 32

namespace tc {

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// *********** SHA224/256 CIPHER FUNCTION ***********
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

typedef struct Sha224256ShaniCTX
{
    uint32_t state[8];
    uint64_t data_bits;

    uint8_t buf[64];
    size_t  buf_size;
} Sha224256ShaniCTX;

// ****************************************
// ************** SHA224 ******************
// ****************************************

typedef Sha224256ShaniCTX Sha224ShaniCTX;

void sha224_shani_init(Sha224ShaniCTX* ctx);

void sha224_shani_reset(Sha224ShaniCTX* ctx);

int sha224_shani_update(Sha224ShaniCTX* ctx, const uint8_t* in, size_t inl);

void sha224_shani_final(Sha224ShaniCTX* ctx, uint8_t digest[28]);

// ****************************************
// ************** SHA256 ******************
// ****************************************

typedef Sha224256ShaniCTX Sha256ShaniCTX;

void sha256_shani_init(Sha256ShaniCTX* ctx);

void sha256_shani_reset(Sha256ShaniCTX* ctx);

int sha256_shani_update(Sha256ShaniCTX* ctx, const uint8_t* in, size_t inl);

void sha256_shani_final(Sha256ShaniCTX* ctx, uint8_t digest[32]);

}; // namespace tc

#endif