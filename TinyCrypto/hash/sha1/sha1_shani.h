#ifndef _TINY_CRYPTO_HASH_SHA1_SHANI_H
#define _TINY_CRYPTO_HASH_SHA1_SHANI_H

#include <stdint.h>
#include <stddef.h>

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20

namespace tc {

typedef struct _Sha1ShaniCTX
{
    uint32_t state[5];
    uint64_t data_bits;

    uint8_t buf[64];
    size_t  buf_size;
} Sha1ShaniCTX;

void sha1_sha_init(Sha1ShaniCTX* ctx);

void sha1_sha_reset(Sha1ShaniCTX* ctx);

int sha1_sha_update(Sha1ShaniCTX* ctx, const uint8_t* in, size_t inl);

void sha1_sha_final(Sha1ShaniCTX* ctx, uint8_t digest[20]);

}; // namespace tc

#endif