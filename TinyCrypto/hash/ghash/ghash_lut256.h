/**
 * McGrew D, Viega J. The Galois/counter mode of operation (GCM)[J]. submission
 * to NIST Modes of Operation Process, 2004, 20: 0278-0070.
 */
#ifndef _TINY_CRYPTO_HASH_GHASH_LUT256_H
#define _TINY_CRYPTO_HASH_GHASH_LUT256_H

#include <stdint.h>
#include <stddef.h>

#define GHASH_BLOCK_SIZE  16
#define GHASH_DIGEST_SIZE 16

namespace tc {

typedef struct GHashLut256CTX
{
    uint64_t T[256][2];
    uint64_t state[2];

    uint8_t buf[16];
    size_t  buf_size;
} GHashLut256CTX;

void ghash_lut256_init(GHashLut256CTX* ctx, const uint8_t H[16]);

void ghash_lut256_reset(GHashLut256CTX* ctx);

void ghash_lut256_update(GHashLut256CTX* ctx, const uint8_t* in, size_t inl);

int ghash_lut256_final(const GHashLut256CTX* ctx, uint8_t digest[16]);

}; // namespace tc

#endif