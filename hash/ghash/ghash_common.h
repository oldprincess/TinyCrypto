/**
 * Dworkin M. Recommendation for block cipher modes of operation: Galois/Counter
 * Mode (GCM) and GMAC[R]. National Institute of Standards and Technology, 2007.
 */
#ifndef _TINY_CRYPTO_HASH_GHASH_COMMON_H
#define _TINY_CRYPTO_HASH_GHASH_COMMON_H

#include <stdint.h>
#include <stddef.h>

#define GHASH_BLOCK_SIZE  16
#define GHASH_DIGEST_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct GHashCommonCTX
{
    uint64_t H[2];
    uint64_t state[2];

    uint8_t buf[16];
    size_t  buf_size;
} GHashCommonCTX;

void ghash_common_init(GHashCommonCTX* ctx, const uint8_t H[16]);

void ghash_common_reset(GHashCommonCTX* ctx);

void ghash_common_update(GHashCommonCTX* ctx, const uint8_t* in, size_t inl);

int ghash_common_final(const GHashCommonCTX* ctx, uint8_t digest[16]);

#ifdef __cplusplus
}
#endif

#endif