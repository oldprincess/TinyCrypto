/**
 * Intel Carry-Less Multiplication Instruction and its Usage for Computing the
 * GCM Mode.
 */
#ifndef _TINY_CRYPTO_HASH_GHASH_PCLMUL_H
#define _TINY_CRYPTO_HASH_GHASH_PCLMUL_H

#include <stdint.h>
#include <stddef.h>

#define GHASH_BLOCK_SIZE  16
#define GHASH_DIGEST_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct GHashPclmulCTX
{
    uint8_t H[16];
    uint8_t state[16];

    uint8_t buf[16];
    size_t  buf_size;
} GHashPclmulCTX;

void ghash_pclmul_init(GHashPclmulCTX* ctx, const uint8_t H[16]);

void ghash_pclmul_reset(GHashPclmulCTX* ctx);

void ghash_pclmul_update(GHashPclmulCTX* ctx, const uint8_t* in, size_t inl);

int ghash_pclmul_final(const GHashPclmulCTX* ctx, uint8_t digest[16]);

#ifdef __cplusplus
}
#endif

#endif