/**
 * ANG Xianwei, KANG Hongjuan. Fast software implementation of SM3 Hash
 * algorithm[J]. CAAI Transactions on Intelligent Systems, 2015, 10(2): 954-95.
 */
#ifndef _TINY_CRYPTO_HASH_SM3_FAST_H
#define _TINY_CRYPTO_HASH_SM3_FAST_H

#include <stdint.h>
#include <stddef.h>

#define SM3_BLOCK_SIZE  64
#define SM3_DIGEST_SIZE 32

namespace tc {

typedef struct Sm3FastCTX
{
    uint32_t state[8];
    uint64_t data_bits;

    uint8_t buf[64];
    size_t  buf_size;
} Sm3FastCTX;

void sm3_fast_init(Sm3FastCTX* ctx);

void sm3_fast_reset(Sm3FastCTX* ctx);

int sm3_fast_update(Sm3FastCTX* ctx, const uint8_t* in, size_t inl);

void sm3_fast_final(Sm3FastCTX* ctx, uint8_t digest[32]);

}; // namespace tc

#endif // !_TINY_CRYPTO_HASH_SM3_GMSSL_H
