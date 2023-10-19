#ifndef _TINY_CRYPTO_HASH_SHA1_STANDARD_H
#define _TINY_CRYPTO_HASH_SHA1_STANDARD_H

#include <stdint.h>
#include <stddef.h>

#define SHA1_BLOCK_SIZE  64
#define SHA1_DIGEST_SIZE 20

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

typedef struct _Sha1StandardCTX
{
    uint32_t state[5];
    uint64_t data_bits;

    uint8_t buf[64];
    size_t  buf_size;
} Sha1StandardCTX;

void sha1_standard_init(Sha1StandardCTX* ctx);

void sha1_standard_reset(Sha1StandardCTX* ctx);

int sha1_standard_update(Sha1StandardCTX* ctx, const uint8_t* in, size_t inl);

void sha1_standard_final(Sha1StandardCTX* ctx, uint8_t digest[20]);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif