#ifndef _TINY_CRYPTO_MD5_STANDARD_H
#define _TINY_CRYPTO_MD5_STANDARD_H

#include <stdint.h>
#include <stddef.h>

#define MD5_BLOCK_SIZE  64
#define MD5_DIGEST_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

/* MD5 context. */
typedef struct MD5_CTX
{
    uint32_t state[4];   /* state (ABCD) */
    uint32_t count[2];   /* number of bits, modulo 2^64 (lsb first) */
    uint8_t  buffer[64]; /* input buffer */
} MD5_CTX;

typedef struct Md5StandardCTX
{
    MD5_CTX ctx;
} Md5StandardCTX;

void md5_standard_init(Md5StandardCTX* ctx);

void md5_standard_reset(Md5StandardCTX* ctx);

void md5_standard_update(Md5StandardCTX* ctx, const uint8_t* in, size_t inl);

void md5_standard_final(Md5StandardCTX* ctx, uint8_t digest[16]);

#ifdef __cplusplus
}
#endif

#endif