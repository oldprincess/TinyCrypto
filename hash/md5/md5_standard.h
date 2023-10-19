/**
 * modify
 * cite: https://www.rfc-editor.org/rfc/rfc1321
 */
#ifndef _TINY_CRYPTO_MD5_STANDARD_H
#define _TINY_CRYPTO_MD5_STANDARD_H

#include <stdint.h>
#include <stddef.h>

#define MD5_BLOCK_SIZE  64
#define MD5_DIGEST_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Md5StandardCTX
{
    uint32_t state[4];
    uint64_t data_bits;

    uint8_t buf[64];
    size_t  buf_size;
} Md5StandardCTX;

void md5_standard_init(Md5StandardCTX* ctx);

void md5_standard_reset(Md5StandardCTX* ctx);

void md5_standard_update(Md5StandardCTX* ctx, const uint8_t* in, size_t inl);

void md5_standard_final(Md5StandardCTX* ctx, uint8_t digest[16]);

#ifdef __cplusplus
}
#endif

#endif