/*
The MIT License (MIT)

Copyright (c) 2023 oldprincess, https://github.com/oldprincess/TinyCrypto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef TINY_CRYPTO_HASH_SHA1_SHANI_H
#define TINY_CRYPTO_HASH_SHA1_SHANI_H

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

/**
 * @brief       SHA1 Context Init
 * @param ctx   SHA1 Context
 */
void sha1_shani_init(Sha1ShaniCTX* ctx);

/**
 * @brief       SHA1 Context Reset
 * @param ctx   SHA1 Context
 */
void sha1_shani_reset(Sha1ShaniCTX* ctx);

/**
 * @brief       SHA1 update message
 * @param ctx   SHA1 Context
 * @param in    input message, inl bytes
 * @param inl   message length
 * @return      0(success), -1(message too long)
 */
int sha1_shani_update(Sha1ShaniCTX* ctx, const uint8_t* in, size_t inl);

/**
 * @brief           SHA1 output digest
 * @param ctx       SHA1 Context
 * @param digest    20-bytes SHA1 digest
 */
void sha1_shani_final(Sha1ShaniCTX* ctx, uint8_t digest[20]);

}; // namespace tc

#endif