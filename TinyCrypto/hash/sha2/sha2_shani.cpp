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

/**
 * part of the code is "derived from miTLS project. sha256-x86.c"
 *
 * https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c
 *
 * sha256-x86.c - Intel SHA extensions using C intrinsics
 * Written and place in public domain by Jeffrey Walton
 * Based on code from Intel, and by Sean Gulley for
 * the miTLS project.
 */
#include "sha2_shani.h"
#include <immintrin.h>
#include <string.h>

namespace tc {

#define MEM_LOAD32BE(src)                        \
    (((uint32_t)(((uint8_t *)(src))[0]) << 24) | \
     ((uint32_t)(((uint8_t *)(src))[1]) << 16) | \
     ((uint32_t)(((uint8_t *)(src))[2]) << 8) |  \
     ((uint32_t)(((uint8_t *)(src))[3]) << 0))

#define MEM_STORE32BE(dst, a)                              \
    (((uint8_t *)(dst))[0] = ((uint32_t)(a) >> 24) & 0xFF, \
     ((uint8_t *)(dst))[1] = ((uint32_t)(a) >> 16) & 0xFF, \
     ((uint8_t *)(dst))[2] = ((uint32_t)(a) >> 8) & 0xFF,  \
     ((uint8_t *)(dst))[3] = ((uint32_t)(a) >> 0) & 0xFF)

#define MEM_LOAD64BE(src)                        \
    (((uint64_t)(((uint8_t *)(src))[0]) << 56) | \
     ((uint64_t)(((uint8_t *)(src))[1]) << 48) | \
     ((uint64_t)(((uint8_t *)(src))[2]) << 40) | \
     ((uint64_t)(((uint8_t *)(src))[3]) << 32) | \
     ((uint64_t)(((uint8_t *)(src))[4]) << 24) | \
     ((uint64_t)(((uint8_t *)(src))[5]) << 16) | \
     ((uint64_t)(((uint8_t *)(src))[6]) << 8) |  \
     ((uint64_t)(((uint8_t *)(src))[7]) << 0))

#define MEM_STORE64BE(dst, a)                              \
    (((uint8_t *)(dst))[0] = ((uint64_t)(a) >> 56) & 0xFF, \
     ((uint8_t *)(dst))[1] = ((uint64_t)(a) >> 48) & 0xFF, \
     ((uint8_t *)(dst))[2] = ((uint64_t)(a) >> 40) & 0xFF, \
     ((uint8_t *)(dst))[3] = ((uint64_t)(a) >> 32) & 0xFF, \
     ((uint8_t *)(dst))[4] = ((uint64_t)(a) >> 24) & 0xFF, \
     ((uint8_t *)(dst))[5] = ((uint64_t)(a) >> 16) & 0xFF, \
     ((uint8_t *)(dst))[6] = ((uint64_t)(a) >> 8) & 0xFF,  \
     ((uint8_t *)(dst))[7] = ((uint64_t)(a) >> 0) & 0xFF)

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// ******* SHA224/256/384/512 CORE FUNCTION *********
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

/**
 * Starting from here, until the next similar comment declaration.
 *
 * part of the code is "derived from miTLS project. sha256-x86.c"
 *
 * https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c
 */

static void sha224_256_compress_block(uint32_t state[8], const uint8_t in[64])
{
    __m128i       STATE0, STATE1;
    __m128i       MSG, TMP;
    __m128i       MSG0, MSG1, MSG2, MSG3;
    __m128i       ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK =
        _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    /* Load initial values */
    TMP    = _mm_loadu_si128((const __m128i *)&state[0]);
    STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);

    TMP    = _mm_shuffle_epi32(TMP, 0xB1);       /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */

    /* Save current state */
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    /* Rounds 0-3 */
    MSG  = _mm_loadu_si128((const __m128i *)(in + 0));
    MSG0 = _mm_shuffle_epi8(MSG, MASK);
    MSG  = _mm_add_epi32(
        MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 4-7 */
    MSG1 = _mm_loadu_si128((const __m128i *)(in + 16));
    MSG1 = _mm_shuffle_epi8(MSG1, MASK);
    MSG  = _mm_add_epi32(
        MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 8-11 */
    MSG2 = _mm_loadu_si128((const __m128i *)(in + 32));
    MSG2 = _mm_shuffle_epi8(MSG2, MASK);
    MSG  = _mm_add_epi32(
        MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 12-15 */
    MSG3 = _mm_loadu_si128((const __m128i *)(in + 48));
    MSG3 = _mm_shuffle_epi8(MSG3, MASK);
    MSG  = _mm_add_epi32(
        MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 16-19 */
    MSG = _mm_add_epi32(
        MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 20-23 */
    MSG = _mm_add_epi32(
        MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 24-27 */
    MSG = _mm_add_epi32(
        MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 28-31 */
    MSG = _mm_add_epi32(
        MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 32-35 */
    MSG = _mm_add_epi32(
        MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 36-39 */
    MSG = _mm_add_epi32(
        MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG0   = _mm_sha256msg1_epu32(MSG0, MSG1);

    /* Rounds 40-43 */
    MSG = _mm_add_epi32(
        MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG1   = _mm_sha256msg1_epu32(MSG1, MSG2);

    /* Rounds 44-47 */
    MSG = _mm_add_epi32(
        MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG3, MSG2, 4);
    MSG0   = _mm_add_epi32(MSG0, TMP);
    MSG0   = _mm_sha256msg2_epu32(MSG0, MSG3);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG2   = _mm_sha256msg1_epu32(MSG2, MSG3);

    /* Rounds 48-51 */
    MSG = _mm_add_epi32(
        MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG0, MSG3, 4);
    MSG1   = _mm_add_epi32(MSG1, TMP);
    MSG1   = _mm_sha256msg2_epu32(MSG1, MSG0);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    MSG3   = _mm_sha256msg1_epu32(MSG3, MSG0);

    /* Rounds 52-55 */
    MSG = _mm_add_epi32(
        MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG1, MSG0, 4);
    MSG2   = _mm_add_epi32(MSG2, TMP);
    MSG2   = _mm_sha256msg2_epu32(MSG2, MSG1);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 56-59 */
    MSG = _mm_add_epi32(
        MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP    = _mm_alignr_epi8(MSG2, MSG1, 4);
    MSG3   = _mm_add_epi32(MSG3, TMP);
    MSG3   = _mm_sha256msg2_epu32(MSG3, MSG2);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Rounds 60-63 */
    MSG = _mm_add_epi32(
        MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG    = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    /* Combine state  */
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    TMP    = _mm_shuffle_epi32(STATE0, 0x1B);    /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    /* ABEF */

    /* Save state */
    _mm_storeu_si128((__m128i *)&state[0], STATE0);
    _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

/**
 * Ending here, to the previous similar comment declaration.
 *
 * the code is "derived from IETF Trust and the persons identified as authors of
 * the code. sha224-256.c, sha384-512.c"
 *
 * cite: https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2
 */

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// *********** SHA224/256 CIPHER FUNCTION ***********
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

static int sha224_256_update(Sha224256ShaniCTX *ctx,
                             const uint8_t     *in,
                             size_t             inl)
{
    if (inl > UINT64_MAX / 8)
    {
        return -1;
    }
    uint64_t t = ctx->data_bits;
    ctx->data_bits += 8 * (uint64_t)inl;
    if (ctx->data_bits < t)
    {
        return -1;
    }

    if (ctx->buf_size == 0)
    {
        size_t block_num = inl / 64;
        while (block_num)
        {
            sha224_256_compress_block(ctx->state, in);
            in += 64, inl -= 64, block_num--;
        }
        if (inl)
        {
            memcpy(ctx->buf, in, inl);
            ctx->buf_size = inl;
        }
        return 0;
    }
    if (inl)
    {
        size_t size = 64 - ctx->buf_size;
        if (size > inl)
        {
            size = inl;
        }
        memcpy(ctx->buf + ctx->buf_size, in, size);
        in += size, inl -= size, ctx->buf_size += size;

        if (ctx->buf_size == 64)
        {
            sha224_256_compress_block(ctx->state, ctx->buf);
            ctx->buf_size = 0;
        }
    }
    if (inl && ctx->buf_size == 0)
    {
        size_t block_num = inl / 64;
        while (block_num)
        {
            sha224_256_compress_block(ctx->state, in);
            in += 64, inl -= 64, block_num--;
        }
        if (inl)
        {
            memcpy(ctx->buf, in, inl);
            ctx->buf_size = inl;
        }
        return 0;
    }
    return 0;
}

/**
 * @brief sha224/256 final block
 * @param ctx           Sha224/256 Context
 * @param digest        output digest
 * @param digest_size   output digest byte length(24/32)
 */
static void sha224_256_final_n(Sha224256ShaniCTX *ctx,
                               uint8_t           *digest,
                               size_t             digest_size)
{
    size_t  pad_num = (64ULL + 56 - 1 - ctx->buf_size) % 64;
    uint8_t buf[64 * 2];
    size_t  buf_size = 0;
    memcpy(buf, ctx->buf, ctx->buf_size);
    buf_size += ctx->buf_size;                     // update
    buf[buf_size] = 0x80;                          // 10..0
    buf_size += 1;                                 // update
    memset(buf + buf_size, 0, pad_num);            // pad 0
    buf_size += pad_num;                           // update
    MEM_STORE64BE(buf + buf_size, ctx->data_bits); //
    buf_size += 8;                                 // update
    // compress
    for (size_t i = 0; i < buf_size; i += 64)
    {
        sha224_256_compress_block(ctx->state, buf + i);
    }
    // output digest
    MEM_STORE32BE(buf + 4 * 0, ctx->state[0]);
    MEM_STORE32BE(buf + 4 * 1, ctx->state[1]);
    MEM_STORE32BE(buf + 4 * 2, ctx->state[2]);
    MEM_STORE32BE(buf + 4 * 3, ctx->state[3]);
    MEM_STORE32BE(buf + 4 * 4, ctx->state[4]);
    MEM_STORE32BE(buf + 4 * 5, ctx->state[5]);
    MEM_STORE32BE(buf + 4 * 6, ctx->state[6]);
    MEM_STORE32BE(buf + 4 * 7, ctx->state[7]);
    memcpy(digest, buf, digest_size);
}

// ****************************************
// ************** SHA224 ******************
// ****************************************

void sha224_shani_init(Sha224ShaniCTX *ctx)
{
    static const uint32_t SHA224_H0[8] = {
        0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
        0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4,
    };
    ctx->state[0]  = SHA224_H0[0];
    ctx->state[1]  = SHA224_H0[1];
    ctx->state[2]  = SHA224_H0[2];
    ctx->state[3]  = SHA224_H0[3];
    ctx->state[4]  = SHA224_H0[4];
    ctx->state[5]  = SHA224_H0[5];
    ctx->state[6]  = SHA224_H0[6];
    ctx->state[7]  = SHA224_H0[7];
    ctx->buf_size  = 0;
    ctx->data_bits = 0;
}

void sha224_shani_reset(Sha224ShaniCTX *ctx)
{
    sha224_shani_init(ctx);
}

int sha224_shani_update(Sha224ShaniCTX *ctx, const uint8_t *in, size_t inl)
{
    return sha224_256_update(ctx, in, inl);
}

void sha224_shani_final(Sha224ShaniCTX *ctx, uint8_t digest[28])
{
    sha224_256_final_n(ctx, digest, 28);
}

// ****************************************
// ************** SHA256 ******************
// ****************************************

void sha256_shani_init(Sha256ShaniCTX *ctx)
{
    static const uint32_t SHA256_H0[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    };
    ctx->state[0]  = SHA256_H0[0];
    ctx->state[1]  = SHA256_H0[1];
    ctx->state[2]  = SHA256_H0[2];
    ctx->state[3]  = SHA256_H0[3];
    ctx->state[4]  = SHA256_H0[4];
    ctx->state[5]  = SHA256_H0[5];
    ctx->state[6]  = SHA256_H0[6];
    ctx->state[7]  = SHA256_H0[7];
    ctx->buf_size  = 0;
    ctx->data_bits = 0;
}

void sha256_shani_reset(Sha256ShaniCTX *ctx)
{
    sha256_shani_init(ctx);
}

int sha256_shani_update(Sha256ShaniCTX *ctx, const uint8_t *in, size_t inl)
{
    return sha224_256_update(ctx, in, inl);
}

void sha256_shani_final(Sha256ShaniCTX *ctx, uint8_t digest[32])
{
    sha224_256_final_n(ctx, digest, 32);
}

}; // namespace tc