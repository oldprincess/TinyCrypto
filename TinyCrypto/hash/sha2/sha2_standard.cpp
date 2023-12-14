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
 * part of the code is "derived from IETF Trust and the persons identified as
 * authors of the code. sha224-256.c, sha384-512.c"
 *
 * Copyright (c) 2011 IETF Trust and the persons identified as authors of the
 * code. All rights reserved.
 */
#include "sha2_standard.h"
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

/*
   Copyright (c) 2011 IETF Trust and the persons identified as
   authors of the code.  All rights reserved.

   Redistribution and use in source and binary forms, with or
   without modification, are permitted provided that the following
   conditions are met:

   - Redistributions of source code must retain the above
     copyright notice, this list of conditions and
     the following disclaimer.
   - Redistributions in binary form must reproduce the above
     copyright notice, this list of conditions and the following
     disclaimer in the documentation and/or other materials provided
     with the distribution.

   - Neither the name of Internet Society, IETF or IETF Trust, nor
     the names of specific contributors, may be used to endorse or
     promote products derived from this software without specific
     prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
   CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
   INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
   MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
   OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
   EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
 * Starting from here, until the next similar comment declaration.
 *
 * the code is "derived from IETF Trust and the persons identified as authors of
 * the code. sha224-256.c, sha384-512.c"
 *
 * cite: https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2
 */

#define SHA_Ch(x, y, z)  (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z) (((x) & ((y) | (z))) | ((y) & (z)))

#define SHA256_SHR(bits, word)  ((word) >> (bits))
#define SHA256_ROTL(bits, word) (((word) << (bits)) | ((word) >> (32 - (bits))))
#define SHA256_ROTR(bits, word) (((word) >> (bits)) | ((word) << (32 - (bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA256_SIGMA0(word) \
    (SHA256_ROTR(2, word) ^ SHA256_ROTR(13, word) ^ SHA256_ROTR(22, word))
#define SHA256_SIGMA1(word) \
    (SHA256_ROTR(6, word) ^ SHA256_ROTR(11, word) ^ SHA256_ROTR(25, word))
#define SHA256_sigma0(word) \
    (SHA256_ROTR(7, word) ^ SHA256_ROTR(18, word) ^ SHA256_SHR(3, word))
#define SHA256_sigma1(word) \
    (SHA256_ROTR(17, word) ^ SHA256_ROTR(19, word) ^ SHA256_SHR(10, word))

/**
 * derived from https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2
 */
static void sha224_256_compress_block(uint32_t state[8], const uint8_t in[64])
{
    /* Constants defined in FIPS 180-3, section 4.2.2 */
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    uint32_t temp1, temp2;
    uint32_t W[64];
    uint32_t A, B, C, D, E, F, G, H;
    // Initialize the first 16 words in the array W
    for (int t = 0; t < 16; t++)
    {
        W[t] = MEM_LOAD32BE(in + 4 * t);
    }
    for (int t = 16; t < 64; t++)
    {
        W[t] = SHA256_sigma1(W[t - 2]) + W[t - 7] + SHA256_sigma0(W[t - 15]) +
               W[t - 16];
    }
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];
    for (int t = 0; t < 64; t++)
    {
        temp1 = H + SHA256_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
        temp2 = SHA256_SIGMA0(A) + SHA_Maj(A, B, C);
        H     = G;
        G     = F;
        F     = E;
        E     = D + temp1;
        D     = C;
        C     = B;
        B     = A;
        A     = temp1 + temp2;
    }
    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
    state[5] += F;
    state[6] += G;
    state[7] += H;
}

#define SHA512_SHR(bits, word) (((uint64_t)(word)) >> (bits))
#define SHA512_ROTR(bits, word) \
    ((((uint64_t)(word)) >> (bits)) | (((uint64_t)(word)) << (64 - (bits))))

#define SHA512_SIGMA0(word) \
    (SHA512_ROTR(28, word) ^ SHA512_ROTR(34, word) ^ SHA512_ROTR(39, word))
#define SHA512_SIGMA1(word) \
    (SHA512_ROTR(14, word) ^ SHA512_ROTR(18, word) ^ SHA512_ROTR(41, word))
#define SHA512_sigma0(word) \
    (SHA512_ROTR(1, word) ^ SHA512_ROTR(8, word) ^ SHA512_SHR(7, word))
#define SHA512_sigma1(word) \
    (SHA512_ROTR(19, word) ^ SHA512_ROTR(61, word) ^ SHA512_SHR(6, word))

/**
 * derived from https://www.rfc-editor.org/rfc/rfc6234#section-8.2.2
 */
static void sha384_512_compress_block(uint64_t state[8], const uint8_t in[128])
{
    /* Constants defined in FIPS 180-3, section 4.2.3 */
    static const uint64_t K[80] = {
        0x428A2F98D728AE22LLU, 0x7137449123EF65CDLLU, 0xB5C0FBCFEC4D3B2FLLU,
        0xE9B5DBA58189DBBCLLU, 0x3956C25BF348B538LLU, 0x59F111F1B605D019LLU,
        0x923F82A4AF194F9BLLU, 0xAB1C5ED5DA6D8118LLU, 0xD807AA98A3030242LLU,
        0x12835B0145706FBELLU, 0x243185BE4EE4B28CLLU, 0x550C7DC3D5FFB4E2LLU,
        0x72BE5D74F27B896FLLU, 0x80DEB1FE3B1696B1LLU, 0x9BDC06A725C71235LLU,
        0xC19BF174CF692694LLU, 0xE49B69C19EF14AD2LLU, 0xEFBE4786384F25E3LLU,
        0x0FC19DC68B8CD5B5LLU, 0x240CA1CC77AC9C65LLU, 0x2DE92C6F592B0275LLU,
        0x4A7484AA6EA6E483LLU, 0x5CB0A9DCBD41FBD4LLU, 0x76F988DA831153B5LLU,
        0x983E5152EE66DFABLLU, 0xA831C66D2DB43210LLU, 0xB00327C898FB213FLLU,
        0xBF597FC7BEEF0EE4LLU, 0xC6E00BF33DA88FC2LLU, 0xD5A79147930AA725LLU,
        0x06CA6351E003826FLLU, 0x142929670A0E6E70LLU, 0x27B70A8546D22FFCLLU,
        0x2E1B21385C26C926LLU, 0x4D2C6DFC5AC42AEDLLU, 0x53380D139D95B3DFLLU,
        0x650A73548BAF63DELLU, 0x766A0ABB3C77B2A8LLU, 0x81C2C92E47EDAEE6LLU,
        0x92722C851482353BLLU, 0xA2BFE8A14CF10364LLU, 0xA81A664BBC423001LLU,
        0xC24B8B70D0F89791LLU, 0xC76C51A30654BE30LLU, 0xD192E819D6EF5218LLU,
        0xD69906245565A910LLU, 0xF40E35855771202ALLU, 0x106AA07032BBD1B8LLU,
        0x19A4C116B8D2D0C8LLU, 0x1E376C085141AB53LLU, 0x2748774CDF8EEB99LLU,
        0x34B0BCB5E19B48A8LLU, 0x391C0CB3C5C95A63LLU, 0x4ED8AA4AE3418ACBLLU,
        0x5B9CCA4F7763E373LLU, 0x682E6FF3D6B2B8A3LLU, 0x748F82EE5DEFB2FCLLU,
        0x78A5636F43172F60LLU, 0x84C87814A1F0AB72LLU, 0x8CC702081A6439ECLLU,
        0x90BEFFFA23631E28LLU, 0xA4506CEBDE82BDE9LLU, 0xBEF9A3F7B2C67915LLU,
        0xC67178F2E372532BLLU, 0xCA273ECEEA26619CLLU, 0xD186B8C721C0C207LLU,
        0xEADA7DD6CDE0EB1ELLU, 0xF57D4F7FEE6ED178LLU, 0x06F067AA72176FBALLU,
        0x0A637DC5A2C898A6LLU, 0x113F9804BEF90DAELLU, 0x1B710B35131C471BLLU,
        0x28DB77F523047D84LLU, 0x32CAAB7B40C72493LLU, 0x3C9EBE0A15C9BEBCLLU,
        0x431D67C49C100D4CLLU, 0x4CC5D4BECB3E42B6LLU, 0x597F299CFC657E2ALLU,
        0x5FCB6FAB3AD6FAECLLU, 0x6C44198C4A475817LLU,
    };
    uint64_t temp1, temp2;
    uint64_t W[80];
    uint64_t A, B, C, D, E, F, G, H;

    for (int t = 0; t < 16; t++)
    {
        W[t] = MEM_LOAD64BE(in + 8 * t);
    }
    for (int t = 16; t < 80; t++)
    {
        W[t] = SHA512_sigma1(W[t - 2]) + W[t - 7] + SHA512_sigma0(W[t - 15]) +
               W[t - 16];
    }
    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];
    F = state[5];
    G = state[6];
    H = state[7];
    for (int t = 0; t < 80; t++)
    {
        temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
        temp2 = SHA512_SIGMA0(A) + SHA_Maj(A, B, C);
        H     = G;
        G     = F;
        F     = E;
        E     = D + temp1;
        D     = C;
        C     = B;
        B     = A;
        A     = temp1 + temp2;
    }
    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
    state[5] += F;
    state[6] += G;
    state[7] += H;
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

static int sha224_256_update(Sha224256StandardCTX *ctx,
                             const uint8_t        *in,
                             size_t                inl)
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
static void sha224_256_final_n(Sha224256StandardCTX *ctx,
                               uint8_t              *digest,
                               size_t                digest_size)
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

void sha224_standard_init(Sha224StandardCTX *ctx)
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

void sha224_standard_reset(Sha224StandardCTX *ctx)
{
    sha224_standard_init(ctx);
}

int sha224_standard_update(Sha224StandardCTX *ctx,
                           const uint8_t     *in,
                           size_t             inl)
{
    return sha224_256_update(ctx, in, inl);
}

void sha224_standard_final(Sha224StandardCTX *ctx, uint8_t digest[28])
{
    sha224_256_final_n(ctx, digest, 28);
}

// ****************************************
// ************** SHA256 ******************
// ****************************************

void sha256_standard_init(Sha256StandardCTX *ctx)
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

void sha256_standard_reset(Sha256StandardCTX *ctx)
{
    sha256_standard_init(ctx);
}

int sha256_standard_update(Sha256StandardCTX *ctx,
                           const uint8_t     *in,
                           size_t             inl)
{
    return sha224_256_update(ctx, in, inl);
}

void sha256_standard_final(Sha256StandardCTX *ctx, uint8_t digest[32])
{
    sha224_256_final_n(ctx, digest, 32);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// *********** SHA384/512 CIPHER FUNCTION ***********
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

static int sha384_512_update(Sha384512StandardCTX *ctx,
                             const uint8_t        *in,
                             size_t                inl)
{
    // u128 add
    if (inl > UINT64_MAX)
    {
        return -1;
    }
    uint64_t in_bits_l = (uint64_t)inl << 3;
    uint64_t in_bits_h = (uint64_t)inl >> (64 - 3);

    uint64_t tl = ctx->data_bits_l;
    uint64_t th = ctx->data_bits_h;
    ctx->data_bits_l += in_bits_l;
    ctx->data_bits_h += in_bits_h;
    if (ctx->data_bits_h < th)
    {
        return -1;
    }
    if (ctx->data_bits_l < tl)
    {
        th = ctx->data_bits_h;
        ctx->data_bits_h++;
        if (ctx->data_bits_h < th)
        {
            return -1;
        }
    }
    // compress
    if (ctx->buf_size == 0)
    {
        size_t block_num = inl / 128;
        while (block_num)
        {
            sha384_512_compress_block(ctx->state, in);
            in += 128, inl -= 128, block_num--;
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
        size_t size = 128 - ctx->buf_size;
        if (size > inl)
        {
            size = inl;
        }
        memcpy(ctx->buf + ctx->buf_size, in, size);
        in += size, inl -= size, ctx->buf_size += size;

        if (ctx->buf_size == 128)
        {
            sha384_512_compress_block(ctx->state, ctx->buf);
            ctx->buf_size = 0;
        }
    }
    if (inl && ctx->buf_size == 0)
    {
        size_t block_num = inl / 128;
        while (block_num)
        {
            sha384_512_compress_block(ctx->state, in);
            in += 128, inl -= 128, block_num--;
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

static void sha384_512_final_n(Sha384512StandardCTX *ctx,
                               uint8_t              *digest,
                               size_t                digest_size)
{
    size_t  pad_num = (128ULL + 128 - 16 - 1 - ctx->buf_size) % 128;
    uint8_t buf[128 * 2];
    size_t  buf_size = 0;
    memcpy(buf, ctx->buf, ctx->buf_size);
    buf_size += ctx->buf_size;                       // update
    buf[buf_size] = 0x80;                            // 10..0
    buf_size += 1;                                   // update
    memset(buf + buf_size, 0, pad_num);              // pad 0
    buf_size += pad_num;                             // update
    MEM_STORE64BE(buf + buf_size, ctx->data_bits_h); //
    buf_size += 8;
    MEM_STORE64BE(buf + buf_size, ctx->data_bits_l); //
    buf_size += 8;                                   // update
    // compress
    for (size_t i = 0; i < buf_size; i += 128)
    {
        sha384_512_compress_block(ctx->state, buf + i);
    }
    // output digest
    MEM_STORE64BE(buf + 8 * 0, ctx->state[0]);
    MEM_STORE64BE(buf + 8 * 1, ctx->state[1]);
    MEM_STORE64BE(buf + 8 * 2, ctx->state[2]);
    MEM_STORE64BE(buf + 8 * 3, ctx->state[3]);
    MEM_STORE64BE(buf + 8 * 4, ctx->state[4]);
    MEM_STORE64BE(buf + 8 * 5, ctx->state[5]);
    MEM_STORE64BE(buf + 8 * 6, ctx->state[6]);
    MEM_STORE64BE(buf + 8 * 7, ctx->state[7]);
    memcpy(digest, buf, digest_size);
}

// ****************************************
// ************** SHA384 ******************
// ****************************************

void sha384_standard_init(Sha384StandardCTX *ctx)
{
    static uint64_t SHA384_H0[8] = {
        0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL, 0x9159015A3070DD17ULL,
        0x152FECD8F70E5939ULL, 0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL,
        0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL,
    };
    ctx->state[0]    = SHA384_H0[0];
    ctx->state[1]    = SHA384_H0[1];
    ctx->state[2]    = SHA384_H0[2];
    ctx->state[3]    = SHA384_H0[3];
    ctx->state[4]    = SHA384_H0[4];
    ctx->state[5]    = SHA384_H0[5];
    ctx->state[6]    = SHA384_H0[6];
    ctx->state[7]    = SHA384_H0[7];
    ctx->buf_size    = 0;
    ctx->data_bits_h = 0;
    ctx->data_bits_l = 0;
}

void sha384_standard_reset(Sha384StandardCTX *ctx)
{
    sha384_standard_init(ctx);
}

int sha384_standard_update(Sha384StandardCTX *ctx,
                           const uint8_t     *in,
                           size_t             inl)
{
    return sha384_512_update(ctx, in, inl);
}

void sha384_standard_final(Sha384StandardCTX *ctx, uint8_t digest[48])
{
    sha384_512_final_n(ctx, digest, 48);
}

// ****************************************
// ************** SHA512 ******************
// ****************************************

void sha512_standard_init(Sha512StandardCTX *ctx)
{
    static uint64_t SHA512_H0[8] = {
        0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL,
        0xA54FF53A5F1D36F1ULL, 0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
        0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL,
    };
    ctx->state[0]    = SHA512_H0[0];
    ctx->state[1]    = SHA512_H0[1];
    ctx->state[2]    = SHA512_H0[2];
    ctx->state[3]    = SHA512_H0[3];
    ctx->state[4]    = SHA512_H0[4];
    ctx->state[5]    = SHA512_H0[5];
    ctx->state[6]    = SHA512_H0[6];
    ctx->state[7]    = SHA512_H0[7];
    ctx->buf_size    = 0;
    ctx->data_bits_h = 0;
    ctx->data_bits_l = 0;
}

void sha512_standard_reset(Sha512StandardCTX *ctx)
{
    sha512_standard_init(ctx);
}

int sha512_standard_update(Sha512StandardCTX *ctx,
                           const uint8_t     *in,
                           size_t             inl)
{
    return sha384_512_update(ctx, in, inl);
}

void sha512_standard_final(Sha512StandardCTX *ctx, uint8_t digest[64])
{
    sha384_512_final_n(ctx, digest, 64);
}

}; // namespace tc