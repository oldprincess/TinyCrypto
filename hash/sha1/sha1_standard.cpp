#include "sha1_standard.h"
#include <string.h>

namespace tc {

#define MEM_LOAD32BE(src)                       \
    (((uint32_t)(((uint8_t*)(src))[0]) << 24) | \
     ((uint32_t)(((uint8_t*)(src))[1]) << 16) | \
     ((uint32_t)(((uint8_t*)(src))[2]) << 8) |  \
     ((uint32_t)(((uint8_t*)(src))[3]) << 0))

#define MEM_STORE32BE(dst, a)                             \
    (((uint8_t*)(dst))[0] = ((uint32_t)(a) >> 24) & 0xFF, \
     ((uint8_t*)(dst))[1] = ((uint32_t)(a) >> 16) & 0xFF, \
     ((uint8_t*)(dst))[2] = ((uint32_t)(a) >> 8) & 0xFF,  \
     ((uint8_t*)(dst))[3] = ((uint32_t)(a) >> 0) & 0xFF)

#define MEM_STORE64BE(dst, a)                             \
    (((uint8_t*)(dst))[0] = ((uint64_t)(a) >> 56) & 0xFF, \
     ((uint8_t*)(dst))[1] = ((uint64_t)(a) >> 48) & 0xFF, \
     ((uint8_t*)(dst))[2] = ((uint64_t)(a) >> 40) & 0xFF, \
     ((uint8_t*)(dst))[3] = ((uint64_t)(a) >> 32) & 0xFF, \
     ((uint8_t*)(dst))[4] = ((uint64_t)(a) >> 24) & 0xFF, \
     ((uint8_t*)(dst))[5] = ((uint64_t)(a) >> 16) & 0xFF, \
     ((uint8_t*)(dst))[6] = ((uint64_t)(a) >> 8) & 0xFF,  \
     ((uint8_t*)(dst))[7] = ((uint64_t)(a) >> 0) & 0xFF)

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// ************** SHA1 CORE FUNCTIONS ***************
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

#define rotl(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/**
 * modify:
 * cite from https://www.rfc-editor.org/rfc/rfc3174#section-7.1
 */
static void sha1_compress(uint32_t state[5], const uint8_t data[64])
{
    static const uint32_t K[4] = {
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6,
    };
    uint32_t W[80];
    uint32_t A, B, C, D, E;
    uint32_t temp;

    W[0]  = MEM_LOAD32BE(data + 0);
    W[1]  = MEM_LOAD32BE(data + 4);
    W[2]  = MEM_LOAD32BE(data + 8);
    W[3]  = MEM_LOAD32BE(data + 12);
    W[4]  = MEM_LOAD32BE(data + 16);
    W[5]  = MEM_LOAD32BE(data + 20);
    W[6]  = MEM_LOAD32BE(data + 24);
    W[7]  = MEM_LOAD32BE(data + 28);
    W[8]  = MEM_LOAD32BE(data + 32);
    W[9]  = MEM_LOAD32BE(data + 36);
    W[10] = MEM_LOAD32BE(data + 40);
    W[11] = MEM_LOAD32BE(data + 44);
    W[12] = MEM_LOAD32BE(data + 48);
    W[13] = MEM_LOAD32BE(data + 52);
    W[14] = MEM_LOAD32BE(data + 56);
    W[15] = MEM_LOAD32BE(data + 60);
    for (int t = 16; t < 80; t++)
    {
        W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    }

    A = state[0];
    B = state[1];
    C = state[2];
    D = state[3];
    E = state[4];

    for (int t = 0; t < 20; t++)
    {
        temp = rotl(A, 5) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E    = D;
        D    = C;
        C    = rotl(B, 30);
        B    = A;
        A    = temp;
    }

    for (int t = 20; t < 40; t++)
    {
        temp = rotl(A, 5) + (B ^ C ^ D) + E + W[t] + K[1];
        E    = D;
        D    = C;
        C    = rotl(B, 30);
        B    = A;
        A    = temp;
    }

    for (int t = 40; t < 60; t++)
    {
        temp = rotl(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E    = D;
        D    = C;
        C    = rotl(B, 30);
        B    = A;
        A    = temp;
    }

    for (int t = 60; t < 80; t++)
    {
        temp = rotl(A, 5) + (B ^ C ^ D) + E + W[t] + K[3];
        E    = D;
        D    = C;
        C    = rotl(B, 30);
        B    = A;
        A    = temp;
    }

    state[0] += A;
    state[1] += B;
    state[2] += C;
    state[3] += D;
    state[4] += E;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// ************* SHA1 CIPHER FUNCTION ***************
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

static int u64_add(uint64_t* r, uint64_t n)
{
    uint32_t a1  = (uint32_t)(*r >> 32);
    uint32_t a0  = *r & UINT32_MAX;
    uint32_t b1  = (uint32_t)(n >> 32);
    uint32_t b0  = n & UINT32_MAX;
    uint64_t tmp = (uint64_t)a0 + b0;
    uint32_t r0  = tmp & UINT32_MAX;
    tmp          = (uint64_t)a1 + b1 + (tmp >> 32);
    uint32_t r1  = tmp & UINT32_MAX;
    *r           = (uint64_t)r1 << 32 | r0;
    return (int)(tmp >> 32); // carry bit
}

void sha1_standard_init(Sha1StandardCTX* ctx)
{
    static const uint32_t SHA1_INIT_DIGEST[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0,
    };
    ctx->state[0]  = SHA1_INIT_DIGEST[0];
    ctx->state[1]  = SHA1_INIT_DIGEST[1];
    ctx->state[2]  = SHA1_INIT_DIGEST[2];
    ctx->state[3]  = SHA1_INIT_DIGEST[3];
    ctx->state[4]  = SHA1_INIT_DIGEST[4];
    ctx->buf_size  = 0;
    ctx->data_bits = 0;
}

void sha1_standard_reset(Sha1StandardCTX* ctx)
{
    sha1_standard_init(ctx);
}

int sha1_standard_update(Sha1StandardCTX* ctx, const uint8_t* in, size_t inl)
{
    if (inl > UINT64_MAX / 8)
    {
        return -1; // input bits overflow
    }
    uint64_t inl_bits = (uint64_t)inl * 8;
    if (u64_add(&(ctx->data_bits), inl_bits))
    {
        return -1; // input bits overflow
    }

    if (ctx->buf_size == 0)
    {
        size_t block_num = inl / 64;
        while (block_num)
        {
            sha1_compress(ctx->state, in);
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
            sha1_compress(ctx->state, ctx->buf);
            ctx->buf_size = 0;
        }
    }
    if (inl && ctx->buf_size == 0)
    {
        size_t block_num = inl / 64;
        while (block_num)
        {
            sha1_compress(ctx->state, in);
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

void sha1_standard_final(Sha1StandardCTX* ctx, uint8_t digest[20])
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
        sha1_compress(ctx->state, buf + i);
    }
    // output digest
    MEM_STORE32BE(digest + 4 * 0, ctx->state[0]);
    MEM_STORE32BE(digest + 4 * 1, ctx->state[1]);
    MEM_STORE32BE(digest + 4 * 2, ctx->state[2]);
    MEM_STORE32BE(digest + 4 * 3, ctx->state[3]);
    MEM_STORE32BE(digest + 4 * 4, ctx->state[4]);
}
}; // namespace tc