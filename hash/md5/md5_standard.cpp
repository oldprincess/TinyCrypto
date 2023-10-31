#include "md5_standard.h"
#include <string.h>

namespace tc {

#define MEM_LOAD32LE(src)                       \
    (((uint32_t)(((uint8_t*)(src))[0]) << 0) |  \
     ((uint32_t)(((uint8_t*)(src))[1]) << 8) |  \
     ((uint32_t)(((uint8_t*)(src))[2]) << 16) | \
     ((uint32_t)(((uint8_t*)(src))[3]) << 24))

#define MEM_STORE32LE(dst, a)                             \
    (((uint8_t*)(dst))[0] = ((uint32_t)(a) >> 0) & 0xFF,  \
     ((uint8_t*)(dst))[1] = ((uint32_t)(a) >> 8) & 0xFF,  \
     ((uint8_t*)(dst))[2] = ((uint32_t)(a) >> 16) & 0xFF, \
     ((uint8_t*)(dst))[3] = ((uint32_t)(a) >> 24) & 0xFF)

#define MEM_STORE64LE(dst, a)                             \
    (((uint8_t*)(dst))[0] = ((uint64_t)(a) >> 0) & 0xFF,  \
     ((uint8_t*)(dst))[1] = ((uint64_t)(a) >> 8) & 0xFF,  \
     ((uint8_t*)(dst))[2] = ((uint64_t)(a) >> 16) & 0xFF, \
     ((uint8_t*)(dst))[3] = ((uint64_t)(a) >> 24) & 0xFF, \
     ((uint8_t*)(dst))[4] = ((uint64_t)(a) >> 32) & 0xFF, \
     ((uint8_t*)(dst))[5] = ((uint64_t)(a) >> 40) & 0xFF, \
     ((uint8_t*)(dst))[6] = ((uint64_t)(a) >> 48) & 0xFF, \
     ((uint8_t*)(dst))[7] = ((uint64_t)(a) >> 56) & 0xFF)

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// *************** MD5 CORE FUNCTIONS ***************
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

/**
 * modify
 * cite: https://www.rfc-editor.org/rfc/rfc1321
 */

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s, ac)                        \
    {                                                   \
        (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); \
        (a) = ROTATE_LEFT((a), (s));                    \
        (a) += (b);                                     \
    }
#define GG(a, b, c, d, x, s, ac)                        \
    {                                                   \
        (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); \
        (a) = ROTATE_LEFT((a), (s));                    \
        (a) += (b);                                     \
    }
#define HH(a, b, c, d, x, s, ac)                        \
    {                                                   \
        (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); \
        (a) = ROTATE_LEFT((a), (s));                    \
        (a) += (b);                                     \
    }
#define II(a, b, c, d, x, s, ac)                        \
    {                                                   \
        (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); \
        (a) = ROTATE_LEFT((a), (s));                    \
        (a) += (b);                                     \
    }

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/**
 * modify
 * cite: https://www.rfc-editor.org/rfc/rfc1321
 */
static void md5_compress(uint32_t state[4], const uint8_t data[64])
{
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];

    x[0]  = MEM_LOAD32LE(data + 0);
    x[1]  = MEM_LOAD32LE(data + 4);
    x[2]  = MEM_LOAD32LE(data + 8);
    x[3]  = MEM_LOAD32LE(data + 12);
    x[4]  = MEM_LOAD32LE(data + 16);
    x[5]  = MEM_LOAD32LE(data + 20);
    x[6]  = MEM_LOAD32LE(data + 24);
    x[7]  = MEM_LOAD32LE(data + 28);
    x[8]  = MEM_LOAD32LE(data + 32);
    x[9]  = MEM_LOAD32LE(data + 36);
    x[10] = MEM_LOAD32LE(data + 40);
    x[11] = MEM_LOAD32LE(data + 44);
    x[12] = MEM_LOAD32LE(data + 48);
    x[13] = MEM_LOAD32LE(data + 52);
    x[14] = MEM_LOAD32LE(data + 56);
    x[15] = MEM_LOAD32LE(data + 60);
    /* Round 1 */
    FF(a, b, c, d, x[0], S11, 0xd76aa478);  /* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756);  /* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db);  /* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee);  /* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf);  /* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a);  /* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613);  /* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501);  /* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8);  /* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af);  /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[1], S21, 0xf61e2562);  /* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340);  /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);  /* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d);  /* 21 */
    GG(d, a, b, c, x[10], S22, 0x2441453);  /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);  /* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6);  /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87);  /* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed);  /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8);  /* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9);  /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[5], S31, 0xfffa3942);  /* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681);  /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44);  /* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9);  /* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60);  /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa);  /* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085);  /* 43 */
    HH(b, c, d, a, x[6], S34, 0x4881d05);   /* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039);  /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665);  /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[0], S41, 0xf4292244);  /* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97);  /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039);  /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92);  /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1);  /* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f);  /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314);  /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82);  /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb);  /* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391);  /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// ************** MD5 CIPHER FUNCTION ***************
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

void md5_standard_init(Md5StandardCTX* ctx)
{
    static const uint32_t MD5_INIT_DIGEST[4] = {
        0x67452301,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
    };
    ctx->state[0]  = MD5_INIT_DIGEST[0];
    ctx->state[1]  = MD5_INIT_DIGEST[1];
    ctx->state[2]  = MD5_INIT_DIGEST[2];
    ctx->state[3]  = MD5_INIT_DIGEST[3];
    ctx->data_bits = 0;
    ctx->buf_size  = 0;
}

void md5_standard_reset(Md5StandardCTX* ctx)
{
    md5_standard_init(ctx);
}

void md5_standard_update(Md5StandardCTX* ctx, const uint8_t* in, size_t inl)
{
    ctx->data_bits += (uint64_t)inl * 8;
    if (ctx->buf_size == 0)
    {
        size_t block_num = inl / 64;
        while (block_num)
        {
            md5_compress(ctx->state, in);
            in += 64, inl -= 64, block_num--;
        }
        if (inl)
        {
            memcpy(ctx->buf, in, inl);
            ctx->buf_size = inl;
        }
        return;
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
            md5_compress(ctx->state, ctx->buf);
            ctx->buf_size = 0;
        }
    }
    if (inl && ctx->buf_size == 0)
    {
        size_t block_num = inl / 64;
        while (block_num)
        {
            md5_compress(ctx->state, in);
            in += 64, inl -= 64, block_num--;
        }
        if (inl)
        {
            memcpy(ctx->buf, in, inl);
            ctx->buf_size = inl;
        }
        return;
    }
    return;
}

void md5_standard_final(Md5StandardCTX* ctx, uint8_t digest[16])
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
    MEM_STORE64LE(buf + buf_size, ctx->data_bits); //
    buf_size += 8;                                 // update
    // compress
    for (size_t i = 0; i < buf_size; i += 64)
    {
        md5_compress(ctx->state, buf + i);
    }
    // output digest
    MEM_STORE32LE(digest + 4 * 0, ctx->state[0]);
    MEM_STORE32LE(digest + 4 * 1, ctx->state[1]);
    MEM_STORE32LE(digest + 4 * 2, ctx->state[2]);
    MEM_STORE32LE(digest + 4 * 3, ctx->state[3]);
}
}; // namespace tc