#include "ghash_common.h"
#include <string.h>

namespace tc {

#define MEM_LOAD64BE(src)                       \
    (((uint64_t)(((uint8_t*)(src))[0]) << 56) | \
     ((uint64_t)(((uint8_t*)(src))[1]) << 48) | \
     ((uint64_t)(((uint8_t*)(src))[2]) << 40) | \
     ((uint64_t)(((uint8_t*)(src))[3]) << 32) | \
     ((uint64_t)(((uint8_t*)(src))[4]) << 24) | \
     ((uint64_t)(((uint8_t*)(src))[5]) << 16) | \
     ((uint64_t)(((uint8_t*)(src))[6]) << 8) |  \
     ((uint64_t)(((uint8_t*)(src))[7]) << 0))

#define MEM_STORE64BE(dst, a)                             \
    (((uint8_t*)(dst))[0] = ((uint64_t)(a) >> 56) & 0xFF, \
     ((uint8_t*)(dst))[1] = ((uint64_t)(a) >> 48) & 0xFF, \
     ((uint8_t*)(dst))[2] = ((uint64_t)(a) >> 40) & 0xFF, \
     ((uint8_t*)(dst))[3] = ((uint64_t)(a) >> 32) & 0xFF, \
     ((uint8_t*)(dst))[4] = ((uint64_t)(a) >> 24) & 0xFF, \
     ((uint8_t*)(dst))[5] = ((uint64_t)(a) >> 16) & 0xFF, \
     ((uint8_t*)(dst))[6] = ((uint64_t)(a) >> 8) & 0xFF,  \
     ((uint8_t*)(dst))[7] = ((uint64_t)(a) >> 0) & 0xFF)

static void ghash_common_update_block(uint64_t       state[2],
                                      const uint64_t H[2],
                                      const uint8_t  in[16])
{
#define Rh 0xE100000000000000ULL // E100...00 (64bit)

    uint64_t Xh = state[0] ^ MEM_LOAD64BE(in);
    uint64_t Xl = state[1] ^ MEM_LOAD64BE(in + 8);
    uint64_t Vh = H[0], Vl = H[1], Zh = 0, Zl = 0, MASK;
    for (int i = 63; i >= 0; i--)
    {
        // IF X_bit[i] IS 1: Z = Z xor V
        if (Xh & 0x8000000000000000ULL)
        {
            Zh ^= Vh, Zl ^= Vl;
        }
        Xh <<= 1;
        MASK = (uint64_t)(-(int64_t)(Vl & 1));
        Vl   = (Vh << 63) | (Vl >> 1);
        Vh   = (Rh & MASK) ^ (Vh >> 1);
    }
    for (int i = 63; i >= 0; i--)
    {
        // IF X_bit[i] IS 1: Z = Z xor V
        if (Xl & 0x8000000000000000ULL)
        {
            Zh ^= Vh, Zl ^= Vl;
        }
        Xl <<= 1;
        MASK = (uint64_t)(-(int64_t)(Vl & 1));
        Vl   = (Vh << 63) | (Vl >> 1);
        Vh   = (Rh & MASK) ^ (Vh >> 1);
    }
    state[0] = Zh;
    state[1] = Zl;

#undef Rh
}

void ghash_common_init(GHashCommonCTX* ctx, const uint8_t H[16])
{
    ctx->H[0]     = MEM_LOAD64BE(H);
    ctx->H[1]     = MEM_LOAD64BE(H + 8);
    ctx->state[0] = 0;
    ctx->state[1] = 0;
    ctx->buf_size = 0;
}

void ghash_common_reset(GHashCommonCTX* ctx)
{
    ctx->state[0] = 0;
    ctx->state[1] = 0;
    ctx->buf_size = 0;
}

void ghash_common_update(GHashCommonCTX* ctx, const uint8_t* in, size_t inl)
{
    if (ctx->buf_size == 0)
    {
        size_t block_num = inl / GHASH_BLOCK_SIZE;
        while (block_num)
        {
            ghash_common_update_block(ctx->state, ctx->H, in);
            in += GHASH_BLOCK_SIZE, inl -= GHASH_BLOCK_SIZE, block_num--;
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
        size_t size = GHASH_BLOCK_SIZE - ctx->buf_size;
        if (size > inl)
        {
            size = inl;
        }
        memcpy(ctx->buf + ctx->buf_size, in, size);
        in += size, inl -= size, ctx->buf_size += size;

        if (ctx->buf_size == GHASH_BLOCK_SIZE)
        {
            ghash_common_update_block(ctx->state, ctx->H, ctx->buf);
            ctx->buf_size = 0;
        }
    }
    if (ctx->buf_size == 0)
    {
        size_t block_num = inl / GHASH_BLOCK_SIZE;
        while (block_num)
        {
            ghash_common_update_block(ctx->state, ctx->H, in);
            in += GHASH_BLOCK_SIZE, inl -= GHASH_BLOCK_SIZE, block_num--;
        }
        if (inl)
        {
            memcpy(ctx->buf, in, inl);
            ctx->buf_size = inl;
        }
        return;
    }
}

int ghash_common_final(const GHashCommonCTX* ctx, uint8_t digest[16])
{
    if (ctx->buf_size != 0)
    {
        return -1;
    }
    MEM_STORE64BE(digest, ctx->state[0]);
    MEM_STORE64BE(digest + 8, ctx->state[1]);
    return 0;
}
}; // namespace tc