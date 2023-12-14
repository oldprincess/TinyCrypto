#ifdef TINY_CRYPTO_TEST

#include "ballet_standard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace tc;

static uint8_t key128128[16] = {
    0xdd, 0xc0, 0x2e, 0x33, 0x71, 0xeb, 0xa4, 0x4d,
    0x24, 0x24, 0x7f, 0xba, 0x9b, 0xf6, 0x72, 0x72,
};
static uint8_t pt128128[16] = {
    0x24, 0xa7, 0xa8, 0x07, 0x02, 0xde, 0x70, 0xce,
    0xd4, 0xc9, 0x14, 0x16, 0xb1, 0x9b, 0x1c, 0xbd,
};
static uint8_t ct128128[16] = {
    0xe9, 0xd3, 0x07, 0x2e, 0x61, 0xbf, 0xb7, 0xaa,
    0x3b, 0x14, 0xd9, 0x64, 0xda, 0x6a, 0xa4, 0x24,
};
static uint8_t ct128128_100[16] = {
    0xaf, 0xa2, 0x46, 0x19, 0x26, 0x93, 0xad, 0x66,
    0x39, 0x40, 0xa5, 0x9f, 0x26, 0xc2, 0x5c, 0x44,
};
static uint8_t ct128128_10000[16] = {
    0xc5, 0x49, 0x39, 0x61, 0x50, 0xa8, 0xbb, 0xa6,
    0x5b, 0x15, 0x48, 0xf2, 0xdb, 0x9a, 0x4a, 0xd5,
};

static uint8_t key128256[32] = {
    0x1B, 0x5D, 0x0C, 0x50, 0x7C, 0x3B, 0xAA, 0x0D,
    0xC1, 0x3D, 0x75, 0x76, 0x61, 0x08, 0x4D, 0x7F, //
    0xD3, 0x4B, 0xF8, 0x65, 0xAF, 0x4F, 0x67, 0xE5,
    0x10, 0xD0, 0x3A, 0xAB, 0x3C, 0x0C, 0x86, 0x0D,
};
static uint8_t pt128256[16] = {
    0xC4, 0x19, 0xAF, 0xDD, 0x74, 0x78, 0x86, 0xB9,
    0xF8, 0xE6, 0x89, 0x0A, 0x3D, 0xB1, 0x9F, 0xA3,
};
static uint8_t ct128256[16] = {
    0x82, 0x72, 0x60, 0x60, 0x2D, 0xE8, 0x7F, 0x86,
    0x5F, 0xE5, 0x74, 0x43, 0xF2, 0x4C, 0xB7, 0xCF,
};

static uint8_t key256256[32] = {
    0xF7, 0xF5, 0xC0, 0xBE, 0x97, 0xC3, 0x88, 0x08,
    0x10, 0x93, 0xA8, 0x40, 0xDF, 0xFF, 0x19, 0x09, //
    0x6C, 0xDD, 0x2D, 0x00, 0x31, 0xCF, 0xD0, 0xEF,
    0x1F, 0x16, 0x0D, 0x44, 0x3D, 0xA7, 0xD4, 0xC1,
};
static uint8_t pt256256[32] = {
    0xFD, 0xC0, 0xBF, 0x9C, 0x6B, 0xFE, 0xB2, 0xFF,
    0xD1, 0x60, 0x12, 0x8E, 0x51, 0x90, 0xAF, 0x6C, //
    0xDA, 0xD2, 0x91, 0x11, 0x4D, 0x95, 0x39, 0x86,
    0xDE, 0x47, 0x2A, 0xD8, 0xBE, 0x6E, 0xA8, 0xC7,
};
static uint8_t ct256256[32] = {
    0x71, 0xFC, 0x5C, 0x31, 0x6C, 0x0B, 0xAE, 0x1B,
    0x2E, 0xD1, 0xE7, 0x69, 0x99, 0x6C, 0x28, 0x93, //
    0x9B, 0xC7, 0x41, 0x92, 0x36, 0x36, 0x77, 0x7C,
    0xB0, 0x7E, 0xFB, 0x8D, 0xBF, 0x2D, 0x07, 0xFF,
};
int main()
{
    uint8_t out[32];

    BalletStandardCTX ctx;
    // 128128-enc
    ballet128128_standard_enc_key_init(&ctx, key128128);
    ballet128128_standard_enc_block(&ctx, out, pt128128);
    if (memcmp(ct128128, out, BALLET128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128128_standard_enc_blocks(&ctx, out, pt128128, 1);
    if (memcmp(ct128128, out, BALLET128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128128_standard_enc_block(&ctx, out, pt128128);
    for (int i = 1; i < 100; i++)
    {
        ballet128128_standard_enc_block(&ctx, out, out);
    }
    if (memcmp(ct128128_100, out, BALLET128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128128_standard_enc_block(&ctx, out, pt128128);
    for (int i = 1; i < 10000; i++)
    {
        ballet128128_standard_enc_block(&ctx, out, out);
    }
    if (memcmp(ct128128_10000, out, BALLET128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    // 128128-dec
    ballet128128_standard_dec_key_init(&ctx, key128128);
    ballet128128_standard_dec_block(&ctx, out, ct128128);
    if (memcmp(pt128128, out, BALLET128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128128_standard_dec_blocks(&ctx, out, ct128128, 1);
    if (memcmp(pt128128, out, BALLET128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128128_standard_dec_block(&ctx, out, ct128128_100);
    for (int i = 1; i < 100; i++)
    {
        ballet128128_standard_dec_block(&ctx, out, out);
    }
    if (memcmp(pt128128, out, BALLET128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128128_standard_dec_block(&ctx, out, ct128128_10000);
    for (int i = 1; i < 10000; i++)
    {
        ballet128128_standard_dec_block(&ctx, out, out);
    }
    if (memcmp(pt128128, out, BALLET128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    // 128256-enc
    ballet128256_standard_enc_key_init(&ctx, key128256);
    ballet128256_standard_enc_block(&ctx, out, pt128256);
    if (memcmp(ct128256, out, BALLET128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128256_standard_enc_blocks(&ctx, out, pt128256, 1);
    if (memcmp(ct128256, out, BALLET128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128256_standard_dec_key_init(&ctx, key128256);
    ballet128256_standard_dec_block(&ctx, out, ct128256);
    if (memcmp(pt128256, out, BALLET128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet128256_standard_dec_blocks(&ctx, out, ct128256, 1);
    if (memcmp(pt128256, out, BALLET128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    // 256256-enc
    ballet256256_standard_enc_key_init(&ctx, key256256);
    ballet256256_standard_enc_block(&ctx, out, pt256256);
    if (memcmp(ct256256, out, BALLET256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ballet256256_standard_enc_blocks(&ctx, out, pt256256, 1);
    if (memcmp(ct256256, out, BALLET256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    // 256256-dec
    ballet256256_standard_dec_key_init(&ctx, key256256);
    ballet256256_standard_dec_block(&ctx, out, ct256256);
    if (memcmp(pt256256, out, BALLET256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
                for(int i=0;i<32;i++)printf("%02x ", out[i]);puts("");
                for(int i=0;i<32;i++)printf("%02x ", pt256256[i]);puts("");
        exit(-1);
    }
    ballet256256_standard_dec_blocks(&ctx, out, ct256256, 1);
    if (memcmp(pt256256, out, BALLET256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ballet standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    puts("test ballet standard ok!");
    return 0;
}
#endif