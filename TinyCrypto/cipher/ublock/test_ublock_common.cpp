#ifdef TINY_CRYPTO_TEST

#include "ublock_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace tc;

static uint8_t key128128[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static uint8_t pt128128[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static uint8_t ct128128[16] = {
    0x32, 0x12, 0x2b, 0xed, 0xd0, 0x23, 0xc4, 0x29,
    0x02, 0x34, 0x70, 0xe1, 0x15, 0x8c, 0x14, 0x7d,
};
static uint8_t ct128128_1000000[16] = {
    0x9d, 0x63, 0x9e, 0x31, 0x06, 0x2f, 0xfb, 0x57,
    0x46, 0x46, 0xe4, 0x28, 0xf9, 0x2e, 0x08, 0xd4,
};
static uint8_t key128256[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, //
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static uint8_t pt128256[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
};
static uint8_t ct128256[16] = {
    0x64, 0xac, 0xcd, 0x6e, 0x34, 0xca, 0xc8, 0x4d,
    0x38, 0x4c, 0xd4, 0xba, 0x7a, 0xea, 0xdd, 0x19,
};
static uint8_t ct128256_1000000[16] = {
    0x9f, 0xca, 0x87, 0xe0, 0xfb, 0xae, 0xbc, 0x91,
    0x05, 0xe7, 0x29, 0xd3, 0x55, 0x39, 0x67, 0xff,
};
static uint8_t key256256[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, //
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static uint8_t pt256256[32] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, //
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static uint8_t ct256256[32] = {
    0xd8, 0xe9, 0x35, 0x1c, 0x5f, 0x4d, 0x27, 0xea,
    0x84, 0x21, 0x35, 0xca, 0x16, 0x40, 0xad, 0x4b, //
    0x0c, 0xe1, 0x19, 0xbc, 0x25, 0xc0, 0x3e, 0x7c,
    0x32, 0x9e, 0xa8, 0xfe, 0x93, 0xe7, 0xbd, 0xfe,
};
static uint8_t ct256256_1000000[32] = {
    0x20, 0xe1, 0x48, 0xe6, 0xeb, 0xf9, 0xd9, 0x9b,
    0x89, 0x4b, 0x2f, 0x7e, 0x5c, 0xcd, 0xe2, 0x3f, //
    0xc5, 0x8c, 0x95, 0x6c, 0x78, 0x47, 0xfa, 0xd8,
    0x2e, 0x08, 0x24, 0x41, 0x35, 0x76, 0xc8, 0x9f,
};

int main()
{
    UBlockCommonCTX ctx;
    uint8_t         out[32];
    // ====================== 128128
    ublock128128_common_enc_key_init(&ctx, key128128);
    ublock128128_common_enc_block(&ctx, out, pt128128);
    if (memcmp(out, ct128128, UBLOCK128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    memcpy(out, pt128128, UBLOCK128128_BLOCK_SIZE);
    for (int i = 0; i < 1000000; i++)
    {
        ublock128128_common_enc_block(&ctx, out, out);
    }
    if (memcmp(out, ct128128_1000000, UBLOCK128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    ublock128128_common_dec_key_init(&ctx, key128128);
    ublock128128_common_dec_block(&ctx, out, ct128128);
    if (memcmp(out, pt128128, UBLOCK128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    // ===================== 128256
    ublock128256_common_enc_key_init(&ctx, key128256);
    ublock128256_common_enc_block(&ctx, out, pt128256);
    if (memcmp(out, ct128256, UBLOCK128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    memcpy(out, pt128256, UBLOCK128256_BLOCK_SIZE);
    for (int i = 0; i < 1000000; i++)
    {
        ublock128256_common_enc_block(&ctx, out, out);
    }
    if (memcmp(out, ct128256_1000000, UBLOCK128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    ublock128256_common_dec_key_init(&ctx, key128256);
    ublock128256_common_dec_block(&ctx, out, ct128256);
    if (memcmp(out, pt128256, UBLOCK128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    // ===================== 256256
    ublock256256_common_enc_key_init(&ctx, key256256);
    ublock256256_common_enc_block(&ctx, out, pt256256);
    if (memcmp(out, ct256256, UBLOCK256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    memcpy(out, pt256256, UBLOCK256256_BLOCK_SIZE);
    for (int i = 0; i < 1000000; i++)
    {
        ublock256256_common_enc_block(&ctx, out, out);
    }
    if (memcmp(out, ct256256_1000000, UBLOCK256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    ublock256256_common_dec_key_init(&ctx, key256256);
    ublock256256_common_dec_block(&ctx, out, ct256256);
    if (memcmp(out, pt256256, UBLOCK256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock common, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }

    puts("ublock common ok!");
    return 0;
}
#endif