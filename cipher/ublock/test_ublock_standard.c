#include "ublock_standard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main()
{
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
    uint8_t out[32];

    UBlockStandardCTX ctx;
    ublock128128_standard_enc_key_init(&ctx, key128128);
    ublock128128_standard_enc_block(&ctx, out, pt128128);
    if (memcmp(ct128128, out, UBLOCK128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock128128_standard_enc_blocks(&ctx, out, pt128128, 1);
    if (memcmp(ct128128, out, UBLOCK128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock128128_standard_dec_key_init(&ctx, key128128);
    ublock128128_standard_dec_block(&ctx, out, ct128128);
    if (memcmp(pt128128, out, UBLOCK128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock128128_standard_dec_blocks(&ctx, out, ct128128, 1);
    if (memcmp(pt128128, out, UBLOCK128128_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }

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

    ublock128256_standard_enc_key_init(&ctx, key128256);
    ublock128256_standard_enc_block(&ctx, out, pt128256);
    if (memcmp(ct128256, out, UBLOCK128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock128256_standard_enc_blocks(&ctx, out, pt128256, 1);
    if (memcmp(ct128256, out, UBLOCK128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock128256_standard_dec_key_init(&ctx, key128256);
    ublock128256_standard_dec_block(&ctx, out, ct128256);
    if (memcmp(pt128256, out, UBLOCK128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock128256_standard_dec_blocks(&ctx, out, ct128256, 1);
    if (memcmp(pt128256, out, UBLOCK128256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }

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
        0xf9, 0x0d, 0x6b, 0x46, 0xd3, 0x69, 0x27, 0x3c, 0x25, 0xb0, 0xa5,
        0x48, 0xea, 0xc8, 0xf2, 0xf5, 0xa8, 0x95, 0x0d, 0x14, 0xeb, 0x96,
        0x64, 0x10, 0x10, 0xa5, 0x0c, 0x7f, 0xc0, 0xc5, 0xa5, 0xff,
    };

    ublock256256_standard_enc_key_init(&ctx, key256256);
    ublock256256_standard_enc_block(&ctx, out, pt256256);
    if (memcmp(ct256256, out, UBLOCK256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock256256_standard_enc_blocks(&ctx, out, pt256256, 1);
    if (memcmp(ct256256, out, UBLOCK256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard enc, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock256256_standard_dec_key_init(&ctx, key256256);
    ublock256256_standard_dec_block(&ctx, out, ct256256);
    if (memcmp(pt256256, out, UBLOCK256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    ublock256256_standard_dec_blocks(&ctx, out, ct256256, 1);
    if (memcmp(pt256256, out, UBLOCK256256_BLOCK_SIZE) != 0)
    {
        fprintf(stderr, "err in ublock standard dec, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    puts("test ublock standard ok!");
    return 0;
}