#ifdef TINY_CRYPTO_TEST

#include "sm3_fast.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

using namespace tc;

static const uint8_t msg[]           = {'a', 'b', 'c'};
static const uint8_t need_digest[32] = {
    0x66, 0xC7, 0xF0, 0xF4, 0x62, 0xEE, 0xED, 0xD9, 0xD1, 0xF2, 0xD4,
    0x6B, 0xDC, 0x10, 0xE4, 0xE2, 0x41, 0x67, 0xC4, 0x87, 0x5C, 0xF2,
    0xF7, 0xA2, 0x29, 0x7D, 0xA0, 0x2B, 0x8F, 0x4B, 0xA8, 0xE0,
};

int main()
{
    Sm3FastCTX ctx;
    uint8_t    digest[SM3_DIGEST_SIZE];
    sm3_fast_init(&ctx);
    if (sm3_fast_update(&ctx, msg, sizeof(msg)) != 0)
    {
        fprintf(stderr, "err in sm3 fast update, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    sm3_fast_final(&ctx, digest);
    if (memcmp(need_digest, digest, SM3_DIGEST_SIZE) != 0)
    {
        fprintf(stderr, "err in sm3 hash, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }

    sm3_fast_reset(&ctx);
    if (sm3_fast_update(&ctx, msg, sizeof(msg)) != 0)
    {
        fprintf(stderr, "err in sm3 fast update, file: %s, line: %d\n",
                __FILE__, __LINE__);
        exit(-1);
    }
    sm3_fast_final(&ctx, digest);
    if (memcmp(need_digest, digest, SM3_DIGEST_SIZE) != 0)
    {
        fprintf(stderr, "err in sm3 hash, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    puts("test sm3 ok!");
    return 0;
}
#endif