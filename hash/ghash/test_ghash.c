#include "ghash_common.h"
#include "ghash_lut256.h"
#include "ghash_pclmul.h"
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

static void rand_mem(void* out, size_t len)
{
    srand((unsigned int)time(NULL));
    uint8_t* out_u8 = (uint8_t*)out;
    for (size_t i = 0; i < len; i++)
    {
        out_u8[i] = rand() % 256;
    }
}

int main()
{
    uint8_t buf[1024], H[16];
    uint8_t d1[16], d2[16], d3[16];

    for (int i = 0; i < 100; i++)
    {
        rand_mem(H, 16);
        rand_mem(buf, sizeof(buf));
        GHashCommonCTX ctx1;
        ghash_common_init(&ctx1, H);
        ghash_common_update(&ctx1, buf, sizeof(buf));
        ghash_common_final(&ctx1, d1);

        GHashLut256CTX ctx2;
        ghash_lut256_init(&ctx2, H);
        ghash_lut256_update(&ctx2, buf, sizeof(buf));
        ghash_lut256_final(&ctx2, d2);

        GHashPclmulCTX ctx3;
        ghash_pclmul_init(&ctx3, H);
        ghash_pclmul_update(&ctx3, buf, sizeof(buf));
        ghash_pclmul_final(&ctx3, d3);

        if (memcmp(d1, d2, 16) != 0 || memcmp(d1, d3, 16) != 0)
        {
            fprintf(stderr, "err in ghash, file: %s, line: %d\n", __FILE__,
                    __LINE__);
            exit(-1);
        }
    }
    puts("test ghash finish!");
    return 0;
}