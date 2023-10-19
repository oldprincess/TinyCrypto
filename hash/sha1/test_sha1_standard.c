/**
 * https://www.rfc-editor.org/rfc/rfc3174#section-7.3
 */
#include "sha1_standard.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 *  Define patterns for testing
 */
#define TEST1  "abc"
#define TEST2a "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b "jkijkljklmklmnlmnomnopnopq"
#define TEST2  TEST2a TEST2b
#define TEST3  "a"
#define TEST4a "01234567012345670123456701234567"
#define TEST4b "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4 TEST4a TEST4b
static char    *testarray[4]   = {TEST1, TEST2, TEST3, TEST4};
static long int repeatcount[4] = {1, 1, 1000000, 10};
static char    *resultarray[4] = {
    "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
    "84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
    "34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
    "DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52"};

int main()
{
    Sha1StandardCTX ctx;
    uint8_t         digest[20];
    for (int j = 0; j < 4; j++)
    {
        sha1_standard_reset(&ctx);
        for (int i = 0; i < repeatcount[j]; i++)
        {
            size_t len = strlen(testarray[j]);
            if (sha1_standard_update(&ctx, (uint8_t *)testarray[j], len))
            {
                fprintf(stderr,
                        "err in sha1 standard update, file: %s, line: %d\n",
                        __FILE__, __LINE__);
                exit(-1);
            }
        }
        sha1_standard_final(&ctx, digest);
        // convert to hex
        char out_hex[20 * 3] = {0};
        for (int i = 0; i < 20; i++)
        {
            char *cur = out_hex + 3 * i;
            sprintf(cur, "%02X", digest[i]);
            *(cur + 2) = ' ';
        }
        out_hex[20 * 3 - 1] = 0;
        if (strcmp(resultarray[j], out_hex) != 0)
        {
            puts(out_hex);
            puts(resultarray[j]);
            fprintf(stderr, "err in sha1 standard, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    puts("test sha1 standard ok!");
    return 0;
}