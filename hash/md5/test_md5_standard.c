#include "md5_standard.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static char* tohex(char* hex, const uint8_t* in, size_t inl)
{
    char* ret = hex;
    while (inl)
    {
        sprintf(hex, "%02x", *in);
        hex += 2, in += 1, inl -= 1;
    }
    *hex = 0;
    return ret;
}

#define TEST1   ""
#define DIGEST1 "d41d8cd98f00b204e9800998ecf8427e"
#define TEST2   "a"
#define DIGEST2 "0cc175b9c0f1b6a831c399e269772661"
#define TEST3   "abc"
#define DIGEST3 "900150983cd24fb0d6963f7d28e17f72"
#define TEST4   "message digest"
#define DIGEST4 "f96b697d7cb7938d525a2f31aaf161d0"
#define TEST5   "abcdefghijklmnopqrstuvwxyz"
#define DIGEST5 "c3fcd3d76192e4007dfb496cca67e13b"
#define TEST6   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define DIGEST6 "d174ab98d277d9f5a5611c2c9f419d9f"
#define TEST7                                                                  \
    "123456789012345678901234567890123456789012345678901234567890123456789012" \
    "34567890"
#define DIGEST7 "57edf4a22be3c955ac49da2e2107b67a"

static const char* test_array[] = {
    TEST1, TEST2, TEST3, TEST4, TEST5, TEST6, TEST7,
};

static const char* digest_array[] = {
    DIGEST1, DIGEST2, DIGEST3, DIGEST4, DIGEST5, DIGEST6, DIGEST7,
};

/**
 * https://www.rfc-editor.org/rfc/rfc1321, A.4
 */

int main()
{
    Md5StandardCTX ctx;
    uint8_t        digest[MD5_DIGEST_SIZE];
    char           hex_digest[MD5_DIGEST_SIZE * 2 + 1];
    md5_standard_init(&ctx);
    // MD5("") = d41d8cd98f00b204e9800998ecf8427e
    // MD5 ("a") = 0cc175b9c0f1b6a831c399e269772661
    // MD5 ("abc") = 900150983cd24fb0d6963f7d28e17f72
    // MD5 ("message digest") = f96b697d7cb7938d525a2f31aaf161d0
    // MD5 ("abcdefghijklmnopqrstuvwxyz") = c3fcd3d76192e4007dfb496cca67e13b
    // MD5 ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    // =d174ab98d277d9f5a5611c2c9f419d9f
    // MD5("12345678901234567890123456789012345678901234567890123456789012345678901234567890")
    // = 57edf4a22be3c955ac49da2e2107b67a
    for (int i = 0; i < sizeof(test_array) / sizeof(test_array[0]); i++)
    {
        md5_standard_reset(&ctx);
        md5_standard_update(&ctx, (const uint8_t*)test_array[i],
                            strlen(test_array[i]));
        md5_standard_final(&ctx, digest);
        if (strcmp(digest_array[i],
                   tohex(hex_digest, digest, MD5_DIGEST_SIZE)) != 0)
        {
            fprintf(stderr, "err in md5 standard, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    puts("test md5 standard ok");
    return 0;
}