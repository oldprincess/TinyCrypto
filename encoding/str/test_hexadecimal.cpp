#ifdef TINY_CRYPTO_TEST

#include "hexadecimal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

using namespace tc;

static void random_mem(uint8_t* buf, size_t size)
{
    for (size_t i = 0; i < size; i++) buf[i] = rand() % 256;
}

static void test_u8array_to_hex()
{
    uint8_t u8array[1024];
    char    hex1[2048 + 1], hex2[2048 + 1];
    random_mem(u8array, sizeof(u8array));
    for (size_t i = 0; i < sizeof(u8array); i++)
    {
        sprintf(hex1 + 2 * i, "%02x", u8array[i]);
    }
    hex1[2048] = '\0';
    u8array_to_hex(hex2, u8array, sizeof(u8array));
    if (strcmp(hex1, hex2) != 0)
    {
        fprintf(stderr, "err in u8array_to_hex, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
}

static void test_uint_to_hex()
{
    int loop = 100;
    for (int i = 0; i < loop; i++)
    {
        uint8_t u8n;
        char    hex1[3], hex2[3];
        random_mem((uint8_t*)&u8n, sizeof(u8n));
        sprintf(hex1, "%02x", u8n);
        uint8_to_hex(hex2, u8n);
        if (strcmp(hex1, hex2) != 0)
        {
            fprintf(stderr, "err in uint_to_hex, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint16_t u16n;
        char     hex1[5], hex2[5];
        random_mem((uint8_t*)&u16n, sizeof(u16n));
        sprintf(hex1, "%04x", u16n);
        uint16_to_hex(hex2, u16n);
        if (strcmp(hex1, hex2) != 0)
        {
            fprintf(stderr, "err in uint_to_hex, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint32_t u32n;
        char     hex1[9], hex2[9];
        random_mem((uint8_t*)&u32n, sizeof(u32n));
        sprintf(hex1, "%08x", u32n);
        uint32_to_hex(hex2, u32n);
        if (strcmp(hex1, hex2) != 0)
        {
            fprintf(stderr, "err in uint_to_hex, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint64_t u64n;
        char     hex1[17], hex2[17];
        random_mem((uint8_t*)&u64n, sizeof(u64n));
        sprintf(hex1, "%016llx", u64n);
        uint64_to_hex(hex2, u64n);
        if (strcmp(hex1, hex2) != 0)
        {
            fprintf(stderr, "err in uint_to_hex, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
}

static void test_hex_to_u8array()
{
    uint8_t u8array1[1024], u8array2[1024];
    char    hex1[2048 + 1];
    random_mem(u8array1, sizeof(u8array1));
    u8array_to_hex(hex1, u8array1, sizeof(u8array1));
    if (hex_to_u8array(u8array2, hex1, 2048))
    {
        fprintf(stderr, "err in hex_to_u8array, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    if (memcmp(u8array1, u8array2, sizeof(u8array1)) != 0)
    {
        fprintf(stderr, "err in hex_to_u8array, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
}

static void test_hex_to_uint()
{
    int loop = 100;
    for (int i = 0; i < loop; i++)
    {
        uint8_t n;
        char    hex[3];
        random_mem((uint8_t*)&n, sizeof(n));
        uint8_to_hex(hex, n);
        if (hex_to_uint8_f(hex) != n)
        {
            fprintf(stderr, "err in hex_to_uint, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint16_t n;
        char     hex[5];
        random_mem((uint8_t*)&n, sizeof(n));
        uint16_to_hex(hex, n);
        if (hex_to_uint16_f(hex) != n)
        {
            fprintf(stderr, "err in hex_to_uint, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint32_t n;
        char     hex[9];
        random_mem((uint8_t*)&n, sizeof(n));
        uint32_to_hex(hex, n);
        if (hex_to_uint32_f(hex) != n)
        {
            fprintf(stderr, "err in hex_to_uint, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint64_t n;
        char     hex[17];
        random_mem((uint8_t*)&n, sizeof(n));
        uint64_to_hex(hex, n);
        if (hex_to_uint64_f(hex) != n)
        {
            fprintf(stderr, "err in hex_to_uint, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
}

int main()
{
    test_u8array_to_hex();
    test_uint_to_hex();
    test_hex_to_u8array();
    test_hex_to_uint();
    puts("hexadecimal test ok");
    return 0;
}
#endif