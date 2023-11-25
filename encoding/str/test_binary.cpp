#ifdef TINY_CRYPTO_TEST

#include "binary.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <bitset>

using namespace tc;

static void random_mem(uint8_t* buf, size_t size)
{
    for (size_t i = 0; i < size; i++) buf[i] = rand() % 256;
}

static void test_u8array_to_bin()
{
    uint8_t u8array[1024];
    char    bin2[1024 * 8 + 1];
    random_mem(u8array, sizeof(u8array));
    std::string bin1;
    for (size_t i = 0; i < sizeof(u8array); i++)
    {
        bin1 += std::bitset<8>(u8array[i]).to_string();
    }
    u8array_to_bin(bin2, u8array, sizeof(u8array));
    if (strcmp(bin1.c_str(), bin2) != 0)
    {
        fprintf(stderr, "err in u8array_to_bin, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
}

static void test_uint_to_bin()
{
    int loop = 100;
    for (int i = 0; i < loop; i++)
    {
        uint8_t u8n;
        char    bin2[8 + 1];
        random_mem((uint8_t*)&u8n, sizeof(u8n));
        std::string bin1 = std::bitset<8>(u8n).to_string();
        uint8_to_bin(bin2, u8n);
        if (strcmp(bin1.c_str(), bin2) != 0)
        {
            fprintf(stderr, "err in uint_to_bin, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint16_t u16n;
        char     bin2[16 + 1];
        random_mem((uint8_t*)&u16n, sizeof(u16n));
        std::string bin1 = std::bitset<16>(u16n).to_string();
        uint16_to_bin(bin2, u16n);
        if (strcmp(bin1.c_str(), bin2) != 0)
        {
            fprintf(stderr, "err in uint_to_bin, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint32_t u32n;
        char     bin2[32 + 1];
        random_mem((uint8_t*)&u32n, sizeof(u32n));
        std::string bin1 = std::bitset<32>(u32n).to_string();
        uint32_to_bin(bin2, u32n);
        if (strcmp(bin1.c_str(), bin2) != 0)
        {
            fprintf(stderr, "err in uint_to_bin, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint64_t u64n;
        char     bin2[64 + 1];
        random_mem((uint8_t*)&u64n, sizeof(u64n));
        uint64_to_bin(bin2, u64n);
        std::string bin1 = std::bitset<64>(u64n).to_string();
        if (strcmp(bin1.c_str(), bin2) != 0)
        {
            fprintf(stderr, "err in uint_to_bin, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
}

static void test_bin_to_u8array()
{
    uint8_t u8array1[1024], u8array2[1024];
    char    bin1[1024 * 8 + 1];
    random_mem(u8array1, sizeof(u8array1));
    u8array_to_bin(bin1, u8array1, sizeof(u8array1));
    if (bin_to_u8array(u8array2, bin1, 1024 * 8))
    {
        fprintf(stderr, "err in bin_to_u8array, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
    if (memcmp(u8array1, u8array2, sizeof(u8array1)) != 0)
    {
        fprintf(stderr, "err in bin_to_u8array, file: %s, line: %d\n", __FILE__,
                __LINE__);
        exit(-1);
    }
}

static void test_bin_to_uint()
{
    int loop = 100;
    for (int i = 0; i < loop; i++)
    {
        uint8_t n;
        char    bin[8 + 1];
        random_mem((uint8_t*)&n, sizeof(n));
        uint8_to_bin(bin, n);
        if (bin_to_uint8_f(bin) != n)
        {
            fprintf(stderr, "err in bin_to_uint, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint16_t n;
        char     bin[16 + 1];
        random_mem((uint8_t*)&n, sizeof(n));
        uint16_to_bin(bin, n);
        if (bin_to_uint16_f(bin) != n)
        {
            fprintf(stderr, "err in bin_to_uint, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint32_t n;
        char     bin[32 + 1];
        random_mem((uint8_t*)&n, sizeof(n));
        uint32_to_bin(bin, n);
        if (bin_to_uint32_f(bin) != n)
        {
            fprintf(stderr, "err in bin_to_uint, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    for (int i = 0; i < loop; i++)
    {
        uint64_t n;
        char     bin[64 + 1];
        random_mem((uint8_t*)&n, sizeof(n));
        uint64_to_bin(bin, n);
        if (bin_to_uint64_f(bin) != n)
        {
            fprintf(stderr, "err in bin_to_uint, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
}

int main()
{
    test_u8array_to_bin();
    test_uint_to_bin();
    test_bin_to_u8array();
    test_bin_to_uint();
    puts("binary test ok");
    return 0;
}
#endif