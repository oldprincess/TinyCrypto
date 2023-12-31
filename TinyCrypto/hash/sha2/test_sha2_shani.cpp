#ifdef TINY_CRYPTO_TEST

#include "sha2_shani.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

using namespace tc;

// static uint8_t msg_0[0]        = {};
static uint8_t digest0_224[28] = {
    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61,
    0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4, 0x15, 0xa2, 0xb0, 0x1f,
    0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f,
};
static uint8_t digest0_256[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
    0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
    0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};
static uint8_t digest0_384[48] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e,
    0xb1, 0xb1, 0xe3, 0x6a, 0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43,
    0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda, 0x27, 0x4e, 0xde, 0xbf,
    0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b,
};
static uint8_t digest0_512[64] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28,
    0x50, 0xd6, 0x6d, 0x80, 0x07, 0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57,
    0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce, 0x47,
    0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2,
    0x87, 0x7e, 0xec, 0x2f, 0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a,
    0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e,
};
static uint8_t msg_1[32] = {
    0x95, 0x5a, 0x88, 0xfc, 0xdd, 0xc5, 0x1b, 0x9f, 0x7b, 0x6c, 0x19,
    0xae, 0xac, 0x96, 0xd7, 0x06, 0x60, 0x73, 0x5c, 0x9f, 0xb9, 0xc0,
    0x6c, 0x50, 0x56, 0x00, 0x38, 0xb0, 0x98, 0x59, 0xe2, 0x6f,
};
static uint8_t digest1_224[28] = {
    0x44, 0x74, 0x78, 0x7c, 0xfa, 0x94, 0x29, 0xdc, 0xc8, 0x47,
    0x85, 0x42, 0xe9, 0x3f, 0x07, 0xa8, 0xc2, 0xdb, 0x99, 0xa8,
    0x33, 0xeb, 0x14, 0x69, 0x7d, 0x42, 0xbe, 0x66,
};
static uint8_t digest1_256[32] = {
    0x5b, 0xb2, 0x15, 0x6c, 0x1a, 0x76, 0x01, 0x59, 0x97, 0x0f, 0xcc,
    0x2e, 0xbb, 0xf9, 0xdb, 0x07, 0xc6, 0x36, 0xe5, 0x77, 0x00, 0xc9,
    0x49, 0xfb, 0x2f, 0x6a, 0x67, 0xba, 0x75, 0x97, 0x2b, 0x96,
};
static uint8_t digest1_384[48] = {
    0x98, 0x4c, 0xf1, 0x10, 0xb6, 0x49, 0xf0, 0x72, 0xe5, 0xd1, 0xf0, 0x5c,
    0xd8, 0xe2, 0xe3, 0x12, 0xa5, 0xc6, 0x04, 0xff, 0xc3, 0xdb, 0x8b, 0x02,
    0x59, 0x69, 0x84, 0x6e, 0x51, 0x18, 0xd3, 0x90, 0xc7, 0xaa, 0x14, 0xde,
    0x07, 0xf4, 0x1d, 0x18, 0x6d, 0x5d, 0x4f, 0xfe, 0xed, 0x07, 0x53, 0xc7,
};
static uint8_t digest1_512[64] = {
    0x57, 0xfc, 0x27, 0xeb, 0xd0, 0xc1, 0x3a, 0x6d, 0x5a, 0x18, 0xf6,
    0xda, 0xde, 0x62, 0xe6, 0x8a, 0x72, 0x22, 0xc4, 0xe0, 0xd6, 0x9c,
    0x0a, 0x7d, 0xc0, 0x6a, 0x7d, 0x35, 0x01, 0x64, 0xa5, 0xbb, 0xfd,
    0x8a, 0x0f, 0x4b, 0x82, 0xd8, 0x62, 0x12, 0xae, 0x03, 0x23, 0x56,
    0x8b, 0xf5, 0x96, 0xf4, 0x51, 0x22, 0x4b, 0xf7, 0x80, 0xd3, 0x37,
    0xbb, 0xb8, 0x8a, 0x31, 0xd9, 0x48, 0xd7, 0xc3, 0xf6,
};
static uint8_t msg_2[64] = {
    0x97, 0x7d, 0xe5, 0x84, 0xf7, 0xd9, 0x8a, 0xca, 0x95, 0x8a, 0xfe,
    0xdd, 0xac, 0xbb, 0x71, 0x17, 0x90, 0xd4, 0x84, 0x30, 0xd5, 0x1d,
    0xe2, 0x1e, 0x89, 0x7f, 0xf9, 0x9a, 0x80, 0x5b, 0x71, 0xbd, 0xc8,
    0x7c, 0x19, 0x5a, 0x40, 0x92, 0xd3, 0x1d, 0x75, 0x6b, 0x65, 0x48,
    0xc6, 0xc3, 0xc4, 0xea, 0x70, 0x0a, 0xb0, 0xd8, 0x50, 0xa1, 0x9a,
    0x81, 0x5b, 0x7a, 0xa0, 0xa3, 0x60, 0x5f, 0x8c, 0xb8,
};
static uint8_t digest2_224[28] = {
    0x1c, 0xee, 0x21, 0xb9, 0x13, 0x25, 0xd9, 0xae, 0x30, 0x5e,
    0x61, 0x8d, 0x39, 0x28, 0x28, 0xc9, 0xd8, 0x70, 0x5e, 0xb5,
    0xc2, 0x1d, 0x69, 0xd1, 0x30, 0xcf, 0x5e, 0x90,
};
static uint8_t digest2_256[32] = {
    0x56, 0x52, 0x3b, 0x2d, 0x70, 0x76, 0xfe, 0x25, 0xc6, 0x40, 0xf5,
    0x02, 0x41, 0x11, 0x3c, 0x72, 0xdd, 0xf0, 0xeb, 0xfe, 0x07, 0xc7,
    0x80, 0x46, 0x6a, 0x09, 0xdb, 0x07, 0x98, 0x3c, 0x88, 0x59,
};
static uint8_t digest2_384[48] = {
    0xdc, 0xb6, 0x22, 0xba, 0xfc, 0x9e, 0x5b, 0x1f, 0x0b, 0xce, 0xb7, 0x95,
    0x32, 0xd6, 0x06, 0x34, 0x39, 0xb3, 0xa4, 0x0c, 0xcf, 0xc1, 0xdb, 0xc2,
    0xd1, 0x7c, 0x01, 0xb3, 0xdf, 0xb2, 0x34, 0x33, 0x0f, 0x08, 0x0b, 0xee,
    0xb1, 0x20, 0x22, 0x4a, 0x4f, 0x56, 0x72, 0xdb, 0x8c, 0xd5, 0xcf, 0xd8,
};
static uint8_t digest2_512[64] = {
    0x08, 0x80, 0xf4, 0xc8, 0x9b, 0x38, 0x44, 0x83, 0xa2, 0x6e, 0x44,
    0xa7, 0x05, 0xad, 0xb6, 0x73, 0xcc, 0x44, 0x46, 0x2a, 0xbb, 0x12,
    0x75, 0x1f, 0x7b, 0x3b, 0x3d, 0xc8, 0x05, 0xd3, 0xc0, 0xcd, 0x6c,
    0x97, 0x7a, 0x99, 0x64, 0x0d, 0xee, 0xaf, 0x5c, 0xe8, 0x14, 0x1c,
    0x4a, 0x07, 0xf4, 0x0e, 0x21, 0x51, 0x97, 0x46, 0x7b, 0xe5, 0x8f,
    0xf9, 0x86, 0xcc, 0xa3, 0xbd, 0xe6, 0x72, 0xb2, 0x8a,
};
static uint8_t msg_3[128] = {
    0xf9, 0x9b, 0x9d, 0x62, 0x76, 0x03, 0x1b, 0xce, 0xdb, 0x33, 0x65, 0xa5,
    0x7b, 0xf2, 0xd9, 0x19, 0xfc, 0x11, 0x75, 0x62, 0xad, 0x61, 0x0e, 0x84,
    0x0a, 0xbd, 0xec, 0xe8, 0x53, 0x17, 0xee, 0x80, 0x45, 0xb9, 0xfa, 0x5d,
    0x83, 0x39, 0xff, 0x4a, 0x53, 0x22, 0xc0, 0xaa, 0x93, 0x76, 0xa2, 0x61,
    0xdb, 0x56, 0xf5, 0xc2, 0x8f, 0xb7, 0x1d, 0x8f, 0xa0, 0x8d, 0xcc, 0xf6,
    0x96, 0x72, 0xcd, 0x38, 0xd6, 0x0a, 0x9b, 0x60, 0xca, 0x4f, 0x76, 0x67,
    0xee, 0xd1, 0x83, 0xa5, 0x47, 0xdf, 0x8e, 0x3d, 0xb2, 0x3a, 0xe8, 0xbe,
    0x7c, 0xc7, 0x89, 0xc4, 0x50, 0x60, 0x79, 0x85, 0xa8, 0xc2, 0xe0, 0x81,
    0xd8, 0xf9, 0x3b, 0x2d, 0xc1, 0xf4, 0x3b, 0xf9, 0x8b, 0x42, 0x13, 0x15,
    0x69, 0x31, 0xfd, 0x80, 0xbd, 0x06, 0xbd, 0x2b, 0x1c, 0xdd, 0xac, 0xa4,
    0xa8, 0x30, 0x2a, 0x05, 0xb0, 0x5e, 0x60, 0xf9,
};
static uint8_t digest3_224[28] = {
    0xef, 0x22, 0x65, 0xc7, 0x77, 0xb1, 0x0a, 0x51, 0x9c, 0x47,
    0x57, 0xf2, 0x19, 0x41, 0x93, 0x6a, 0xac, 0x65, 0x0d, 0x43,
    0x23, 0x5b, 0x5b, 0xc4, 0x9c, 0x70, 0x96, 0xe0,
};
static uint8_t digest3_256[32] = {
    0x64, 0x49, 0x1c, 0xe2, 0xef, 0xc6, 0x49, 0x2b, 0xee, 0xa0, 0x42,
    0x94, 0x44, 0x3f, 0xae, 0xe2, 0x22, 0xcc, 0xc1, 0x03, 0x40, 0x83,
    0x2a, 0x9a, 0xdf, 0xcb, 0x4f, 0xfe, 0xf8, 0x75, 0x93, 0x3d,
};
static uint8_t digest3_384[48] = {
    0x09, 0x41, 0x09, 0x78, 0xdf, 0x7f, 0xdb, 0xd5, 0x6d, 0x83, 0x6a, 0x5c,
    0xee, 0xe6, 0xa3, 0x46, 0xa4, 0x62, 0x26, 0x82, 0x03, 0xf4, 0xe1, 0xb9,
    0xba, 0xe0, 0x59, 0xed, 0x76, 0x00, 0x5c, 0x54, 0x54, 0x0b, 0xab, 0x1e,
    0xf4, 0xa1, 0xc9, 0x57, 0xb3, 0x16, 0x27, 0x87, 0xab, 0x7a, 0xce, 0x6b,
};
static uint8_t digest3_512[64] = {
    0xe8, 0x1a, 0x5c, 0x61, 0xeb, 0x45, 0xf5, 0xe4, 0x58, 0x06, 0x3f,
    0x49, 0xc3, 0x3e, 0xe9, 0x58, 0xae, 0xfb, 0xb9, 0x96, 0xbd, 0xd9,
    0x9d, 0x13, 0xeb, 0xf6, 0x0a, 0xc1, 0xab, 0xd4, 0x4c, 0x0e, 0x9e,
    0x13, 0x92, 0x34, 0x75, 0xca, 0xdb, 0x09, 0xe8, 0x64, 0x00, 0x36,
    0xfc, 0xb4, 0xf2, 0xe9, 0x0a, 0xe9, 0x26, 0x82, 0x92, 0xca, 0x86,
    0x33, 0x89, 0xd9, 0xe6, 0xad, 0x16, 0x0d, 0xaa, 0xa5,
};
static uint8_t msg_4[129] = {
    0xbd, 0x5c, 0x26, 0x28, 0xed, 0x8d, 0xd9, 0xd2, 0x7a, 0x1a, 0x76, 0xe1,
    0x54, 0x10, 0x81, 0xe1, 0xc0, 0x10, 0x28, 0x5b, 0x7c, 0xe5, 0x97, 0x60,
    0x30, 0x72, 0x67, 0x56, 0x92, 0xdf, 0xfd, 0x63, 0x2a, 0xe4, 0x04, 0xef,
    0x80, 0x0c, 0xfc, 0xb7, 0x60, 0x81, 0xf8, 0x97, 0xef, 0x83, 0x57, 0x79,
    0x7f, 0xdb, 0xfc, 0x93, 0xa0, 0x5a, 0x50, 0x67, 0xab, 0x77, 0x6f, 0x92,
    0x4f, 0x6e, 0x63, 0xb3, 0x44, 0x7a, 0xb9, 0x3c, 0x99, 0xb3, 0xcb, 0xbf,
    0x20, 0x5a, 0x50, 0x96, 0x59, 0xf4, 0x34, 0xeb, 0xd2, 0x12, 0x94, 0x66,
    0x06, 0x82, 0xaf, 0x9b, 0x70, 0x63, 0xff, 0x63, 0x05, 0xd3, 0x3f, 0xab,
    0x34, 0x52, 0x3c, 0x69, 0x22, 0x36, 0xd3, 0x68, 0xdc, 0x05, 0x0e, 0xb6,
    0x79, 0x1e, 0xb9, 0x41, 0x30, 0xc7, 0x30, 0x35, 0xcc, 0xd8, 0x31, 0xd5,
    0xd1, 0x0c, 0xac, 0x9a, 0x5f, 0x20, 0xb3, 0xf6, 0x62,
};
static uint8_t digest4_224[28] = {
    0xc6, 0x49, 0x3e, 0x7a, 0x35, 0x72, 0xa7, 0xdb, 0xa4, 0x6c,
    0xa0, 0x52, 0x75, 0x12, 0x68, 0x06, 0xc8, 0xa5, 0x64, 0x4a,
    0x77, 0x33, 0x80, 0xeb, 0xb1, 0x0e, 0x76, 0xb5,
};
static uint8_t digest4_256[32] = {
    0xa2, 0xe5, 0x00, 0x4c, 0x35, 0x9f, 0x92, 0x58, 0xe2, 0xc1, 0x50,
    0x88, 0x4a, 0xe8, 0x6e, 0x0b, 0xb6, 0x0b, 0xf1, 0xfc, 0x85, 0xac,
    0x2f, 0x6d, 0xa4, 0x80, 0x97, 0x87, 0x41, 0xbf, 0xbf, 0xc7,
};
static uint8_t digest4_384[48] = {
    0x59, 0x65, 0xcc, 0xd7, 0x51, 0x21, 0xee, 0x47, 0xa2, 0xee, 0x6f, 0xd5,
    0x39, 0x14, 0xad, 0x0e, 0x8d, 0x9e, 0x51, 0x8e, 0xcb, 0x00, 0x27, 0x04,
    0xd5, 0x43, 0x7d, 0x60, 0x9f, 0xda, 0x4e, 0xdf, 0x82, 0x93, 0xc3, 0x27,
    0x0b, 0x08, 0x7b, 0xb1, 0xb4, 0xee, 0x6e, 0xa6, 0x5e, 0x7a, 0x17, 0x0f,
};
static uint8_t digest4_512[64] = {
    0xa9, 0xff, 0x60, 0x32, 0xa5, 0x78, 0x7e, 0xe2, 0x8e, 0x2f, 0x3e,
    0xf8, 0x7e, 0x3e, 0x59, 0xc7, 0xf7, 0xba, 0xe0, 0x73, 0x25, 0xba,
    0xd2, 0x43, 0x1f, 0xb3, 0x8d, 0xa3, 0xea, 0x11, 0xb1, 0xa8, 0xc3,
    0x88, 0xc2, 0xf0, 0x1c, 0x51, 0x75, 0x94, 0x0b, 0x30, 0xae, 0x53,
    0x67, 0xf0, 0x20, 0x76, 0x27, 0x34, 0xf7, 0x52, 0x07, 0x24, 0x19,
    0x0c, 0x39, 0xc8, 0x10, 0xa9, 0x4e, 0x27, 0x2a, 0x1e,
};

int main()
{
    const size_t msg_size[5] = {0, sizeof(msg_1), sizeof(msg_2), sizeof(msg_3),
                                sizeof(msg_4)};
    const uint8_t* msg[5]    = {NULL, msg_1, msg_2, msg_3, msg_4};
    const uint8_t* digest224[5] = {digest0_224, digest1_224, digest2_224,
                                   digest3_224, digest4_224};
    const uint8_t* digest256[5] = {digest0_256, digest1_256, digest2_256,
                                   digest3_256, digest4_256};
    const uint8_t* digest384[5] = {digest0_384, digest1_384, digest2_384,
                                   digest3_384, digest4_384};
    const uint8_t* digest512[5] = {digest0_512, digest1_512, digest2_512,
                                   digest3_512, digest4_512};
    // ****************************************
    // ************** SHA224 ******************
    // ****************************************
    Sha224ShaniCTX ctx224;
    sha224_shani_init(&ctx224);
    uint8_t out224[SHA224_DIGEST_SIZE];
    for (int i = 0; i < 5; i++)
    {
        sha224_shani_reset(&ctx224);
        if (sha224_shani_update(&ctx224, msg[i], msg_size[i]))
        {
            fprintf(stderr, "err in sha224 shani, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
        sha224_shani_final(&ctx224, out224);
        if (memcmp(out224, digest224[i], SHA224_DIGEST_SIZE) != 0)
        {
            fprintf(stderr, "err in sha224 shani, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    // ****************************************
    // ************** SHA256 ******************
    // ****************************************
    Sha256ShaniCTX ctx256;
    sha256_shani_init(&ctx256);
    uint8_t out256[SHA256_DIGEST_SIZE];
    for (int i = 0; i < 5; i++)
    {
        sha256_shani_reset(&ctx256);
        if (sha256_shani_update(&ctx256, msg[i], msg_size[i]))
        {
            fprintf(stderr, "err in sha256 shani, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
        sha256_shani_final(&ctx256, out256);
        if (memcmp(out256, digest256[i], SHA256_DIGEST_SIZE) != 0)
        {
            fprintf(stderr, "err in sha256 shani, file: %s, line: %d\n",
                    __FILE__, __LINE__);
            exit(-1);
        }
    }
    
    puts("sha2 shani (sha224/256) test ok!");
    return 0;
}

// clang-format off
// # python test file
// import hashlib
// import os
//
//
// def dump_mem(prefix: str, data: bytes, end: str):
//     print(prefix, end='')
//     for item in data:
//         print("0x" + hex(item)[2::].rjust(2, '0'), end=', ')
//     print(end)
//
//
// SIZE = [0, 32, 64, 128, 129]
// for i in range(len(SIZE)):
//     msg = os.urandom(SIZE[i])
//     dump_mem(f"static uint8_t msg_{i}[{SIZE[i]}] = " + "{", msg, "};")
//     dump_mem(f"static uint8_t digest{i}_224[28] = " + "{", hashlib.sha224(msg).digest(), "};")
//     dump_mem(f"static uint8_t digest{i}_256[32] = " + "{", hashlib.sha256(msg).digest(), "};")
//     dump_mem(f"static uint8_t digest{i}_384[48] = " + "{", hashlib.sha384(msg).digest(), "};")
//     dump_mem(f"static uint8_t digest{i}_512[64] = " + "{", hashlib.sha512(msg).digest(), "};")
// clang-format on

#endif