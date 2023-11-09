#ifdef TINY_CRYPTO_TEST

#include "uint256_mont.h"
#include "uint256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace tc;

static uint32_t hex_to_u32(const char* hex)
{
    static const int32_t HEX_CHAR_TO_UINT4[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,
        6,  7,  8,  9,  -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1,
    };
    uint32_t ret = 0;
    for (int i = 0; i < 8; i++)
    {
        if (HEX_CHAR_TO_UINT4[hex[i]] == (-1))
        {
            fprintf(stderr, "invalid hex string");
            exit(-1);
        }
        ret = ((uint8_t)HEX_CHAR_TO_UINT4[hex[i]] << (28 - 4 * i)) | ret;
    }
    return ret;
}

static int hex_to_bytes(uint8_t bytes[32], const char hex[64])
{
    static const int8_t HEX_CHAR_TO_UINT4[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,
        6,  7,  8,  9,  -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1,
    };
    for (int i = 0; i < 32; i++)
    {
        uint8_t u4high = (uint8_t)HEX_CHAR_TO_UINT4[hex[2 * i + 0]];
        if (u4high == (uint8_t)(-1)) return -1;
        uint8_t u4low = (uint8_t)HEX_CHAR_TO_UINT4[hex[2 * i + 1]];
        if (u4low == (uint8_t)(-1)) return -1;
        bytes[i] = (u4high << 4) | u4low;
    }
    return 0;
}

static void bytes_to_hex(char hex[65], const uint8_t bytes[32])
{
    static const char UINT4_TO_HEX_CHAR[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    };
    for (int i = 0; i < 32; i++)
    {
        hex[2 * i + 0] = UINT4_TO_HEX_CHAR[bytes[i] >> 4];
        hex[2 * i + 1] = UINT4_TO_HEX_CHAR[bytes[i] & 0xF];
    }
    hex[64] = 0;
}

static int uint256_from_hex(uint32_t num[8], const char hex[64])
{
    int     err_code = 0;
    uint8_t bytes[32];
    err_code = hex_to_bytes(bytes, hex);
    if (err_code) return err_code;
    uint256_from_bytes(num, bytes);
    return 0;
}

static void uint256_to_hex(char hex[65], const uint32_t num[8])
{
    uint8_t bytes[32];
    uint256_to_bytes(bytes, num);
    bytes_to_hex(hex, bytes);
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// ************** UINT256 Montgeomery ***************
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

/// @brief SM2椭圆曲线 p = 2^256 - 2^224 - 2^96 + 2^64 - 1
static const uint32_t SM2_CURVE_P[8] = {
    0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

// SM2_CURVE_P - 2
static const uint32_t SM2_CURVE_P_SUB2[8] = {
    0xfffffffd, 0xffffffff, 0x00000000, 0xffffffff,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};

// R mod SM2_CURVE_P = 2^256 mod p
static const uint32_t SM2_FP_MONT_R[8] = {
    0x00000001, 0x00000000, 0xffffffff, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000001,

};

// R^2 mod SM2_CURVE_P = (2^256)^2 mod p
static const uint32_t SM2_FP_MONT_R_POW2[8] = {
    0x00000003, 0x00000002, 0xffffffff, 0x00000002,
    0x00000001, 0x00000001, 0x00000002, 0x00000004,
};

static const Mont256CTX SM2_FP_MONT_CTX = {
    SM2_CURVE_P, SM2_CURVE_P_SUB2, SM2_FP_MONT_R, SM2_FP_MONT_R_POW2, 1,
};

// ****************************************
// ************ Arithmetic ****************
// ****************************************

static bool test_uint256_mont_add()
{
    static const char* TEST_VECTOR[][3] = {
        {"ea23a9490f0da0aceb14f40360069f8aedbeb9d9c4b4d3d11ee354ac30d0c7f8",
         "28023cb59d1d2d3a06307a4fd643e9d71e4cc0f0091ca6cffd72ff67be06931f",
         "1225e5ffac2acde6f1456e53364a89620c0b7acacdd17aa01c565413eed75b18"},
        {"350431184ce0d280847d34136b4d1050f3d100482f0422db600c1863e061347e",
         "c07eeb161d9f9a864cb4e39b3f0534c878ebc59aa463ef93307d80f067981a62",
         "f5831c2e6a806d06d13217aeaa5245196cbcc5e2d368126e9089995447f94ee0"},
        {"8a9e2b03c8f891638d5ab864f803d76e06a95733945393546f6aa186310ae387",
         "f56a4334b29e2d4f24014d15285d678885d0307aa7768ebeaba498c264da4412",
         "80086e397b96beb2b15c057a20613ef68c7987af3bca22121b0f3a4895e5279a"},
        {"6921ef8276fac5b6f0a6d57af0c4011f38206f85179db9e38189563750fa5982",
         "bf268ea7cb1d1f9816543c69f7c8bb12dd89661c2301dafbe84fa7a5ed919d4e",
         "28487e2b4217e54f06fb11e4e88cbc3215a9d5a23a9f94de69d8fddd3e8bf6d1"},
        {"8e6cc41157c0c5682c0d2f4c8100f4d721ea8ef55bfcd86031ddf58a35375686",
         "949c9e971b4dce4c6985f47d6bcca275b4e91ddc3abbcdc5c142febeb1d41869",
         "230962a9730e93b4959323c9eccd974cd6d3acd296b8a624f320f448e70b6ef0"},
        {"6f5ddb74dc226d129e4a72b5ce9c356219f4e408b08b4bfc069c6aed253ff1b7",
         "ef37b6056852864e69a6a76612cc3567977eeeeb098b34fe4e97e7d0944fb035",
         "5e95917b4474f36107f11a1be1686ac9b173d2f4ba1680f9553452bdb98fa1ed"},
        {"c89fa88cc54850f9f69f16c584a28449d6a89a943da4b59c2108c12d4c39e175",
         "e0d0b0660cd2f54485c41024f7712877b4ee5ba3bb268c9019228896613a5d0b",
         "a97058f3d21b463e7c6326ea7c13acc18b96f638f8cb422b3a2b49c3ad743e81"},
        {"89ee2b08656239ac813b1c796bf85b4c0e551cda0068f1bba0236258f1db0df6",
         "7a35d8b51eb09db1e9e81434a44a83f834f48d29459e56f6d2f9ecaa742576f4",
         "042403be8412d75e6b2330ae1042df444349aa04460748b1731d4f03660084eb"},
        {"17db9daf8f3919e68deef9b9004e921939c11c2272f57e8470714d4490187a95",
         "12e06d02524ee288125383000cbaa17e0e4848e9bec8b377ca9e6528660fa724",
         "2abc0ab1e187fc6ea0427cb90d0933974809650c31be31fc3b0fb26cf62821b9"},
        {"811e53a0cbdf9181fd20ca542ce73f7bbc785b398e9c8eb85f180d56b0cb3aee",
         "d731a2c9cbb74933688349b4e74452e310d4e5d3c4e159c1358b9f250077d5d3",
         "584ff66b9796dab565a41409142b925ecd4d410e537de87894a3ac7bb14310c2"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], y[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(y, TEST_VECTOR[i][1]);
        uint256_from_hex(need_z, TEST_VECTOR[i][2]);
        uint256_mont_add(&SM2_FP_MONT_CTX, z, x, y);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_sub()
{
    static const char* TEST_VECTOR[][3] = {
        {"7b851099334809bd9e56adb8e75865757ee06b1f928965d1fa1014a2894fa35b",
         "bab8515374391adc05d7c60a007dcff23bfbd7fda711d05fb6b72c006a1dfe77",
         "c0ccbf44bf0eeee1987ee7aee6da958342e49320eb7795734358e8a21f31a4e3"},
        {"9737b82357efa447b061348fc22e92c7624d547b8d1b35ecdc35dc00074dd1ef",
         "b0caa2cd768aaffce1b1c9a58f499c41ac28691aead10749d56904eadd2e087a",
         "e66d1554e164f44aceaf6aea32e4f685b624eb5fa24a2ea406ccd7152a1fc974"},
        {"1f2208ccbf2044c1b95b1ffdf77d4146628e4bbca31cf7142a56798068d453f9",
         "8a7a92c1ada000b09d7d47407953c9a99ffc6df6e5e04147a6cd812709063341",
         "94a7760a118044111bddd8bd7e29779cc291ddc4bd3cb5cd8388f8595fce20b7"},
        {"5fee58ed66baf9c9af68e28d30b6b201bf5325542d9044195a03702f7c1ae3dc",
         "59744bc5bf24f0895194a3334cabf57d41823bd1444d5bc966d3714a76b247a3",
         "067a0d27a79609405dd43f59e40abc847dd0e982e942e84ff32ffee505689c39"},
        {"dbb812301b8c680ce00cde636d6c193771937bec20236e4bc2505b2c85d075d7",
         "38ceec65b4e785e3fdbd4f685452186c816ca2783acc461ad8cd87ff77800f96",
         "a2e925ca66a4e228e24f8efb191a00caf026d973e5572830e982d32d0e506641"},
        {"74b517c9269eae1c38c166819eee2026646d5003ae079d245195ef0ad1592d07",
         "ea1ffb2908108871786f40b56bf9fca66ee598199016d506a751cffee557ba9b",
         "8a951c9f1e8e25aac05225cc32f4237ff587b7e91df0c81eaa441f0bec01726b"},
        {"a7d51c312143965e681b1154603b1d7cc9d4c818e0cbff8cd347ddea6656029e",
         "11f2e802f050a187c3ac52363cd550fd07f709e5e62d7660484c7344088283bc",
         "95e2342e30f2f4d6a46ebf1e2365cc7fc1ddbe32fa9e892c8afb6aa65dd37ee2"},
        {"049babec6ae424fd2b628b5ec0c022f7c8b5762d61f612b6a8b0e912c4f14c92",
         "f290a6361082b25e1f227da1a54fc15ebdb863b40809ba5210d38afaa5378527",
         "120b05b55a61729f0c400dbd1b7061990afd127859ec586597dd5e181fb9c76a"},
        {"01b24c6bf710b57f0fc9906038f9d1654cfbfd60b957529c8c78733cecf10144",
         "d088dba7d8d43abd0ee97db9ce758c9aabdb9833343d44d70a96dd72c939b1f0",
         "312970c31e3c7ac200e012a66a8444caa120652c851a0dc681e195ca23b74f53"},
        {"67534e86aced2b4cf5bc7424e9a69c2da1d29c78f6b84c4f088e2bc3484e5157",
         "4062cc2db1f229d9f61a59527c8fe622d228715573650c26444339d5336a7fb8",
         "26f08258fafb0172ffa21ad26d16b60acfaa2b2383534028c44af1ee14e3d19f"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], y[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(y, TEST_VECTOR[i][1]);
        uint256_from_hex(need_z, TEST_VECTOR[i][2]);
        uint256_mont_sub(&SM2_FP_MONT_CTX, z, x, y);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_dbl()
{
    static const char* TEST_VECTOR[][2] = {
        {"8af6c34ed9d96e2069e041806462e91ecd4aa0a5ca28e2aaa3e6ef706742f29e",
         "15ed869eb3b2dc40d3c08300c8c5d23d9a95414c9451c55447cddee0ce85e53d"},
        {"9d066c36fd1d91325c373ca42481b9ff85316192a087512d3e8be2cf95f5edc3",
         "3a0cd86efa3b2264b86e7948490373ff0a62c326410ea2597d17c59f2bebdb87"},
        {"d50c02917511f1168f0dbccf1a3fefdfd99acc5e9ea6323c23c5d7a1d8d9e427",
         "aa180523ea23e22d1e1b799e347fdfbfb33598be3d4c6477478baf43b1b3c84f"},
        {"b73bac0cf5344154348abd9ba8b1544a81094bc10d879de693ba648bca69b088",
         "6e77581aea6882a869157b375162a895021297831b0f3bcc2774c91794d36111"},
        {"4ba78395d1496c8ac7ff18b2dab0f2519c34022187640aaacc002b48032ea224",
         "974f072ba292d9158ffe3165b561e4a3386804430ec8155598005690065d4448"},
        {"7871946e1e652feb7c109e9539d03e5180a9a4f855d30912d197e0513f534d25",
         "f0e328dc3cca5fd6f8213d2a73a07ca3015349f0aba61225a32fc0a27ea69a4a"},
        {"fae851e624933f5baaf71c08b51be167184e750c20aa77ac39f3822bea228f5d",
         "f5d0a3cd49267eb755ee38116a37c2ce309cea194154ef5773e70457d4451ebb"},
        {"46e8e4095ec19462a0ba9e2b9ec0a49dc64a107297fdd788ca0985aa40eb7b31",
         "8dd1c812bd8328c541753c573d81493b8c9420e52ffbaf1194130b5481d6f662"},
        {"4afacd953efd886e8b43b57e23758df0fa937017077eec68a9d3268be6af5fdf",
         "95f59b2a7dfb10dd16876afc46eb1be1f526e02e0efdd8d153a64d17cd5ebfbe"},
        {"ec51483fda4e7586f7e60c90539a52b7138db5711eedbae97eebd873989cc86f",
         "d8a29080b49ceb0defcc1920a734a56e271b6ae33ddb75d1fdd7b0e7313990df"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(need_z, TEST_VECTOR[i][1]);
        uint256_mont_dbl(&SM2_FP_MONT_CTX, z, x);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_tpl()
{
    static const char* TEST_VECTOR[][2] = {
        {"c75a4d135df2bc87a04ba954d76f45d43dd38cd075c3756b5aec45ddf8845e48",
         "560ee73c19d83596e0e2fbfe864dd17cb97aa673614a604010c4d199e98d1ada"},
        {"1c5a6c22ee741b4bb786158753fa6b684f331b712b59d4040f9d5b45885b2b1e",
         "550f4468cb5c51e326924095fbef4238ed995253820d7c0c2ed811d09911815a"},
        {"ac22e5561b71a19102e541f598bd431aaabbb3fc84ef7d818bf95c89ea029543",
         "0468b0045254e4b308afc5e0ca37c95000331bf78ece7882a3ec159dbe07bfcb"},
        {"480dc31612253add20b459e2e7b8ca59f6927d6ce957ee2702790940782c1db8",
         "d8294942366fb097621d0da8b72a5f0de3b77846bc07ca75076b1bc168845928"},
        {"b3a70c85966e8d50ddc194b4853c2d7fa7ad17b8f45aba1adc010930121a542c",
         "1af52592c34ba7f29944be1d8fb4887ef707472cdd102e4e94031b90364efc86"},
        {"979ef4be35567a11d54b2b552b3838753038288a4b5fa8994266e64dcde12cb1",
         "c6dcde3ba0036e357fe181ff81a8a95f90a8799fe21ef9cac734b2e969a38614"},
        {"1988a054cf8e625672b72582658bcf4758f1f5bca3536ce422a273395d2bd551",
         "4c99e0fe6eab27035825708730a36dd60ad5e135e9fa46ac67e759ac17837ff3"},
        {"f608bd749cd39ddde17b1bb3251ca1f29ce0090a2aff15edff8e889a5d39e188",
         "e21a385fd67ad999a47153196f55e5d7d6a01b2080fd41c7feab99cf17ada49a"},
        {"5ebb348dbbc0d477420fda48b96c4c97d379ed355bc189e71e17593ab21c4619",
         "1c319daa33427d65c62f8eda2c44e5c77a6dc7a113449db45a460bb01654d24c"},
        {"7a3573e7d53abf6822c388deb02db60a4eaba14dbef00f00a229e8d0b620ffb4",
         "6ea05bb87fb03e38684a9a9c1089221eec02e3ea3cd02d00e67dba722262ff1d"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(need_z, TEST_VECTOR[i][1]);
        uint256_mont_tpl(&SM2_FP_MONT_CTX, z, x);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_neg()
{
    static const char* TEST_VECTOR[][2] = {
        {"7e37190387f22b8d88d7d8fb9fab8b0995e1f2c5b08c30a139293cfb0657a922",
         "81c8e6fb780dd47277282704605474f66a1e0d394f73cf5fc6d6c304f9a856dd"},
        {"242fb3a1a31f9ccc0b51a93bcc7da87b2b1c7dd40cd80d98600a33b4262b78d3",
         "dbd04c5d5ce06333f4ae56c433825784d4e3822af327f2689ff5cc4bd9d4872c"},
        {"27e2644fe9e7bfebee4c16b124c8eef52054297ae48e9af904d05dd213559e59",
         "d81d9baf1618401411b3e94edb37110adfabd6841b716507fb2fa22decaa61a6"},
        {"eb8a074da29d6a542f174e1a7e75cfeb13ecbc8de037ddebd0082dab1575e0c4",
         "1475f8b15d6295abd0e8b1e5818a3014ec1343711fc822152ff7d254ea8a1f3b"},
        {"bc473b0324cbfa7a879d4fb035c7064af3069db915e12986c9064e48517238cf",
         "43b8c4fbdb3405857862b04fca38f9b50cf96245ea1ed67a36f9b1b7ae8dc730"},
        {"67af0512bc6ff0470efc47a4831727fae6b4864040681ed73d52964507bffe8b",
         "9850faec43900fb8f103b85b7ce8d805194b79bebf97e129c2ad69baf8400174"},
        {"e8f52ad78529a012e4556fcffa0bcf1a3b436275884446c9fddee642c8770bab",
         "170ad5277ad65fed1baa903005f430e5c4bc9d8977bbb937022119bd3788f454"},
        {"198739aac2f71900be925582da04a5dedd3090240b6faf4d2ee625ecd9c2c3db",
         "e678c6543d08e6ff416daa7d25fb5a2122cf6fdaf49050b3d119da13263d3c24"},
        {"72469f059a937d152e354c8e80f34ea62ac5c4b794e0d40920f398a4bb190d5e",
         "8db960f9656c82ead1cab3717f0cb159d53a3b476b1f2bf7df0c675b44e6f2a1"},
        {"9379c5060da77c7727bd42a32c72328a0f6c2b310dfdd29a1095fa98bcba6c90",
         "6c863af8f2588388d842bd5cd38dcd75f093d4cdf2022d66ef6a05674345936f"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(need_z, TEST_VECTOR[i][1]);
        uint256_mont_neg(&SM2_FP_MONT_CTX, z, x);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_mul()
{
    static const char* TEST_VECTOR[][3] = {
        {"69014f60aaa9287368169ca5f19ec503bd7c24aeffe64e54dea9cb1ebfd4cf12",
         "8b0b1892efd6bdf186ad57e5466062b555403e7178f70db4a82b0657351479d4",
         "26a22fc20be5d940371e16e128d098edc5d6f3c79fa5fd2aa3cb4dc53eeddd45"},
        {"915f96f1485f7db54dfa1e881356ce2f850e71074772a26cfecf2f433f775847",
         "8ee551d63f660d661f196f5d7266e3bb9fcdfa32d2d724ab14a45d3c9635921e",
         "312151ebbe2c2fc6e94f44f688954556fddb211fb92f9b1d330430481ff445dc"},
        {"c3c181d0671d4fe7d2edb688ea8646650e9fd7e3ccdf2798c322e3146537d965",
         "32a6208faf901b81ee3aaa5f6556399c4db0e32e01e8333df2d81ec1b44b9472",
         "f5b9d77547b00751c3ec7ca3c61a963f7d01d05ac8cf22f1fdd608814c8d6707"},
        {"7f1f7d34a07a27d040ff88ac84d6673c25e984175a15c6221faa2e647262298a",
         "76127c8d06c0c1e6ca4d00e8e43b0c8496444c5cfd0f284350b1cf7d86a9b53b",
         "5b8f708aedbd5f5b04073255df3be44924332e0f7db4fc95c33b05259932f1cc"},
        {"95eaaa0ae7ddd7e4abca981608490ec3fb93d2d5089d5652a011acf8d2a9612f",
         "79a7d701072f65113656cbffa76ecca915d94b62ac251dad089e34db1fe92e38",
         "eed32d981f59172738dc060e12f354945136383f2574570c55f2675ad7ed68c0"},
        {"566c62d3f242fc4f97e3d27ef626e365a8568f1c003fb6dd81c46f2c1a4cb75a",
         "981a49a54c7eeff8825aa28d6d25a45b4da6c9ee5b8f2f54f90d15d6222686c6",
         "64003d1595eded0bfc6c96eadc50885ee4099d106bf72b7761bea648208c64f4"},
        {"d7bdf06b886e842a22d792aef0e2df2e174fdb347335a931c410ba32b372d11f",
         "d8c6c19dd7f516139e2c83c888c8c5068577c591dad530690554499e47560796",
         "d25e49cf66dd4767d32bd1ef49bb130c3691da12e21c0b3320d7e651262d3d07"},
        {"0ac97e6efd17c9a561c6884a795320b2d53c91f5b1805bd75e8d8c8941bd5b29",
         "312e448a655148cee6b435b0620ec878f895c42b25c426a23128ada3d1c4f7ee",
         "f5080040bcc144c86f989e10c75daea5cc6b84c94a9b833252d659e3fe9a15df"},
        {"af58bcddaa041d361042e0da97edb40cd1847f6dbff803489d655721240976d1",
         "5ce7216aec8282ce12441071d117f7fd88097ee3b5c625941c96352f2e0d8ee3",
         "253f02ba66f92c1fa5b89dfd181bc2de9ba142dc6bfc32ad231ed78a0a29b709"},
        {"b98078ca48d2967179c3aea2be76b25c4ea7bdeda8d1e09e6b05ff25e0a1c793",
         "b201d4d36831df33b218353dbb8202b67617b65a41189277b07f81df5af81772",
         "4f165421ca1540590e1f9dce5995735eebee441d6e877019618a9a9465a4bdea"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], y[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(y, TEST_VECTOR[i][1]);
        uint256_from_hex(need_z, TEST_VECTOR[i][2]);
        uint256_mont_mul(&SM2_FP_MONT_CTX, z, x, y);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_sqr()
{
    static const char* TEST_VECTOR[][2] = {
        {"e75de16bfae097b676903915cdfd21649e6c17208b73ab7cb4dfa7b832c29773",
         "f3185045fe984b546ddce6a737af89f000a8b62df6a793cc2f77e00440c68707"},
        {"638aee8dbe931f0b78bdc9dd8e71bf0af3bcebaa859bbe87f086228ac47f297c",
         "e72c22106ae7e5c956aa0fe734c6136296b53f7dcc27329dea9a19e661ec6e2a"},
        {"9f455164dd4293ea04dc1f9592d135c9d904a3a4adf42438d71b466779ebbbf4",
         "3f43264885d283dbc98bb0b1ec44d93ae8a3fdb705ed0245bdddb4402b156633"},
        {"9a6cde199ed3395ed7280381b9d89d5acb87ef82af387342128dd98a7bff8d0c",
         "89f17a00c81c1ae16e078c54ceba3dfd6d45623d8f56d3bcb15798586b5a6c70"},
        {"5a7a2e2f06957670da2eee17c48174b0ac4f02d608b8a988f7d593df66e0ebea",
         "d451c8ab066bab08a95dea742d3798ef33dde26a2a0f652d1052ae7838b15fe9"},
        {"138fde36f0047ecafd1da16c9dd6589a071ecbf5c8529615b5f63e55a1f1b6b8",
         "0670aa8799d8c7e5d1c5bbff870ab7ed1b6ba84718e979d6b986b32673e23594"},
        {"2a95fcb1da858de56c3a11fb59d7cd8ebe0b6b8a16db308b1c357de3eb8a2eff",
         "589b1204e1c8ec4fee802312d1c607f99cda53c39a4bd5c5c28259446d0c381c"},
        {"846a8553a4c7bb9a505177a44f9495297dfe571c53e269c147c7e12a5f34de4a",
         "0c82b115cdc8eb4584cc29f6c34b7fef86363666586fa9f55538c54116ef36c5"},
        {"60ce4e845a2d9cbde43361643b89bb460c3060d48f496fb25794de8f0fb3e5e6",
         "ae9c4cedc2844ccf2b2a523662acbca44449862cb269805ffed8acafe015eb44"},
        {"3c76b14073cb55a5672129a4da7e7641827df74fc2a11562428ce58a98e26db0",
         "3774c66d6e0f1a6e9f23c6ab303680c771ea410ff87812ac87f2c5bf67a95cd8"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(need_z, TEST_VECTOR[i][1]);
        uint256_mont_sqr(&SM2_FP_MONT_CTX, z, x);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_inv()
{
    static const char* TEST_VECTOR[][2] = {
        {"1949a5e93b1853ce719ce3af6e34840b6a88bfbcd1ccaf928cbc442746fdfb72",
         "18d14abd50c6bf2df53f98af48c6f04e810b704752591fc2e5cd978dafe63834"},
        {"4a57cb17a527ea63718a67f844f56f7ab10f1c5285306821893297c2a5930aca",
         "8848b03b8a062723812c0bbdfd2e81dc7b58a2a8b50211dd40476e4f694412fb"},
        {"0eccb92cfbbeb509f7c9c20f1f0c5bfdc473644f7f8cd1f7207d621dc97d6f9a",
         "63e465b341ac34267383cc1c1b0cbed1112979db3ee750cbfaa8838de7c11417"},
        {"dda51998e88acac6f35d108a70ac260b2027f97e0a6874d4ec8faf5dff6d1565",
         "a4461844616bce43543fb31cbe526a8b5ee270d8e7b3cdf37cad42cf9e7ad765"},
        {"0af5e40943fa44363a5364abba9bd44f05769e58f082fd6179ccb8428b9a6e02",
         "26a099c35ae27befa8207ecaaacde460be47f3486c9fed208c9937816a55b421"},
        {"e1fa1780c07a4e30c1faf7ba6f3d744e80724ebf3738864e267cb0402a3303be",
         "481b640ad2e5d7984b5c30653a4d44219092fc09543ea7b15a97c4d846ce46e4"},
        {"d2044d791ed11b7bc847b2ebfcefacaa89fbde70e83a110c9726a9910a8021f7",
         "e6fca9f41abf45b0aca258c7ed8cf3b6d707f71262ec78bfbc682a2500ab437f"},
        {"642c1c63fec17cad783a445b31694da78086be367f212dba1c8f8d2af5effb79",
         "4b27013b2db72f9e5a802b426f7aac1484bfd6d1a112d8f56d7214f0e1937826"},
        {"a9f3a07b0b5ea524503fbb8c88b003c501abe64c5453e6ce73a2134d5d8d4719",
         "4b3437e68f6c4aa5a2e7d01a65a09c47f6aed1d30a55fbadb1856c56918521b7"},
        {"00dc67f4dac95abfb4fab68d5d6aebe68d1c1ac76c5b2eda1bae9457f0eec5c3",
         "bf3d35104f70ece8017e11119b180e27cacaaf7109355a01efe6a391657e6e16"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(need_z, TEST_VECTOR[i][1]);
        uint256_mont_inv(&SM2_FP_MONT_CTX, z, x);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

// ****************************************
// *************** Compare ****************
// ****************************************

static bool test_uint256_mont_equal_one()
{
    return uint256_mont_equal_one(&SM2_FP_MONT_CTX, SM2_FP_MONT_CTX.R);
}

// ****************************************
// ************* Set & Move ***************
// ****************************************

static bool test_uint256_mont_set_one()
{
    uint32_t x[8] = {0};
    uint256_mont_set_one(&SM2_FP_MONT_CTX, x);
    return uint256_equal(SM2_FP_MONT_CTX.R, x);
}

// ****************************************
// *************** Convert ****************
// ****************************************

static bool test_uint256_mont_from_bytes()
{
    static const char* TEST_VECTOR[][2] = {
        {"5e039e4761ecc5f9bb7b2bd06913b4239cbc01257e40966f8b857ca26619f835",
         "339e331f5cac656757afc4c8d1f186d1a2d06960f0f8995e4af1bcae6c86e0b4"},
        {"1c6bb2d6c575d3a4c33b98ad5aa2694dd4edcecff3362cf9be15f2cfdc6823a1",
         "7e8cd5feb6cf554bb4befef9834b4eeb74511394dcd07d3d67dafd8c077eb9da"},
        {"12111e70725418939b83cf6fca1b5cbfe5a743d278205a0f2b35013869b467db",
         "d8caebcc6a0c7ad6aa1a7ef3878d7cffd4e3de505d3eaee9f7663951fc9e709c"},
        {"9c9650233be89d03c867158010810acdeea56d9607ccd8206d30cb8ef940223f",
         "5c479e93c7245abe45492aeb5a80760861b3b2cb953f5faded890be2af3043a2"},
        {"37b3e8e1df7a55971e916bdb999bbfd504c8f51f9481fc2976506c4887868dde",
         "6d8ca8a51bf7339901f58f6025262c097a3c5903041d4466f62506349c3cffee"},
        {"e79564e25f516d1335c0972a9b553f634b67e7f7d0398119010f3dc96d9f3a35",
         "a1de96fb924eb9ef34764f1c785d536106c461dcfc3f83c37b9421551ef3f2b5"},
        {"36bea51f21c070c88a403955cd74d134981e2c4a312f79df05d9d7c02586ca17",
         "8bd52e03f09d42324aad6e3bd7ce68faf8195029289eb40ad7dab44387a1b7b0"},
        {"1452156d3c74f58ffbc1a80d48eb05415deb2737aadeb403e418d92932e30d51",
         "5eff47baaeb232350bb97c7bb6018705220394e1b0cd7be8d31d77ae01c22d0c"},
        {"4b3effea6fd006ccc0e488f2775bf22b92eab764cab3cee55c9716e2e1548dc9",
         "cd682e8b4df9be1c91e65e79bfb69f8528734ff5915fcb95689425ba0acd3c75"},
        {"abdf607f1813dc5d67ca50a74612dc96f9a6d288ce2c1a11deeff7b02cbbda08",
         "62fef309bd9a0f66a5c9081568d43e28fffd675474760142dc868b43710cb5f3"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], z[8], need_z[8];
    uint8_t  bytes[32];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_to_bytes(bytes, x);
        uint256_from_hex(need_z, TEST_VECTOR[i][1]);
        uint256_mont_from_bytes(&SM2_FP_MONT_CTX, z, bytes);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_to_bytes()
{
    static const char* TEST_VECTOR[][2] = {
        {"f650e660f17eb0ef09a0bd5514794a3584c073344bdd5ff2c2bdb978d40bf6f5",
         "0dc9a3ece1e7beee6d78394a147b4b7f01cd4e139ead7d42c0eca3a2a3d60433"},
        {"dda566f943a526a4939d5dad385a8fcb03d4d8064ec27fbf4bbda43376c45bf9",
         "5ba1e5e5c158e7cd89e9d4820b3f251a26aa58f09116d591c4dde0ada11ce344"},
        {"5bb17fdf449f6b25f6fc1b8f3fb5b931961172645d48f1f6e4d5fafae22d044c",
         "2f6f557916cb61130a05d7d34a152619fe64b499774c37b68e94a3a4f351317e"},
        {"cb8e74266fc4535d3696ae3290ab9eb92a4b6540fd014a1df56ffec0e38814fb",
         "fe81fe39b0d4052ce2ea9ab8e98460f0c06e4ff4a5d411d864129a7b0b2d7b81"},
        {"25a2e0abf51d839fcc327c9bdd4c7bd86bf13f46530a2a509855aa72239a8380",
         "7ca712f8536589a5662d986585614a332510e7011951349fce4b72fc251740a8"},
        {"f4c1d3ee0f1ab0ae251daf3592ff2d20839ec7683705db229195e025501efb3e",
         "7f233a78536fed41907b5d6a257f9e373c8788f342ebef98b7011c832e0dbdaf"},
        {"cda02863e0a47d66f9845129d2ad3253864454442a6a23889ec94fe1deb8050c",
         "e899dfffeebb09525f62de5c064e4357094f9412da32a97aa6ec1dfae08bd6ce"},
        {"39c0f7424643e7f1a37eeed33300924bb4667e6c7a4f221a170e9271e800b372",
         "f821e51ce8ef7acd439216c8599e5eb26532880586b99302cbcf42188d600a37"},
        {"6e1844ff4885d373e865cb682e9e292696d884201cbc5e9970238a873f9dfbc7",
         "670ed42034ede572b76cca54c76b7517ac8919e02ded735fdedb4ab4180da6eb"},
        {"df95d65e29a8e1c50bf8e1037d9670e204053e793449f241a6bc804bc16714f7",
         "51464d30bb92e294f2c953d2cce874361ccfb1febb101039f578967e27e140d9"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8];
    uint8_t  bytes[32], need_bytes[32];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_mont_to_bytes(&SM2_FP_MONT_CTX, bytes, x);
        uint256_from_hex(x, TEST_VECTOR[i][1]);
        uint256_to_bytes(need_bytes, x);
        if (memcmp(bytes, need_bytes, 32) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mont_from_bytes_ex()
{
    // clang-format off
    static int num = 4;
    static uint8_t a_0[] ={0xdf, 0xe1, 0xd6, 0x12, 0x05, 0xc1, 0xc9, 0x23, 0x5d, 0x8f, 0xc7, 0xd1, 0x63, 0xe2, 0xd6, 0x5b, 0xcf, 0xfd, 0xbc, 0x31, 0x72, };
    static size_t a_size_0 = 21 ;
    static uint8_t c_0[32] ={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdf, 0xe1, 0xd6, 0x12, 0x05, 0xc1, 0xc9, 0x23, 0x5d, 0x8f, 0xc7, 0xd1, 0x63, 0xe2, 0xd6, 0x5b, 0xcf, 0xfd, 0xbc, 0x31, 0x72, };
    static uint8_t a_1[] ={0x02, 0x87, 0xeb, 0x0a, 0xab, 0x98, 0x67, 0x91, 0x43, 0xbd, 0x52, 0x4d, 0x05, 0x55, 0x75, 0xaa, 0x72, 0x76, 0x13, 0x4e, 0x13, };
    static size_t a_size_1 = 21 ;
    static uint8_t c_1[32] ={0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x87, 0xeb, 0x0a, 0xab, 0x98, 0x67, 0x91, 0x43, 0xbd, 0x52, 0x4d, 0x05, 0x55, 0x75, 0xaa, 0x72, 0x76, 0x13, 0x4e, 0x13, };
    static uint8_t a_2[] ={0x66, 0xc2, 0x0c, 0x02, 0xb1, 0xc9, 0xd0, 0x07, 0xb5, 0x39, 0x99, 0xea, 0x07, 0x53, 0x4a, 0xa1, 0xa6, 0xf9, 0x94, 0xf9, 0xb2, 0xa6, 0x68, 0xb0, 0xcc, 0xb7, 0x0f, 0x10, 0x2d, 0x6b, 0x72, 0x25, 0x34, 0xef, 0x1d, 0x93, 0x24, 0xcf, 0xcb, 0x62, 0xa0, 0x9f, 0x0d, 0xfa, 0xb4, 0xc2, 0x61, 0xf7, 0x9b, 0xd3, 0xe9, 0xa1, 0x32, 0xd0, 0x90, 0x46, 0x5d, 0xa8, };
    static size_t a_size_2 = 58 ;
    static uint8_t c_2[32] ={0xa9, 0x5b, 0xf6, 0xa0, 0x0c, 0x0f, 0xa3, 0x04, 0x74, 0x37, 0xe4, 0x55, 0x3c, 0x67, 0x87, 0xcc, 0xf8, 0xa3, 0x08, 0x5b, 0x58, 0x4a, 0x03, 0xeb, 0x3f, 0x31, 0xc8, 0x4b, 0x5a, 0x8a, 0x71, 0xa3, };
    static uint8_t a_3[] ={0x01, 0x65, 0x37, 0x9d, 0x22, 0x50, 0xb5, 0xd0, 0xf2, 0xb1, 0x48, 0x51, 0x7f, 0xb9, 0xb8, 0x65, 0xcc, 0xf7, 0x1c, 0x65, 0x3c, 0xaa, 0x35, 0x1d, 0xc8, 0x17, 0xc4, 0x80, 0x00, 0x35, 0x21, 0xa1, 0x4a, 0x4c, 0x6d, 0x74, 0x87, 0x41, };
    static size_t a_size_3 = 38 ;
    static uint8_t c_3[32] ={0xed, 0x6e, 0x16, 0x66, 0x48, 0x51, 0x7f, 0xb9, 0xb8, 0x65, 0xcc, 0xf7, 0x1c, 0x65, 0x3e, 0x0f, 0x6c, 0xba, 0xea, 0x67, 0x8c, 0xe2, 0xdc, 0x80, 0x21, 0xa1, 0x4b, 0xb1, 0xa5, 0x11, 0xaa, 0xf6, };
    static const uint8_t* a[4] = { a_0,a_1,a_2,a_3 };
    static const size_t a_size[4] = { a_size_0,a_size_1,a_size_2,a_size_3 };
    static const uint8_t* c[4] = { c_0,c_1,c_2,c_3 };
    // clang-format on
    uint32_t x[8], y[8];
    for (int i = 0; i < num; i++)
    {
        uint256_mont_from_bytes_ex(&SM2_FP_MONT_CTX, x, a[i], a_size[i]);
        uint256_mont_from_bytes_ex(&SM2_FP_MONT_CTX, y, c[i], 32);
        if (!uint256_mont_equal(&SM2_FP_MONT_CTX, x, y))
        {
            printf("%d\n", i);
            uint8_t buf[32];
            char    hex[65] = {0};
            uint256_mont_to_bytes(&SM2_FP_MONT_CTX, buf, x);
            bytes_to_hex(hex, buf);
            puts(hex);
            uint256_mont_to_bytes(&SM2_FP_MONT_CTX, buf, y);
            bytes_to_hex(hex, buf);
            puts(hex);
            return false;
        }
    }
    return true;
}

#define TEST(func)                                                     \
    if (!test_##func())                                                \
    {                                                                  \
        fprintf(stderr, "err in test %s, line %d\n", #func, __LINE__); \
        exit(-1);                                                      \
    }

int main()
{
    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    // **************************************************
    // ************** UINT256 Montgeomery ***************
    // **************************************************
    // ++++++++++++++++++++++++++++++++++++++++++++++++++
    // ****************************************
    // ************ Arithmetic ****************
    // ****************************************
    TEST(uint256_mont_add);
    TEST(uint256_mont_sub);
    TEST(uint256_mont_dbl);
    TEST(uint256_mont_tpl);
    TEST(uint256_mont_neg);
    TEST(uint256_mont_mul);
    TEST(uint256_mont_sqr);
    TEST(uint256_mont_inv);
    // ****************************************
    // *************** Compare ****************
    // ****************************************
    TEST(uint256_mont_equal_one);
    // ****************************************
    // ************* Set & Move ***************
    // ****************************************
    TEST(uint256_mont_set_one);
    // ****************************************
    // *************** Convert ****************
    // ****************************************
    TEST(uint256_mont_from_bytes);
    TEST(uint256_mont_to_bytes);
    TEST(uint256_mont_from_bytes_ex);
    puts("uint256 mont test ok!");
    return 0;
}
#endif