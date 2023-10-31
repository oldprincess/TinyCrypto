#ifdef TINY_CRYPTO_TEST

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

// ****************************************
// ************ Arithmetic ****************
// ****************************************

static bool test_uint256_add_carry()
{
    // a, b, (a + b) / 2^256, (a + b) mod 2^256
    static const char* TEST_VECTOR[][4] = {
        {"b362d7b751b1acc93054ead48fc9a7f6d47462b5259773af9e6bca99c66e8a6d",
         "e966bf9e1730b1b855b4895ec5e4efbfdf6da5c34b7f5df137a14fcb9fc68a5a",
         "1",
         "9cc9975568e25e818609743355ae97b6b3e208787116d1a0d60d1a65663514c7"},
        {"bb2d9e96e69bc46bb2e3123975567fbec8f1e64ed85ac7d5f067d7d22b91c34a",
         "f3d121b265670c9e513356938ba0e8331bca3fb89d457c87e0b052370b3f5f07",
         "1",
         "aefec0494c02d10a041668cd00f767f1e4bc260775a0445dd1182a0936d12251"},
        {"c8a4152fdf719ee33e07c926e8fbb35c8ede1cd1c3e7b4bf400a8b31734a069c",
         "e2a0db63f97d2829168528fa512540978b67baea3945b5000c763b34b350e583",
         "1",
         "ab44f093d8eec70c548cf2213a20f3f41a45d7bbfd2d69bf4c80c666269aec1f"},
        {"bc28aece5d4a0cfde61c4ffb8e5e0ddeeb0db371eb2303a4f5e796d81ad6ca82",
         "c6f7cecbb971ee272a70363ba4a80840eb775fa7c7427f43a22a3dfc4e9924b0",
         "1",
         "83207d9a16bbfb25108c86373306161fd6851319b26582e89811d4d4696fef32"},
        {"69fbdf93f1c01c5abb8602d8daec9e67f9ccb74524aae223ea60b899f693d1e0",
         "276fe4b9de4a4caa3eadd44552e80b5c740bbb4366b50e28220cb872525f52ff",
         "0",
         "916bc44dd00a6904fa33d71e2dd4a9c46dd872888b5ff04c0c6d710c48f324df"},
        {"052dbe3d1eef2470bf8df146d7344b08178b54dcbba0ca595f279c1146b8280e",
         "8df743bed36be0676e9a5679825e60eaa1515a0c7a37490df70936a9b04a7096",
         "0",
         "932501fbf25b04d82e2847c05992abf2b8dcaee935d813675630d2baf70298a4"},
        {"e4d77e1cd0e94ab5d1e0757f63d9092fde0ada26294c58374f26f8df93626f37",
         "de76c68f5b905475ec98c523f3bac84faaa48a256b3e2a119195f6b86d28f833",
         "1",
         "c34e44ac2c799f2bbe793aa35793d17f88af644b948a8248e0bcef98008b676a"},
        {"dc3d80f172af42edd81be6fea583c37531955a9b28bd497f4975cb3006b91f88",
         "19ae36e68163b7247115b3dfa5e9734a3bc843d97a04327c2b38dc84cf75bc75",
         "0",
         "f5ebb7d7f412fa1249319ade4b6d36bf6d5d9e74a2c17bfb74aea7b4d62edbfd"},
        {"42321cbea06d675dfe4b2a63503ae374582c123d6e5aa6d78f3ecb0fadf3e08b",
         "c54c50c2407b080d842f20fb87c1b2432481e6047fcd8f1b84ab5dd9eee0933d",
         "1",
         "077e6d80e0e86f6b827a4b5ed7fc95b77cadf841ee2835f313ea28e99cd473c8"},
        {"ee7ed8445b54b836f1bf22e575f3b86c889daf712663ad75a07c55dfc920b3ab",
         "5d1320db47c9fe8a6274c4c0e6412ddd67d9b6733a2e573ab5f8b9bab5b70b70",
         "1",
         "4b91f91fa31eb6c15433e7a65c34e649f07765e4609204b056750f9a7ed7bf1b"},
    };

    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    int      carry, need_carry;
    uint32_t x[8], y[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(y, TEST_VECTOR[i][1]);
        need_carry = atoi(TEST_VECTOR[i][2]);
        uint256_from_hex(need_z, TEST_VECTOR[i][3]);
        carry = uint256_add_carry(z, x, y);
        if (carry != need_carry || uint256_cmp(z, need_z) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_add_carry_uint32()
{
    static const char* TEST_VECTOR[][4] = {
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe78b4e38",
         "7aec9ccc", "1",
         "000000000000000000000000000000000000000000000000000000006277eb04"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff4faa877e",
         "5d4e3368", "0",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffacf8bae6"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff654edeb0",
         "ea3196cf", "1",
         "000000000000000000000000000000000000000000000000000000004f80757f"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffb116faba",
         "f3e3dbb3", "1",
         "00000000000000000000000000000000000000000000000000000000a4fad66d"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff311d90e7",
         "2dcc38a6", "0",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff5ee9c98d"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff62373824",
         "7dd5562d", "0",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00c8e51"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff76b1e9d0",
         "a4228d0e", "1",
         "000000000000000000000000000000000000000000000000000000001ad476de"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff5bb8f49d",
         "d0119def", "1",
         "000000000000000000000000000000000000000000000000000000002bca928c"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff8c2b87c1",
         "dee52a96", "1",
         "000000000000000000000000000000000000000000000000000000006b10b257"},
        {"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff46e5f6f1",
         "999650c9", "0",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffe07c47ba"},
    };

    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    int      carry, need_carry;
    uint32_t x[8], y, z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        y          = hex_to_u32(TEST_VECTOR[i][1]);
        need_carry = atoi(TEST_VECTOR[i][2]);
        uint256_from_hex(need_z, TEST_VECTOR[i][3]);
        carry = uint256_add_carry_uint32(z, x, y);
        if (carry != need_carry || uint256_cmp(z, need_z) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_dbl_carry()
{
    // a, (a + a) / 2^256, (a + a) mod 2^256
    static const char* TEST_VECTOR[][3] = {
        {"b7936d9567a03f8f3dd09bdc7b9ffaf44169f7487aef6bfcbfb4e500891ce5c7",
         "1",
         "6f26db2acf407f1e7ba137b8f73ff5e882d3ee90f5ded7f97f69ca011239cb8e"},
        {"d7c1a0ba1e647f5a66ed89e95c90d1366e081851bc64a67b3f4110591b847a15",
         "1",
         "af8341743cc8feb4cddb13d2b921a26cdc1030a378c94cf67e8220b23708f42a"},
        {"64e8bf97d91c37865528888dd6dd0bfa27efefb316fc5bd454cd887052c8d7e2",
         "0",
         "c9d17f2fb2386f0caa51111badba17f44fdfdf662df8b7a8a99b10e0a591afc4"},
        {"8dddd67c30882703831ca8a9fdfe66142c2fef920606ff7e6fd5337f94985408",
         "1",
         "1bbbacf861104e0706395153fbfccc28585fdf240c0dfefcdfaa66ff2930a810"},
        {"5b8c76a7a5b6d8f3f955bb10c282b7e0673e4f6a0996dfa004d71d99d35605b7",
         "0",
         "b718ed4f4b6db1e7f2ab762185056fc0ce7c9ed4132dbf4009ae3b33a6ac0b6e"},
        {"5080ca7258b7093fcf6bc952a69b9388feaa0351932fba4eaff83d00aca36a83",
         "0",
         "a10194e4b16e127f9ed792a54d372711fd5406a3265f749d5ff07a015946d506"},
        {"6d8e413acbf61dc359f1536068296333263b2ed967f5b4fc5e7bee0c7ac60d39",
         "0",
         "db1c827597ec3b86b3e2a6c0d052c6664c765db2cfeb69f8bcf7dc18f58c1a72"},
        {"c7504aec308364a15b99c4a7239946da4185373edc4948692d519dc73a901d16",
         "1",
         "8ea095d86106c942b733894e47328db4830a6e7db89290d25aa33b8e75203a2c"},
        {"b01c98c40c0961a38509c687f9a979f47a84edb041dafb763996c1b14e7fc78d",
         "1",
         "603931881812c3470a138d0ff352f3e8f509db6083b5f6ec732d83629cff8f1a"},
        {"fd281a5c2552056be17e4c9de096a445d8c96da4099f26f447288368c14d26eb",
         "1",
         "fa5034b84aa40ad7c2fc993bc12d488bb192db48133e4de88e5106d1829a4dd6"},
    };

    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    int      carry, need_carry;
    uint32_t x[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        need_carry = atoi(TEST_VECTOR[i][1]);
        uint256_from_hex(need_z, TEST_VECTOR[i][2]);
        carry = uint256_dbl_carry(z, x);
        if (carry != need_carry || uint256_cmp(z, need_z) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_tpl_carry()
{
    // a, (a + a + a) / 2^256, (a + a + a) mod 2^256
    static const char* TEST_VECTOR[][3] = {
        {"0f2e67e47974782ee8db77f20ecba9744f5d83a1d129d51a3746a75220c49485",
         "0",
         "2d8b37ad6c5d688cba9267d62c62fc5cee188ae5737d7f4ea5d3f5f6624dbd8f"},
        {"78cb4fb079c39ee3a08622ce6f3ee04172e43d831aece0eab227047c9b2a08aa",
         "1",
         "6a61ef116d4adcaae192686b4dbca0c458acb88950c6a2c016750d75d17e19fe"},
        {"8ca160ccc11ed045b37605062224166cb64087f440db2fc18d568a38e8e74c82",
         "1",
         "a5e42266435c70d11a620f12666c434622c197dcc2918f44a8039eaabab5e586"},
        {"f7b2870f7fa5cb4d0a0ecc6128645c88490b75abfc15007f519edaa7ed282241",
         "2",
         "e717952e7ef161e71e2c6523792d1598db226103f43f017df4dc8ff7c77866c3"},
        {"244384a487ba73b7d90829ae45bf6fcc5b2b46b486f1585c02c5f2fe398b1c47",
         "0",
         "6cca8ded972f5b278b187d0ad13e4f651181d41d94d409140851d8faaca154d5"},
        {"0a190caec0e4847a181ee078d1fa911b8b953f379bd77f945ed04baedcbeeff5",
         "0",
         "1e4b260c42ad8d6e485ca16a75efb352a2bfbda6d3867ebd1c70e30c963ccfdf"},
        {"c212f0e9958f1de7a1ee3fc805c528c0293689222978c202567f5f8450bfd7da",
         "2",
         "4638d2bcc0ad59b6e5cabf58114f7a407ba39b667c6a4607037e1e8cf23f878e"},
        {"40651dce716574f8aff212fe3fe1b6548438fa1921f10e51b9e02ab802f350df",
         "0",
         "c12f596b54305eea0fd638fabfa522fd8caaee4b65d32af52da0802808d9f29d"},
        {"47953d34451c18e4f134b52e7561ebf66256adf06c31abfebbc1a3e65ccde3b5",
         "0",
         "d6bfb79ccf544aaed39e1f8b6025c3e3270409d1449503fc3344ebb31669ab1f"},
        {"d258e19552f9e8b63654a421d20420724f92b0d8c1bcb72220b93a072259bdbf",
         "2",
         "770aa4bff8edba22a2fdec65760c6156eeb8128a45362566622bae15670d393d"},
    };

    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    int      carry, need_carry;
    uint32_t x[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        need_carry = atoi(TEST_VECTOR[i][1]);
        uint256_from_hex(need_z, TEST_VECTOR[i][2]);
        carry = uint256_tpl_carry(z, x);
        if (carry != need_carry || uint256_cmp(z, need_z) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_sub_borrow()
{
    // a, b, (a - b) / 2^256, (a - b) mod 2^256
    static const char* TEST_VECTOR[][4] = {
        {"4ea447984a71fb733fd0c03ce5708694422736eb674b6577ea086a3fa96da939",
         "88380dc10cd8e8481de23a49b48f72326cdea7ffeab7e335bb5949f2cc60fa53",
         "-1",
         "c66c39d73d99132b21ee85f330e11461d5488eeb7c9382422eaf204cdd0caee6"},
        {"d5018f5360b10e90881d6eff8b1d87b34bbe36c77625011fa16f2724412794fb",
         "693e69f9ba5b25415341ec3b61357b4646b380c1bbc7531648a186e6a5e6ee81",
         "0",
         "6bc32559a655e94f34db82c429e80c6d050ab605ba5dae0958cda03d9b40a67a"},
        {"b66f6c35f6f2310fecffcf4e9f04a687c6123fe5c6a4fb3936540bbb79eaf1ea",
         "3cfb29697cf4bf966f9b8d90401b0b4c86bf567204c2c241280cbee3dc1353f0",
         "0",
         "797442cc79fd71797d6441be5ee99b3b3f52e973c1e238f80e474cd79dd79dfa"},
        {"92c29352adc1087b2781a14a5ba9567824e82709e0c515127791387fbbcea562",
         "e777aad96fb3afeb46471fdc311d54a8b5e368990d42f8741373dd81dd3c6308",
         "-1",
         "ab4ae8793e0d588fe13a816e2a8c01cf6f04be70d3821c9e641d5afdde92425a"},
        {"0585d87c6273c34148678f1d6aacaea26ba98d14e156a32d837db31a3b6734bc",
         "62fce90ae17279dcdfa34369df8b940030abc9b32038fad0b0e95c4f097d556c",
         "-1",
         "a288ef718101496468c44bb38b211aa23afdc361c11da85cd29456cb31e9df50"},
        {"f7be3aab99586b9efeb91c49eb073fe2ad24dd3d721c8b069cb1f49469dea167",
         "3a4d4229c740301e5d027db5466c5e7f19eb8a527a6fd7f10e4d72e2d0f1c6e2",
         "0",
         "bd70f881d2183b80a1b69e94a49ae163933952eaf7acb3158e6481b198ecda85"},
        {"165b871079b1c089a387631d2c43af3d40e2bee998d686ed315c342de4bb2273",
         "af989e29df2de9e6765d575314f46b53bb5e287f3d7db703d08c9db97f6fbe2c",
         "-1",
         "66c2e8e69a83d6a32d2a0bca174f43e98584966a5b58cfe960cf9674654b6447"},
        {"1b6165fb7b5a32e08dacffe8e465b83be97709f9deac1ec3ce10b5c226bebc25",
         "52d25fbdecdc4b9c3695bedaab08bdce31eeeaaa071253440066bbaf79445cbf",
         "-1",
         "c88f063d8e7de7445717410e395cfa6db7881f4fd799cb7fcda9fa12ad7a5f66"},
        {"4f062715a33d2083bc46904d8b9dd4169e40819ac64f6ea76317cba83fd13fc6",
         "dfac191654654df7efcad0d4ff2d5f3bd54efa73adaa0ee92d8de8aa7798e7fc",
         "-1",
         "6f5a0dff4ed7d28bcc7bbf788c7074dac8f1872718a55fbe3589e2fdc83857ca"},
        {"b770ea6faf496f7a8a42ee250510bd0820588d38abb4a4d3c94e5dae0d9b4e9d",
         "bae5585eaa48b84dc2ecd1b839e578611c5ed7e2c056d5dd7cde3cde6b127720",
         "-1",
         "fc8b92110500b72cc7561c6ccb2b44a703f9b555eb5dcef64c7020cfa288d77d"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    int      borrow, need_borrow;
    uint32_t x[8], y[8], z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(y, TEST_VECTOR[i][1]);
        need_borrow = atoi(TEST_VECTOR[i][2]);
        uint256_from_hex(need_z, TEST_VECTOR[i][3]);
        borrow = uint256_sub_borrow(z, x, y);
        if (borrow != need_borrow || uint256_cmp(z, need_z) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_sub_borrow_uint32()
{
    static const char* TEST_VECTOR[][4] = {
        {"0000000000000000000000000000000000000000000000000000000061e7d15d",
         "df51149c", "-1",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff8296bcc1"},
        {"00000000000000000000000000000000000000000000000000000000ce18acc0",
         "2e1bf966", "0",
         "000000000000000000000000000000000000000000000000000000009ffcb35a"},
        {"0000000000000000000000000000000000000000000000000000000030ec8a22",
         "6ed5c48b", "-1",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffc216c597"},
        {"00000000000000000000000000000000000000000000000000000000dfca39d0",
         "69a136df", "0",
         "00000000000000000000000000000000000000000000000000000000762902f1"},
        {"00000000000000000000000000000000000000000000000000000000e032d2c3",
         "97b1481b", "0",
         "0000000000000000000000000000000000000000000000000000000048818aa8"},
        {"000000000000000000000000000000000000000000000000000000007ac17d0b",
         "e225d653", "-1",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff989ba6b8"},
        {"00000000000000000000000000000000000000000000000000000000866a3670",
         "873debb6", "-1",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2c4aba"},
        {"0000000000000000000000000000000000000000000000000000000030db7684",
         "8cb913d9", "-1",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffa42262ab"},
        {"000000000000000000000000000000000000000000000000000000000a33d538",
         "e5423081", "-1",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff24f1a4b7"},
        {"000000000000000000000000000000000000000000000000000000004f2aa3bf",
         "d8758102", "-1",
         "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff76b522bd"},
    };

    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    int      borrow, need_borrow;
    uint32_t x[8], y, z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        y           = hex_to_u32(TEST_VECTOR[i][1]);
        need_borrow = atoi(TEST_VECTOR[i][2]);
        uint256_from_hex(need_z, TEST_VECTOR[i][3]);
        borrow = uint256_sub_borrow_uint32(z, x, y);
        if (borrow != need_borrow || uint256_cmp(z, need_z) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mul()
{
    static const char* TEST_VECTOR[][4] = {
        {"8cf0d14db04a577b09f87cc146d560adddc5ae316646d34d7473c9cc76b9d168",
         "0a100b1466281506649b9ad0240980dabaa8ea466db20744c8e0f276413ed2d0",
         "058a3d53b1caa14e2c3aa1ff420d30afc1435cee2a82826f453363134df02d4e",
         "a3636cc9128e7c13b195c187ec30ba12580bf6f3fc65a5083fe274a103f17480"},
        {"29e02f2e22599fef688707b4f2660c7d0c8978d455feea3b7387f65039b193a9",
         "27c6cd0dc1aecb0cf0ea01b4145280b306863bcb8552995f9a76b7795d300bb4",
         "0681ac1f4ac32ab16c4c69cb8cf849ce9953bedbc6b676132482227aa09972a3",
         "32a0a996b9e9d58d58d07cddc7f4577ec06031452ab94a4b569190b446e415d4"},
        {"1d9ddc1ffcea12750cffc1249f14ac496605383e4cf4a552607e159382163940",
         "f0af5574df8acb8b949b4a1073e8d5b2e1ae0531125bd116209f1ede90f0812d",
         "1bd8472a6674442d86683bd853d4bf359fb45cb9a8b45addc99eed57b16bff3d",
         "049097b17994206119c1c982b55ff2637b9c0ae298f5b210ab3aba04bcc15040"},
        {"c44a7aee9628695b6820b3ca3b1e5d5dacbbbb6365d4b3f7e2048973ccfa7b22",
         "83b9fe4c888b91597b5f316ea502ab50e789b4fbc4362f28d37366864d197cc9",
         "6500b9b78208fe20e14e9a99f9e7477da833c0fe117ec40530d9b6e72ed89ae3",
         "7bef17358e6d7c2b1142f770891aa3436ddad1937063e87f578c5e8084a125b2"},
        {"8bd02aeda2bd926f744cf6e52dc01dfcd1767d8fe7b4072366fb3f199b78e0e2",
         "aa409c68170da6152675209dc351b5bc880b1c021f7acea4f31d56803e9d0de0",
         "5cfb85f83ccbfa7a51f25e78dc79d0d95439252169bc6b239b582ae2b14dc467",
         "1928e60b51800077514b8c5a4c522ea6609cb99696f07a8b1bfd7fe5d3ca3fc0"},
        {"7b5abfc41b5c97186fb9914c2d142d449d107241a840e19a47e372d168746c82",
         "b456836eaf71f9b570fb55789beab61d98edbe00d58005a811a784a5c9691b12",
         "56e57ea714c800147a42f2a8348ce44c0bd1b98c2a5f97d3cae7592f52ed2103",
         "05a0ea12214835dd9d750c1c225f8897d1cee391fff1cd2a53cc617a32f35724"},
        {"e4828336d3a2a74b882c6426ea1ac3439c5152d2bdb961312f7ed54efff72329",
         "f6d8140e9f00b9f402e11d59812b48506e5985f080c1e8318980431f152e923d",
         "dc564a1ca4f2090331c8457f69ece020740ddfbb2832f3f82ca39cee36af169a",
         "bfc31c77389ee2ee02acdb05d9b63828c247b7154714c7e2a8b2230f9e4ec2c5"},
        {"1ff242aa79d99d5b622ae37e7a3019189a49a871f687108dff5d68036041e556",
         "849c88705ce3aa999455fafc0679685de68e4245ebb6d7d2d65ff34777e1a48e",
         "108c73073fb5aa2058a16a2f01fe5e367ef5bcf8c95f7978bb1d16f421f00ca2",
         "5f903a588722acd4d641d16b22f5b0809831311a073038d1b70953e9260e4db4"},
        {"44272b08fb886b995592d97c377b33f4877992db50f8d035b314c9b295019897",
         "3cb653c8f624d1c0cdf4d1cd69a796e54b8c6989644b65edc11e9c0847c0f9df",
         "1029b83ce66bc57a29d7a53a921dfe6972528df68bf9111fc1940c3a54eab43c",
         "c2cb293e45b485e36e3b7a999b8c5f983001ec7564f04ee45e4860baac0eca89"},
        {"4702f274c3735b2b9d6e91b901d4ca42f09b59274ec848e601f85f2d59045ca5",
         "4e8bf06c7c31deaf9c468ad3d946cc0b1da2d511f893cee03cc9aa44bfc20114",
         "15c9b72a13f248aea06d2b0a97393da3fa8acdf3b5f7306252c14808fd7dc789",
         "11fc950aa44d6f236ce0d3efe7f0d69864b0a9ca0b768ae109c9812548bde1e4"},
    };

    int       size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t  x[8], y[8], z[16], need_z[16];
    uint32_t *zh = z + 8, *zl = z, *need_zh = need_z + 8, *need_zl = need_z;
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(y, TEST_VECTOR[i][1]);
        uint256_from_hex(need_zh, TEST_VECTOR[i][2]);
        uint256_from_hex(need_zl, TEST_VECTOR[i][3]);
        uint256_mul(z, x, y);
        if (uint256_cmp(zh, need_zh) != 0 || uint256_cmp(zl, need_zl) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_mul_carry_uint32()
{
    static const char* TEST_VECTOR[][4] = {
        {"0352064557f083a7f8f8e5c05d70aca4d4e6dbd2bac67382185065631a13b036",
         "db8a1e45", "02d8f5f9",
         "3573f9468dca4e2aafa43a3a76961be0355c657a27f442fc6847d71f8510d28e"},
        {"8e552c91bd11d9ad9df96295565e048fcc7359b7485ee08daf864bceb5715486",
         "0574aa1d", "0308870b",
         "b9f9d9674c54678017124ef617d4e713fe1b8532b87eaef173c348e8baaf8f2e"},
        {"9c928e52a914e2aa66bf1a7ad1b992a984411bee82391901df61b7645767c7d8",
         "0aacad46", "06875600",
         "b46531c04b63a175d3dc65b8e9ea0f903f038a8f117f0149407bbc09bd8d9d10"},
        {"13f0ef7515fda272a78b9cd963cbafea3a439f6b0c64bcc0a554ce10a8a029b6",
         "5653ccd4", "06b97783",
         "7ab0f04a82f31d6ae29ce7afad5fefe0c8e82e9873d5eb00e67c661befe192b8"},
        {"ed6427a13dbbeab849d25b73d558a12a597eb600730bf5b98d055018879ceabc",
         "6989a05a", "61ddb38c",
         "6596d21b59aa7c02e09b12990441fe483db9bd3f86ec0110d2ad6ca27a7c0618"},
        {"da37c6a8dcf97c6689f32c4c6bc84528981435563305face93f586cd8d41782d",
         "03aff0d6", "0324a0bf",
         "7ce45b53dae445cb784fb3a49ac810f28b6b58eb211458d16ccab86b2327a59e"},
        {"57f3b37541ad8f1bc407bbaeffdda927404d68dffc49f59102a3c63c550022bd",
         "20d7a670", "0b488d48",
         "e0ac6689ef8d3737470a2ec7a4aa22fd67854065b2b5277a617d40f81350c0b0"},
        {"b33f60994fad89b3569e21c264b8f9220c406f1063e82aa548460a9b835c0427",
         "7537fa16", "521328df",
         "1e227333dd80d966f75aeaab611abd7e542e1f5803239cadf6d30e4fdd57715a"},
        {"5bea8c48198bcf419801094cbd3137cdfdbcd345f66e7c6d34eb04372530aa58",
         "d8283f0b", "4d9c59a5",
         "6c6bba1a3b83ac3bfcf45fa1c4200f0f69f705e65d14c8fe4c219fda70c2f9c8"},
        {"594dda830bc18644573fb6241c082f9bbce2e9fa1b81c1bc7152adb5d882b427",
         "6dba1f2d", "2647137a",
         "af5d383c2714656bc36d3df5d1c814bd2ba6a60f8b6f69e191e083da622063db"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], y, z[8], need_z[8], carry, need_carry;
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        y          = hex_to_u32(TEST_VECTOR[i][1]);
        need_carry = hex_to_u32(TEST_VECTOR[i][2]);
        uint256_from_hex(need_z, TEST_VECTOR[i][3]);
        carry = uint256_mul_carry_uint32(z, x, y);
        if (uint256_cmp(z, need_z) != 0 || carry != need_carry)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_sqr()
{
    // a, (a * a) / 2^256, (a * a) mod 2^256
    static const char* TEST_VECTOR[][3] = {
        {"12ea5d461aa3761398e00f2812af227abb577bcfd1e9b86337bc573af4fc9efa",
         "0165cbac81e3b1fbf54767e34be67357cce435e0c2944ebc6ecc09de548b3338",
         "95619a1bd49f38e7f4f4450ad19cfcd82dc27389c893d4cc8c287d9deee98c24"},
        {"1be1b407598dc58e23a6361e68e6c0c090b6ac83d6dea860796bafe419d91cf1",
         "030962f78069a906a2444b5d4697b3f7cfc7f5a4249e1da350a32a97208cfc12",
         "c738be45f135bf1ae2220f19b12bd58185cd8e2998c4842ee65f2b1125d79ae1"},
        {"180fb2616c808ae7e4d9dc7cbf09c23fd35af1eaeb4e1c0e53b3d4f02d01f109",
         "0242f268a80e7111eaa61e987a82487280083f3229d99775ec8b881a9db40da5",
         "a6ce56b8b875a6fc22a9e98a2120e8938e4e82adf69933de8b5a87a0ef03f251"},
        {"de41a521d8890add50d87cd5dc089fb68a3c570b2d208a56ecd6aab3d8a587dc",
         "c0f5eb3bf9424a098f18296a50b8722ba3d1a7231f009121d959169410991aac",
         "83485d6fc9765d686a0f40a9e3f9e41f5232a532c2a339214b13edf3a9b1c510"},
        {"8c17f8332f0127c837d9cc63e66c83361f59bc57a4bd72af444d4581ca521755",
         "4caa39b6853eeb06233b734915041b9ec7a1ace11f9f001fa654837433aafb3b",
         "da9c4f5cecdcbe3efb32bde491c3aff117ce62c4eaf424daf856fccf18946239"},
        {"d571822d69b13f832fcd0afe0f7328390bc274963db446185bd1916102ae63ca",
         "b1f614f3c02a6990b7cfd8cc079f4ae94f7119cb5d4eea866de6da89f2a4242d",
         "1d14413ec36d55975e0e7f7b782137786861da142232935d210da36ef57ddb64"},
        {"368dd65f8cea7815aae6d5e026cad0950b3b41f556c8d609f211c5f979155ae3",
         "0ba025062838083350524868610b029a90d8babf1bac96709f998a4218af0a15",
         "cb79eaf34005a0501c7575a157debec595f3646e4b4c4418e0d75d489f826549"},
        {"5e906d7824125bb1c42210a69827d3309fcb0a32a18dcc491d1a10dcdd2fd70c",
         "22ee61df907597172c662d54fa46ec0012a88322f9f3623deb2cfcdcc3b2544f",
         "ce272d1ea024af4f030ab38eb6c7ee3da1134cd3d751e37b4aa6bedb630d2890"},
        {"3e0e568f870ed6538ba068ffd93f85b1abc831cd0d6cca22aae654172e9bbc10",
         "0f0af2bb1a62b4a60a9932756ecdf87d6a42ab878628a788fbc0463d74217917",
         "2b241e2b9533042a7a26f3c4e4696cf21eae18c072d5028ac8a2a13305878100"},
        {"192b257fae10e4c8d49402dc67e17cd00dba84a2b66721d91898f48c181fd440",
         "027974988e61ee5b223c571c1c8d9b6f4607128c9deeb16726ca55e59abeb37f",
         "bbfd9e4769ee1e971283baac05c8233c67eb095e7aac4cbf1db021c1177a1000"},
    };
    int       size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t  x[8], z[16], need_z[16];
    uint32_t *zh = z + 8, *zl = z, *need_zh = need_z + 8, *need_zl = need_z;
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(need_zh, TEST_VECTOR[i][1]);
        uint256_from_hex(need_zl, TEST_VECTOR[i][2]);
        uint256_sqr(z, x);
        if (uint256_cmp(zh, need_zh) != 0 || uint256_cmp(zl, need_zl) != 0)
        {
            return false;
        }
    }
    return true;
}

// ****************************************
// *************** Compare ****************
// ****************************************

static bool test_uint256_cmp()
{
    static const char* TEST_VECTOR[][3] = {
        {"fdd8323798de58199946b134d5395027c26c0af315cfcdcd4683b132adb5cec5",
         "1df522c352960690a7772b3a73c51f5198fe623b2f5d8fda3a608dd3fad1d190",
         "1"},
        {"f22b0de54ea5a9ce37776589675eeaccf8af797153308a81fae891a59754021e",
         "1a69e38b5c52334e55459a7d0d538ed4605683c73ca28c42e455de34fa8fc974",
         "1"},
        {"0186353ad96294b1f8cc26d4643ef509f9bc492081192c3c091a1ee17bf88a20",
         "9c6620931af0a3c5b385c3023ce48cfd2e6e3a460cd2c9549eb508c8b7698409",
         "-1"},
        {"088454edb4604f1bd0308cebe079a605f8aaec3385c27d3a38a69a877a8b2017",
         "479f9c9b92b24c0576d68fe261fcbffdd38673fcee212150e5987b86444397cb",
         "-1"},
        {"b2be01aaa8e5f1dac3807ec02ce25265d3b385e31925bf2cd55b935f03beab0c",
         "a45fd28b9231cf6ab888ed205574a1c63cf2a715d87ef23d3f912ae208287661",
         "1"},
        {"94ed39f2aee6575655aabfda873190303b68b69c66257acab5a24f803772a004",
         "9b8a9682913c96a213e178a1ff8f1447ada2d492f6153551a541f34bee8e9828",
         "-1"},
        {"015c7eddeb5a8b04b434efafabffad5004d1169503c4a831d7307210ac5c4b81",
         "a13e04d7c6c44eea80679aedfa69f0d468ed81eabd2ec27e1dc03dbaae7cb963",
         "-1"},
        {"5ec2e8562317427ec017bc04014ec11564f27aec0dc88d4e6618a64bc8efa07b",
         "2ba926e5da3755676129836fdb0e4827df22b36eede52b8c93d07589deb19839",
         "1"},
        {"1e9c641f9788dda67e7607fd12bd39d5e5c4ee5e98e778e7be7a8e4ca6910491",
         "c1cc044424fefdcacf771f7a46f4a21daeef71dbb1e05ab881359abfe3fe65d0",
         "-1"},
        {"b0567a995047af287fe629fb5aa890778e95e061ce76fa86e22620d8e57b8729",
         "a8c1b062d77ef5521890e47286e260f52238731d44e8890894d2f453bd39cf28",
         "1"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], y[8];
    int      need_cmp, cmp;
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(y, TEST_VECTOR[i][1]);
        need_cmp = atoi(TEST_VECTOR[i][2]);
        cmp      = uint256_cmp(x, y);
        if (cmp != need_cmp)
        {
            return false;
        }
        if (uint256_cmp(x, x) != 0 || uint256_cmp(y, y) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_cmp_uint32()
{
    static const char* TEST_VECTOR[][3] = {
        {"7fee4d2b27153394a2d6f41b9bc9c4b52762f3ce71553b40aca0770b2c21df81",
         "b9842f33", "1"},
        {"69de12247783f37e6410bd7d187b209e687f0eb352ac4f39774b4894149bdfc5",
         "477f9839", "1"},
        {"5b1ad76c18f9d8976700eb4ceade7a1e41c9775012c0053e07d265f02801f409",
         "66580dad", "1"},
        {"e002e2f8ffa1d0a264865dd591fe116406e7f4dffbed5b778e1670285db4b0a8",
         "d074f65d", "1"},
        {"0000000000000000000000000000000000000000000000000000000096c3f9d3",
         "96c3f9d3", "0"},
        {"0000000000000000000000000000000000000000000000000000000053799003",
         "48ba8f90", "1"},
        {"000000000000000000000000000000000000000000000000000000007ca15920",
         "2ba3cdf7", "1"},
        {"00000000000000000000000000000000000000000000000000000000734713a6",
         "2df60af5", "1"},
        {"000000000000000000000000000000000000000000000000000000009bece119",
         "3e613a02", "1"},
        {"00000000000000000000000000000000000000000000000000000000376f13f3",
         "93cb19ba", "-1"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], y;
    int      need_cmp, cmp;
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        y        = hex_to_u32(TEST_VECTOR[i][1]);
        need_cmp = atoi(TEST_VECTOR[i][2]);
        cmp      = uint256_cmp_uint32(x, y);
        if (cmp != need_cmp)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_equal()
{
    static const char* TEST_VECTOR[][1] = {
        {"fdd8323798de58199946b134d5395027c26c0af315cfcdcd4683b132adb5cec5"},
        {"f22b0de54ea5a9ce37776589675eeaccf8af797153308a81fae891a59754021e"},
        {"0186353ad96294b1f8cc26d4643ef509f9bc492081192c3c091a1ee17bf88a20"},
        {"088454edb4604f1bd0308cebe079a605f8aaec3385c27d3a38a69a877a8b2017"},
        {"b2be01aaa8e5f1dac3807ec02ce25265d3b385e31925bf2cd55b935f03beab0c"},
        {"94ed39f2aee6575655aabfda873190303b68b69c66257acab5a24f803772a004"},
        {"015c7eddeb5a8b04b434efafabffad5004d1169503c4a831d7307210ac5c4b81"},
        {"5ec2e8562317427ec017bc04014ec11564f27aec0dc88d4e6618a64bc8efa07b"},
        {"1e9c641f9788dda67e7607fd12bd39d5e5c4ee5e98e778e7be7a8e4ca6910491"},
        {"b0567a995047af287fe629fb5aa890778e95e061ce76fa86e22620d8e57b8729"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8], y[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_from_hex(y, TEST_VECTOR[i][0]);
        if (uint256_equal(x, y) == false)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_equal_zero()
{
    uint32_t x[8] = {0};
    return uint256_equal_zero(x);
}

static bool test_uint256_equal_one()
{
    uint32_t x[8] = {1};
    return uint256_equal_one(x);
}

// ****************************************
// ************* Set & Move ***************
// ****************************************

static bool test_uint256_cpy()
{
    uint32_t x[8] = {1, 2, 3, 4, 5, 6, 7, 8}, y[8] = {0};
    uint256_cpy(x, y);
    return uint256_equal(x, y);
}

static bool test_uint256_set_uint32()
{
    uint32_t x[8] = {1, 2, 3, 4, 5, 6, 7, 8}, y[8] = {2};
    uint256_set_uint32(x, 2);
    return uint256_equal(x, y);
}

static bool test_uint256_set_zero()
{
    uint32_t x[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint256_set_zero(x);
    return uint256_equal_zero(x);
}

static bool test_uint256_set_one()
{
    uint32_t x[8] = {8, 2, 3, 4, 5, 6, 7, 8};
    uint256_set_one(x);
    return uint256_equal_one(x);
}

// ****************************************
// *************** Convert ****************
// ****************************************

static bool test_uint256_to_bytes()
{
    static const char* TEST_VECTOR[][1] = {
        {"d2ae49642ef5e36ae82d87d18c475e471f5e72ac1e15e98e672739edf029c4d7"},
        {"7d05b319e5f24600734a1d69650492bc22eeab5ab9014b4e1e9ee11b85f04a9a"},
        {"a412f6151b7785f3f71a3b47a93d2532c642a871f01c0da57fcb349f0bad2b66"},
        {"b02a14083ca994de4b24a36ec6fe434b04d6826946758d9d580e6b521294e3d8"},
        {"ddbb5cc31aeddb9504513f099deffc6e98ced411e21d49fe513099c794af4a24"},
        {"5710783d4545d56c5e2f46adeb1c8b239f6afad76ea1de2a8c13c5aa340d31c9"},
        {"867dabf1a6f48389aa2a8911de60a7764b01cab89a33e42d89e58aaa9446e8df"},
        {"a27292214d56461cb715133d2d50b9ad456ba4043c0390cdca722cf871b18b9d"},
        {"4b557569233c8e1f695059ba89d59dcecfc3164871698e9a95e59d73b6f29b34"},
        {"239529564fd53e9a917e86ed127f21a38beaea6c2a06d7c67987b0ea87dca2d0"},
    };
    static const uint8_t TEST_VECTOR_BYTES[][32] = {
        {210, 174, 73,  100, 46, 245, 227, 106, 232, 45, 135,
         209, 140, 71,  94,  71, 31,  94,  114, 172, 30, 21,
         233, 142, 103, 39,  57, 237, 240, 41,  196, 215},
        {125, 5,   179, 25,  229, 242, 70,  0,   115, 74,  29,
         105, 101, 4,   146, 188, 34,  238, 171, 90,  185, 1,
         75,  78,  30,  158, 225, 27,  133, 240, 74,  154},
        {164, 18,  246, 21,  27, 119, 133, 243, 247, 26,  59,
         71,  169, 61,  37,  50, 198, 66,  168, 113, 240, 28,
         13,  165, 127, 203, 52, 159, 11,  173, 43,  102},
        {176, 42,  20,  8,  60,  169, 148, 222, 75,  36, 163,
         110, 198, 254, 67, 75,  4,   214, 130, 105, 70, 117,
         141, 157, 88,  14, 107, 82,  18,  148, 227, 216},
        {221, 187, 92,  195, 26,  237, 219, 149, 4,  81,  63,
         9,   157, 239, 252, 110, 152, 206, 212, 17, 226, 29,
         73,  254, 81,  48,  153, 199, 148, 175, 74, 36},
        {87,  16,  120, 61,  69,  69,  213, 108, 94,  47,  70,
         173, 235, 28,  139, 35,  159, 106, 250, 215, 110, 161,
         222, 42,  140, 19,  197, 170, 52,  13,  49,  201},
        {134, 125, 171, 241, 166, 244, 131, 137, 170, 42,  137,
         17,  222, 96,  167, 118, 75,  1,   202, 184, 154, 51,
         228, 45,  137, 229, 138, 170, 148, 70,  232, 223},
        {162, 114, 146, 33,  77,  86,  70,  28,  183, 21, 19,
         61,  45,  80,  185, 173, 69,  107, 164, 4,   60, 3,
         144, 205, 202, 114, 44,  248, 113, 177, 139, 157},
        {75,  85,  117, 105, 35,  60,  142, 31,  105, 80,  89,
         186, 137, 213, 157, 206, 207, 195, 22,  72,  113, 105,
         142, 154, 149, 229, 157, 115, 182, 242, 155, 52},
        {35,  149, 41,  86,  79,  213, 62,  154, 145, 126, 134,
         237, 18,  127, 33,  163, 139, 234, 234, 108, 42,  6,
         215, 198, 121, 135, 176, 234, 135, 220, 162, 208},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8];
    uint8_t  z[32];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        uint256_to_bytes(z, x);
        if (memcmp(z, TEST_VECTOR_BYTES[i], 32) != 0)
        {
            return false;
        }
    }
    return true;
}

static bool test_uint256_from_bytes()
{
    static const char* TEST_VECTOR[][1] = {
        {"d2ae49642ef5e36ae82d87d18c475e471f5e72ac1e15e98e672739edf029c4d7"},
        {"7d05b319e5f24600734a1d69650492bc22eeab5ab9014b4e1e9ee11b85f04a9a"},
        {"a412f6151b7785f3f71a3b47a93d2532c642a871f01c0da57fcb349f0bad2b66"},
        {"b02a14083ca994de4b24a36ec6fe434b04d6826946758d9d580e6b521294e3d8"},
        {"ddbb5cc31aeddb9504513f099deffc6e98ced411e21d49fe513099c794af4a24"},
        {"5710783d4545d56c5e2f46adeb1c8b239f6afad76ea1de2a8c13c5aa340d31c9"},
        {"867dabf1a6f48389aa2a8911de60a7764b01cab89a33e42d89e58aaa9446e8df"},
        {"a27292214d56461cb715133d2d50b9ad456ba4043c0390cdca722cf871b18b9d"},
        {"4b557569233c8e1f695059ba89d59dcecfc3164871698e9a95e59d73b6f29b34"},
        {"239529564fd53e9a917e86ed127f21a38beaea6c2a06d7c67987b0ea87dca2d0"},
    };
    static const uint8_t TEST_VECTOR_BYTES[][32] = {
        {210, 174, 73,  100, 46, 245, 227, 106, 232, 45, 135,
         209, 140, 71,  94,  71, 31,  94,  114, 172, 30, 21,
         233, 142, 103, 39,  57, 237, 240, 41,  196, 215},
        {125, 5,   179, 25,  229, 242, 70,  0,   115, 74,  29,
         105, 101, 4,   146, 188, 34,  238, 171, 90,  185, 1,
         75,  78,  30,  158, 225, 27,  133, 240, 74,  154},
        {164, 18,  246, 21,  27, 119, 133, 243, 247, 26,  59,
         71,  169, 61,  37,  50, 198, 66,  168, 113, 240, 28,
         13,  165, 127, 203, 52, 159, 11,  173, 43,  102},
        {176, 42,  20,  8,  60,  169, 148, 222, 75,  36, 163,
         110, 198, 254, 67, 75,  4,   214, 130, 105, 70, 117,
         141, 157, 88,  14, 107, 82,  18,  148, 227, 216},
        {221, 187, 92,  195, 26,  237, 219, 149, 4,  81,  63,
         9,   157, 239, 252, 110, 152, 206, 212, 17, 226, 29,
         73,  254, 81,  48,  153, 199, 148, 175, 74, 36},
        {87,  16,  120, 61,  69,  69,  213, 108, 94,  47,  70,
         173, 235, 28,  139, 35,  159, 106, 250, 215, 110, 161,
         222, 42,  140, 19,  197, 170, 52,  13,  49,  201},
        {134, 125, 171, 241, 166, 244, 131, 137, 170, 42,  137,
         17,  222, 96,  167, 118, 75,  1,   202, 184, 154, 51,
         228, 45,  137, 229, 138, 170, 148, 70,  232, 223},
        {162, 114, 146, 33,  77,  86,  70,  28,  183, 21, 19,
         61,  45,  80,  185, 173, 69,  107, 164, 4,   60, 3,
         144, 205, 202, 114, 44,  248, 113, 177, 139, 157},
        {75,  85,  117, 105, 35,  60,  142, 31,  105, 80,  89,
         186, 137, 213, 157, 206, 207, 195, 22,  72,  113, 105,
         142, 154, 149, 229, 157, 115, 182, 242, 155, 52},
        {35,  149, 41,  86,  79,  213, 62,  154, 145, 126, 134,
         237, 18,  127, 33,  163, 139, 234, 234, 108, 42,  6,
         215, 198, 121, 135, 176, 234, 135, 220, 162, 208},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t z[8], need_z[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(need_z, TEST_VECTOR[i][0]);
        uint256_from_bytes(z, TEST_VECTOR_BYTES[i]);
        if (uint256_equal(z, need_z) == false)
        {
            return false;
        }
    }
    return true;
}

// ****************************************
// ********** Bit Manipulation ************
// ****************************************

static bool test_uint256_bittest()
{
    static const char* TEST_VECTOR[][2] = {
        {"e80afd819f6bb1d0e664d76fbe3e0110ad4e6bb1581ab7de6204aa97bf875e3d",
         "111010000000101011111101100000011001111101101011101100011101000011100"
         "110011001001101011101101111101111100011111000000001000100001010110101"
         "001110011010111011000101011000000110101011011111011110011000100000010"
         "0101010101001011110111111100001110101111000111101"},
        {"e3eb482d3182183cc52771a837b4b600e4973acec1fb08a8548b941ab81ba0c7",
         "111000111110101101001000001011010011000110000010000110000011110011000"
         "101001001110111000110101000001101111011010010110110000000001110010010"
         "010111001110101100111011000001111110110000100010101000010101001000101"
         "1100101000001101010111000000110111010000011000111"},
        {"e7f0ca2fdef9206c26fa99e3c4b6fd9562a34907fb14f6b6fb0d37ef2f5daa37",
         "111001111111000011001010001011111101111011111001001000000110110000100"
         "110111110101001100111100011110001001011011011111101100101010110001010"
         "100011010010010000011111111011000101001111011010110110111110110000110"
         "1001101111110111100101111010111011010101000110111"},
        {"cce040b92debd5f8a25eeacec2b18e0e499d4425a3513be0329c21027bb5cb5e",
         "110011001110000001000000101110010010110111101011110101011111100010100"
         "010010111101110101011001110110000101011000110001110000011100100100110"
         "011101010001000010010110100011010100010011101111100000001100101001110"
         "0001000010000001001111011101101011100101101011110"},
        {"fde859481ca09f993951032534e29ce7dfbad7b2c4fc8ff57a804f2d862844b7",
         "111111011110100001011001010010000001110010100000100111111001100100111"
         "001010100010000001100100101001101001110001010011100111001111101111110"
         "111010110101111011001011000100111111001000111111110101011110101000000"
         "0010011110010110110000110001010000100010010110111"},
        {"a82e1883b1b3e2b48612faa1e40b49699ebf09889d0140f2194c43831fa8500d",
         "101010000010111000011000100000111011000110110011111000101011010010000"
         "110000100101111101010100001111001000000101101001001011010011001111010"
         "111111000010011000100010011101000000010100000011110010000110010100110"
         "0010000111000001100011111101010000101000000001101"},
        {"a37cc939e68d3f99024a83736e1200ebcd29a1dc65b32e75c680a7d946d2e4dd",
         "101000110111110011001001001110011110011010001101001111111001100100000"
         "010010010101000001101110011011011100001001000000000111010111100110100"
         "101001101000011101110001100101101100110010111001110101110001101000000"
         "0101001111101100101000110110100101110010011011101"},
        {"6a3bda3dbd65a0ae1d78046e7e4c89a474ac7f3cbb8f8b1f6b673325c75174b2",
         "011010100011101111011010001111011011110101100101101000001010111000011"
         "101011110000000010001101110011111100100110010001001101001000111010010"
         "101100011111110011110010111011100011111000101100011111011010110110011"
         "1001100110010010111000111010100010111010010110010"},
        {"7c4dd695d74347595887cc5201c33cf521f8973a641804848167206d338bac7e",
         "011111000100110111010110100101011101011101000011010001110101100101011"
         "000100001111100110001010010000000011100001100111100111101010010000111"
         "111000100101110011101001100100000110000000010010000100100000010110011"
         "1001000000110110100110011100010111010110001111110"},
        {"2abd44d40a0acca1b0ac33cd581d42d827e1dbf908a7170033f06360c664f04d",
         "001010101011110101000100110101000000101000001010110011001010000110110"
         "000101011000011001111001101010110000001110101000010110110000010011111"
         "100001110110111111100100001000101001110001011100000000001100111111000"
         "0011000110110000011000110011001001111000001001101"},
    };
    int      size = sizeof(TEST_VECTOR) / sizeof(TEST_VECTOR[0]);
    uint32_t x[8];
    for (int i = 0; i < size; i++)
    {
        uint256_from_hex(x, TEST_VECTOR[i][0]);
        const char* bin = TEST_VECTOR[i][1];
        for (int j = 0; j < 256; j++)
        {
            char need_c = bin[255 - j];
            char c      = uint256_bittest(x, j) ? '1' : '0';
            if (need_c != c)
            {
                return false;
            }
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
    // ************** UINT256 Common Algo ***************
    // **************************************************
    // ++++++++++++++++++++++++++++++++++++++++++++++++++

    // ****************************************
    // ************ Arithmetic ****************
    // ****************************************
    TEST(uint256_add_carry);
    TEST(uint256_add_carry_uint32);
    TEST(uint256_dbl_carry);
    TEST(uint256_tpl_carry);
    TEST(uint256_sub_borrow);
    TEST(uint256_sub_borrow_uint32);
    TEST(uint256_mul);
    TEST(uint256_mul_carry_uint32);
    TEST(uint256_sqr);
    // // ****************************************
    // // *************** Compare ****************
    // // ****************************************
    TEST(uint256_cmp);
    TEST(uint256_cmp_uint32);
    TEST(uint256_equal);
    TEST(uint256_equal_zero);
    TEST(uint256_equal_one);
    // // ****************************************
    // // ************* Set & Move ***************
    // // ****************************************
    TEST(uint256_cpy);
    TEST(uint256_set_uint32);
    TEST(uint256_set_zero);
    TEST(uint256_set_one);
    // // ****************************************
    // // *************** Convert ****************
    // // ****************************************
    TEST(uint256_to_bytes);
    TEST(uint256_from_bytes);
    // // ****************************************
    // // ********** Bit Manipulation ************
    // // ****************************************
    TEST(uint256_bittest);
    puts("uint256 test ok!");
    return 0;
}
#endif