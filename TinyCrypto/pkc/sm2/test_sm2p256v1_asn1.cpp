#ifdef TINY_CRYPTO_TEST

#include "sm2p256v1_asn1.h"
#include "../../encoding/str/hexadecimal.h"
#include "../../encoding/asn1/asn1.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

using namespace tc;
using namespace tc::sm2p256v1;

static const char* SM2CT_HEX =
    "3082011c02206e2ecae6c8377fbb8500c050f1eb3f49790f44464de183bcf7620f67330133"
    "d7022100e3db13e48c88d7366da0cd234727ada4ecf07b47a7039c7e0e11e62b8ee0abc504"
    "20e862a3f0b2883027b937390405e9c8c7a57d013700951eadaedafeed93cd56200481b2dd"
    "9311056f43feb26b34ac2912f7d1d80f06442bb10ef5f576d74cbd43c498f5bd2cb5b27f01"
    "9df74bcbd62b4aaa886b497de37709d7d3d7d75fd33c4ee10362389778d759522c30036289"
    "487c82058a21132e44b93dec54d076f8f7fbe3f1517e27971a115d9fc14ba4a4c6033162c5"
    "f750eea64a58175f8695dc46d63a16bd0766c939e06cd57e119d9c9448203fb9937340af26"
    "90332666443a6671d575d440eb2105e32df963f89dd1767d1a3c8ddb05";

static const char* SM2SIG_HEX =
    "3045022100a24386417d7960e79474b6cafa7720098d791c947e96c0670fa60032f4c687d8"
    "022015010a81b5d22787cf5206afbaaed09f51c9e0f1be29e6a9c6f136aec2872305";

int main()
{
    uint8_t der[1024], asn1data[1024];
    size_t  der_len, asn1_len, n;
    hex_to_u8array(der, SM2CT_HEX, strlen(SM2CT_HEX));
    der_len = hex_to_u8array_outl(strlen(SM2CT_HEX));
    // if (asn1_dump(der, der_len))
    // {
    //     fprintf(stderr, "err %s, file: %s, line: %d\n", __FUNCTION__,
    //     __FILE__,
    //             __LINE__);
    //     exit(-1);
    // }
    SM2Cipher cipher;
    if (sm2_cipher_asn1_decode(&cipher, &n, der, der_len))
    {
        fprintf(stderr, "err %s, file: %s, line: %d\n", __FUNCTION__, __FILE__,
                __LINE__);
        exit(-1);
    }
    if (n != der_len)
    {
        fprintf(stderr, "err %s, file: %s, line: %d\n", __FUNCTION__, __FILE__,
                __LINE__);
        exit(-1);
    }
    sm2_cipher_asn1_encode(asn1data, &asn1_len, &cipher);
    if (asn1_len != der_len && memcmp(der, asn1data, der_len) != 0)
    {
        fprintf(stderr, "err %s, file: %s, line: %d\n", __FUNCTION__, __FILE__,
                __LINE__);
        exit(-1);
    }

    hex_to_u8array(der, SM2SIG_HEX, strlen(SM2SIG_HEX));
    der_len = hex_to_u8array_outl(strlen(SM2SIG_HEX));
    // if (asn1_dump(der, der_len))
    // {
    //     fprintf(stderr, "err %s, file: %s, line: %d\n", __FUNCTION__,
    //     __FILE__,
    //             __LINE__);
    //     exit(-1);
    // }
    SM2Signature sig;
    if (sm2_signature_asn1_decode(&sig, &n, der, der_len))
    {
        fprintf(stderr, "err %s, file: %s, line: %d\n", __FUNCTION__, __FILE__,
                __LINE__);
        exit(-1);
    }
    if (n != der_len)
    {
        fprintf(stderr, "err %s, file: %s, line: %d\n", __FUNCTION__, __FILE__,
                __LINE__);
        exit(-1);
    }
    sm2_signature_asn1_encode(asn1data, &asn1_len, &sig);
    if (asn1_len != der_len && memcmp(der, asn1data, der_len) != 0)
    {
        fprintf(stderr, "err %s, file: %s, line: %d\n", __FUNCTION__, __FILE__,
                __LINE__);
        exit(-1);
    }
    puts("sm2p256v1 asn.1 test finish");
    return 0;
}

#endif