#ifndef TINY_CRYPTO_PKC_SM2_P256V1_ASN1_H
#define TINY_CRYPTO_PKC_SM2_P256V1_ASN1_H

#include <stdint.h>
#include <stddef.h>

namespace tc {
namespace sm2p256v1 {

// ****************************************
// ********** PrivateKey ******************
// ****************************************

/**
 * SM2PrivateKey ::= INTEGER
 */
typedef struct SM2PrivateKey
{
    const uint8_t* value; // INTEGER 256-bit(32-bytes)
} SM2PrivateKey;

size_t sm2_private_key_asn1_encode_max_outl();

size_t sm2_private_key_asn1_encode_outl(const SM2PrivateKey* priv);

void sm2_private_key_asn1_encode_outl(uint8_t*             out,
                                      size_t*              outl,
                                      const SM2PrivateKey* priv);

int sm2_private_key_asn1_decode(SM2PrivateKey* priv,
                                size_t*        read_num,
                                const uint8_t* in,
                                size_t         inl);

// ****************************************
// *********** PublicKey ******************
// ****************************************

/**
 * SM2PublicKey ::= BIT STRING
 * 04 || X || Y
 */
typedef struct SM2PublicKey
{
    const uint8_t* value; // BIT STRING 8+256+256=520-bit (65 bytes)
} SM2PublicKey;

size_t sm2_public_key_asn1_encode_max_outl();

size_t sm2_public_key_asn1_encode_outl(const SM2PublicKey* pub);

void sm2_public_key_asn1_encode(uint8_t*            out,
                                size_t*             outl,
                                const SM2PublicKey* pub);

int sm2_public_key_asn1_decode(SM2PublicKey*  pub,
                               size_t*        read_num,
                               const uint8_t* in,
                               size_t         inl);

// ****************************************
// *********** Signature ******************
// ****************************************

/**
 * SM2Signature ::= SEQUENCE {
 *      R   INTEGER,
 *      S   INTEGER
 * }
 */
typedef struct SM2Signature
{
    const uint8_t* R; // INTEGER 256-bit(32-bytes)
    const uint8_t* S; // INTEGER 256-bit(32-bytes)
} SM2Signature;

size_t sm2_signature_asn1_encode_max_outl();

size_t sm2_signature_asn1_encode_outl(const SM2Signature* sig);

void sm2_signature_asn1_encode(uint8_t*            out,
                               size_t*             outl,
                               const SM2Signature* sig);

int sm2_signature_asn1_decode(SM2Signature*  sig,
                              size_t*        read_num,
                              const uint8_t* in,
                              size_t         inl);

// ****************************************
// ************ cipher ********************
// ****************************************

/**
 * SM2Cipher ::= SEQUENCE {
 *      XCoordinate     INTEGER,
 *      YCoordinate     INTEGER,
 *      HASH            OCTET STRING,
 *      CipherText      OCTET STRING
 * }
 */
typedef struct SM2Cipher
{
    const uint8_t* XCoordinate; // INTEGER 256-bit(32-bytes)
    const uint8_t* YCoordinate; // INTEGER 256-bit(32-bytes)
    struct C3
    {
        const uint8_t* value;
        size_t         length;
    } HASH; // OCTET STRING
    struct C2
    {
        const uint8_t* value;
        size_t         length;
    } CipherText; // OCTET STRING
} SM2Cipher;

size_t sm2_cipher_asn1_encode_max_outl(size_t C3_length, size_t C2_length);

size_t sm2_cipher_asn1_encode_outl(const SM2Cipher* cipher);

void sm2_cipher_asn1_encode(uint8_t*         out,
                            size_t*          outl,
                            const SM2Cipher* cipher);

int sm2_cipher_asn1_decode(SM2Cipher*     cipher,
                           size_t*        read_num,
                           const uint8_t* in,
                           size_t         inl);

} // namespace sm2p256v1
} // namespace tc

#endif