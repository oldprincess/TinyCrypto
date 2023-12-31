#include "sm2p256v1_asn1.h"
#include "../../encoding/asn1/asn1.h"
#include <string.h>
#include <stdio.h>

namespace tc {
namespace sm2p256v1 {

// ****************************************
// ********** PrivateKey ******************
// ****************************************

size_t sm2_private_key_asn1_encode_max_outl()
{
    return ASN1_ENCODE_INTEGER_MAX_OUTL(32);
}

size_t sm2_private_key_asn1_encode_outl(const SM2PrivateKey* priv)
{
    return asn1_encode_integer_outl(priv->value, 32);
}

void sm2_private_key_asn1_encode_outl(uint8_t*             out,
                                      size_t*              outl,
                                      const SM2PrivateKey* priv)
{
    asn1_encode_integer_tlv(out, outl, priv->value, 32);
}

int sm2_private_key_asn1_decode(SM2PrivateKey* priv,
                                size_t*        read_num,
                                const uint8_t* in,
                                size_t         inl)
{
    uint8_t* data;
    size_t   data_length;
    if (asn1_decode_integer_value(&priv->value, &data_length, read_num, in,
                                  inl))
    {
        return -1;
    }
    if (data_length != 32)
    {
        return -1;
    }
    return 0;
}

// ****************************************
// *********** PublicKey ******************
// ****************************************

size_t sm2_public_key_asn1_encode_max_outl()
{
    return ASN1_ENCODE_BIT_STRING_MAX_OUTL(65 * 8);
}

size_t sm2_public_key_asn1_encode_outl(const SM2PublicKey* pub)
{
    return asn1_encode_bit_string_outl(65 * 8);
}

void sm2_public_key_asn1_encode(uint8_t*            out,
                                size_t*             outl,
                                const SM2PublicKey* pub)
{
    asn1_encode_bit_string_tlv(out, outl, pub->value, 65, 65 * 8);
}

int sm2_public_key_asn1_decode(SM2PublicKey*  pub,
                               size_t*        read_num,
                               const uint8_t* in,
                               size_t         inl)
{
    size_t data_length, data_bits;
    if (asn1_decode_bit_string_value(&pub->value, &data_length, &data_bits,
                                     read_num, in, inl))
    {
        return -1;
    }
    if (data_length != 65 && data_bits != 65 * 8)
    {
        return -1;
    }
    return 0;
}

// ****************************************
// *********** Signature ******************
// ****************************************

size_t sm2_signature_asn1_encode_max_outl()
{
    return ASN1_ENCODE_SEQUENCE_MAX_OUTL(ASN1_ENCODE_INTEGER_MAX_OUTL(32) +
                                         ASN1_ENCODE_INTEGER_MAX_OUTL(32));
}

size_t sm2_signature_asn1_encode_outl(const SM2Signature* sig)
{
    return asn1_encode_sequence_outl(asn1_encode_integer_outl(sig->R, 32) +
                                     asn1_encode_integer_outl(sig->S, 32));
}

void sm2_signature_asn1_encode(uint8_t*            out,
                               size_t*             outl,
                               const SM2Signature* sig)
{
    size_t seq_v_len = asn1_encode_integer_outl(sig->R, 32) +
                       asn1_encode_integer_outl(sig->S, 32);

    size_t   n;
    uint8_t* out_save = out;
    asn1_encode_sequence_tl(out, &n, seq_v_len);
    out += n;
    asn1_encode_integer_tlv(out, &n, sig->R, 32);
    out += n;
    asn1_encode_integer_tlv(out, &n, sig->S, 32);
    out += n;
    *outl = (size_t)out - (size_t)out_save;
}

int sm2_signature_asn1_decode(SM2Signature*  sig,
                              size_t*        read_num,
                              const uint8_t* in,
                              size_t         inl)
{
    size_t inl_save = inl, n;

    const uint8_t* seq_value;
    size_t         seq_v_len, int_1_v_len, int_2_v_len;

    // decode SEQUENCE
    if (asn1_decode_sequence_value(&seq_value, &seq_v_len, &n, in, inl))
    {
        return -1;
    }
    in += n, inl -= n;
    // decode INTEGER
    if (asn1_decode_integer_value(&sig->R, &int_1_v_len, &n, seq_value,
                                  seq_v_len))
    {
        return -1;
    }
    if (int_1_v_len != 32)
    {
        return -1;
    }
    seq_value += n, seq_v_len -= n;
    // decode INTEGER
    if (asn1_decode_integer_value(&sig->S, &int_2_v_len, &n, seq_value,
                                  seq_v_len))
    {
        return -1;
    }
    if (int_2_v_len != 32)
    {
        return -1;
    }
    *read_num = inl_save - inl;
    return 0;
}

// ****************************************
// ************ cipher ********************
// ****************************************

size_t sm2_cipher_asn1_encode_max_outl(size_t C3_length, size_t C2_length)
{
    return ASN1_ENCODE_SEQUENCE_MAX_OUTL(
        ASN1_ENCODE_INTEGER_MAX_OUTL(32) +             //
        ASN1_ENCODE_INTEGER_MAX_OUTL(32) +             //
        ASN1_ENCODE_OCTET_STRING_MAX_OUTL(C3_length) + //
        ASN1_ENCODE_OCTET_STRING_MAX_OUTL(C2_length));
}

size_t sm2_cipher_asn1_encode_outl(const SM2Cipher* cipher)
{
    return asn1_encode_sequence_outl(
        asn1_encode_integer_outl(cipher->XCoordinate, 32) +
        asn1_encode_integer_outl(cipher->YCoordinate, 32) +
        asn1_encode_octet_string_outl(cipher->HASH.length) +
        asn1_encode_octet_string_outl(cipher->CipherText.length));
}

void sm2_cipher_asn1_encode(uint8_t* out, size_t* outl, const SM2Cipher* cipher)
{
    size_t seq_v_len = asn1_encode_integer_outl(cipher->XCoordinate, 32) +
                       asn1_encode_integer_outl(cipher->YCoordinate, 32) +
                       asn1_encode_octet_string_outl(cipher->HASH.length) +
                       asn1_encode_octet_string_outl(cipher->CipherText.length);

    size_t   n;
    uint8_t* out_save = out;
    asn1_encode_sequence_tl(out, &n, seq_v_len);
    out += n;
    asn1_encode_integer_tlv(out, &n, cipher->XCoordinate, 32);
    out += n;
    asn1_encode_integer_tlv(out, &n, cipher->YCoordinate, 32);
    out += n;
    asn1_encode_octet_string_tlv(out, &n, cipher->HASH.value,
                                 cipher->HASH.length);
    out += n;
    asn1_encode_octet_string_tlv(out, &n, cipher->CipherText.value,
                                 cipher->CipherText.length);
    out += n;
    *outl = (size_t)(out) - (size_t)(out_save);
}

int sm2_cipher_asn1_decode(SM2Cipher*     cipher,
                           size_t*        read_num,
                           const uint8_t* in,
                           size_t         inl)
{
    size_t inl_save = inl, n;

    const uint8_t* seq_value;
    size_t         seq_v_len, int_1_v_len, int_2_v_len;
    size_t         octet_1_v_len, octet_2_v_len;

    if (asn1_decode_sequence_value(&seq_value, &seq_v_len, &n, in, inl))
    {
        return -1;
    }
    in += n, inl -= n;
    if (asn1_decode_integer_value(&cipher->XCoordinate, &int_1_v_len, &n,
                                  seq_value, seq_v_len))
    {
        return -1;
    }
    if (int_1_v_len != 32)
    {
        return -1;
    }
    seq_value += n, seq_v_len -= n;
    if (asn1_decode_integer_value(&cipher->YCoordinate, &int_2_v_len, &n,
                                  seq_value, seq_v_len))
    {
        return -1;
    }
    if (int_2_v_len != 32)
    {
        return -1;
    }
    seq_value += n, seq_v_len -= n;
    if (asn1_decode_octet_string_value(&cipher->HASH.value,
                                       &cipher->HASH.length, &n, seq_value,
                                       seq_v_len))
    {
        return -1;
    }
    seq_value += n, seq_v_len -= n;
    if (asn1_decode_octet_string_value(&cipher->CipherText.value,
                                       &cipher->CipherText.length, &n,
                                       seq_value, seq_v_len))
    {
        return -1;
    }
    seq_value += n, seq_v_len -= n;
    *read_num = inl_save - inl;
    return 0;
}

} // namespace sm2p256v1
} // namespace tc