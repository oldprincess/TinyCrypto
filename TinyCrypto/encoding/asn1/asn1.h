#ifndef TINY_CRYPTO_ENCODING_ASN1_H
#define TINY_CRYPTO_ENCODING_ASN1_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

namespace tc {

typedef enum Asn1TagClass
{
    ASN1_TAG_CLASS_UNIVERSAL        = 0b00000000,
    ASN1_TAG_CLASS_APPLICATION      = 0b01000000,
    ASN1_TAG_CLASS_CONTEXT_SPECIFIC = 0b10000000,
    ASN1_TAG_CLASS_PRIVATE          = 0b11000000,
} Asn1TagClass;

typedef enum Asn1TagPC
{
    ASN1_TAG_PC_PRIMITIVE   = 0b00000000,
    ASN1_TAG_PC_CONSTRUCTED = 0b00100000,
} Asn1TagPC;

typedef enum Asn1TagNumber
{
    ASN1_TAG_END_OF_CONTENTS   = 0, // MUST PRIMITIVE
    ASN1_TAG_BOOLEAN           = 1, // MUST PRIMITIVE
    ASN1_TAG_INTEGER           = 2, // MUST PRIMITIVE
    ASN1_TAG_BIT_STRING        = 3, // PRIMITIVE OR CONSTRUCTED
    ASN1_TAG_OCTET_STRING      = 4, // PRIMITIVE OR CONSTRUCTED
    ASN1_TAG_NULL              = 5, // MUST PRIMITIVE
    ASN1_TAG_OBJECT_IDENTIFIER = 6,
    ASN1_TAG_OBJECT_DESCRIPTOR = 7,
    ASN1_TAG_EXTERNAL          = 8,
    ASN1_TAG_REAL              = 9,
    ASN1_TAG_ENUMERATED        = 10,
    ASN1_TAG_UTF8_STRING       = 12,
    ASN1_TAG_SEQUENCE          = 16, // MUST CONSTRUCTED
    ASN1_TAG_SET               = 17, // MUST CONSTRUCTED
    ASN1_TAG_NUMERIC_STRING    = 18,
    ASN1_TAG_PRINTABLE_STRING  = 19,
    ASN1_TAG_TELETEX_STRING    = 20,
    ASN1_TAG_VIDEOTEX_STRING   = 21,
    ASN1_TAG_IA5_STRING        = 22,
    ASN1_TAG_UTC_TIME          = 23,
    ASN1_TAG_GENERALIZED_TIME  = 24,
    ASN1_TAG_GRAPHIC_STRING    = 25,
    ASN1_TAG_VISIBLE_STRING    = 26,
    ASN1_TAG_GENERAL_STRING    = 27,
    ASN1_TAG_UNIVERSAL_STRING  = 28,
    ASN1_TAG_BMP_STRING        = 30,
} Asn1TagNumber;

typedef struct Asn1TLV
{
    Asn1TagClass   tag_class;
    Asn1TagPC      tag_pc;
    Asn1TagNumber  tag_number;
    size_t         length;
    const uint8_t* value;
} Asn1TLV;

int asn1_dump(const uint8_t* in, size_t inl);

int asn1_decode_tlv(Asn1TLV*       tlv,
                    size_t*        read_num,
                    const uint8_t* in,
                    size_t         inl);

const char* asn1_tag_class_name(Asn1TagClass tag_class);

const char* asn1_tag_pc_name(Asn1TagPC tag_pc);

const char* asn1_tag_number_name(Asn1TagNumber tag_number);

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// ************ ASN1 ENCODING/DECODING **************
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

// ****************************************
// ************ ENCODING ******************
// ****************************************

size_t asn1_encode_tlv_outl(size_t value_length);

size_t asn1_encode_boolean_outl();

size_t asn1_encode_integer_outl(const uint8_t* data, size_t data_len);

size_t asn1_encode_bit_string_outl(size_t bits);

size_t asn1_encode_octet_string_outl(size_t data_len);

size_t asn1_encode_sequence_outl(size_t value_length);

size_t asn1_encode_set_outl(size_t value_length);

void asn1_encode_boolean_tlv(uint8_t* out, size_t* outl, bool value);

void asn1_encode_integer_tlv(uint8_t*       out,
                             size_t*        outl,
                             const uint8_t* data,
                             size_t         data_len);

void asn1_encode_bit_string_tl(uint8_t* out, size_t* outl, size_t value_length);

void asn1_encode_bit_string_tlv(uint8_t*       outr,
                                size_t*        outl,
                                const uint8_t* data,
                                size_t         data_len,
                                size_t         data_bits);

void asn1_encode_octet_string_tl(uint8_t* out,
                                 size_t*  outl,
                                 size_t   value_length);

void asn1_encode_octet_string_tlv(uint8_t*       out,
                                  size_t*        outl,
                                  const uint8_t* data,
                                  size_t         data_len);

void asn1_encode_sequence_tl(uint8_t* out, size_t* outl, size_t value_length);

void asn1_encode_set_tl(uint8_t* out, size_t* outl, size_t value_length);

#define ASN1_ENCODE_TLV_MAX_OUTL(value_length) \
    (1 + (1 + sizeof(size_t)) + (value_length))

#define ASN1_ENCODE_BOOLEAN_MAX_OUTL() 3

#define ASN1_ENCODE_INTEGER_MAX_OUTL(data_length) \
    ASN1_ENCODE_TLV_MAX_OUTL((data_length) + 1)

#define ASN1_ENCODE_BIT_STRING_MAX_OUTL(bits) \
    ASN1_ENCODE_TLV_MAX_OUTL(1 + ((bits) + 7 / 8))

#define ASN1_ENCODE_OCTET_STRING_MAX_OUTL ASN1_ENCODE_TLV_MAX_OUTL

#define ASN1_ENCODE_SEQUENCE_MAX_OUTL ASN1_ENCODE_TLV_MAX_OUTL

#define ASN1_ENCODE_SET_MAX_OUTL ASN1_ENCODE_TLV_MAX_OUTL

// ****************************************
// ************ DECODING ******************
// ****************************************

int asn1_decode_boolean_value(bool*          ret,
                              size_t*        read_num,
                              const uint8_t* in,
                              size_t         inl);

int asn1_decode_integer_value(const uint8_t** data_ptr,
                              size_t*         data_length,
                              size_t*         read_num,
                              const uint8_t*  in,
                              size_t          inl);

int asn1_decode_bit_string_value(const uint8_t** data_ptr,
                                 size_t*         data_length,
                                 size_t*         bits_length,
                                 size_t*         read_num,
                                 const uint8_t*  in,
                                 size_t          inl);

int asn1_decode_octet_string_value(const uint8_t** data_ptr,
                                   size_t*         data_length,
                                   size_t*         read_num,
                                   const uint8_t*  in,
                                   size_t          inl);

int asn1_decode_null_value(size_t* read_num, const uint8_t* in, size_t inl);

int asn1_decode_sequence_value(const uint8_t** value_ptr,
                               size_t*         value_length,
                               size_t*         read_num,
                               const uint8_t*  in,
                               size_t          inl);

int asn1_decode_set_value(const uint8_t** value_ptr,
                          size_t*         value_length,
                          size_t*         read_num,
                          const uint8_t*  in,
                          size_t          inl);

} // namespace tc

#endif