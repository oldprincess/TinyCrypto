#include "asn1.h"
#include <stdio.h>
#include <string.h>

namespace tc {

int r_asn1_dump(const uint8_t* in, size_t inl, size_t depth)
{
    Asn1TLV tlv;
    size_t  read_num;
    int     err;
    while (inl)
    {
        err = asn1_decode_tlv(&tlv, &read_num, in, inl);
        if (err)
        {
            return err;
        }
        // dump
        for (size_t i = 0; i < depth; i++) printf("   ");
        for (const uint8_t* ptr = in; ptr != tlv.value; ptr++)
        {
            printf("%02x ", *ptr);
        }
        for (size_t i = (size_t)tlv.value - (size_t)in; i < 8 + 1; i++)
        {
            printf("   ");
        }
        printf(";  %s(", asn1_tag_number_name(tlv.tag_number));
        printf("length = %zu Bytes", tlv.length);
        printf(",%s", asn1_tag_class_name(tlv.tag_class));
        printf(",%s)\n", asn1_tag_pc_name(tlv.tag_pc));
        if (tlv.tag_pc == ASN1_TAG_PC_CONSTRUCTED)
        {
            r_asn1_dump(tlv.value, tlv.length, depth + 1);
        }
        else
        {
            for (size_t i = 0; i < tlv.length; i++)
            {
                if (i % 8 == 0)
                {
                    for (size_t j = 0; j < depth + 1; j++) printf("   ");
                }
                printf("%02x ", tlv.value[i]);
                if (i % 8 == 7) printf("\n");
            }
            if (tlv.length % 8 != 0) printf("\n");
        }
        // next
        in += read_num, inl -= read_num;
    }
    return 0;
}

int asn1_dump(const uint8_t* in, size_t inl)
{
    return r_asn1_dump(in, inl, 0);
}

static void asn1_encode_identifier_octets(uint8_t       out[1],
                                          Asn1TagClass  tag_class,
                                          Asn1TagPC     tag_pc,
                                          Asn1TagNumber tag_number)
{
    out[0] = (tag_class << 6) | (tag_pc << 5) | tag_number;
}

static void asn1_encode_length_octets(uint8_t* out, size_t* outl, size_t length)
{
    if (length < 0x80)
    {
        *out  = (uint8_t)length;
        *outl = 1;
    }
    else
    {
        uint8_t tmp[sizeof(size_t)];
        uint8_t tmp_size = 0;
        while (length)
        {
            tmp[tmp_size] = length & 0xFF;
            length >>= 8;
            tmp_size += 1;
        }
        *outl = 1 + tmp_size;
        *out  = 0x80 | tmp_size;
        out++;
        for (uint8_t i = tmp_size - 1; i >= 0; i--)
        {
            *out = tmp[i];
            out++;
        }
    }
}

static int asn1_decode_identifier_octets(Asn1TagClass*  tag_class,
                                         Asn1TagPC*     tag_pc,
                                         Asn1TagNumber* tag_number,
                                         size_t*        read_num,
                                         const uint8_t* in,
                                         size_t         inl)
{
    static const size_t TAG_CLASS_MASK  = 0b11000000;
    static const size_t TAG_PC_MASK     = 0b00100000;
    static const size_t TAG_NUMBER_MASK = 0b00011111;
    if (inl == 0)
    {
        return -1;
    }
    *tag_class = (Asn1TagClass)(in[0] & TAG_CLASS_MASK);
    *tag_pc    = (Asn1TagPC)(in[0] & TAG_PC_MASK);
    if ((in[0] & TAG_NUMBER_MASK) == 0b00011111)
    {
        // tags with a number greater than or equal to 31
        return -2; // unsupport
    }
    *tag_number = (Asn1TagNumber)(in[0] & TAG_NUMBER_MASK);
    *read_num   = 1;
    return 0;
}

static int asn1_decode_length_octets(size_t*        ret,
                                     size_t*        read_num,
                                     const uint8_t* in,
                                     size_t         inl)
{
    if (inl == 0)
    {
        return -1;
    }
    if (in[0] == 0x80)
    {
        // indefinite_form
        return -2; // unsupport
    }
    else
    {
        // definite_form
        if ((in[0] & 0x80) == 0)
        {
            // short form
            *ret      = in[0];
            *read_num = 1;
            return 0;
        }
        else
        {
            // long form
            size_t subsequent_octet_length = (size_t)(in[0] & 0x7f);
            if (subsequent_octet_length > sizeof(size_t))
            {
                return -2; // unsupport
            }
            if (inl < 1 + subsequent_octet_length)
            {
                return -1;
            }
            *ret = 0;
            for (size_t i = 1; i <= subsequent_octet_length; i++)
            {
                *ret = (*ret << 8) | (size_t)in[i];
            }
            *read_num = 1 + subsequent_octet_length;
            return 0;
        }
    }
}

int asn1_decode_tlv(Asn1TLV*       tlv,
                    size_t*        read_num,
                    const uint8_t* in,
                    size_t         inl)
{
    int    err;
    size_t n;
    *read_num = 0;
    // tag: identifier
    err = asn1_decode_identifier_octets(&tlv->tag_class, &tlv->tag_pc,
                                        &tlv->tag_number, &n, in, inl);
    if (err)
    {
        return err;
    }
    in += n, inl -= n, *read_num += n;
    // length
    err = asn1_decode_length_octets(&tlv->length, &n, in, inl);
    if (err)
    {
        return err;
    }
    in += n, inl -= n, *read_num += n;
    // value
    tlv->value = in;
    *read_num += tlv->length;
    return 0;
}

const char* asn1_tag_class_name(Asn1TagClass tag_class)
{
    switch (tag_class)
    {
        case ASN1_TAG_CLASS_UNIVERSAL: return "UNIVERSAL";
        case ASN1_TAG_CLASS_APPLICATION: return "APPLICATION";
        case ASN1_TAG_CLASS_CONTEXT_SPECIFIC: return "CONTEXT_SPECIFIC";
        case ASN1_TAG_CLASS_PRIVATE: return "PRIVATE";
        default: return "UNKNOWN";
    }
}

const char* asn1_tag_pc_name(Asn1TagPC tag_pc)
{
    switch (tag_pc)
    {
        case ASN1_TAG_PC_PRIMITIVE: return "PRIMITIVE";
        case ASN1_TAG_PC_CONSTRUCTED: return "CONSTRUCTED";
        default: return "UNKNOWN";
    }
}

const char* asn1_tag_number_name(Asn1TagNumber tag_number)
{
    switch (tag_number)
    {
        case ASN1_TAG_END_OF_CONTENTS: return "END_OF_CONTENTS";
        case ASN1_TAG_BOOLEAN: return "BOOLEAN";
        case ASN1_TAG_INTEGER: return "INTEGER";
        case ASN1_TAG_BIT_STRING: return "BIT_STRING";
        case ASN1_TAG_OCTET_STRING: return "OCTET_STRING";
        case ASN1_TAG_NULL: return "NULL";
        case ASN1_TAG_OBJECT_IDENTIFIER: return "OBJECT_IDENTIFIER";
        case ASN1_TAG_OBJECT_DESCRIPTOR: return "OBJECT_DESCRIPTOR";
        case ASN1_TAG_EXTERNAL: return "EXTERNAL";
        case ASN1_TAG_REAL: return "REAL";
        case ASN1_TAG_ENUMERATED: return "ENUMERATED";
        case ASN1_TAG_UTF8_STRING: return "UTF8_STRING";
        case ASN1_TAG_SEQUENCE: return "SEQUENCE";
        case ASN1_TAG_SET: return "SET";
        case ASN1_TAG_NUMERIC_STRING: return "NUMERIC_STRING";
        case ASN1_TAG_PRINTABLE_STRING: return "PRINTABLE_STRING";
        case ASN1_TAG_TELETEX_STRING: return "TELETEX_STRING";
        case ASN1_TAG_VIDEOTEX_STRING: return "VIDEOTEX_STRING";
        case ASN1_TAG_IA5_STRING: return "IA5_STRING";
        case ASN1_TAG_UTC_TIME: return "UTC_TIME";
        case ASN1_TAG_GENERALIZED_TIME: return "GENERALIZED_TIME";
        case ASN1_TAG_GRAPHIC_STRING: return "GRAPHIC_STRING";
        case ASN1_TAG_VISIBLE_STRING: return "VISIBLE_STRING";
        case ASN1_TAG_GENERAL_STRING: return "GENERAL_STRING";
        case ASN1_TAG_UNIVERSAL_STRING: return "UNIVERSAL_STRING";
        case ASN1_TAG_BMP_STRING: return "BMP_STRING";
        default: return "UNKNOWN";
    }
}

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// ************ ASN1 ENCODING/DECODING **************
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

// ****************************************
// ************ ENCODING ******************
// ****************************************

size_t asn1_encode_tlv_outl(size_t value_length)
{
    uint8_t l_buf[sizeof(size_t)];
    size_t  l_size;
    asn1_encode_length_octets(l_buf, &l_size, value_length);
    return 1 + l_size + value_length;
}

size_t asn1_encode_boolean_outl()
{
    return 3; // tag(1), length(1), value(1)
}

static size_t asn1_encode_integer_value_length(const uint8_t* data,
                                               size_t         data_len)
{
    size_t value_length;
    if (data_len == 0)
    {
        value_length = 0;
    }
    else
    {
        value_length = (data[0] < 0x80) ? data_len : (data_len + 1);
    }
    return value_length;
}

size_t asn1_encode_integer_outl(const uint8_t* data, size_t data_len)
{
    size_t value_length = asn1_encode_integer_value_length(data, data_len);
    return asn1_encode_tlv_outl(value_length);
}

static size_t asn1_encode_bit_string_value_length(size_t bits)
{
    return (bits + 7) / 8 + 1;
}

size_t asn1_encode_bit_string_outl(size_t bits)
{
    size_t value_length = asn1_encode_bit_string_value_length(bits);
    return asn1_encode_tlv_outl(value_length);
}

size_t asn1_encode_octet_string_outl(size_t data_len)
{
    return asn1_encode_tlv_outl(data_len);
}

size_t asn1_encode_sequence_outl(size_t value_length)
{
    return asn1_encode_tlv_outl(value_length);
}

size_t asn1_encode_set_outl(size_t value_length)
{
    return asn1_encode_tlv_outl(value_length);
}

static void asn1_encode_tl(uint8_t*      out,
                           size_t*       outl,
                           Asn1TagClass  tag_class,
                           Asn1TagPC     tag_pc,
                           Asn1TagNumber tag_number,
                           size_t        value_length)
{
    // encode tag
    *out = tag_class | tag_pc | tag_number;
    out += 1;
    // encode length
    size_t n;
    asn1_encode_length_octets(out, &n, value_length);
    *outl = 1 + n;
}

void asn1_encode_boolean_tlv(uint8_t* out, size_t* outl, bool value)
{
    out[0] = (ASN1_TAG_CLASS_UNIVERSAL << 6) | // tag CLASS
             (ASN1_TAG_PC_PRIMITIVE << 5) |    // tag PC
             ASN1_TAG_BOOLEAN;                 // tag NUMBER
    out[1] = 1;                                // length
    out[2] = value ? 0xFF : 0;                 // value
    *outl  = 3;
}

void asn1_encode_integer_tlv(uint8_t*       out,
                             size_t*        outl,
                             const uint8_t* data,
                             size_t         data_len)
{
    size_t n;
    asn1_encode_tl(out, &n,
                   ASN1_TAG_CLASS_UNIVERSAL, //
                   ASN1_TAG_PC_PRIMITIVE,    //
                   ASN1_TAG_INTEGER,         //
                   asn1_encode_integer_value_length(data, data_len));
    out += n, *outl = n;
    if (data_len)
    {
        if (data[0] >= 0x80)
        {
            *out = 0, *outl += 1;
        }
        memmove(out, data, data_len);
        *outl += data_len;
    }
}

void asn1_encode_bit_string_tl(uint8_t* out, size_t* outl, size_t value_length)
{
    asn1_encode_tl(out, outl,
                   ASN1_TAG_CLASS_UNIVERSAL, //
                   ASN1_TAG_PC_CONSTRUCTED,  //
                   ASN1_TAG_BIT_STRING,      //
                   value_length);
}

void asn1_encode_bit_string_tlv(uint8_t*       out,
                                size_t*        outl,
                                const uint8_t* data,
                                size_t         data_len,
                                size_t         data_bits)
{
    size_t n;
    asn1_encode_tl(out, &n,
                   ASN1_TAG_CLASS_UNIVERSAL, //
                   ASN1_TAG_PC_PRIMITIVE,    //
                   ASN1_TAG_BIT_STRING,      //
                   asn1_encode_bit_string_value_length(data_bits));
    out += n, *outl = n;

    *out = (8 - data_bits % 8) % 8;
    out += 1, *outl += 1;
    memmove(out, data, data_len);
    *outl += data_len;
}

void asn1_encode_octet_string_tl(uint8_t* out,
                                 size_t*  outl,
                                 size_t   value_length)
{
    asn1_encode_tl(out, outl,
                   ASN1_TAG_CLASS_UNIVERSAL, //
                   ASN1_TAG_PC_CONSTRUCTED,  //
                   ASN1_TAG_OCTET_STRING,    //
                   value_length);
}

void asn1_encode_octet_string_tlv(uint8_t*       out,
                                  size_t*        outl,
                                  const uint8_t* data,
                                  size_t         data_len)
{
    size_t n;
    asn1_encode_tl(out, &n,
                   ASN1_TAG_CLASS_UNIVERSAL, //
                   ASN1_TAG_PC_PRIMITIVE,    //
                   ASN1_TAG_OCTET_STRING,    //
                   data_len);
    out += n, *outl = n;
    memmove(out, data, data_len);
    *outl += data_len;
}

void asn1_encode_sequence_tl(uint8_t* out, size_t* outl, size_t value_length)
{
    asn1_encode_tl(out, outl,
                   ASN1_TAG_CLASS_UNIVERSAL, //
                   ASN1_TAG_PC_CONSTRUCTED,  //
                   ASN1_TAG_SEQUENCE,        //
                   value_length);
}

void asn1_encode_set_tl(uint8_t* out, size_t* outl, size_t value_length)
{
    asn1_encode_tl(out, outl,
                   ASN1_TAG_CLASS_UNIVERSAL, //
                   ASN1_TAG_PC_CONSTRUCTED,  //
                   ASN1_TAG_SET,             //
                   value_length);
}

// ****************************************
// ************ DECODING ******************
// ****************************************

int asn1_decode_boolean_value(bool*          ret,
                              size_t*        read_num,
                              const uint8_t* in,
                              size_t         inl)
{
    Asn1TLV tlv;
    int     err = asn1_decode_tlv(&tlv, read_num, in, inl);
    if (err)
    {
        return err;
    }
    if (tlv.tag_pc != ASN1_TAG_PC_PRIMITIVE ||
        tlv.tag_number != ASN1_TAG_BOOLEAN || tlv.length != 1)
    {
        return -1;
    }
    *ret = (tlv.value[0] == 0) ? false : true;
    return 0;
}

int asn1_decode_integer_value(const uint8_t** data_ptr,
                              size_t*         data_length,
                              size_t*         read_num,
                              const uint8_t*  in,
                              size_t          inl)
{
    Asn1TLV tlv;
    int     err = asn1_decode_tlv(&tlv, read_num, in, inl);
    if (err)
    {
        return err;
    }
    if (tlv.tag_pc != ASN1_TAG_PC_PRIMITIVE ||
        tlv.tag_number != ASN1_TAG_INTEGER || tlv.length == 0)
    {
        return -1;
    }
    // decode contents value
    if (tlv.length > 1)
    {
        if (tlv.value[0] == 0 && (tlv.value[1] & 0x80) == 0)
        {
            return -1;
        }
        if (tlv.value[0] == 0xff && (tlv.value[1] & 0x80) == 0x80)
        {
            return -1;
        }
    }
    if (tlv.length > 1 && tlv.value[0] == 0)
    {
        *data_ptr    = tlv.value + 1;
        *data_length = tlv.length - 1;
    }
    else
    {
        *data_ptr    = tlv.value;
        *data_length = tlv.length;
    }
    return 0;
}

int asn1_decode_bit_string_value(const uint8_t** data_ptr,
                                 size_t*         data_length,
                                 size_t*         bits_length,
                                 size_t*         read_num,
                                 const uint8_t*  in,
                                 size_t          inl)
{
    Asn1TLV tlv;
    int     err = asn1_decode_tlv(&tlv, read_num, in, inl);
    if (err)
    {
        return err;
    }
    if (tlv.tag_number != ASN1_TAG_BIT_STRING || tlv.length == 0)
    {
        return -1;
    }
    // contents
    if (tlv.length == 1 && tlv.value[0] != 0)
    {
        return -1;
    }
    if (!(0 <= tlv.value[0] && tlv.value[0] <= 7))
    {
        return -1;
    }
    *data_ptr    = tlv.value + 1;
    *data_length = tlv.length - 1;
    *bits_length = 8 * (tlv.length - 1) - in[0];
    return 0;
}

int asn1_decode_octet_string_value(const uint8_t** data_ptr,
                                   size_t*         data_length,
                                   size_t*         read_num,
                                   const uint8_t*  in,
                                   size_t          inl)
{
    Asn1TLV tlv;
    int     err = asn1_decode_tlv(&tlv, read_num, in, inl);
    if (err)
    {
        return err;
    }
    if (tlv.tag_number != ASN1_TAG_OCTET_STRING || tlv.length == 0)
    {
        return -1;
    }
    // contents
    *data_ptr    = tlv.value;
    *data_length = tlv.length;
    return 0;
}

int asn1_decode_null_value(size_t* read_num, const uint8_t* in, size_t inl)
{
    Asn1TLV tlv;
    int     err = asn1_decode_tlv(&tlv, read_num, in, inl);
    if (err)
    {
        return err;
    }
    if (tlv.tag_pc != ASN1_TAG_PC_PRIMITIVE ||
        tlv.tag_number != ASN1_TAG_NULL || tlv.length != 0)
    {
        return -1;
    }
    return 0;
}

int asn1_decode_sequence_value(const uint8_t** value_ptr,
                               size_t*         value_length,
                               size_t*         read_num,
                               const uint8_t*  in,
                               size_t          inl)
{
    Asn1TLV tlv;
    int     err = asn1_decode_tlv(&tlv, read_num, in, inl);
    if (err)
    {
        return err;
    }
    if (tlv.tag_pc != ASN1_TAG_PC_CONSTRUCTED ||
        tlv.tag_number != ASN1_TAG_SEQUENCE || tlv.length != 0)
    {
        return -1;
    }
    // contents
    *value_ptr    = tlv.value;
    *value_length = tlv.length;
    return 0;
}

int asn1_decode_set_value(const uint8_t** value_ptr,
                          size_t*         value_length,
                          size_t*         read_num,
                          const uint8_t*  in,
                          size_t          inl)
{
    Asn1TLV tlv;
    int     err = asn1_decode_tlv(&tlv, read_num, in, inl);
    if (err)
    {
        return err;
    }
    if (tlv.tag_pc != ASN1_TAG_PC_CONSTRUCTED ||
        tlv.tag_number != ASN1_TAG_SET || tlv.length != 0)
    {
        return -1;
    }
    // contents
    *value_ptr    = tlv.value;
    *value_length = tlv.length;
    return 0;
}

} // namespace tc
