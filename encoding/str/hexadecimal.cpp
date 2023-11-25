#include "hexadecimal.h"

namespace tc {

static const char U8ARRAY_TO_HEX_MAP[256][2] = {
    {'0', '0'}, {'0', '1'}, {'0', '2'}, {'0', '3'}, {'0', '4'}, {'0', '5'},
    {'0', '6'}, {'0', '7'}, {'0', '8'}, {'0', '9'}, {'0', 'a'}, {'0', 'b'},
    {'0', 'c'}, {'0', 'd'}, {'0', 'e'}, {'0', 'f'}, {'1', '0'}, {'1', '1'},
    {'1', '2'}, {'1', '3'}, {'1', '4'}, {'1', '5'}, {'1', '6'}, {'1', '7'},
    {'1', '8'}, {'1', '9'}, {'1', 'a'}, {'1', 'b'}, {'1', 'c'}, {'1', 'd'},
    {'1', 'e'}, {'1', 'f'}, {'2', '0'}, {'2', '1'}, {'2', '2'}, {'2', '3'},
    {'2', '4'}, {'2', '5'}, {'2', '6'}, {'2', '7'}, {'2', '8'}, {'2', '9'},
    {'2', 'a'}, {'2', 'b'}, {'2', 'c'}, {'2', 'd'}, {'2', 'e'}, {'2', 'f'},
    {'3', '0'}, {'3', '1'}, {'3', '2'}, {'3', '3'}, {'3', '4'}, {'3', '5'},
    {'3', '6'}, {'3', '7'}, {'3', '8'}, {'3', '9'}, {'3', 'a'}, {'3', 'b'},
    {'3', 'c'}, {'3', 'd'}, {'3', 'e'}, {'3', 'f'}, {'4', '0'}, {'4', '1'},
    {'4', '2'}, {'4', '3'}, {'4', '4'}, {'4', '5'}, {'4', '6'}, {'4', '7'},
    {'4', '8'}, {'4', '9'}, {'4', 'a'}, {'4', 'b'}, {'4', 'c'}, {'4', 'd'},
    {'4', 'e'}, {'4', 'f'}, {'5', '0'}, {'5', '1'}, {'5', '2'}, {'5', '3'},
    {'5', '4'}, {'5', '5'}, {'5', '6'}, {'5', '7'}, {'5', '8'}, {'5', '9'},
    {'5', 'a'}, {'5', 'b'}, {'5', 'c'}, {'5', 'd'}, {'5', 'e'}, {'5', 'f'},
    {'6', '0'}, {'6', '1'}, {'6', '2'}, {'6', '3'}, {'6', '4'}, {'6', '5'},
    {'6', '6'}, {'6', '7'}, {'6', '8'}, {'6', '9'}, {'6', 'a'}, {'6', 'b'},
    {'6', 'c'}, {'6', 'd'}, {'6', 'e'}, {'6', 'f'}, {'7', '0'}, {'7', '1'},
    {'7', '2'}, {'7', '3'}, {'7', '4'}, {'7', '5'}, {'7', '6'}, {'7', '7'},
    {'7', '8'}, {'7', '9'}, {'7', 'a'}, {'7', 'b'}, {'7', 'c'}, {'7', 'd'},
    {'7', 'e'}, {'7', 'f'}, {'8', '0'}, {'8', '1'}, {'8', '2'}, {'8', '3'},
    {'8', '4'}, {'8', '5'}, {'8', '6'}, {'8', '7'}, {'8', '8'}, {'8', '9'},
    {'8', 'a'}, {'8', 'b'}, {'8', 'c'}, {'8', 'd'}, {'8', 'e'}, {'8', 'f'},
    {'9', '0'}, {'9', '1'}, {'9', '2'}, {'9', '3'}, {'9', '4'}, {'9', '5'},
    {'9', '6'}, {'9', '7'}, {'9', '8'}, {'9', '9'}, {'9', 'a'}, {'9', 'b'},
    {'9', 'c'}, {'9', 'd'}, {'9', 'e'}, {'9', 'f'}, {'a', '0'}, {'a', '1'},
    {'a', '2'}, {'a', '3'}, {'a', '4'}, {'a', '5'}, {'a', '6'}, {'a', '7'},
    {'a', '8'}, {'a', '9'}, {'a', 'a'}, {'a', 'b'}, {'a', 'c'}, {'a', 'd'},
    {'a', 'e'}, {'a', 'f'}, {'b', '0'}, {'b', '1'}, {'b', '2'}, {'b', '3'},
    {'b', '4'}, {'b', '5'}, {'b', '6'}, {'b', '7'}, {'b', '8'}, {'b', '9'},
    {'b', 'a'}, {'b', 'b'}, {'b', 'c'}, {'b', 'd'}, {'b', 'e'}, {'b', 'f'},
    {'c', '0'}, {'c', '1'}, {'c', '2'}, {'c', '3'}, {'c', '4'}, {'c', '5'},
    {'c', '6'}, {'c', '7'}, {'c', '8'}, {'c', '9'}, {'c', 'a'}, {'c', 'b'},
    {'c', 'c'}, {'c', 'd'}, {'c', 'e'}, {'c', 'f'}, {'d', '0'}, {'d', '1'},
    {'d', '2'}, {'d', '3'}, {'d', '4'}, {'d', '5'}, {'d', '6'}, {'d', '7'},
    {'d', '8'}, {'d', '9'}, {'d', 'a'}, {'d', 'b'}, {'d', 'c'}, {'d', 'd'},
    {'d', 'e'}, {'d', 'f'}, {'e', '0'}, {'e', '1'}, {'e', '2'}, {'e', '3'},
    {'e', '4'}, {'e', '5'}, {'e', '6'}, {'e', '7'}, {'e', '8'}, {'e', '9'},
    {'e', 'a'}, {'e', 'b'}, {'e', 'c'}, {'e', 'd'}, {'e', 'e'}, {'e', 'f'},
    {'f', '0'}, {'f', '1'}, {'f', '2'}, {'f', '3'}, {'f', '4'}, {'f', '5'},
    {'f', '6'}, {'f', '7'}, {'f', '8'}, {'f', '9'}, {'f', 'a'}, {'f', 'b'},
    {'f', 'c'}, {'f', 'd'}, {'f', 'e'}, {'f', 'f'},

};

static const int8_t HEX_CHAR_TO_UINT4[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0,  1,  2,  3,  4,  5,  6,  7,  8,
    9,  -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

void u8array_to_hex(char* out, const uint8_t* in, size_t inl)
{
    while (inl)
    {
        out[0] = U8ARRAY_TO_HEX_MAP[*in][0];
        out[1] = U8ARRAY_TO_HEX_MAP[*in][1];
        out += 2, in += 1, inl -= 1;
    }
    *out = '\0';
}

void uint8_to_hex(char out[3], uint8_t in)
{
    out[0] = U8ARRAY_TO_HEX_MAP[in][0];
    out[1] = U8ARRAY_TO_HEX_MAP[in][1];
    out[2] = '\0';
}

void uint16_to_hex(char out[5], uint16_t in)
{
    out[0] = U8ARRAY_TO_HEX_MAP[(in >> 8) & 0xFF][0];
    out[1] = U8ARRAY_TO_HEX_MAP[(in >> 8) & 0xFF][1];
    out[2] = U8ARRAY_TO_HEX_MAP[in & 0xFF][0];
    out[3] = U8ARRAY_TO_HEX_MAP[in & 0xFF][1];
    out[4] = '\0';
}

void uint32_to_hex(char out[9], uint32_t in)
{
    out[0] = U8ARRAY_TO_HEX_MAP[(in >> 24) & 0xFF][0];
    out[1] = U8ARRAY_TO_HEX_MAP[(in >> 24) & 0xFF][1];
    out[2] = U8ARRAY_TO_HEX_MAP[(in >> 16) & 0xFF][0];
    out[3] = U8ARRAY_TO_HEX_MAP[(in >> 16) & 0xFF][1];
    out[4] = U8ARRAY_TO_HEX_MAP[(in >> 8) & 0xFF][0];
    out[5] = U8ARRAY_TO_HEX_MAP[(in >> 8) & 0xFF][1];
    out[6] = U8ARRAY_TO_HEX_MAP[in & 0xFF][0];
    out[7] = U8ARRAY_TO_HEX_MAP[in & 0xFF][1];
    out[8] = '\0';
}

void uint64_to_hex(char out[17], uint64_t in)
{
    uint32_t in_h = (in >> 32) & UINT32_MAX;
    uint32_t in_l = in & UINT32_MAX;
    uint32_to_hex(out, in_h);
    uint32_to_hex(out + 8, in_l);
    out[16] = '\0';
}

int hex_to_u8array(uint8_t* out, const char* in, size_t inl)
{
    if (inl % 2 != 0) return -1;
    for (int i = 0; i < inl / 2; i++)
    {
        uint8_t u4high = (uint8_t)HEX_CHAR_TO_UINT4[in[2 * i + 0]];
        if (u4high == (uint8_t)(-1)) return -1;
        uint8_t u4low = (uint8_t)HEX_CHAR_TO_UINT4[in[2 * i + 1]];
        if (u4low == (uint8_t)(-1)) return -1;
        out[i] = (u4high << 4) | u4low;
    }
    return 0;
}

static bool hex_check(const char* in, size_t inl)
{
    for (size_t i = 0; i < inl; i++)
    {
        if (HEX_CHAR_TO_UINT4[in[i]] == -1)
        {
            return false;
        }
    }
    return true;
}

int hex_to_uint8(uint8_t* out, const char in[2])
{
    if (!hex_check(in, 2))
    {
        return -1;
    }
    *out = hex_to_uint8_f(in);
    return 0;
}

int hex_to_uint16(uint16_t* out, const char in[4])
{
    if (!hex_check(in, 4))
    {
        return -1;
    }
    *out = hex_to_uint16_f(in);
    return 0;
}

int hex_to_uint32(uint32_t* out, const char in[8])
{
    if (!hex_check(in, 8))
    {
        return -1;
    }
    *out = hex_to_uint32_f(in);
    return 0;
}

int hex_to_uint64(uint64_t* out, const char in[16])
{
    if (!hex_check(in, 16))
    {
        return -1;
    }
    *out = hex_to_uint64_f(in);
    return 0;
}

uint8_t hex_to_uint8_f(const char in[2])
{
    return (uint8_t)HEX_CHAR_TO_UINT4[in[0]] << 4 |
           (uint8_t)HEX_CHAR_TO_UINT4[in[1]];
}

uint16_t hex_to_uint16_f(const char in[4])
{
    return (uint16_t)HEX_CHAR_TO_UINT4[in[0]] << 12 |
           (uint16_t)HEX_CHAR_TO_UINT4[in[1]] << 8 |
           (uint16_t)HEX_CHAR_TO_UINT4[in[2]] << 4 |
           (uint16_t)HEX_CHAR_TO_UINT4[in[3]];
}

uint32_t hex_to_uint32_f(const char in[8])
{
    return (uint32_t)HEX_CHAR_TO_UINT4[in[0]] << 28 |
           (uint32_t)HEX_CHAR_TO_UINT4[in[1]] << 24 |
           (uint32_t)HEX_CHAR_TO_UINT4[in[2]] << 20 |
           (uint32_t)HEX_CHAR_TO_UINT4[in[3]] << 16 |
           (uint32_t)HEX_CHAR_TO_UINT4[in[4]] << 12 |
           (uint32_t)HEX_CHAR_TO_UINT4[in[5]] << 8 |
           (uint32_t)HEX_CHAR_TO_UINT4[in[6]] << 4 |
           (uint32_t)HEX_CHAR_TO_UINT4[in[7]];
}

uint64_t hex_to_uint64_f(const char in[16])
{
    return (uint64_t)hex_to_uint32_f(in) << 32 |
           (uint64_t)hex_to_uint32_f(in + 8);
}

}; // namespace tc