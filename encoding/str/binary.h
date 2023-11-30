#ifndef _TINY_CRYPTO_ENCODE_BINARY_H
#define _TINY_CRYPTO_ENCODE_BINARY_H

#include <stdint.h>
#include <stddef.h>

namespace tc {

static inline size_t u8array_to_bin_outl(size_t inl)
{
    return 8 * inl + 1;
}

static inline size_t u8array_to_bin_strl(size_t inl)
{
    return 8 * inl;
}

static inline size_t bin_to_u8array_outl(size_t inl)
{
    return inl / 8;
}

void u8array_to_bin(char* out, const uint8_t* in, size_t inl);

void uint8_to_bin(char out[9], uint8_t in);

void uint16_to_bin(char out[17], uint16_t in);

void uint32_to_bin(char out[33], uint32_t in);

void uint64_to_bin(char out[65], uint64_t in);

int bin_to_u8array(uint8_t* out, const char* in, size_t inl);

int bin_to_uint8(uint8_t* out, const char in[8]);

int bin_to_uint16(uint16_t* out, const char in[16]);

int bin_to_uint32(uint32_t* out, const char in[32]);

int bin_to_uint64(uint64_t* out, const char in[64]);

uint8_t bin_to_uint8_f(const char in[8]);

uint16_t bin_to_uint16_f(const char in[16]);

uint32_t bin_to_uint32_f(const char in[32]);

uint64_t bin_to_uint64_f(const char in[64]);

}; // namespace tc

#endif