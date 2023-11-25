#ifndef _TINY_CRYPTO_ENCODING_STR_HEXADECIMAL_H
#define _TINY_CRYPTO_ENCODING_STR_HEXADECIMAL_H

#include <stdint.h>
#include <stddef.h>

namespace tc {

void u8array_to_hex(char* out, const uint8_t* in, size_t inl);

void uint8_to_hex(char out[3], uint8_t in);

void uint16_to_hex(char out[5], uint16_t in);

void uint32_to_hex(char out[9], uint32_t in);

void uint64_to_hex(char out[17], uint64_t in);

int hex_to_u8array(uint8_t* out, const char* in, size_t inl);

int hex_to_uint8(uint8_t* out, const char in[2]);

int hex_to_uint16(uint16_t* out, const char in[4]);

int hex_to_uint32(uint32_t* out, const char in[8]);

int hex_to_uint64(uint64_t* out, const char in[16]);

uint8_t hex_to_uint8_f(const char in[2]);

uint16_t hex_to_uint16_f(const char in[4]);

uint32_t hex_to_uint32_f(const char in[8]);

uint64_t hex_to_uint64_f(const char in[16]);

}; // namespace tc

#endif