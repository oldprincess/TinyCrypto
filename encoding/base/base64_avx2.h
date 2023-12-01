#ifndef _TINY_CRYPTO_ENCODING_BASE64_AVX2_H
#define _TINY_CRYPTO_ENCODING_BASE64_AVX2_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

namespace tc {

bool base64_avx2_is_b64(const char* in, size_t inl);

size_t base64_avx2_encode_outl(size_t inl);

size_t base64_avx2_encode_strl(size_t inl);

size_t base64_avx2_decode_outl(const char* in, size_t inl);

void base64_avx2_encode(char* out, const uint8_t* in, size_t inl);

void base64_avx2_decode(uint8_t* out, const char* in, size_t inl);

} // namespace tc

#endif