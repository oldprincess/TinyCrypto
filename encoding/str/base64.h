/**
 * RFC 4648: The Base16, Base32, and Base64 Data Encodings
 * https://www.rfc-editor.org/rfc/rfc4648
 */
#ifndef _TINY_CRYPTO_ENCODING_BASE64_H
#define _TINY_CRYPTO_ENCODING_BASE64_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

namespace tc {

bool base64_is_b64(const char* in, size_t inl);

size_t base64_encode_outl(size_t inl);

size_t base64_encode_strl(size_t inl);

size_t base64_decode_outl(const char* in, size_t inl);

void base64_encode(char* out, const uint8_t* in, size_t inl);

void base64_decode(uint8_t* out, const char* in, size_t inl);

} // namespace tc

#endif