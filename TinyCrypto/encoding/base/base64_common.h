/*
The MIT License (MIT)

Copyright (c) 2023 oldprincess, https://github.com/oldprincess/TinyCrypto

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
*/

/**
 * RFC 4648: The Base16, Base32, and Base64 Data Encodings
 * https://www.rfc-editor.org/rfc/rfc4648
 */
#ifndef TINY_CRYPTO_ENCODING_BASE64_H
#define TINY_CRYPTO_ENCODING_BASE64_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

namespace tc {

/**
 * @example
 *
 *
 */

/**
 * @brief       Test whether the string conforms to BASE64 format
 * @param in    input string
 * @param inl   input length, strlen(in) = inl
 * @return true/false
 */
bool base64_common_is_b64(const char* in, size_t inl);

/**
 * @brief       calculate the length after base64 encoding
 * @param inl   input string length
 * @return      coding length, included '\0'
 */
size_t base64_common_encode_outl(size_t inl);

/**
 * @brief       calculate the length after base64 encoding
 * @param inl   input string length
 * @return      coding length, not included '\0'
 */
size_t base64_common_encode_strl(size_t inl);

/**
 * @brief       calculate the length after base64 decoding
 * @param in    input base64 string
 * @param inl   input string length
 * @return      decoded length
 */
size_t base64_common_decode_outl(const char* in, size_t inl);

/**
 * @brief       base64 encode
 * @param out   base64 coding, end with '\0'
 * @param in    input data, inl bytes
 * @param inl   input length
 */
void base64_common_encode(char* out, const uint8_t* in, size_t inl);

/**
 * @brief       base64 decode
 * @param out   output data
 * @param in    input string
 * @param inl   input length, not included '\0'
 * @return 0(success), -1(invalid input string)
 */
int base64_common_decode(uint8_t* out, const char* in, size_t inl);

} // namespace tc

#endif