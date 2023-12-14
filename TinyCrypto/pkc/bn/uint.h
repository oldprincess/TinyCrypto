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

#ifndef _TINYCRYPTO_PKC_BN_UINT_H
#define _TINYCRYPTO_PKC_BN_UINT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

namespace tc {

// ****************************************
// ************ Arithmetic ****************
// ****************************************

/**
 * @brief           unsigned addition, sum = augend + addend + carry
 * @param dsize     data size, 32-bit words size, never be 0
 * @param sum       32*dsize bit data
 * @param augend    32*dsize bit data
 * @param addend    32*dsize bit data
 * @param carry     carry input
 * @return carry bit (1/0)
 */
int uint_add_carry(size_t          dsize,
                   uint32_t*       sum,
                   const uint32_t* augend,
                   const uint32_t* addend,
                   int             carry);

/**
 * @brief               unsigned subtraction,
 *                      difference = minuend - subtrahend + borrow
 * @param dsize         data size, 32-bit words size, never be 0
 * @param difference    32*dsize bit data
 * @param minuend       32*dsize bit data
 * @param subtrahend    32*dsize bit data
 * @param borrow        borrow input
 * @return borrow bit(-1/0)
 */
int uint_sub_borrow(size_t          dsize,
                    uint32_t*       difference,
                    const uint32_t* minuend,
                    const uint32_t* subtrahend,
                    int             borrow);

/**
 * @brief               unsigned multiply, product = multiplier * multiplicand
 * @param dsize         data size,  32-bit words size, never be 0
 * @param product       2*32*dsize  bit data, does not allow memory overlap with
 *                      'multiplier' or 'multiplicand'
 * @param multiplier    32*dsize bit data
 * @param multiplicand  32*dsize bit data
 */
void uint_mul(size_t          dsize,
              uint32_t*       product,
              const uint32_t* multiplier,
              const uint32_t* multiplicand);

/**
 * @brief               unsigned square, product = multiplier^2
 * @param dsize         data size,  32-bit words size, never be 0
 * @param product       2*32*dsize  bit data
 * @param multiplier    32*dsize bit data
 */
void uint_sqr(size_t dsize, uint32_t* product, const uint32_t* multiplier);

/**
 * @brief               unsigned division,
 *                      dividend = quotient * divisor + remainder
 * @param dsize         data size,  32-bit words size, never be 0
 * @param quotient      32*dsize bit data, support NULL
 * @param remainder     32*dsize bit data, support NULL
 * @param dividend      32*dsize bit data
 * @param divisor       32*dsize bit data
 * @return Success(0), Error(-1)
 * @retval 0:   Success
 * @retval -1:  Error Happened, malloc fail or divisor=0
 */
int uint_div(size_t          dsize,
             uint32_t*       quotient,
             uint32_t*       remainder,
             const uint32_t* dividend,
             const uint32_t* divisor);

/**
 * @brief           unsigned addition, sum = augend + addend
 * @param dsize     data size, 32-bit words size, never be 0
 * @param sum       32*dsize bit data
 * @param augend    32*dsize bit data
 * @param addend    32 bit data
 * @return carry bit (1/0)
 */
int uint_add_carry_uint32(size_t          dsize,
                          uint32_t*       sum,
                          const uint32_t* augend,
                          uint32_t        addend);

/**
 * @brief               unsigned subtraction,
 *                      difference = minuend - subtrahend
 * @param dsize         data size, 32-bit words size, never be 0
 * @param difference    32*dsize bit data
 * @param minuend       32*dsize bit data
 * @param subtrahend    32 bit data
 * @return borrow bit(-1/0)
 */
int uint_sub_borrow_uint32(size_t          dsize,
                           uint32_t*       difference,
                           const uint32_t* minuend,
                           uint32_t        subtrahend);

/**
 * @brief               unsigned multiply, product = multiplier * multiplicand
 * @param dsize         data size,  32-bit words size, never be 0
 * @param product       32*dsize bit data
 * @param multiplier    32*dsize bit data
 * @param multiplicand  32 bit data
 */
uint32_t uint_mul_carry_uint32(size_t          dsize,
                               uint32_t*       product,
                               const uint32_t* multiplier,
                               uint32_t        multiplicand);

/**
 * @brief               unsigned division,
 *                      dividend = quotient * divisor + remainder
 * @param dsize         data size,  32-bit words size, never be 0
 * @param quotient      32*dsize bit data, support NULL
 * @param dividend      32 bit data
 * @param divisor       32*dsize bit data
 * @return 32-bit remainder
 */
uint32_t uint_div_uint32(size_t          dsize,
                         uint32_t*       quotient,
                         const uint32_t* dividend,
                         uint32_t        divisor);

// ****************************************
// *************** Compare ****************
// ****************************************

int uint_cmp(size_t dsize, const uint32_t* a, const uint32_t* b);

int uint_cmp_uint32(size_t dsize, const uint32_t* a, uint32_t b);

bool uint_equal(size_t dsize, const uint32_t* a, const uint32_t* b);

bool uint_equal_zero(size_t dsize, const uint32_t* a);

bool uint_equal_one(size_t dsize, const uint32_t* a);

// ****************************************
// ************* Set & Move ***************
// ****************************************

void uint_cpy(size_t dsize, uint32_t* ret, const uint32_t* num);

void uint_set_zero(size_t dsize, uint32_t* num);

void uint_set_one(size_t dsize, uint32_t* num);

void uint_set_uint32(size_t dsize, uint32_t* ret, uint32_t num);

// ****************************************
// *************** Logical ****************
// ****************************************

void uint_xor(size_t          dsize,
              uint32_t*       ret,
              const uint32_t* a,
              const uint32_t* b);

void uint_and(size_t          dsize,
              uint32_t*       ret,
              const uint32_t* a,
              const uint32_t* b);

void uint_or(size_t dsize, uint32_t* ret, const uint32_t* a, const uint32_t* b);

void uint_not(size_t dsize, uint32_t* ret, const uint32_t* a);

void uint_sll(size_t dsize, uint32_t* ret, const uint32_t* a, size_t s);

void uint_srl(size_t dsize, uint32_t* ret, const uint32_t* a, size_t s);

// ****************************************
// *************** Convert ****************
// ****************************************

/**
 * @brief               cast unsigned integer.
 *                      extension   if out_dsize > in_dsize,
 *                      truncation  if out_dsize < in_dsize,
 *                      copy        if out_dsize = in_dsize.
 * @param out           output unsigned integer
 * @param out_dsize     output dsize, 32*out_dsize bit data
 * @param in            input unsigned integer
 * @param in_dsize      input dsize, 32*in_dsize bit data
 */
void uint_cast(uint32_t*       out,
               size_t          out_dsize,
               const uint32_t* in,
               size_t          in_dsize);

/**
 * @brief           load from bytes, as big endian
 * @param dsize     data size,  32-bit words size, never be 0
 * @param ret       32*dsize bit data
 * @param bytes     8*dsize  byte data
 */
void uint_from_bytes(size_t dsize, uint32_t* ret, const uint8_t* bytes);

/**
 * @brief           store to bytes, as big endian
 * @param dsize     data size,  32-bit words size, never be 0
 * @param bytes     8*dsize  byte data
 * @param num       32*dsize bit data
 */
void uint_to_bytes(size_t dsize, uint8_t* bytes, const uint32_t* num);

/**
 * @brief           load uint from string
 * @param dsize     data size,  32-bit words size, never be 0
 * @param out       32*dsize bit data
 * @param in        input string, in 'radix' base
 * @param inl       input string length
 * @param radix     [2, 36]
 * @return 0 (Success), -1(Error)
 * @retval 0 (Success)
 * @retval -1(Invalid radix, or Invalid str, or str overflow)
 */
int uint_from_str(size_t      dsize,
                  uint32_t*   out,
                  const char* in,
                  size_t      inl,
                  int         radix);

/**
 * @brief           predict 'uint_to_str' output length, include '\0'
 * @param dsize     data size,  32-bit words size, never be 0
 * @param radix     [2, 36]
 * @return max outl
 * @retval -1, Invalid radix
 */
size_t uint_to_str_max_outl(size_t dsize, int radix);

/**
 * @brief
 * @param dsize     data size,  32-bit words size, never be 0
 * @param ret       output string, in 'radix' base
 * @param num       32*dsize bit data
 * @param radix     [2, 36]
 * @return 0 (Success), -1(Error)
 * @retval 0 (Success)
 * @retval -1(Invalid radix, or malloc fail)
 */
int uint_to_str(size_t dsize, char* ret, const uint32_t* num, int radix);

// ****************************************
// ********** Bit Manipulation ************
// ****************************************

/**
 * @brief           get bit length
 * @param dsize     data size,  32-bit words size, never be 0
 * @param num       32*dsize bit data
 * @return          bit length
 */
size_t uint_bitlength(size_t dsize, const uint32_t* num);

/**
 * @brief           test bit
 * @param dsize     data size,  32-bit words size, never be 0
 * @param num       32*dsize bit data
 * @param i         bit index, least significant
 * @return true(bit is 1), false(bit is 0 or outrange)
 */
bool uint_bittest(size_t dsize, const uint32_t* num, size_t i);

} // namespace tc

#endif