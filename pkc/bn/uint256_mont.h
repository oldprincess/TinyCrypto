#ifndef _TINY_CRYPTO_PKC_BN_UINT256_MONT_H
#define _TINY_CRYPTO_PKC_BN_UINT256_MONT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

namespace tc {

// ++++++++++++++++++++++++++++++++++++++++++++++++++
// **************************************************
// ************** UINT256 Montgeomery ***************
// **************************************************
// ++++++++++++++++++++++++++++++++++++++++++++++++++

typedef struct Mont256CTX
{
    const uint32_t* P;      // 8x32-bit: p
    const uint32_t* P_SUB2; // 8x32-bit: p - 2
    const uint32_t* R;      // 8x32-bit: 2^256 mod p
    const uint32_t* R_POW2; // 8x32-bit: R^2 mod p
    const uint32_t  N_;     // 8x32-bit: N':N'*p=-1 mod B, B=2^32, R=B^8
} Mont256CTX;

// ****************************************
// ************ Arithmetic ****************
// ****************************************

void uint256_mont_add(const Mont256CTX* ctx,
                      uint32_t          sum[8],
                      const uint32_t    augend[8],
                      const uint32_t    addend[8]);

void uint256_mont_sub(const Mont256CTX* ctx,
                      uint32_t          difference[8],
                      const uint32_t    minuend[8],
                      const uint32_t    subtrahend[8]);

void uint256_mont_dbl(const Mont256CTX* ctx,
                      uint32_t          product[8],
                      const uint32_t    multiplier[8]);

void uint256_mont_tpl(const Mont256CTX* ctx,
                      uint32_t          product[8],
                      const uint32_t    multiplier[8]);

void uint256_mont_neg(const Mont256CTX* ctx,
                      uint32_t          ret[8],
                      const uint32_t    num[8]);

void uint256_mont_mul(const Mont256CTX* ctx,
                      uint32_t          product[8],
                      const uint32_t    multiplier[8],
                      const uint32_t    multiplicand[8]);

void uint256_mont_sqr(const Mont256CTX* ctx,
                      uint32_t          product[8],
                      const uint32_t    multiplier[8]);

void uint256_mont_div2(const Mont256CTX* ctx,
                       uint32_t          quotient[8],
                       const uint32_t    dividend[8]);

void uint256_mont_pow(const Mont256CTX* ctx,
                      uint32_t          power[8],
                      const uint32_t    base[8],
                      const uint32_t    exponent[8]);

void uint256_mont_inv(const Mont256CTX* ctx,
                      uint32_t          inverse[8],
                      const uint32_t    num[8]);

// ****************************************
// *************** Compare ****************
// ****************************************

bool uint256_mont_equal(const Mont256CTX* ctx,
                        const uint32_t    a[8],
                        const uint32_t    b[8]);

bool uint256_mont_equal_zero(const Mont256CTX* ctx, const uint32_t a[8]);

bool uint256_mont_equal_one(const Mont256CTX* ctx, const uint32_t a[8]);

// ****************************************
// ************* Set & Move ***************
// ****************************************

void uint256_mont_cpy(const Mont256CTX* ctx,
                      uint32_t          ret[8],
                      const uint32_t    num[8]);

void uint256_mont_set_zero(const Mont256CTX* ctx, uint32_t num[8]);

void uint256_mont_set_one(const Mont256CTX* ctx, uint32_t num[8]);

void uint256_mont_set_uint32(const Mont256CTX* ctx,
                             uint32_t          ret[8],
                             uint32_t          num);

// ****************************************
// *************** Convert ****************
// ****************************************

void uint256_mont_from_bytes(const Mont256CTX* ctx,
                             uint32_t          num[8],
                             const uint8_t     bytes[32]);

void uint256_mont_to_bytes(const Mont256CTX* ctx,
                           uint8_t           bytes[32],
                           const uint32_t    num[8]);

void uint256_mont_from_bytes_ex(const Mont256CTX* ctx,
                                uint32_t          num[8],
                                const uint8_t*    bytes,
                                size_t            bytes_len);

}; // namespace tc

#endif // !_TINY_CRYPTO_PKC_BN_UINT256_MONT_H