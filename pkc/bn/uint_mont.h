#ifndef _TINY_CRYPTO_PCK_BN_UINT_MONT_H
#define _TINY_CRYPTO_PCK_BN_UINT_MONT_H

#include <stdint.h>
#include <stddef.h>

namespace tc {

typedef struct MontCTX
{
    const uint32_t* P;           // k*32-bit: p
    const uint32_t* P_SUB2;      // k*32-bit: p - 2
    const uint32_t* R;           // k*32-bit: 2^(32k) mod p
    const uint32_t* R_POW2;      // k*32-bit: R^2 mod p
    const uint32_t  N_;          // k*32-bit: N':N'*p=-1 mod B, B=2^32, R=B^k
    uint32_t*       PRODUCT_TMP; // (2k)*32-bit
} MontCTX;

void uint_mont_init(MontCTX*        ctx,
                    const uint32_t* P,
                    uint32_t*       P_SUB2,
                    uint32_t*       R,
                    uint32_t*       R_SUB2,
                    uint32_t*       R_POW2,
                    uint32_t*       product_tmp,
                    size_t          dsize);

// ****************************************
// ************ Arithmetic ****************
// ****************************************

void uint_mont_add(const MontCTX*  ctx,
                   uint32_t*       sum,
                   const uint32_t* augend,
                   const uint32_t* addend,
                   size_t          dsize);

void uint_mont_sub(const MontCTX*  ctx,
                   uint32_t*       difference,
                   const uint32_t* minuend,
                   const uint32_t* subtrahend,
                   size_t          dsize);

void uint_mont_dbl(const MontCTX*  ctx,
                   uint32_t*       product,
                   const uint32_t* multiplier,
                   size_t          dsize);

void uint_mont_tpl(const MontCTX*  ctx,
                   uint32_t*       product,
                   const uint32_t* multiplier,
                   size_t          dsize);

void uint_mont_neg(const MontCTX*  ctx,
                   uint32_t*       ret,
                   const uint32_t* num,
                   size_t          dsize);

void uint_mont_mul(const MontCTX*  ctx,
                   uint32_t*       product,
                   const uint32_t* multiplier,
                   const uint32_t* multiplicand,
                   size_t          dsize);

void uint_mont_sqr(const MontCTX*  ctx,
                   uint32_t*       product,
                   const uint32_t* multiplier,
                   size_t          dsize);

void uint_mont_div2(const MontCTX*  ctx,
                    uint32_t*       quotient,
                    const uint32_t* dividend,
                    size_t          dsize);

void uint_mont_pow(const MontCTX*  ctx,
                   uint32_t*       power,
                   const uint32_t* base,
                   const uint32_t* exponent,
                   size_t          dsize);

void uint_mont_inv(const MontCTX*  ctx,
                   uint32_t*       inverse,
                   const uint32_t* num,
                   size_t          dsize);

// ****************************************
// *************** Compare ****************
// ****************************************

bool uint_mont_equal(const MontCTX*  ctx,
                     const uint32_t* a,
                     const uint32_t* b,
                     size_t          dsize);

bool uint_mont_equal_zero(const MontCTX* ctx, const uint32_t* a, size_t dsize);

bool uint_mont_equal_one(const MontCTX* ctx, const uint32_t* a, size_t dsize);

// ****************************************
// ************* Set & Move ***************
// ****************************************

void uint_mont_cpy(const MontCTX*  ctx,
                   uint32_t*       ret,
                   const uint32_t* num,
                   size_t          dsize);

void uint_mont_set_zero(const MontCTX* ctx, uint32_t* num, size_t dsize);

void uint_mont_set_one(const MontCTX* ctx, uint32_t* num, size_t dsize);

void uint_mont_set_uint32(const MontCTX* ctx,
                          uint32_t*      ret,
                          uint32_t       num,
                          size_t         dsize);

// ****************************************
// *************** Convert ****************
// ****************************************

void uint_from_mont(const MontCTX*  ctx,
                    uint32_t*       ret,
                    const uint32_t* num,
                    size_t          dsize);

void uint_mont_from_bytes(const MontCTX* ctx,
                          uint32_t*      num,
                          const uint8_t* bytes,
                          size_t         dsize);

void uint_mont_to_bytes(const MontCTX* ctx,
                        uint8_t*       bytes,
                        const uint32_t num,
                        size_t         dsize);

} // namespace tc

#endif