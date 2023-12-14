#ifndef _TINY_CRYPTO_PKC_BN_UINT256_H
#define _TINY_CRYPTO_PKC_BN_UINT256_H

#include <stdint.h>
#include <stdbool.h>

namespace tc {

// ****************************************
// ************ Arithmetic ****************
// ****************************************

int uint256_add_carry(uint32_t       sum[8],
                      const uint32_t augend[8],
                      const uint32_t addend[8]);

int uint256_sub_borrow(uint32_t       difference[8],
                       const uint32_t minuend[8],
                       const uint32_t subtrahend[8]);

int uint256_dbl_carry(uint32_t product[8], const uint32_t multiplier[8]);

int uint256_tpl_carry(uint32_t product[8], const uint32_t multiplier[8]);

void uint256_mul(uint32_t       product[16],
                 const uint32_t multiplier[8],
                 const uint32_t multiplicand[8]);

void uint256_sqr(uint32_t product[16], const uint32_t multiplier[8]);

int uint256_add_carry_uint32(uint32_t       sum[8],
                             const uint32_t augend[8],
                             uint32_t       addend);

int uint256_sub_borrow_uint32(uint32_t       difference[8],
                              const uint32_t minuend[8],
                              uint32_t       subtrahend);

uint32_t uint256_mul_carry_uint32(uint32_t       product[8],
                                  const uint32_t multiplier[8],
                                  uint32_t       multiplicand);

// ****************************************
// *************** Compare ****************
// ****************************************

int uint256_cmp(const uint32_t a[8], const uint32_t b[8]);

int uint256_cmp_uint32(const uint32_t a[8], uint32_t b);

bool uint256_equal(const uint32_t a[8], const uint32_t b[8]);

bool uint256_equal_zero(const uint32_t a[8]);

bool uint256_equal_one(const uint32_t a[8]);

// ****************************************
// ************* Set & Move ***************
// ****************************************

void uint256_cpy(uint32_t ret[8], const uint32_t num[8]);

void uint256_set_zero(uint32_t num[8]);

void uint256_set_one(uint32_t num[8]);

void uint256_set_uint32(uint32_t ret[8], uint32_t num);

// ****************************************
// *************** Convert ****************
// ****************************************

void uint256_from_bytes(uint32_t ret[8], const uint8_t bytes[32]);

void uint256_to_bytes(uint8_t bytes[32], const uint32_t num[8]);

// ****************************************
// ********** Bit Manipulation ************
// ****************************************

bool uint256_bittest(const uint32_t num[8], int i);

}; // namespace tc

#endif // !_TINY_CRYPTO_PKC_BN_UINT256_H
