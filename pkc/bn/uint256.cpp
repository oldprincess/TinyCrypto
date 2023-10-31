#include "uint256.h"
#include <assert.h>

namespace tc {

/// @brief r = a + b + carry
/// @return (1/0)
static inline int _add_carry(uint32_t* r, uint32_t a, uint32_t b, int carry)
{
    uint64_t tmp = (uint64_t)a + (uint64_t)b + carry;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

/// @brief  r = 2a + carry
/// @return (1/0)
static inline int _dbl_carry(uint32_t* r, uint32_t a, int carry)
{
    uint64_t tmp = (uint64_t)a + (uint64_t)a + carry;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

/// @brief r = 3a + carry
/// @return (2/1/0)
static inline int _tpl_carry(uint32_t* r, uint32_t a, int carry)
{
    uint64_t tmp = (uint64_t)a + (uint64_t)a + (uint64_t)a + carry;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

/// @brief r = a - b + borrow
/// @return (-1/0)
static inline int _sub_borrow(uint32_t* r, uint32_t a, uint32_t b, int borrow)
{
    uint64_t tmp = (uint64_t)a - (uint64_t)b + borrow;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

/// @brief r = a * b + carry
/// @return [0,2^32)
static inline uint32_t _mul_carry(uint32_t* r,
                                  uint32_t  a,
                                  uint32_t  b,
                                  uint32_t  carry)
{
    uint64_t tmp = (uint64_t)a * (uint64_t)b + carry;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

/// @brief r += n * mulVal + carry
/// @return [0,2^32)
static inline uint32_t _add_mul_carry(uint32_t* r,
                                      uint32_t  n,
                                      uint32_t  mulVal,
                                      uint32_t  carry)
{
    uint64_t tmp = (uint64_t)n * (uint64_t)mulVal + *r + carry;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

static inline uint32_t MEM_LOAD32BE(const void* src)
{
    return ((uint32_t)(((uint8_t*)src)[0]) << 24) |
           ((uint32_t)(((uint8_t*)src)[1]) << 16) |
           ((uint32_t)(((uint8_t*)src)[2]) << 8) |
           ((uint32_t)(((uint8_t*)src)[3]) << 0);
}

static inline void MEM_STORE32BE(void* dst, uint32_t a)
{
    ((uint8_t*)dst)[0] = ((uint32_t)a >> 24) & 0xFF;
    ((uint8_t*)dst)[1] = ((uint32_t)a >> 16) & 0xFF;
    ((uint8_t*)dst)[2] = ((uint32_t)a >> 8) & 0xFF;
    ((uint8_t*)dst)[3] = ((uint32_t)a >> 0) & 0xFF;
}

// ****************************************
// ************ Arithmetic ****************
// ****************************************

int uint256_add_carry(uint32_t       sum[8],
                      const uint32_t augend[8],
                      const uint32_t addend[8])
{
    int carry;
    carry = _add_carry(&sum[0], augend[0], addend[0], 0);
    carry = _add_carry(&sum[1], augend[1], addend[1], carry);
    carry = _add_carry(&sum[2], augend[2], addend[2], carry);
    carry = _add_carry(&sum[3], augend[3], addend[3], carry);
    carry = _add_carry(&sum[4], augend[4], addend[4], carry);
    carry = _add_carry(&sum[5], augend[5], addend[5], carry);
    carry = _add_carry(&sum[6], augend[6], addend[6], carry);
    carry = _add_carry(&sum[7], augend[7], addend[7], carry);
    return carry;
}

int uint256_sub_borrow(uint32_t       difference[8],
                       const uint32_t minuend[8],
                       const uint32_t subtrahend[8])
{
    int borrow;
    borrow = _sub_borrow(&difference[0], minuend[0], subtrahend[0], 0);
    borrow = _sub_borrow(&difference[1], minuend[1], subtrahend[1], borrow);
    borrow = _sub_borrow(&difference[2], minuend[2], subtrahend[2], borrow);
    borrow = _sub_borrow(&difference[3], minuend[3], subtrahend[3], borrow);
    borrow = _sub_borrow(&difference[4], minuend[4], subtrahend[4], borrow);
    borrow = _sub_borrow(&difference[5], minuend[5], subtrahend[5], borrow);
    borrow = _sub_borrow(&difference[6], minuend[6], subtrahend[6], borrow);
    borrow = _sub_borrow(&difference[7], minuend[7], subtrahend[7], borrow);
    return borrow;
}

int uint256_dbl_carry(uint32_t product[8], const uint32_t multiplier[8])
{
    int carry;
    carry = _dbl_carry(&product[0], multiplier[0], 0);
    carry = _dbl_carry(&product[1], multiplier[1], carry);
    carry = _dbl_carry(&product[2], multiplier[2], carry);
    carry = _dbl_carry(&product[3], multiplier[3], carry);
    carry = _dbl_carry(&product[4], multiplier[4], carry);
    carry = _dbl_carry(&product[5], multiplier[5], carry);
    carry = _dbl_carry(&product[6], multiplier[6], carry);
    carry = _dbl_carry(&product[7], multiplier[7], carry);
    return carry;
}

int uint256_tpl_carry(uint32_t product[8], const uint32_t multiplier[8])
{
    int carry;
    carry = _tpl_carry(&product[0], multiplier[0], 0);
    carry = _tpl_carry(&product[1], multiplier[1], carry);
    carry = _tpl_carry(&product[2], multiplier[2], carry);
    carry = _tpl_carry(&product[3], multiplier[3], carry);
    carry = _tpl_carry(&product[4], multiplier[4], carry);
    carry = _tpl_carry(&product[5], multiplier[5], carry);
    carry = _tpl_carry(&product[6], multiplier[6], carry);
    carry = _tpl_carry(&product[7], multiplier[7], carry);
    return carry;
}

void uint256_mul(uint32_t       product[16],
                 const uint32_t multiplier[8],
                 const uint32_t multiplicand[8])
{
    uint32_t carry;
    // step 0
    carry = _mul_carry(&product[0], multiplier[0], multiplicand[0], 0);
    carry = _mul_carry(&product[1], multiplier[1], multiplicand[0], carry);
    carry = _mul_carry(&product[2], multiplier[2], multiplicand[0], carry);
    carry = _mul_carry(&product[3], multiplier[3], multiplicand[0], carry);
    carry = _mul_carry(&product[4], multiplier[4], multiplicand[0], carry);
    carry = _mul_carry(&product[5], multiplier[5], multiplicand[0], carry);
    carry = _mul_carry(&product[6], multiplier[6], multiplicand[0], carry);
    carry = _mul_carry(&product[7], multiplier[7], multiplicand[0], carry);

    product[8] = carry;
    // step 1
    carry = _add_mul_carry(&product[1], multiplier[0], multiplicand[1], 0);
    carry = _add_mul_carry(&product[2], multiplier[1], multiplicand[1], carry);
    carry = _add_mul_carry(&product[3], multiplier[2], multiplicand[1], carry);
    carry = _add_mul_carry(&product[4], multiplier[3], multiplicand[1], carry);
    carry = _add_mul_carry(&product[5], multiplier[4], multiplicand[1], carry);
    carry = _add_mul_carry(&product[6], multiplier[5], multiplicand[1], carry);
    carry = _add_mul_carry(&product[7], multiplier[6], multiplicand[1], carry);
    carry = _add_mul_carry(&product[8], multiplier[7], multiplicand[1], carry);
    product[9] = carry;
    // step 2
    carry = _add_mul_carry(&product[2], multiplier[0], multiplicand[2], 0);
    carry = _add_mul_carry(&product[3], multiplier[1], multiplicand[2], carry);
    carry = _add_mul_carry(&product[4], multiplier[2], multiplicand[2], carry);
    carry = _add_mul_carry(&product[5], multiplier[3], multiplicand[2], carry);
    carry = _add_mul_carry(&product[6], multiplier[4], multiplicand[2], carry);
    carry = _add_mul_carry(&product[7], multiplier[5], multiplicand[2], carry);
    carry = _add_mul_carry(&product[8], multiplier[6], multiplicand[2], carry);
    carry = _add_mul_carry(&product[9], multiplier[7], multiplicand[2], carry);
    product[10] = carry;
    // step 3
    carry = _add_mul_carry(&product[3], multiplier[0], multiplicand[3], 0);
    carry = _add_mul_carry(&product[4], multiplier[1], multiplicand[3], carry);
    carry = _add_mul_carry(&product[5], multiplier[2], multiplicand[3], carry);
    carry = _add_mul_carry(&product[6], multiplier[3], multiplicand[3], carry);
    carry = _add_mul_carry(&product[7], multiplier[4], multiplicand[3], carry);
    carry = _add_mul_carry(&product[8], multiplier[5], multiplicand[3], carry);
    carry = _add_mul_carry(&product[9], multiplier[6], multiplicand[3], carry);
    carry = _add_mul_carry(&product[10], multiplier[7], multiplicand[3], carry);
    product[11] = carry;
    // step 4
    carry = _add_mul_carry(&product[4], multiplier[0], multiplicand[4], 0);
    carry = _add_mul_carry(&product[5], multiplier[1], multiplicand[4], carry);
    carry = _add_mul_carry(&product[6], multiplier[2], multiplicand[4], carry);
    carry = _add_mul_carry(&product[7], multiplier[3], multiplicand[4], carry);
    carry = _add_mul_carry(&product[8], multiplier[4], multiplicand[4], carry);
    carry = _add_mul_carry(&product[9], multiplier[5], multiplicand[4], carry);
    carry = _add_mul_carry(&product[10], multiplier[6], multiplicand[4], carry);
    carry = _add_mul_carry(&product[11], multiplier[7], multiplicand[4], carry);
    product[12] = carry;
    // step 5
    carry = _add_mul_carry(&product[5], multiplier[0], multiplicand[5], 0);
    carry = _add_mul_carry(&product[6], multiplier[1], multiplicand[5], carry);
    carry = _add_mul_carry(&product[7], multiplier[2], multiplicand[5], carry);
    carry = _add_mul_carry(&product[8], multiplier[3], multiplicand[5], carry);
    carry = _add_mul_carry(&product[9], multiplier[4], multiplicand[5], carry);
    carry = _add_mul_carry(&product[10], multiplier[5], multiplicand[5], carry);
    carry = _add_mul_carry(&product[11], multiplier[6], multiplicand[5], carry);
    carry = _add_mul_carry(&product[12], multiplier[7], multiplicand[5], carry);
    product[13] = carry;
    // step 6
    carry = _add_mul_carry(&product[6], multiplier[0], multiplicand[6], 0);
    carry = _add_mul_carry(&product[7], multiplier[1], multiplicand[6], carry);
    carry = _add_mul_carry(&product[8], multiplier[2], multiplicand[6], carry);
    carry = _add_mul_carry(&product[9], multiplier[3], multiplicand[6], carry);
    carry = _add_mul_carry(&product[10], multiplier[4], multiplicand[6], carry);
    carry = _add_mul_carry(&product[11], multiplier[5], multiplicand[6], carry);
    carry = _add_mul_carry(&product[12], multiplier[6], multiplicand[6], carry);
    carry = _add_mul_carry(&product[13], multiplier[7], multiplicand[6], carry);
    product[14] = carry;
    // step 7
    carry = _add_mul_carry(&product[7], multiplier[0], multiplicand[7], 0);
    carry = _add_mul_carry(&product[8], multiplier[1], multiplicand[7], carry);
    carry = _add_mul_carry(&product[9], multiplier[2], multiplicand[7], carry);
    carry = _add_mul_carry(&product[10], multiplier[3], multiplicand[7], carry);
    carry = _add_mul_carry(&product[11], multiplier[4], multiplicand[7], carry);
    carry = _add_mul_carry(&product[12], multiplier[5], multiplicand[7], carry);
    carry = _add_mul_carry(&product[13], multiplier[6], multiplicand[7], carry);
    carry = _add_mul_carry(&product[14], multiplier[7], multiplicand[7], carry);
    product[15] = carry;
}

void uint256_sqr(uint32_t product[16], const uint32_t multiplier[8])
{
    uint256_mul(product, multiplier, multiplier);
}

int uint256_add_carry_uint32(uint32_t       sum[8],
                             const uint32_t augend[8],
                             uint32_t       addend)
{
    int carry;
    carry = _add_carry(&sum[0], augend[0], addend, 0);
    carry = _add_carry(&sum[1], augend[1], 0, carry);
    carry = _add_carry(&sum[2], augend[2], 0, carry);
    carry = _add_carry(&sum[3], augend[3], 0, carry);
    carry = _add_carry(&sum[4], augend[4], 0, carry);
    carry = _add_carry(&sum[5], augend[5], 0, carry);
    carry = _add_carry(&sum[6], augend[6], 0, carry);
    carry = _add_carry(&sum[7], augend[7], 0, carry);
    return carry;
}

int uint256_sub_borrow_uint32(uint32_t       difference[8],
                              const uint32_t minuend[8],
                              uint32_t       subtrahend)
{
    int borrow;
    borrow = _sub_borrow(&difference[0], minuend[0], subtrahend, 0);
    borrow = _sub_borrow(&difference[1], minuend[1], 0, borrow);
    borrow = _sub_borrow(&difference[2], minuend[2], 0, borrow);
    borrow = _sub_borrow(&difference[3], minuend[3], 0, borrow);
    borrow = _sub_borrow(&difference[4], minuend[4], 0, borrow);
    borrow = _sub_borrow(&difference[5], minuend[5], 0, borrow);
    borrow = _sub_borrow(&difference[6], minuend[6], 0, borrow);
    borrow = _sub_borrow(&difference[7], minuend[7], 0, borrow);
    return borrow;
}

uint32_t uint256_mul_carry_uint32(uint32_t       product[8],
                                  const uint32_t multiplier[8],
                                  uint32_t       multiplicand)
{
    uint32_t carry;
    carry = _mul_carry(&product[0], multiplier[0], multiplicand, 0);
    carry = _mul_carry(&product[1], multiplier[1], multiplicand, carry);
    carry = _mul_carry(&product[2], multiplier[2], multiplicand, carry);
    carry = _mul_carry(&product[3], multiplier[3], multiplicand, carry);
    carry = _mul_carry(&product[4], multiplier[4], multiplicand, carry);
    carry = _mul_carry(&product[5], multiplier[5], multiplicand, carry);
    carry = _mul_carry(&product[6], multiplier[6], multiplicand, carry);
    carry = _mul_carry(&product[7], multiplier[7], multiplicand, carry);
    return carry;
}

// ****************************************
// *************** Compare ****************
// ****************************************

int uint256_cmp(const uint32_t a[8], const uint32_t b[8])
{
    for (int i = 7; i >= 0; i--)
    {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

int uint256_cmp_uint32(const uint32_t a[8], uint32_t b)
{
    for (int i = 7; i >= 1; i--)
    {
        if (a[i] > 0) return 1;
    }
    if (a[0] > b) return 1;
    if (a[0] < b) return -1;
    return 0;
}

bool uint256_equal(const uint32_t a[8], const uint32_t b[8])
{
    return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2]) | (a[3] ^ b[3]) |
            (a[4] ^ b[4]) | (a[5] ^ b[5]) | (a[6] ^ b[6]) | (a[7] ^ b[7])) == 0;
}

bool uint256_equal_zero(const uint32_t a[8])
{
    return (a[0] | a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7]) == 0;
}

bool uint256_equal_one(const uint32_t a[8])
{
    return ((a[1] | a[2] | a[3] | a[4] | a[5] | a[6] | a[7]) == 0) &&
           (a[0] == 1);
}

// ****************************************
// ************* Set & Move ***************
// ****************************************

void uint256_cpy(uint32_t ret[8], const uint32_t num[8])
{
    ret[0] = num[0], ret[1] = num[1], ret[2] = num[2], ret[3] = num[3];
    ret[4] = num[4], ret[5] = num[5], ret[6] = num[6], ret[7] = num[7];
}

void uint256_set_zero(uint32_t num[8])
{
    num[0] = num[1] = num[2] = num[3] = num[4] = num[5] = num[6] = num[7] = 0;
}

void uint256_set_one(uint32_t num[8])
{
    num[0] = 1;
    num[1] = num[2] = num[3] = num[4] = num[5] = num[6] = num[7] = 0;
}

void uint256_set_uint32(uint32_t ret[8], uint32_t num)
{
    ret[0] = num;
    ret[1] = ret[2] = ret[3] = ret[4] = ret[5] = ret[6] = ret[7] = 0;
}

// ****************************************
// *************** Convert ****************
// ****************************************

void uint256_from_bytes(uint32_t ret[8], const uint8_t bytes[32])
{
    ret[7] = MEM_LOAD32BE(bytes + 0);
    ret[6] = MEM_LOAD32BE(bytes + 4);
    ret[5] = MEM_LOAD32BE(bytes + 8);
    ret[4] = MEM_LOAD32BE(bytes + 12);
    ret[3] = MEM_LOAD32BE(bytes + 16);
    ret[2] = MEM_LOAD32BE(bytes + 20);
    ret[1] = MEM_LOAD32BE(bytes + 24);
    ret[0] = MEM_LOAD32BE(bytes + 28);
}

void uint256_to_bytes(uint8_t bytes[32], const uint32_t num[8])
{
    MEM_STORE32BE(bytes + 0, num[7]);
    MEM_STORE32BE(bytes + 4, num[6]);
    MEM_STORE32BE(bytes + 8, num[5]);
    MEM_STORE32BE(bytes + 12, num[4]);
    MEM_STORE32BE(bytes + 16, num[3]);
    MEM_STORE32BE(bytes + 20, num[2]);
    MEM_STORE32BE(bytes + 24, num[1]);
    MEM_STORE32BE(bytes + 28, num[0]);
}

// ****************************************
// ********** Bit Manipulation ************
// ****************************************

bool uint256_bittest(const uint32_t num[8], int i)
{
    return ((num[i / 32] >> (i % 32)) & 1) == 1;
}

}; // namespace tc