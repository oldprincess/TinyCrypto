#include "uint256.h"
#include "uint256_mont.h"
#include <cassert>

namespace tc {

/// @brief r = a + b + carry
/// @return (1/0)
static inline int _add_carry(uint32_t* r, uint32_t a, uint32_t b, int carry)
{
    uint64_t tmp = (uint64_t)a + (uint64_t)b + carry;
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

static void uint256_mont_redc(const Mont256CTX* ctx,
                              uint32_t          r[8],
                              uint32_t          t[16])
{
    const uint32_t N_ = ctx->N_; // N':N'*N=-1 mod B, B=2^32, R=B^8

    uint32_t t16 = 0; // overflow
    for (int i = 0; i < 8; i++)
    {
        uint32_t carry = 0;
        uint32_t m     = (uint32_t)(t[i] * N_);

        carry = _add_mul_carry(&t[i + 0], m, ctx->P[0], 0);
        carry = _add_mul_carry(&t[i + 1], m, ctx->P[1], carry);
        carry = _add_mul_carry(&t[i + 2], m, ctx->P[2], carry);
        carry = _add_mul_carry(&t[i + 3], m, ctx->P[3], carry);
        carry = _add_mul_carry(&t[i + 4], m, ctx->P[4], carry);
        carry = _add_mul_carry(&t[i + 5], m, ctx->P[5], carry);
        carry = _add_mul_carry(&t[i + 6], m, ctx->P[6], carry);
        carry = _add_mul_carry(&t[i + 7], m, ctx->P[7], carry);

        int c = _add_carry(&t[i + 8], t[i + 8], carry, 0);
        for (int j = 9; j < 8 + 8 - i && c != 0; j++)
        {
            c = _add_carry(&t[i + j], t[i + j], 0, c);
        }
        t16 += c;
    }
    uint256_cpy(r, t + 8);
    if (t16 || uint256_cmp(r, ctx->P) >= 0)
    {
        uint256_sub_borrow(r, r, ctx->P);
    }
}

static void uint256_to_mont(const Mont256CTX* ctx,
                            uint32_t          r[8],
                            const uint32_t    a[8])
{
    uint256_mont_mul(ctx, r, a, ctx->R_POW2);
}

static void uint256_from_mont(const Mont256CTX* ctx,
                              uint32_t          r[8],
                              const uint32_t    a[8])
{
    uint32_t t[16];
    t[0] = a[0], t[1] = a[1], t[2] = a[2], t[3] = a[3];
    t[4] = a[4], t[5] = a[5], t[6] = a[6], t[7] = a[7];
    t[8] = t[9] = t[10] = t[11] = t[12] = t[13] = t[14] = t[15] = 0;
    uint256_mont_redc(ctx, r, t);
}

// ****************************************
// ************ Arithmetic ****************
// ****************************************

void uint256_mont_add(const Mont256CTX* ctx,
                      uint32_t          sum[8],
                      const uint32_t    augend[8],
                      const uint32_t    addend[8])
{
    int carry = uint256_add_carry(sum, augend, addend);
    if (carry || uint256_cmp(sum, ctx->P) >= 0)
    {
        uint256_sub_borrow(sum, sum, ctx->P);
    }
}

void uint256_mont_sub(const Mont256CTX* ctx,
                      uint32_t          difference[8],
                      const uint32_t    minuend[8],
                      const uint32_t    subtrahend[8])
{
    int borrow = uint256_sub_borrow(difference, minuend, subtrahend);
    if (borrow || uint256_cmp(difference, ctx->P) >= 0)
    {
        uint256_add_carry(difference, difference, ctx->P);
    }
}

void uint256_mont_dbl(const Mont256CTX* ctx,
                      uint32_t          product[8],
                      const uint32_t    multiplier[8])
{
    int carry = uint256_dbl_carry(product, multiplier);
    if (carry || uint256_cmp(product, ctx->P) >= 0)
    {
        uint256_sub_borrow(product, product, ctx->P);
    }
}

void uint256_mont_tpl(const Mont256CTX* ctx,
                      uint32_t          product[8],
                      const uint32_t    multiplier[8])
{
    int carry = uint256_tpl_carry(product, multiplier);
    while (carry)
    {
        carry += uint256_sub_borrow(product, product, ctx->P);
    }
    if (uint256_cmp(product, ctx->P) >= 0)
    {
        uint256_sub_borrow(product, product, ctx->P);
    }
}

void uint256_mont_neg(const Mont256CTX* ctx,
                      uint32_t          ret[8],
                      const uint32_t    num[8])
{
    if (uint256_equal_zero(num))
    {
        uint256_set_zero(ret);
    }
    uint256_sub_borrow(ret, ctx->P, num);
}

void uint256_mont_mul(const Mont256CTX* ctx,
                      uint32_t          product[8],
                      const uint32_t    multiplier[8],
                      const uint32_t    multiplicand[8])
{
    uint32_t T[16];
    uint256_mul(T, multiplier, multiplicand);
    uint256_mont_redc(ctx, product, T);
}

void uint256_mont_sqr(const Mont256CTX* ctx,
                      uint32_t          product[8],
                      const uint32_t    multiplier[8])
{
    uint32_t T[16];
    uint256_sqr(T, multiplier);
    uint256_mont_redc(ctx, product, T);
}

void uint256_mont_div2(const Mont256CTX* ctx,
                       uint32_t          quotient[8],
                       const uint32_t    dividend[8])
{
    assert(0);
}

void uint256_mont_pow(const Mont256CTX* ctx,
                      uint32_t          power[8],
                      const uint32_t    base[8],
                      const uint32_t    exponent[8])
{
    if (uint256_equal_zero(exponent))
    {
        uint256_set_zero(power);
        return;
    }

    uint32_t mont_t[8];

    int i = 255;
    while (uint256_bittest(exponent, i) == 0) i -= 1;
    uint256_cpy(mont_t, base);
    i -= 1;
    for (; i >= 0; i--)
    {
        uint256_mont_sqr(ctx, mont_t, mont_t);
        if (uint256_bittest(exponent, i))
        {
            uint256_mont_mul(ctx, mont_t, mont_t, base);
        }
    }
    uint256_cpy(power, mont_t);
}

void uint256_mont_inv(const Mont256CTX* ctx,
                      uint32_t          inverse[8],
                      const uint32_t    num[8])
{
    uint256_mont_pow(ctx, inverse, num, ctx->P_SUB2);
}

// ****************************************
// *************** Compare ****************
// ****************************************

bool uint256_mont_equal(const Mont256CTX* ctx,
                        const uint32_t    a[8],
                        const uint32_t    b[8])
{
    return uint256_equal(a, b);
}

bool uint256_mont_equal_zero(const Mont256CTX* ctx, const uint32_t a[8])
{
    return uint256_equal_zero(a);
}

bool uint256_mont_equal_one(const Mont256CTX* ctx, const uint32_t a[8])
{
    return uint256_equal(a, ctx->R);
}

// ****************************************
// ************* Set & Move ***************
// ****************************************

void uint256_mont_cpy(const Mont256CTX* ctx,
                      uint32_t          ret[8],
                      const uint32_t    num[8])
{
    uint256_cpy(ret, num);
}

void uint256_mont_set_zero(const Mont256CTX* ctx, uint32_t num[8])
{
    uint256_set_zero(num);
}

void uint256_mont_set_one(const Mont256CTX* ctx, uint32_t ret[8])
{
    uint256_cpy(ret, ctx->R);
}

void uint256_mont_set_uint32(const Mont256CTX* ctx,
                             uint32_t          ret[8],
                             uint32_t          num)
{
    uint256_set_uint32(ret, num);
    uint256_to_mont(ctx, ret, ret);
}

// ****************************************
// *************** Convert ****************
// ****************************************

void uint256_mont_from_bytes(const Mont256CTX* ctx,
                             uint32_t          num[8],
                             const uint8_t     bytes[32])
{
    uint256_from_bytes(num, bytes);
    uint256_to_mont(ctx, num, num);
}

void uint256_mont_to_bytes(const Mont256CTX* ctx,
                           uint8_t           bytes[32],
                           const uint32_t    num[8])
{
    uint32_t t[8];
    uint256_from_mont(ctx, t, num);
    uint256_to_bytes(bytes, t);
}

static void uint256_mont_sll_n(const Mont256CTX* ctx,
                               uint32_t          r[8],
                               const uint32_t    a[8],
                               size_t            n)
{
    uint256_mont_cpy(ctx, r, a);
    for (size_t i = 0; i < n; i++)
    {
        uint256_mont_dbl(ctx, r, r);
    }
}

void uint256_mont_from_bytes_ex(const Mont256CTX* ctx,
                                uint32_t          num[8],
                                const uint8_t*    bytes,
                                size_t            bytes_len)
{
    if (bytes_len == 32)
    {
        uint256_mont_from_bytes(ctx, num, bytes);
        return;
    }
    uint32_t t[8];
    uint8_t  tmp_buf[32] = {0};
    uint256_mont_set_zero(ctx, num);
    while (bytes_len >= 32)
    {
        uint256_mont_sll_n(ctx, num, num, 32);
        uint256_mont_from_bytes(ctx, t, bytes);
        uint256_mont_add(ctx, num, num, t);
        bytes_len -= 32, bytes += 32;
    }
    while (bytes_len)
    {
        uint256_mont_sll_n(ctx, num, num, 8);
        tmp_buf[31] = *bytes;
        uint256_mont_from_bytes(ctx, t, tmp_buf);
        uint256_mont_add(ctx, num, num, t);
        bytes_len -= 1, bytes += 1;
    }
}

}; // namespace tc