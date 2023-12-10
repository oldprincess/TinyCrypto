#include "uint.h"
#include <string.h>
#include <math.h>
#include <stdlib.h>

namespace tc {

/**
 * @brief r = a + b + carry, 32-bit
 * @return carry (1/0)
 */
static inline int _add_carry(uint32_t* r, uint32_t a, uint32_t b, int carry)
{
    uint64_t tmp = (uint64_t)a + (uint64_t)b + carry;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

/**
 * @brief r = a - b + borrow, 32-bit
 * @return borrow (-1/0)
 */
static inline int _sub_borrow(uint32_t* r, uint32_t a, uint32_t b, int borrow)
{
    uint64_t tmp = (uint64_t)a - (uint64_t)b + borrow;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

/**
 * @brief r = a * b + carry, 32-bit
 * @return higher product, [0,2^32)
 */
static inline uint32_t _mul_carry(uint32_t* r,
                                  uint32_t  a,
                                  uint32_t  b,
                                  uint32_t  carry)
{
    uint64_t tmp = (uint64_t)a * (uint64_t)b + carry;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

/**
 * @brief r += n * mulVal + carry
 * @return higher product, [0,2^32)
 */
static inline uint32_t _add_mul_carry(uint32_t* r,
                                      uint32_t  n,
                                      uint32_t  mulVal,
                                      uint32_t  carry)
{
    uint64_t tmp = (uint64_t)n * (uint64_t)mulVal + *r + carry;
    *r           = tmp & UINT32_MAX;
    return tmp >> 32;
}

#define MEM_LOAD32BE(src)                       \
    (((uint32_t)(((uint8_t*)(src))[0]) << 24) | \
     ((uint32_t)(((uint8_t*)(src))[1]) << 16) | \
     ((uint32_t)(((uint8_t*)(src))[2]) << 8) |  \
     ((uint32_t)(((uint8_t*)(src))[3]) << 0))

#define MEM_STORE32BE(dst, a)                             \
    (((uint8_t*)(dst))[0] = ((uint32_t)(a) >> 24) & 0xFF, \
     ((uint8_t*)(dst))[1] = ((uint32_t)(a) >> 16) & 0xFF, \
     ((uint8_t*)(dst))[2] = ((uint32_t)(a) >> 8) & 0xFF,  \
     ((uint8_t*)(dst))[3] = ((uint32_t)(a) >> 0) & 0xFF)

/**
 * @brief           get interger effective dsize
 * @param dsize     data size, 32-bit words size, never be 0
 * @param num       32*dsize bit data
 * @return          effective dsize, only these data have value in 'num'.
 *                  effective dsize can be 0, which means num=0
 */
static size_t uint_effective_dsize(size_t dsize, const uint32_t* num);

// ****************************************
// ************ Arithmetic ****************
// ****************************************

int uint_add_carry(size_t          dsize,
                   uint32_t*       sum,
                   const uint32_t* augend,
                   const uint32_t* addend,
                   int             carry)
{
    for (size_t i = 0; i < dsize; i++)
    {
        carry = _add_carry(&sum[i], augend[i], addend[i], carry);
    }
    return carry;
}

int uint_sub_borrow(size_t          dsize,
                    uint32_t*       difference,
                    const uint32_t* minuend,
                    const uint32_t* subtrahend,
                    int             borrow)
{
    for (size_t i = 0; i < dsize; i++)
    {
        borrow = _sub_borrow(&difference[i], minuend[i], subtrahend[i], borrow);
    }
    return borrow;
}

void uint_mul(size_t          dsize,
              uint32_t*       product,
              const uint32_t* multiplier,
              const uint32_t* multiplicand)
{
    size_t asize = uint_effective_dsize(dsize, multiplier);
    size_t bsize = uint_effective_dsize(dsize, multiplicand);
    if (asize == 0 || bsize == 0)
    {
        uint_set_zero(dsize, product);
        return;
    }

    {
        uint32_t carry   = 0;
        uint32_t mul_val = multiplicand[0];
        for (size_t ia = 0; ia < asize; ia++)
        {
            carry = _mul_carry(&product[ia], multiplier[ia], mul_val, carry);
        }
        product[asize] = carry;
    }
    for (size_t ib = 1; ib < bsize; ib++)
    {
        uint32_t carry   = 0;
        uint32_t mul_val = multiplicand[ib];
        for (size_t ia = 0; ia < asize; ia++)
        {
            carry = _add_mul_carry(&product[ia + ib], multiplier[ia], mul_val,
                                   carry);
        }
        product[ib + asize] = carry;
    }
    uint_cast(product, 2 * dsize, product, asize + bsize);
}

void uint_sqr(size_t dsize, uint32_t* product, const uint32_t* multiplier)
{
    uint_mul(dsize, product, multiplier, multiplier);
}

static size_t uint_effective_dsize(size_t dsize, const uint32_t* num)
{
    while (dsize > 0 && num[dsize - 1] == 0)
    {
        dsize--;
    }
    return dsize;
}

/**
 * @brief predict qhat, (uh ul ul2) = qhat * (div_h div_l)
 * @return qhat
 */
static uint32_t div_knuth_predict_qhat(uint32_t uh,
                                       uint32_t ul,
                                       uint32_t ul2,
                                       uint32_t div_h,
                                       uint32_t div_l)
{
    uint64_t qhat, rhat;
    uint64_t uhl = (uint64_t)uh << 32 | (uint64_t)ul;

    qhat = uhl / div_h;
    if (qhat > UINT32_MAX)
    {
        qhat = UINT32_MAX;
    }
    rhat = uhl - div_h * qhat;
    while (qhat * div_l > (rhat << 32 | ul2))
    {
        rhat += div_h, qhat -= 1;
        if (rhat >= (1ULL << 32))
        {
            break;
        }
    }
    return (uint32_t)qhat;
}

/**
 * @brief
 * @param q         quotient
 * @param qsize     memory of "q" is qsize*32-bit
 * @param u         input is dividend, output is remainder
 * @param usize_out memory of output "u" is usize_out*32-bit
 * @param usize_in  memory of input "u" is (usize_in+1)*32-bit,
 *                  effective dsize is usize_in
 * @param v         divisor, v.bits mod 32 = 0
 * @param vsize     memory of "v" is vsize*32-bit
 */
static void div_knuth(uint32_t*       q,
                      size_t*         qsize,
                      uint32_t*       u,
                      size_t*         usize_out,
                      size_t          usize_in,
                      const uint32_t* v,
                      size_t          vsize)
{
    uint32_t div_h = v[vsize - 1];
    uint32_t div_l = v[vsize - 2];
    uint64_t base  = 1ULL << 32;
    size_t   usize = usize_in;

    u[usize] = 0;
    for (size_t _j = 0; _j <= usize - vsize; _j++)
    {
        size_t j = usize - vsize - _j;
        // D3
        uint32_t qhat = div_knuth_predict_qhat(u[j + vsize], u[j + vsize - 1],
                                               u[j + vsize - 2], div_h, div_l);
        if (qhat == 0)
        {
            q[j] = 0;
            continue;
        }
        // D4
        int      borrow = 0;
        uint32_t carry  = 0;
        for (size_t iv = 0; iv < vsize; iv++)
        {
            //  u - div*qhat
            uint32_t t;
            carry  = _mul_carry(&t, (uint32_t)qhat, v[iv], carry);
            borrow = _sub_borrow(&u[j + iv], u[j + iv], t, borrow);
        }
        borrow = _sub_borrow(&u[j + vsize], u[j + vsize], carry, borrow);
        // D5
        q[j] = (borrow == 0) ? (uint32_t)qhat : (uint32_t)qhat - 1;
        // D6
        if (borrow != 0)
        {
            int carry = uint_add_carry(vsize, u + j, u + j, v, 0);
            _add_carry(&u[j + vsize], u[j + vsize], 0, carry);
        }
    } // D7
    *qsize     = uint_effective_dsize(usize - vsize, q);
    *usize_out = uint_effective_dsize(vsize, u);
}

int uint_div(size_t          dsize,
             uint32_t*       quotient,
             uint32_t*       remainder,
             const uint32_t* dividend,
             const uint32_t* divisor)
{
    if (uint_equal_zero(dsize, divisor))
    {
        return -1;
    }
    int cmp = uint_cmp(dsize, dividend, divisor);
    if (cmp < 0)
    {
        if (remainder != NULL)
        {
            uint_cpy(dsize, remainder, dividend);
        }
        if (quotient != NULL)
        {
            uint_set_zero(dsize, quotient);
        }
        return 0;
    }
    else if (cmp == 0)
    {
        if (quotient != NULL)
        {
            uint_set_one(dsize, quotient);
        }
        if (remainder != NULL)
        {
            uint_set_zero(dsize, remainder);
        }
        return 0;
    }
    size_t divisor_dsize = uint_effective_dsize(dsize, divisor);
    if (divisor_dsize == 1)
    {
        uint32_t rem = uint_div_uint32(dsize, quotient, dividend, divisor[0]);
        if (remainder != NULL)
        {
            uint_set_uint32(dsize, remainder, rem);
        }
        return 0;
    }
    else
    {
        // div knuth
        size_t    d = (32 - uint_bitlength(dsize, divisor) % 32) % 32;
        uint32_t *u = NULL, *v = NULL, *q = NULL;
        size_t    usize    = uint_effective_dsize(dsize, dividend) + 1;
        size_t    vsize    = divisor_dsize + 1;
        size_t    qsize    = usize;
        uint32_t* data_buf = (uint32_t*)malloc(sizeof(uint32_t) * (usize + 1) +
                                               sizeof(uint32_t) * vsize +
                                               sizeof(uint32_t) * qsize);
        if (data_buf == NULL)
        {
            return -1;
        }
        u = data_buf;
        v = u + sizeof(uint32_t) * (usize + 1);
        q = v + sizeof(uint32_t) * qsize;
        uint_cast(u, usize, dividend, dsize);
        uint_cast(v, vsize, divisor, dsize);
        uint_sll(usize, u, u, d);
        uint_sll(vsize, v, v, d);
        usize = uint_effective_dsize(usize, u);
        vsize = uint_effective_dsize(vsize, v);
        div_knuth(q, &qsize, u, &usize, usize, v, vsize);
        if (quotient != NULL)
        {
            uint_cast(quotient, dsize, q, qsize);
        }
        if (remainder != NULL)
        {
            uint_srl(usize, u, u, d);
            uint_cast(remainder, dsize, u, usize);
        }
        free(data_buf);
        return 0;
    }
}

int uint_add_carry_uint32(size_t          dsize,
                          uint32_t*       sum,
                          const uint32_t* augend,
                          uint32_t        addend)
{
    int carry = _add_carry(&sum[0], augend[0], addend, 0);
    for (size_t i = 1; i < dsize; i++)
    {
        carry = _add_carry(&sum[i], augend[i], 0, carry);
    }
    return carry;
}

int uint_sub_borrow_uint32(size_t          dsize,
                           uint32_t*       difference,
                           const uint32_t* minuend,
                           uint32_t        subtrahend)
{
    int borrow = _sub_borrow(&difference[0], minuend[0], subtrahend, 0);
    for (size_t i = 1; i < dsize; i++)
    {
        borrow = _sub_borrow(&difference[i], minuend[i], 0, borrow);
    }
    return borrow;
}

uint32_t uint_mul_carry_uint32(size_t          dsize,
                               uint32_t*       product,
                               const uint32_t* multiplier,
                               uint32_t        multiplicand)
{
    uint32_t carry = 0;
    for (size_t i = 0; i < dsize; i++)
    {
        carry = _mul_carry(&product[i], multiplier[i], multiplicand, carry);
    }
    return carry;
}

uint32_t uint_div_uint32(size_t          dsize,
                         uint32_t*       quotient,
                         const uint32_t* dividend,
                         uint32_t        divisor)
{
    uint32_t rem = 0;
    for (size_t _i = 0; _i < dsize; _i++)
    {
        size_t   i   = dsize - 1 - _i;
        uint64_t tmp = ((uint64_t)rem << 32) | (uint64_t)dividend[i];
        rem          = tmp % divisor;
        if (quotient != NULL)
        {
            quotient[i] = (uint32_t)(tmp / divisor);
        }
    }
    return rem;
}

// ****************************************
// *************** Compare ****************
// ****************************************

int uint_cmp(size_t dsize, const uint32_t* a, const uint32_t* b)
{
    for (size_t _i = 0; _i < dsize; _i++)
    {
        size_t i = dsize - 1 - _i;
        if (a[i] > b[i])
        {
            return 1;
        }
        else if (a[i] < b[i])
        {
            return -1;
        }
    }
    return 0;
}

int uint_cmp_uint32(size_t dsize, const uint32_t* a, uint32_t b)
{
    for (size_t i = dsize - 1; i >= 1; i--)
    {
        if (a[i] > 0)
        {
            return 1;
        }
    }
    if (a[0] > b)
    {
        return 1;
    }
    else if (a[0] < b)
    {
        return -1;
    }
    return 0;
}

bool uint_equal(size_t dsize, const uint32_t* a, const uint32_t* b)
{
    return uint_cmp(dsize, a, b) == 0;
}

bool uint_equal_zero(size_t dsize, const uint32_t* a)
{
    return uint_cmp_uint32(dsize, a, 0) == 0;
}

bool uint_equal_one(size_t dsize, const uint32_t* a)
{
    return uint_cmp_uint32(dsize, a, 1) == 0;
}

// ****************************************
// ************* Set & Move ***************
// ****************************************

void uint_cpy(size_t dsize, uint32_t* ret, const uint32_t* num)
{
    memmove(ret, num, sizeof(uint32_t) * dsize);
}

void uint_set_zero(size_t dsize, uint32_t* num)
{
    memset(num, 0, sizeof(uint32_t) * dsize);
}

void uint_set_one(size_t dsize, uint32_t* num)
{
    uint_set_uint32(dsize, num, 1);
}

void uint_set_uint32(size_t dsize, uint32_t* ret, uint32_t num)
{
    ret[0] = num;
    memset(ret + 1, 0, sizeof(uint32_t) * (dsize - 1));
}

// ****************************************
// *************** Logical ****************
// ****************************************

void uint_xor(size_t dsize, uint32_t* ret, const uint32_t* a, const uint32_t* b)
{
    for (size_t i = 0; i < dsize; i++)
    {
        ret[i] = a[i] ^ b[i];
    }
}

void uint_and(size_t dsize, uint32_t* ret, const uint32_t* a, const uint32_t* b)
{
    for (size_t i = 0; i < dsize; i++)
    {
        ret[i] = a[i] & b[i];
    }
}

void uint_or(size_t dsize, uint32_t* ret, const uint32_t* a, const uint32_t* b)
{
    for (size_t i = 0; i < dsize; i++)
    {
        ret[i] = a[i] | b[i];
    }
}

void uint_not(size_t dsize, uint32_t* ret, const uint32_t* a)
{
    for (size_t i = 0; i < dsize; i++)
    {
        ret[i] = ~a[i];
    }
}

void uint_sll(size_t dsize, uint32_t* ret, const uint32_t* a, size_t bits)
{
    if (bits >= dsize * 32)
    {
        uint_set_zero(dsize, ret);
        return;
    }
    size_t b = bits % 32, b32 = bits / 32;
    memmove(ret + b32, a, sizeof(uint32_t) * (dsize - b32));
    memset(ret, 0, sizeof(uint32_t) * b32);
    if (b != 0)
    {
        uint32_t carry = 0;
        for (size_t i = b32; i < dsize; i++)
        {
            // r[i] = r[i]<<b | r[i-1]>>(32-b)
            uint32_t tmp = ret[i] << b | carry;
            carry        = ret[i] >> (32 - b);
            ret[i]       = tmp;
        }
    }
}

void uint_srl(size_t dsize, uint32_t* ret, const uint32_t* a, size_t bits)
{
    if (bits >= dsize * 32)
    {
        uint_set_zero(dsize, ret);
        return;
    }
    size_t b = bits % 32, b32 = bits / 32;
    memmove(ret, a + b32, sizeof(uint32_t) * (dsize - b32));
    memset(ret + dsize - b32, 0, sizeof(uint32_t) * b32);
    if (b != 0)
    {
        ret[0] >>= b;
        for (size_t i = 1; i < dsize - b32; i++)
        {
            // r[i-1] = r[i]<<(32-b) | r[i-1]>>b
            ret[i - 1] |= ret[i] << (32 - b);
            ret[i] >>= b;
        }
    }
}

// ****************************************
// *************** Convert ****************
// ****************************************

void uint_cast(uint32_t*       out,
               size_t          out_dsize,
               const uint32_t* in,
               size_t          in_dsize)
{
    if (in_dsize < out_dsize)
    {
        memmove(out, in, sizeof(uint32_t) * in_dsize);
        size_t diff = sizeof(uint32_t) * (out_dsize - in_dsize);
        memset(out + in_dsize, 0, diff);
    }
    else
    {
        memmove(out, in, sizeof(uint32_t) * out_dsize);
    }
}

void uint_from_bytes(size_t dsize, uint32_t* ret, const uint8_t* bytes)
{
    const uint8_t* ptr = bytes + 4 * (dsize - 1);
    for (size_t i = 0; i < dsize; i++)
    {
        ret[i] = MEM_LOAD32BE(ptr);
        ptr -= 4;
    }
}

void uint_to_bytes(size_t dsize, uint8_t* bytes, const uint32_t* num)
{
    uint8_t* ptr = bytes + 4 * (dsize - 1);
    for (size_t i = 0; i < dsize; i++)
    {
        MEM_STORE32BE(ptr, num[i]);
        ptr -= 4;
    }
}

int uint_from_str(size_t      dsize,
                  uint32_t*   out,
                  const char* in,
                  size_t      inl,
                  int         radix)
{
    static const int PARSE_SPAN[] = {
        0, 0, 30, 19, 15, 13, 11, 11, 10, 9, 9, 8, 8, 8, 8, 7, 7, 7, 7,
        7, 7, 7,  6,  6,  6,  6,  6,  6,  6, 6, 6, 6, 6, 6, 6, 6, 5,
    };
    if (!(2 <= radix && radix <= 36))
    {
        return -1;
    }
    uint_set_zero(dsize, out);
    while (inl)
    {
        uint32_t add_val = 0, mul_val = 1;
        for (int i = 0; i < PARSE_SPAN[radix]; i++)
        {
            uint32_t tmp = 0;
            if (inl == 0)
            {
                break;
            }
            if ('0' <= *in && *in <= '9')
            {
                tmp = *in - '0';
            }
            else if ('A' <= *in && *in <= 'A' + radix - 10 - 1)
            {
                tmp = *in - 'A' + 10;
            }
            else if ('a' <= *in && *in <= 'a' + radix - 10 - 1)
            {
                tmp = *in - 'a' + 10;
            }
            else
            {
                return -1;
            }
            mul_val = mul_val * radix;
            add_val = add_val * radix + tmp;
            in += 1, inl -= 1;
        }
        if (uint_mul_carry_uint32(dsize, out, out, mul_val))
        {
            return -1;
        }
        if (uint_add_carry_uint32(dsize, out, out, add_val))
        {
            return -1;
        }
    }
    return 0;
}

size_t uint_to_str_max_outl(size_t dsize, int radix)
{
    if (!(2 <= radix && radix <= 36))
    {
        return (size_t)(-1);
    }
    double len = ceil(32.0 * (double)dsize * log(2) / log(radix));
    return (size_t)len + 1;
}

int uint_to_str(size_t dsize, char* ret, const uint32_t* num, int radix)
{
    if (!(2 <= radix && radix <= 36))
    {
        return -1;
    }
    size_t    tsize   = uint_effective_dsize(dsize, num);
    uint32_t* tmp     = (uint32_t*)malloc(sizeof(uint32_t) * tsize);
    char*     cur_str = ret;
    if (tmp == NULL)
    {
        return -1;
    }
    uint_cast(tmp, tsize, num, dsize);
    do
    {
        uint32_t rem = uint_div_uint32(tsize, tmp, tmp, (uint32_t)radix);
        *cur_str     = (0 <= rem && rem <= 9) ? ('0' + rem) : ('A' + rem - 10);
        cur_str++;
        tsize = uint_effective_dsize(tsize, tmp);
    } while (tsize > 0);
    *cur_str = '\0';
    // reverse
    size_t s_len = ((size_t)cur_str - (size_t)ret);
    for (size_t i = 0; i < s_len / 2; i++)
    {
        char c             = ret[i];
        ret[i]             = ret[s_len - 1 - i];
        ret[s_len - 1 - i] = c;
    }
    free(tmp);
    return 0;
}

// ****************************************
// ********** Bit Manipulation ************
// ****************************************

size_t uint_bitlength(size_t dsize, const uint32_t* num)
{
    dsize = uint_effective_dsize(dsize, num);
    for (size_t bits = dsize * 32; bits > 0; bits--)
    {
        if (uint_bittest(dsize, num, bits - 1))
        {
            return bits;
        }
    }
    return 0;
}

bool uint_bittest(size_t dsize, const uint32_t* num, size_t i)
{
    if (i >= dsize * 32)
    {
        return false;
    }
    else
    {
        return ((num[i / 32] >> (i % 32)) & 1) == 1;
    }
}

} // namespace tc
