#ifndef _TINY_CRYPTO_PKC_SM2_P256V1_H
#define _TINY_CRYPTO_PKC_SM2_P256V1_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

namespace tc {

namespace sm2p256v1 {

extern uint8_t SM2_DEFAULT_ID[];
extern size_t  SM2_DEFAULT_ID_LEN;
extern uint8_t SM2_CURVE_P[];  // 32-byte length
extern uint8_t SM2_CURVE_A[];  // 32-byte length
extern uint8_t SM2_CURVE_B[];  // 32-byte length
extern uint8_t SM2_CURVE_N[];  // 32-byte length
extern uint8_t SM2_CURVE_GX[]; // 32-byte length
extern uint8_t SM2_CURVE_GY[]; // 32-byte length

typedef uint32_t sm2_bn_t[8];
typedef uint32_t sm2_fn_t[8];
typedef uint32_t sm2_fp_t[8];
typedef union sm2_num_t
{
    sm2_bn_t bn;
    sm2_fp_t fp;
    sm2_fn_t fn;
} sm2_num_t;
typedef sm2_fp_t sm2_ec_a[2];
typedef sm2_fp_t sm2_ec_j[3];
typedef union sm2_ec_t
{
    sm2_ec_a a;
    sm2_ec_j j;
} sm2_ec_t;

int  sm2_bn_cmp(const sm2_bn_t a, const sm2_bn_t b);
int  sm2_bn_add_uint32(sm2_bn_t r, const sm2_bn_t a, uint32_t b);
void sm2_bn_mod_n_sub2(sm2_bn_t a);
void sm2_bn_mod_n_sub3(sm2_bn_t a);
void sm2_bn_from_bytes(sm2_bn_t r, const uint8_t in[32]);
void sm2_bn_to_bytes(uint8_t out[32], const sm2_bn_t a);

void sm2_fp_add(sm2_fp_t r, const sm2_fp_t a, const sm2_fp_t b);
void sm2_fp_dbl(sm2_fp_t r, const sm2_fp_t a);
void sm2_fp_tpl(sm2_fp_t r, const sm2_fp_t a);
void sm2_fp_sub(sm2_fp_t r, const sm2_fp_t a, const sm2_fp_t b);
void sm2_fp_mul(sm2_fp_t r, const sm2_fp_t a, const sm2_fp_t b);
void sm2_fp_sqr(sm2_fp_t r, const sm2_fp_t a);
void sm2_fp_neg(sm2_fp_t r, const sm2_fp_t a);
void sm2_fp_inv(sm2_fp_t r, const sm2_fp_t a);
bool sm2_fp_equal(const sm2_fp_t a, const sm2_fp_t b);
bool sm2_fp_equal_zero(const sm2_fp_t a);
bool sm2_fp_equal_one(const sm2_fp_t a);
void sm2_fp_cpy(sm2_fp_t r, const sm2_fp_t a);
void sm2_fp_set_zero(sm2_fp_t r);
void sm2_fp_set_one(sm2_fp_t r);
void sm2_fp_from_bytes(sm2_fp_t r, const uint8_t in[32]);
void sm2_fp_to_bytes(uint8_t out[32], const sm2_fp_t a);

// =============================================================================
// =================================== n =======================================
// = 0xfffffffe_ffffffff_ffffffff_ffffffff_7203df6b_21c6052b_53bbf409_39d54123 =
// =============================================================================

void sm2_fn_add(sm2_fn_t r, const sm2_fn_t a, const sm2_fn_t b);
void sm2_fn_sub(sm2_fn_t r, const sm2_fn_t a, const sm2_fn_t b);
void sm2_fn_mul(sm2_fn_t r, const sm2_fn_t a, const sm2_fn_t b);
void sm2_fn_sqr(sm2_fn_t r, const sm2_fn_t a);
void sm2_fn_inv(sm2_fn_t r, const sm2_fn_t a);
bool sm2_fn_equal(const sm2_fn_t a, const sm2_fn_t b);
bool sm2_fn_equal_zero(const sm2_fn_t a);
bool sm2_fn_equal_one(const sm2_fn_t a);
void sm2_fn_cpy(sm2_fn_t r, const sm2_fn_t a);
void sm2_fn_set_zero(sm2_fn_t r);
void sm2_fn_set_one(sm2_fn_t r);
void sm2_fn_from_bytes(sm2_fn_t r, const uint8_t in[32]);
void sm2_fn_from_bytes_ex(sm2_fn_t r, const uint8_t* in, size_t inl);
void sm2_fn_to_bytes(uint8_t out[32], const sm2_fn_t a);

void sm2_fp_to_bn(sm2_bn_t r, const sm2_fp_t a);
void sm2_fp_from_bn(sm2_fp_t r, const sm2_bn_t a);
void sm2_fn_to_bn(sm2_bn_t r, const sm2_fn_t a);
void sm2_fn_from_bn(sm2_fn_t r, const sm2_bn_t a);
void sm2_fn_from_fp(sm2_fn_t r, const sm2_fp_t a);
void sm2_fn_to_fp(sm2_fp_t r, const sm2_fn_t a);

bool sm2_ec_a_check(const sm2_ec_a P);
void sm2_ec_a_neg(sm2_ec_a R, const sm2_ec_a P);
void sm2_ec_a_to_bytes04(uint8_t out[64], const sm2_ec_a P);
void sm2_ec_a_from_bytes04(sm2_ec_a R, const uint8_t in[64]);

void sm2_ec_j_cpy(sm2_ec_j R, const sm2_ec_j P);
bool sm2_ec_j_is_inf(const sm2_ec_j P);
void sm2_ec_j_set_inf(sm2_ec_j R);
void sm2_ec_j_neg(sm2_ec_j R, const sm2_ec_j P);
void sm2_ec_j_add(sm2_ec_j R, const sm2_ec_j P, const sm2_ec_j Q);
void sm2_ec_j_add_a(sm2_ec_j R, const sm2_ec_j P, const sm2_ec_a Q);
void sm2_ec_j_dbl(sm2_ec_j R, const sm2_ec_j P);
void sm2_ec_j_mul_a(sm2_ec_j R, const uint8_t k[32], const sm2_ec_a P);
void sm2_ec_j_mul_g(sm2_ec_j R, const uint8_t k[32]);
void sm2_ec_j_from_a(sm2_ec_j R, const sm2_ec_a P);
void sm2_ec_j_to_a(sm2_ec_a R, const sm2_ec_j P);
void sm2_ec_j_normal(sm2_ec_j R, const sm2_ec_j P);
bool sm2_ec_j_equal(const sm2_ec_j P, const sm2_ec_j Q);

}; // namespace sm2p256v1

}; // namespace tc

#endif