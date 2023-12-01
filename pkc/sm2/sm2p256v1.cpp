#include "sm2p256v1.h"
#include "../bn/uint256.h"
#include "../bn/uint256_mont.h"

namespace tc {

namespace sm2p256v1 {

#pragma region "SM2 Field Param"

uint8_t SM2_DEFAULT_ID[16] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
};
// 16
size_t SM2_DEFAULT_ID_LEN = sizeof(SM2_DEFAULT_ID);
// 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
uint8_t SM2_CURVE_P[32] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};
// -3
uint8_t SM2_CURVE_A[32] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc,
};
// 0x28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93
uint8_t SM2_CURVE_B[32] = {
    0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e,
    0x4b, 0xcf, 0x65, 0x09, 0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab,
    0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93,
};
uint8_t SM2_CURVE_N[32] = {
    0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0x72, 0x03, 0xdf, 0x6b, 0x21, 0xc6,
    0x05, 0x2b, 0x53, 0xbb, 0xf4, 0x09, 0x39, 0xd5, 0x41, 0x23,
};
// 0x32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7
uint8_t SM2_CURVE_GX[32] = {
    0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04,
    0x46, 0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66,
    0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7,
};
// 0xbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0
uint8_t SM2_CURVE_GY[32] = {
    0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce,
    0xe3, 0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a,
    0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0,
};

// SM2 Curve p = 2^256 - 2^224 - 2^96 + 2^64 - 1
// 0xfffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff
static const uint32_t _SM2_CURVE_P[8] = {
    0xffffffffU, 0xffffffffU, 0x00000000U, 0xffffffffU,
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xfffffffeU,
};
// SM2_CURVE_P - 2
static const uint32_t _SM2_CURVE_P_SUB2[8] = {
    0xfffffffdU, 0xffffffffU, 0x00000000U, 0xffffffffU,
    0xffffffffU, 0xffffffffU, 0xffffffffU, 0xfffffffeU,
};
// R mod SM2_CURVE_P = 2^256 mod p
static const uint32_t _SM2_FP_MONT_R[8] = {
    0x00000001U, 0x00000000U, 0xffffffffU, 0x00000000U,
    0x00000000U, 0x00000000U, 0x00000000U, 0x00000001U,

};
// R^2 mod SM2_CURVE_P = (2^256)^2 mod p
static const uint32_t _SM2_FP_MONT_R_POW2[8] = {
    0x00000003, 0x00000002, 0xffffffff, 0x00000002,
    0x00000001, 0x00000001, 0x00000002, 0x00000004,
};
static const Mont256CTX SM2_FP_MONT_CTX = {
    _SM2_CURVE_P, _SM2_CURVE_P_SUB2, _SM2_FP_MONT_R, _SM2_FP_MONT_R_POW2, 1U,
};

// n = 0xfffffffe_ffffffff_ffffffff_ffffffff_7203df6b_21c6052b_53bbf409_39d54123
static const uint32_t _SM2_CURVE_N[8] = {
    0x39d54123, 0x53bbf409, 0x21c6052b, 0x7203df6b,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};
// R = 2^256 mod n
// 0x000000010000000000000000000000008dfc2094de39fad4ac440bf6c62abedd
static const uint32_t _SM2_FN_MONT_R[8] = {
    0xc62abedd, 0xac440bf6, 0xde39fad4, 0x8dfc2094,
    0x00000000, 0x00000000, 0x00000000, 0x00000001,
};
// R^2 mod n
// 0x1eb5e412a22b3d3b620fc84c3affe0d43464504ade6fa2fa901192af7c114f20
static const uint32_t _SM2_FN_MONT_R_POW2[8] = {
    0x7c114f20, 0x901192af, 0xde6fa2fa, 0x3464504a,
    0x3affe0d4, 0x620fc84c, 0xa22b3d3b, 0x1eb5e412,
};
// n - 2
static const uint32_t _SM2_CURVE_N_SUB2[8] = {
    0x39d54121, 0x53bbf409, 0x21c6052b, 0x7203df6b,
    0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
};
static const Mont256CTX SM2_FN_MONT_CTX = {
    _SM2_CURVE_N,        _SM2_CURVE_N_SUB2, _SM2_FN_MONT_R,
    _SM2_FN_MONT_R_POW2, 0x72350975,
};

#pragma endregion

#pragma region "SM2 BN"

int sm2_bn_cmp(const sm2_bn_t a, const sm2_bn_t b)
{
    return uint256_cmp(a, b);
}

int sm2_bn_add_uint32(sm2_bn_t r, const sm2_bn_t a, uint32_t b)
{
    return uint256_add_carry_uint32(r, a, b);
}

void sm2_bn_mod_n_sub2(sm2_bn_t a)
{
    if (uint256_cmp(a, _SM2_CURVE_N_SUB2) >= 0)
    {
        uint256_sub_borrow(a, a, _SM2_CURVE_N_SUB2);
    }
}

void sm2_bn_mod_n_sub3(sm2_bn_t a)
{
    static const uint32_t _SM2_CURVE_N_SUB3[8] = {
        0x39d54120, 0x53bbf409, 0x21c6052b, 0x7203df6b,
        0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe,
    };
    if (uint256_cmp(a, _SM2_CURVE_N_SUB3) >= 0)
    {
        uint256_sub_borrow(a, a, _SM2_CURVE_N_SUB3);
    }
}

void sm2_bn_from_bytes(sm2_bn_t r, const uint8_t in[32])
{
    uint256_from_bytes(r, in);
}

void sm2_bn_to_bytes(uint8_t out[32], const sm2_bn_t a)
{
    uint256_to_bytes(out, a);
}

#pragma endregion

#pragma region "SM2 FP"

void sm2_fp_add(sm2_fp_t r, const sm2_fp_t a, const sm2_fp_t b)
{
    uint256_mont_add(&SM2_FP_MONT_CTX, r, a, b);
}

void sm2_fp_dbl(sm2_fp_t r, const sm2_fp_t a)
{
    uint256_mont_dbl(&SM2_FP_MONT_CTX, r, a);
}

void sm2_fp_tpl(sm2_fp_t r, const sm2_fp_t a)
{
    uint256_mont_tpl(&SM2_FP_MONT_CTX, r, a);
}

void sm2_fp_sub(sm2_fp_t r, const sm2_fp_t a, const sm2_fp_t b)
{
    uint256_mont_sub(&SM2_FP_MONT_CTX, r, a, b);
}

void sm2_fp_mul(sm2_fp_t r, const sm2_fp_t a, const sm2_fp_t b)
{
    uint256_mont_mul(&SM2_FP_MONT_CTX, r, a, b);
}

void sm2_fp_sqr(sm2_fp_t r, const sm2_fp_t a)
{
    uint256_mont_sqr(&SM2_FP_MONT_CTX, r, a);
}

void sm2_fp_neg(sm2_fp_t r, const sm2_fp_t a)
{
    uint256_mont_neg(&SM2_FP_MONT_CTX, r, a);
}

void sm2_fp_inv(sm2_fp_t r, const sm2_fp_t a)
{
    uint256_mont_inv(&SM2_FP_MONT_CTX, r, a);
}

bool sm2_fp_equal(const sm2_fp_t a, const sm2_fp_t b)
{
    return uint256_mont_equal(&SM2_FP_MONT_CTX, a, b);
}

bool sm2_fp_equal_zero(const sm2_fp_t a)
{
    return uint256_mont_equal_zero(&SM2_FP_MONT_CTX, a);
}

bool sm2_fp_equal_one(const sm2_fp_t a)
{
    return uint256_mont_equal_one(&SM2_FP_MONT_CTX, a);
}

void sm2_fp_cpy(sm2_fp_t r, const sm2_fp_t a)
{
    uint256_mont_cpy(&SM2_FP_MONT_CTX, r, a);
}

void sm2_fp_set_zero(sm2_fp_t r)
{
    uint256_mont_set_zero(&SM2_FP_MONT_CTX, r);
}

void sm2_fp_set_one(sm2_fp_t r)
{
    uint256_mont_set_one(&SM2_FP_MONT_CTX, r);
}

void sm2_fp_from_bytes(sm2_fp_t r, const uint8_t in[32])
{
    uint256_mont_from_bytes(&SM2_FP_MONT_CTX, r, in);
}

void sm2_fp_to_bytes(uint8_t out[32], const sm2_fp_t a)
{
    uint256_mont_to_bytes(&SM2_FP_MONT_CTX, out, a);
}

#pragma endregion

#pragma region "SM2 FN"

void sm2_fn_add(sm2_fn_t r, const sm2_fn_t a, const sm2_fn_t b)
{
    uint256_mont_add(&SM2_FN_MONT_CTX, r, a, b);
}

void sm2_fn_sub(sm2_fn_t r, const sm2_fn_t a, const sm2_fn_t b)
{
    uint256_mont_sub(&SM2_FN_MONT_CTX, r, a, b);
}

void sm2_fn_mul(sm2_fn_t r, const sm2_fn_t a, const sm2_fn_t b)
{
    uint256_mont_mul(&SM2_FN_MONT_CTX, r, a, b);
}

void sm2_fn_sqr(sm2_fn_t r, const sm2_fn_t a)
{
    uint256_mont_sqr(&SM2_FN_MONT_CTX, r, a);
}

void sm2_fn_inv(sm2_fn_t r, const sm2_fn_t a)
{
    uint256_mont_inv(&SM2_FN_MONT_CTX, r, a);
}

bool sm2_fn_equal(const sm2_fn_t a, const sm2_fn_t b)
{
    return uint256_mont_equal(&SM2_FN_MONT_CTX, a, b);
}

bool sm2_fn_equal_zero(const sm2_fn_t a)
{
    return uint256_mont_equal_zero(&SM2_FN_MONT_CTX, a);
}

bool sm2_fn_equal_one(const sm2_fn_t a)
{
    return uint256_mont_equal_one(&SM2_FN_MONT_CTX, a);
}

void sm2_fn_cpy(sm2_fn_t r, const sm2_fn_t a)
{
    uint256_mont_cpy(&SM2_FN_MONT_CTX, r, a);
}

void sm2_fn_set_zero(sm2_fn_t r)
{
    uint256_mont_set_zero(&SM2_FN_MONT_CTX, r);
}

void sm2_fn_set_one(sm2_fn_t r)
{
    uint256_mont_set_one(&SM2_FN_MONT_CTX, r);
}

void sm2_fn_from_bytes(sm2_fn_t r, const uint8_t in[32])
{
    uint256_mont_from_bytes(&SM2_FN_MONT_CTX, r, in);
}

void sm2_fn_from_bytes_ex(sm2_fn_t r, const uint8_t* in, size_t inl)
{
    uint256_mont_from_bytes_ex(&SM2_FN_MONT_CTX, r, in, inl);
}

void sm2_fn_to_bytes(uint8_t out[32], const sm2_fn_t a)
{
    uint256_mont_to_bytes(&SM2_FN_MONT_CTX, out, a);
}

#pragma endregion

#pragma region "SM2 NUM"

void sm2_fp_to_bn(sm2_bn_t r, const sm2_fp_t a)
{
    uint8_t buf[32];
    sm2_fp_to_bytes(buf, a);
    sm2_bn_from_bytes(r, buf);
}

void sm2_fp_from_bn(sm2_fp_t r, const sm2_bn_t a)
{
    uint8_t buf[32];
    sm2_bn_to_bytes(buf, a);
    sm2_fp_from_bytes(r, buf);
}

void sm2_fn_to_bn(sm2_bn_t r, const sm2_fn_t a)
{
    uint8_t buf[32];
    sm2_fn_to_bytes(buf, a);
    sm2_bn_from_bytes(r, buf);
}

void sm2_fn_from_bn(sm2_fn_t r, const sm2_bn_t a)
{
    uint8_t buf[32];
    sm2_bn_to_bytes(buf, a);
    sm2_fn_from_bytes(r, buf);
}

void sm2_fn_from_fp(sm2_fn_t r, const sm2_fp_t a)
{
    uint8_t buf[32];
    sm2_fp_to_bytes(buf, a);
    sm2_fn_from_bytes(r, buf);
}

void sm2_fn_to_fp(sm2_fp_t r, const sm2_fn_t a)
{
    uint8_t buf[32];
    sm2_fn_to_bytes(buf, a);
    sm2_fp_from_bytes(r, buf);
}

#pragma endregion

#pragma region "SM2 EC"

bool sm2_ec_a_check(const sm2_ec_a P)
{
    // y^2 = x^3 + ax + b
    sm2_fp_t left, right, t;
    sm2_fp_sqr(left, P[1]);
    sm2_fp_from_bytes(right, SM2_CURVE_B);
    sm2_fp_from_bytes(t, SM2_CURVE_A);
    sm2_fp_mul(t, t, P[0]);
    sm2_fp_add(right, right, t);
    sm2_fp_sqr(t, P[0]);
    sm2_fp_mul(t, t, P[0]);
    sm2_fp_add(right, right, t);
    return sm2_fp_equal(left, right);
}

void sm2_ec_a_neg(sm2_ec_a R, const sm2_ec_a P)
{
    sm2_fp_cpy(R[0], P[0]);
    sm2_fp_neg(R[1], P[1]);
}

void sm2_ec_a_to_bytes04(uint8_t out[64], const sm2_ec_a P)
{
    sm2_fp_to_bytes(out + 0, P[0]);
    sm2_fp_to_bytes(out + 32, P[1]);
}

void sm2_ec_a_from_bytes04(sm2_ec_a R, const uint8_t in[64])
{
    sm2_fp_from_bytes(R[0], in + 0);
    sm2_fp_from_bytes(R[1], in + 32);
}

void sm2_ec_j_cpy(sm2_ec_j R, const sm2_ec_j P)
{
    sm2_fp_cpy(R[0], P[0]);
    sm2_fp_cpy(R[1], P[1]);
    sm2_fp_cpy(R[2], P[2]);
}

bool sm2_ec_j_is_inf(const sm2_ec_j P)
{
    return sm2_fp_equal_zero(P[2]);
}

void sm2_ec_j_set_inf(sm2_ec_j R)
{
    // 1,1,0
    sm2_fp_set_one(R[0]);
    sm2_fp_set_one(R[1]);
    sm2_fp_set_zero(R[2]);
}

void sm2_ec_j_neg(sm2_ec_j R, const sm2_ec_j P)
{
    sm2_fp_cpy(R[0], P[0]);
    sm2_fp_neg(R[1], P[1]);
    sm2_fp_cpy(R[2], P[2]);
}

void sm2_ec_j_add(sm2_ec_j R, const sm2_ec_j P, const sm2_ec_j Q)
{
    // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
    // Cost: 11M + 5S + 9add + 4*2.

#define X3 R[0]
#define Y3 R[1]
#define Z3 R[2]
#define X1 P[0]
#define Y1 P[1]
#define Z1 P[2]
#define X2 Q[0]
#define Y2 Q[1]
#define Z2 Q[2]

    sm2_fp_t Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V;
    sm2_fp_sqr(Z1Z1, Z1);
    sm2_fp_sqr(Z2Z2, Z2);
    sm2_fp_mul(U1, X1, Z2Z2);
    sm2_fp_mul(U2, X2, Z1Z1);
    sm2_fp_mul(S1, Y1, Z2);
    sm2_fp_mul(S1, S1, Z2Z2);
    sm2_fp_mul(S2, Y2, Z1);
    sm2_fp_mul(S2, S2, Z1Z1);

    if (sm2_fp_equal(U1, U2))
    {
        if (sm2_fp_equal(S1, S2))
        {
            sm2_ec_j_dbl(R, P);
        }
        else
        {
            sm2_ec_j_set_inf(R);
        }
        return;
    }

    sm2_fp_sub(H, U2, U1);
    sm2_fp_dbl(I, H);
    sm2_fp_sqr(I, I);
    sm2_fp_mul(J, H, I);
    sm2_fp_sub(r, S2, S1);
    sm2_fp_dbl(r, r);
    sm2_fp_mul(V, U1, I);

    // X3 = r2-J-2*V
    sm2_fp_sqr(X3, r);
    sm2_fp_sub(X3, X3, J);
    sm2_fp_sub(X3, X3, V);
    sm2_fp_sub(X3, X3, V);
    // Y3 = r*(V-X3)-2*S1*J
    sm2_fp_sub(Y3, V, X3);
    sm2_fp_mul(Y3, Y3, r);
    sm2_fp_mul(V, S1, J); // use V as tmp
    sm2_fp_dbl(V, V);
    sm2_fp_sub(Y3, Y3, V);
    // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
    sm2_fp_add(Z3, Z1, Z2);
    sm2_fp_sqr(Z3, Z3);
    sm2_fp_sub(Z3, Z3, Z1Z1);
    sm2_fp_sub(Z3, Z3, Z2Z2);
    sm2_fp_mul(Z3, Z3, H);
#undef X1
#undef Y1
#undef Z1
#undef X2
#undef Y2
#undef Z2
#undef X3
#undef Y3
#undef Z3
}

void sm2_ec_j_add_a(sm2_ec_j R, const sm2_ec_j P, const sm2_ec_a Q)
{
    // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-madd-2007-bl
    // Cost: 7M + 4S + 9add + 3*2 + 1*4.
#define X3 R[0]
#define Y3 R[1]
#define Z3 R[2]
#define X1 P[0]
#define Y1 P[1]
#define Z1 P[2]
#define X2 Q[0]
#define Y2 Q[1]

    sm2_fp_t Z1Z1, U2, S2, H, HH, I, J, r, V;

    sm2_fp_sqr(Z1Z1, Z1);     // Z1Z1 = Z1^2
    sm2_fp_mul(U2, X2, Z1Z1); //  U2 = X2*Z1Z1
    sm2_fp_mul(S2, Y2, Z1);
    sm2_fp_mul(S2, S2, Z1Z1); //  S2 = Y2*Z1*Z1Z1
    sm2_fp_sub(H, U2, X1);    // H = U2-X1
    sm2_fp_sqr(HH, H);        // HH = H^2
    sm2_fp_dbl(I, HH);
    sm2_fp_dbl(I, I);    // I = 4*HH
    sm2_fp_mul(J, H, I); // J = H*I
    sm2_fp_sub(r, S2, Y1);
    sm2_fp_dbl(r, r);     // r = 2*(S2-Y1)
    sm2_fp_mul(V, X1, I); // V = X1*I
    // X3 = r^2-J-2*V
    sm2_fp_sqr(X3, r);
    sm2_fp_sub(X3, X3, J);
    sm2_fp_sub(X3, X3, V);
    sm2_fp_sub(X3, X3, V);
    // Y3 = r*(V-X3)-2*Y1*J
    sm2_fp_sub(V, V, X3);
    sm2_fp_mul(V, r, V);
    sm2_fp_mul(Y3, Y1, J);
    sm2_fp_dbl(Y3, Y3);
    sm2_fp_sub(Y3, V, Y3);
    // Z3 = (Z1+H)^2-Z1Z1-HH
    sm2_fp_add(Z3, Z1, H);
    sm2_fp_sqr(Z3, Z3);
    sm2_fp_sub(Z3, Z3, Z1Z1);
    sm2_fp_sub(Z3, Z3, HH);

#undef X1
#undef Y1
#undef Z1
#undef X2
#undef Y2
#undef X3
#undef Y3
#undef Z3
}

void sm2_ec_j_dbl(sm2_ec_j R, const sm2_ec_j P)
{
    // http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2001-b
    // Cost: 3M + 5S + 8add + 1*3 + 1*4 + 2*8.
#define X3 R[0]
#define Y3 R[1]
#define Z3 R[2]
#define X1 P[0]
#define Y1 P[1]
#define Z1 P[2]

    sm2_fp_t delta, gamma, beta, alpha;
    // delta = Z1^2, gamma = Y1^2
    sm2_fp_sqr(delta, Z1);
    sm2_fp_sqr(gamma, Y1);
    // alpha = 3*(X1-delta)*(X1+delta), use 'beta' as tmp
    sm2_fp_sub(alpha, X1, delta);
    sm2_fp_add(beta, X1, delta);
    sm2_fp_mul(alpha, alpha, beta);
    sm2_fp_tpl(alpha, alpha);
    // beta = X1*gamma
    sm2_fp_mul(beta, X1, gamma);

    // X3 = alpha^2-8*beta
    sm2_fp_sqr(X3, alpha);
    sm2_fp_dbl(beta, beta);
    sm2_fp_dbl(beta, beta);
    sm2_fp_sub(X3, X3, beta);
    sm2_fp_sub(X3, X3, beta);
    // Z3 = (Y1+Z1)^2-gamma-delta
    sm2_fp_add(Z3, Y1, Z1);
    sm2_fp_sqr(Z3, Z3);
    sm2_fp_sub(Z3, Z3, gamma);
    sm2_fp_sub(Z3, Z3, delta);
    // Y3 = alpha*(4*beta-X3)-8*gamma^2
    sm2_fp_sub(Y3, beta, X3);
    sm2_fp_mul(Y3, Y3, alpha);
    sm2_fp_dbl(gamma, gamma);
    sm2_fp_sqr(gamma, gamma);
    sm2_fp_dbl(gamma, gamma);
    sm2_fp_sub(Y3, Y3, gamma);

#undef X1
#undef Y1
#undef Z1
#undef X3
#undef Y3
#undef Z3
}

void sm2_ec_j_mul_a(sm2_ec_j R, const uint8_t k[32], const sm2_ec_a P)
{
    uint32_t e[8];
    uint256_from_bytes(e, k);
    if (uint256_cmp(e, _SM2_CURVE_N) >= 0)
    {
        uint256_sub_borrow(e, e, _SM2_CURVE_N);
    }
    if (uint256_equal_zero(e))
    {
        sm2_ec_j_set_inf(R);
        return;
    }
    int i = 255;
    while (!uint256_bittest(e, i)) i--;
    sm2_ec_j T;
    sm2_ec_j_from_a(T, P);
    i--;
    for (; i >= 0; i--)
    {
        sm2_ec_j_dbl(T, T);
        if (uint256_bittest(e, i))
        {
            sm2_ec_j_add_a(T, T, P);
        }
    }
    sm2_ec_j_cpy(R, T);
}

void sm2_ec_j_mul_g(sm2_ec_j R, const uint8_t k[32])
{
    sm2_ec_a G;
    sm2_fp_from_bytes(G[0], SM2_CURVE_GX);
    sm2_fp_from_bytes(G[1], SM2_CURVE_GY);
    sm2_ec_j_mul_a(R, k, G);
}

void sm2_ec_j_from_a(sm2_ec_j R, const sm2_ec_a P)
{
    sm2_fp_cpy(R[0], P[0]);
    sm2_fp_cpy(R[1], P[1]);
    sm2_fp_set_one(R[2]);
}

void sm2_ec_j_to_a(sm2_ec_a R, const sm2_ec_j P)
{
    // x = X/Z^2, y = Y/Z^3
    sm2_fp_t inv2, inv3;
    sm2_fp_inv(inv3, P[2]);
    sm2_fp_sqr(inv2, inv3);
    sm2_fp_mul(inv3, inv3, inv2);
    sm2_fp_mul(R[0], P[0], inv2);
    sm2_fp_mul(R[1], P[1], inv3);
}

void sm2_ec_j_normal(sm2_ec_j R, const sm2_ec_j P)
{
    if (sm2_ec_j_is_inf(P))
    {
        sm2_ec_j_set_inf(R);
        return;
    }
    // x = X/Z^2, y = Y/Z^3
    sm2_fp_t inv2, inv3;
    sm2_fp_inv(inv3, P[2]);
    sm2_fp_sqr(inv2, inv3);
    sm2_fp_mul(inv3, inv3, inv2);
    sm2_fp_mul(R[0], P[0], inv2);
    sm2_fp_mul(R[1], P[1], inv3);
    sm2_fp_set_one(R[2]);
}

bool sm2_ec_j_equal(const sm2_ec_j P, const sm2_ec_j Q)
{
    // Xp * Zq^2 = Xq * Zp^2
    // Yp * Zq^3 = Yq * Zp^3
    sm2_fp_t Zq2, Zq3, Zp2, Zp3, t1, t2;
    sm2_fp_sqr(Zp2, P[2]);
    sm2_fp_mul(Zp3, Zp2, P[2]);
    sm2_fp_sqr(Zq2, Q[2]);
    sm2_fp_mul(Zq3, Zq2, Q[2]);
    sm2_fp_mul(t1, P[0], Zq2);
    sm2_fp_mul(t2, Q[0], Zp2);
    if (!sm2_fp_equal(t1, t2))
    {
        return false;
    }
    sm2_fp_mul(t1, P[1], Zq3);
    sm2_fp_mul(t2, Q[1], Zp3);
    if (!sm2_fp_equal(t1, t2))
    {
        return false;
    }
    return true;
}

#pragma endregion

}; // namespace sm2p256v1
}; // namespace tc