/*******************************************************************************
*  (c) 2018 - 2023 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>   // uint*_t
#include "constants.h"
#include "ff1.h"
#include "zxformat.h"
#include "zxmacros.h"

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)

#else
    #include "../../deps/sapling-rust/app/rust/include/rslib.h"
#endif

const uint32_t FIRSTVALUE = 0x80000020; // 32^0x80000000;
const uint32_t COIN_TYPE = 0x8000036d; // 877^0x80000000; hardened, fixed value from slip-0044
#include "fr.h"
#include "sapling.h"

void get_expanded_spending_key_from_seed(uint8_t *seed, expanded_spending_key_t* out);


/// q is the modulus of Fq
/// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
static const uint8_t fq_m[32] = {
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
        0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
        0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01
};

/// r is the modulus of Fr
/// r = 0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7
static const uint8_t fr_m[32] = {
        0x0e, 0x7d, 0xb4, 0xea, 0x65, 0x33, 0xaf, 0xa9,
        0x06, 0x67, 0x3b, 0x01, 0x01, 0x34, 0x3b, 0x00,
        0xa6, 0x68, 0x20, 0x93, 0xcc, 0xc8, 0x10, 0x82,
        0xd0, 0x97, 0x0e, 0x5e, 0xd6, 0xf7, 0x2c, 0xb7
};

/// the parameter d of JJ in Fq
/// JJ is a twisted Edward curve: -u^2 + v^2 = 1 + d.u^2.v^2
static const uint8_t fq_D[32] = {
        0x2A, 0x93, 0x18, 0xE7, 0x4B, 0xFA, 0x2B, 0x48,
        0xF5, 0xFD, 0x92, 0x07, 0xE6, 0xBD, 0x7F, 0xD4,
        0x29, 0x2D, 0x7F, 0x6D, 0x37, 0x57, 0x9D, 0x26,
        0x01, 0x06, 0x5F, 0xD6, 0xD6, 0x34, 0x3E, 0xB1,
};

/// 2*d in Fq
static const uint8_t fq_D2[32] = {
        0x55, 0x26, 0x31, 0xCE, 0x97, 0xF4, 0x56, 0x91,
        0xEB, 0xFB, 0x24, 0x0F, 0xCD, 0x7A, 0xFF, 0xA8,
        0x52, 0x5A, 0xFE, 0xDA, 0x6E, 0xAF, 0x3A, 0x4C,
        0x02, 0x0C, 0xBF, 0xAD, 0xAC, 0x68, 0x7D, 0x62,
};

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

uint32_t HtoLE32(uint32_t value) {
    return value;
}

#else

uint32_t HtoLE32(uint32_t value) {
    return ((value & 0x000000FFu) << 24u) |
           ((value & 0x0000FF00u) << 8u) |
           ((value & 0x00FF0000u) >> 8u) |
           ((value & 0xFF000000u) >> 24u);
}

#endif

static void little_endian_write_u32(uint32_t n, uint8_t* out, uint8_t out_len){
    if (out_len < 4){
        MEMZERO(out, out_len);
        return;
        // todo error?
    }
    *out = HtoLE32(n);
}


#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)

    #include "cx.h"
    #include <lcx_ecfp.h>
    #include <lcx_hash.h>
    #include <ox_bn.h>
    #include "cx_blake2.h"

static cx_bn_t M; // M is the modulus in the base field of jubjub, Fq
    #ifndef NO_MONTGOMERY
    static const uint8_t mont_h[] = {
        0x07, 0x48, 0xd9, 0xd9, 0x9f, 0x59, 0xff, 0x11, 0x05, 0xd3, 0x14, 0x96, 0x72, 0x54, 0x39, 0x8f, 0x2b, 0x6c, 0xed, 0xcb, 0x87, 0x92, 0x5c, 0x23, 0xc9, 0x99, 0xe9, 0x90, 0xf3, 0xf2, 0x9c, 0x6d
    };
    #endif

    #include "mont.h"


void e_to_en(jj_en_t *dest, jj_e_t *src);
void e_double(jj_e_t *r);
void een_add_assign(jj_e_t *x, jj_en_t *y);

static void alloc_e(jj_e_t *r) {
    cx_bn_alloc(&r->u, 32);
    cx_bn_alloc(&r->v, 32);
    cx_bn_alloc(&r->z, 32);
    cx_bn_alloc(&r->t1, 32);
    cx_bn_alloc(&r->t2, 32);
}

static void destroy_e(jj_e_t *r) {
    cx_bn_destroy(&r->u);
    cx_bn_destroy(&r->v);
    cx_bn_destroy(&r->z);
    cx_bn_destroy(&r->t1);
    cx_bn_destroy(&r->t2);
}

static void alloc_en(jj_en_t *r) {
    cx_bn_alloc(&r->vpu, 32);
    cx_bn_alloc(&r->vmu, 32);
    cx_bn_alloc(&r->z, 32);
    cx_bn_alloc(&r->t2d, 32);
}

static void destroy_en(jj_en_t *r) {
    cx_bn_destroy(&r->vpu);
    cx_bn_destroy(&r->vmu);
    cx_bn_destroy(&r->z);
    cx_bn_destroy(&r->t2d);
}

/// @brief load ff into bn, convert to MF
/// @param dest
/// @param src
static void load_en(jj_en_t *dest, const ff_jj_en_t *src) {
    cx_bn_init(dest->vpu, src->vpu, 32); TO_MONT(dest->vpu);
    cx_bn_init(dest->vmu, src->vmu, 32); TO_MONT(dest->vmu);
    cx_bn_init(dest->z, src->z, 32); TO_MONT(dest->z);
    cx_bn_init(dest->t2d, src->t2d, 32); TO_MONT(dest->t2d);
}

/// @brief set r to identity
/// @param r
static void e_set0(jj_e_t *r) {
    // (0, 1, 1, 0, 0)
    cx_bn_set_u32(r->u, 0);
    cx_bn_set_u32(r->v, 1); TO_MONT(r->v);
    cx_bn_copy(r->z, r->v);
    cx_bn_copy(r->t1, r->u);
    cx_bn_copy(r->t2, r->u);
}

/// @brief Multiplies G by sk
/// @param pk output point in extended coord
/// @param G generator in extended niels coord
/// @param sk scalar
void en_mul(jj_e_t *pk, jj_en_t *G, cx_bn_t sk) {
    bool bit;
    e_set0(pk);
    jj_en_t id; alloc_en(&id);
    e_to_en(&id, pk);
    // Skip the higest 4 bits as they are always 0 for Fr
    for (uint16_t i = 4; i < 256; i++) {
        cx_bn_tst_bit(sk, 255 - i, &bit);
        e_double(pk);
        PRINTF("*");
        if (bit) {
            PRINTF("+");
            een_add_assign(pk, G);
        }
        else
            een_add_assign(pk, &id); // make it constant time
    }
    destroy_en(&id);
    PRINTF("\n");
}

void e_double(jj_e_t *r) {
    BN_DEF(temp);
    BN_DEF(uu);
    cx_bn_copy(uu, r->u);
    CX_MUL(temp, uu, uu);
    cx_bn_copy(uu, temp);

    BN_DEF(vv);
    cx_bn_copy(vv, r->v);
    CX_MUL(temp, vv, vv);
    cx_bn_copy(vv, temp);

    BN_DEF(zz2);
    cx_bn_copy(zz2, r->z);
    CX_MUL(temp, zz2, zz2);
    cx_bn_copy(zz2, temp);
    cx_bn_mod_add_fixed(zz2, zz2, zz2, M);

    BN_DEF(uv2);
    cx_bn_mod_add_fixed(uv2, r->u, r->v, M);
    CX_MUL(temp, uv2, uv2);
    cx_bn_copy(uv2, temp);

    BN_DEF(vpu);
    cx_bn_mod_add_fixed(vpu, vv, uu, M); // vpu = v*v + u*u

    BN_DEF(vmu);
    cx_bn_mod_sub(vmu, vv, uu, M); // vmu = v*v - u*u

    BN_DEF(t);
    cx_bn_mod_sub(t, zz2, vmu, M);

    cx_bn_mod_sub(r->t1, uv2, vpu, M);
    cx_bn_copy(r->t2, vpu);
    CX_MUL(r->u, r->t1, t);
    CX_MUL(r->v, r->t2, vmu);
    CX_MUL(r->z, vmu, t);

    cx_bn_destroy(&temp);
    cx_bn_destroy(&t);
    cx_bn_destroy(&vmu);
    cx_bn_destroy(&vpu);
    cx_bn_destroy(&uv2);
    cx_bn_destroy(&zz2);
    cx_bn_destroy(&vv);
    cx_bn_destroy(&uu);
}

/// @brief x += y
/// @param r point in extended coord
/// @param a point in extended niels coord
void een_add_assign(jj_e_t *x, jj_en_t *y) {
    BN_DEF(temp);
    BN_DEF(a);
    BN_DEF(b);
    cx_bn_mod_sub(a, x->v, x->u, M); // a = (v - u) * vmu
    CX_MUL(temp, a, y->vmu);
    cx_bn_copy(a, temp);
    cx_bn_mod_add_fixed(b, x->v, x->u, M); // b = (v + u) * vpu
    CX_MUL(temp, b, y->vpu);
    cx_bn_copy(b, temp);

    BN_DEF(c);
    BN_DEF(d);
    CX_MUL(temp, x->t1, x->t2);
    CX_MUL(c, temp, y->t2d); // c = t1 * t2 * t2d
    CX_MUL(d, x->z, y->z);
    cx_bn_mod_add_fixed(d, d, d, M); // d = 2zz

    BN_DEF(u);
    BN_DEF(v);
    cx_bn_mod_sub(u, b, a, M); // u = b - a
    cx_bn_mod_add_fixed(v, b, a, M); // v = b + a

    BN_DEF(z);
    BN_DEF(t);
    cx_bn_mod_add_fixed(z, d, c, M); // z = d + c
    cx_bn_mod_sub(t, d, c, M); // t = d - c

    cx_bn_destroy(&a);
    cx_bn_destroy(&b);
    cx_bn_destroy(&c);
    cx_bn_destroy(&d);

    CX_MUL(x->u, u, t); // u = ut
    CX_MUL(x->v, v, z); // v = vz
    CX_MUL(x->z, z, t); // z = zt
    cx_bn_copy(x->t1, u); // t1 = u
    cx_bn_copy(x->t2, v); // t2 = v

    cx_bn_destroy(&u);
    cx_bn_destroy(&v);
    cx_bn_destroy(&z);
    cx_bn_destroy(&t);
    cx_bn_destroy(&temp);
}

/// @brief Convert from ext to ext niels
/// @param dest
/// @param src
void e_to_en(jj_en_t *dest, jj_e_t *src) {
    BN_DEF(D2); cx_bn_init(D2, fq_D2, 32); TO_MONT(D2);
    BN_DEF(temp);
    cx_bn_mod_add_fixed(dest->vpu, src->v, src->u, M);
    cx_bn_mod_sub(dest->vmu, src->v, src->u, M);
    cx_bn_copy(dest->z, src->z);
    CX_MUL(temp, src->t1, src->t2);
    CX_MUL(dest->t2d, temp, D2);
    cx_bn_destroy(&D2);
    cx_bn_destroy(&temp);
}

/// @brief convert a point into its compressed bytes representation
/// @param pkb v coord with highest bit set to the parity of u, in LE
/// @param p
void e_to_bytes(uint8_t *pkb, jj_e_t *p) {
    BN_DEF(zinv);
    cx_bn_copy(zinv, p->z);
    cx_bn_mod_invert_nprime(zinv, zinv, M);

    // Do not use the Montgomery Multiplication because
    // zinv contains the 1/h factor equivalent to FROM_MONT
    BN_DEF(u);
    CX_BN_MOD_MUL(u, p->u, zinv);
    BN_DEF(v);
    CX_BN_MOD_MUL(v, p->v, zinv);

    bool sign; // put the parity of u into highest bit of v
    cx_bn_tst_bit(u, 0, &sign);
    if (sign)
        cx_bn_set_bit(v, 255);
    cx_bn_export(v, pkb, 32);
    swap_endian(pkb, 32); // to LE
    cx_bn_destroy(&zinv);
    cx_bn_destroy(&u);
    cx_bn_destroy(&v);
}

/// @brief Coordinate u extractor
/// @param u 32 bytes
/// @param p
void e_to_u(uint8_t *ub, const jj_e_t *p) {
    BN_DEF(zinv);
    cx_bn_copy(zinv, p->z);
    cx_bn_mod_invert_nprime(zinv, zinv, M);

    // Do not use the Montgomery Multiplication because
    // zinv contains the 1/h factor equivalent to FROM_MONT
    BN_DEF(u);
    CX_BN_MOD_MUL(u, p->u, zinv);

    cx_bn_export(u, ub, 32);
    swap_endian(ub, 32);
    cx_bn_destroy(&zinv);
    cx_bn_destroy(&u);
}

/// @brief hash into an extended point
/// @param p
/// @param msg
/// @param len
/// @return CX_INVALID_PARAMETER if hash does not correspond to a point
int hash_to_e(jj_e_t *p, const uint8_t *msg, size_t len) {
    int cx_error = 0;

    blake2s_param hash_params;
    blake2s_state hash_ctx;
    uint8_t hash[32];

    memset(&hash_params, 0, sizeof(hash_params));
    hash_params.digest_length = 32;
    hash_params.fanout = 1;
    hash_params.depth = 1;
    memmove(&hash_params.personal, "MASP__gd", 8);

    blake2s_init_param(&hash_ctx, &hash_params);
    blake2s_update(&hash_ctx, "096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0", 64);
    blake2s_update(&hash_ctx, msg, len);
    blake2s_final(&hash_ctx, hash, 32);

    BN_DEF(one); cx_bn_set_u32(one, 1); TO_MONT(one);
    BN_DEF(v);
    BN_DEF(temp);
    BN_DEF(v2);
    BN_DEF(v2m1);
    BN_DEF(D); cx_bn_init(D, fq_D, 32); TO_MONT(D);
    BN_DEF(u2);
    BN_DEF(u);

    uint8_t sign = hash[31] >> 7;
    hash[31] &= 0x7F;
    swap_endian(hash, 32);

    cx_bn_init(v, hash, 32);
    int diff;
    cx_bn_cmp(v, M, &diff);
    if (diff >= 0) {
        cx_error = CX_INVALID_PARAMETER;
        goto end;
    }

    TO_MONT(v);
    CX_MUL(v2, v, v);

    cx_bn_mod_sub(v2m1, v2, one, M); // v2-1

    CX_MUL(temp, v2, D); //v2*D
    cx_bn_mod_add_fixed(v2, temp, one, M); //v2*D+1 (*h)
    cx_bn_mod_invert_nprime(temp, v2, M); // 1/(v2*D+1) (/h)

    // Don't use Mont. Mult because temp has 1/h
    CX_BN_MOD_MUL(u2, v2m1, temp); // u2 = (v2-1)/(v2*D+1)
    print_bn("u2", u2);

    cx_error = cx_bn_mod_sqrt(u, u2, M, sign);
    if (cx_error) {
        cx_error = CX_INVALID_PARAMETER;
        goto end;
    }
    TO_MONT(u);

    cx_bn_copy(p->u, u);
    cx_bn_copy(p->v, v);
    cx_bn_copy(p->z, one);
    cx_bn_copy(p->t1, u);
    cx_bn_copy(p->t1, v);

    e_double(p);
    e_double(p);
    e_double(p); // *8 (cofactor)

    end:
    cx_bn_destroy(&v);
    cx_bn_destroy(&one);
    cx_bn_destroy(&temp);
    cx_bn_destroy(&v2);
    cx_bn_destroy(&v2m1);
    cx_bn_destroy(&D);
    cx_bn_destroy(&u2);
    cx_bn_destroy(&u);

    return cx_error;
}
void sk_to_pk(uint8_t *pkb, jj_en_t *G, cx_bn_t sk) {
    jj_e_t pk; alloc_e(&pk);
    en_mul(&pk, G, sk);
    e_to_bytes(pkb, &pk);
    destroy_e(&pk);
}

void ask_to_ak(uint8_t *ask_bytes, uint8_t *ak_out){
    // ak is the byte representation of A = G.ask where G is the spending auth generator point
    cx_bn_t ask;
    CX_THROW(cx_bn_alloc(&ask, 32));
    cx_bn_init(ask, ask_bytes, 32);
    jj_en_t G;
    alloc_en(&G);
    load_en(&G, &SPENDING_GEN);

    sk_to_pk(ak_out, &G, ask);
    cx_bn_destroy(&ask);
    destroy_en(&G);
}

void nsk_to_nk(uint8_t *nsk_bytes, uint8_t *nk_out){
    cx_bn_t nsk;
    CX_THROW(cx_bn_alloc(&nsk, 32));
    cx_bn_init(nsk, nsk_bytes, 32);
    jj_en_t G; alloc_en(&G); load_en(&G, &PROOF_GEN);
    sk_to_pk(nk_out, &G, nsk);
    cx_bn_destroy(&nsk);
    destroy_en(&G);
}
#else
void ask_to_ak(uint8_t *ask_bytes, uint8_t *ak_out){
    sapling_ask_to_ak(ask_bytes,ak_out);
}

void nsk_to_nk(uint8_t *nsk_bytes, uint8_t *nk_out){
    sapling_nsk_to_nk(nsk_bytes, nk_out);
}
#endif

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
static void derive_master_spending_key_from_seed(uint8_t *seed, uint8_t* out_spending_key) {
    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 512, NULL, 0, (uint8_t *) "MASP_IP32Sapling", 16);
    cx_hash_no_throw(&ctx.header, CX_LAST, seed, ZIP32_SEED_SIZE, out_spending_key, 512);
}

// Reduce a 64 byte value modulo M
// dest: 32 bytes
// src: 64 bytes, src is modified!
// mod: the modulus M
static void from_bytes_wide(cx_bn_t dest, uint8_t *src, cx_bn_t mod) {
    swap_endian(src, 64);
    cx_bn_t SRC; cx_bn_alloc_init(&SRC, 64, src, 64);
    cx_bn_reduce(dest, SRC, mod);
    cx_bn_destroy(&SRC);
}

static void prf_expand(const uint8_t *sk, uint32_t sk_len,
                       const uint8_t *t, uint32_t t_len,
                       uint8_t *out) {
    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 8 * CTX_EXPAND_SEED_HASH_LEN, NULL, 0, (uint8_t *) CTX_EXPAND_SEED, CTX_EXPAND_SEED_LEN);
    cx_hash_no_throw(&ctx.header, 0, sk, sk_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, CX_LAST, t, t_len, out, CTX_EXPAND_SEED_HASH_LEN);
}
#else
static void derive_master_spending_key_from_seed(uint8_t *seed, uint8_t* out_spending_key) {
    master_spending_key_zip32(seed, out_spending_key);
}

void prf_expand(const uint8_t *sk, uint32_t sk_len,
                       const uint8_t *t, uint32_t t_len,
                       uint8_t *out) {
    rust_prf_expand(sk, t, out);
}
#endif




#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)

void masp_blake2b_expand_vec_four(const uint8_t *a, uint32_t a_len,
                                     const uint8_t *b, uint32_t b_len,
                                     const uint8_t *c, uint32_t c_len,
                                     const uint8_t *d, uint32_t d_len,
                                     const uint8_t *e, uint32_t e_len,
                                     uint8_t *out) {
    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 8 * CTX_EXPAND_SEED_HASH_LEN, NULL, 0, (uint8_t *) CTX_EXPAND_SEED, CTX_EXPAND_SEED_LEN);
    cx_hash_no_throw(&ctx.header, 0, a, a_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, 0, b, b_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, 0, c, c_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, 0, d, d_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, CX_LAST, e, e_len, out, CTX_EXPAND_SEED_HASH_LEN);
}

void masp_blake2b_expand_vec_three(const uint8_t *a, uint32_t a_len,
                                  const uint8_t *b, uint32_t b_len,
                                  const uint8_t *c, uint32_t c_len,
                                  const uint8_t *d, uint32_t d_len,
                                  uint8_t *out) {
    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 8 * CTX_EXPAND_SEED_HASH_LEN, NULL, 0, (uint8_t *) CTX_EXPAND_SEED, CTX_EXPAND_SEED_LEN);
    cx_hash_no_throw(&ctx.header, 0, a, a_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, 0, b, b_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, 0, c, c_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, CX_LAST, d, d_len, out, CTX_EXPAND_SEED_HASH_LEN);
}

void masp_blake2b_expand_vec_two(const uint8_t *a, uint32_t a_len,
                                    const uint8_t *b, uint32_t b_len,
                                    const uint8_t *c, uint32_t c_len,
                                    uint8_t *out) {
    cx_blake2b_t ctx;
    cx_blake2b_init2_no_throw(&ctx, 8 * CTX_EXPAND_SEED_HASH_LEN, NULL, 0, (uint8_t *) CTX_EXPAND_SEED, CTX_EXPAND_SEED_LEN);
    cx_hash_no_throw(&ctx.header, 0, a, a_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, 0, b, b_len, NULL, 0);
    cx_hash_no_throw(&ctx.header, CX_LAST, c, c_len, out, CTX_EXPAND_SEED_HASH_LEN);
}

#else

void masp_blake2b_expand_vec_four(const uint8_t *a, uint32_t a_len,
                                  const uint8_t *b, uint32_t b_len,
                                  const uint8_t *c, uint32_t c_len,
                                  const uint8_t *d, uint32_t d_len,
                                  const uint8_t *e, uint32_t e_len,
                                  uint8_t *out) {
rust_blake2b_expand_vec_four(a, a_len, b, b_len, c, c_len, d, d_len, e, e_len, out, 64);
}

void masp_blake2b_expand_vec_three(const uint8_t *a, uint32_t a_len,
                                   const uint8_t *b, uint32_t b_len,
                                   const uint8_t *c, uint32_t c_len,
                                   const uint8_t *d, uint32_t d_len,
                                   uint8_t *out) {
    rust_blake2b_expand_vec_three(a, a_len, b, b_len, c, c_len, d, d_len, out, 64);
}

void masp_blake2b_expand_vec_two(const uint8_t *a, uint32_t a_len,
                                 const uint8_t *b, uint32_t b_len,
                                 const uint8_t *c, uint32_t c_len,
                                 uint8_t *out) {
    rust_blake2b_expand_vec_two(a, a_len, b, b_len, c, c_len, out, 64);

}


#endif


void derive_dummy_ask_and_nsk(uint8_t *key_in, uint8_t *ask_out, uint8_t *nsk_out){
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    cx_bn_lock(32, 0);
    cx_bn_t rM; CX_THROW(cx_bn_alloc(&rM, 32));
    cx_bn_init(rM, fr_m, 32);
    init_mont(fq_m);

    cx_bn_t temp;
    CX_THROW(cx_bn_alloc(&temp, 32));
#endif

    // derive the first layer of keys
    // ask, nsk are scalars obtained by hashing into 512 bit integer and then reducing mod R
    // ovk, dk are the first 256 bits of the 512 bit hash
    uint8_t buffer[64]={0};
    uint8_t *const_ask = {0x00};
    prf_expand(key_in, sizeof(key_in), const_ask, sizeof(const_ask), buffer);
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    from_bytes_wide(temp, buffer, rM);
    cx_bn_export(temp, ask_out, ASK_SIZE);
#else
    rust_from_bytes_wide(ask_out, buffer);
#endif

    MEMZERO(buffer, sizeof(buffer));

    uint8_t const_nsk[] = {0x01};
    prf_expand(key_in, sizeof(key_in), const_nsk, sizeof(const_nsk), buffer);
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    from_bytes_wide(temp, buffer, rM);
    cx_bn_export(temp, nsk_out, NSK_SIZE);

    cx_bn_destroy(&temp);

#else
    rust_from_bytes_wide(nsk_out, buffer);
#endif
    MEMZERO(buffer, sizeof(buffer));
}

void get_fvk(uint8_t *seed, uint32_t pos, full_viewing_key_t* out){
    uint32_t path[3] = {FIRSTVALUE, COIN_TYPE, pos};

    uint8_t master_spending_key[64] = {0};
    derive_master_spending_key_from_seed(seed, master_spending_key);
    uint8_t key[32] = {0};
    uint8_t chain[32] = {0};
    memcpy(key, master_spending_key,  32);
    memcpy(chain, master_spending_key + 32,  32);

    expanded_spending_key_t expandedSpendingKey;
    get_expanded_spending_key_from_seed(seed, &expandedSpendingKey);

    uint8_t ask_bytes[ASK_SIZE] = {0};
    uint8_t nsk_bytes[NSK_SIZE] = {0};

    memcpy(ask_bytes, &expandedSpendingKey, ASK_SIZE);
    memcpy(nsk_bytes, &expandedSpendingKey + ASK_SIZE, NSK_SIZE);

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
    cx_bn_t ask; CX_THROW(cx_bn_alloc(&ask, 32));
    cx_bn_init(ask, ask_bytes, 32);
    cx_bn_t nsk; CX_THROW(cx_bn_alloc(&nsk, 32));
    cx_bn_init(nsk, nsk_bytes, 32);
#endif
    uint8_t tmp[64] = {0};
    for (unsigned int i = 0; i < sizeof(path); ++i) {
        uint32_t p = path[i];
        uint8_t hardened = ((p & 0x80000000) != 0);
        uint32_t c = (p & 0x7FFFFFFF);
        if (hardened){
            uint8_t le_i[4] = {0};
            uint8_t tmp_const[] = {0x11};
            little_endian_write_u32((c+(1<<31)), le_i, sizeof (le_i));
            uint8_t *start_esk = expandedSpendingKey.ask;
            masp_blake2b_expand_vec_three(chain, sizeof (chain),
                                         tmp_const, sizeof (tmp_const),
                                          start_esk, sizeof (expandedSpendingKey),
                                         le_i, sizeof (le_i), tmp);
        } else {
            full_viewing_key_t fvk;
            ask_to_ak(expandedSpendingKey.ask, fvk.ak);
            nsk_to_nk(expandedSpendingKey.nsk, fvk.nk);
            memcpy(fvk.dk, expandedSpendingKey.dk, DK_SIZE);

            uint8_t buffer[64]={0};
            uint8_t ovk_const[] = {0x10};
            prf_expand(key, sizeof(key), ovk_const, sizeof(ovk_const), buffer);
            memcpy(&fvk.ovk, buffer, OVK_SIZE);

            uint8_t le_i[4] = {0};
            uint8_t tmp_const[] = {0x12};
            little_endian_write_u32(c, le_i, sizeof (le_i));
            uint8_t *start_fvk = fvk.ak;
            masp_blake2b_expand_vec_three(chain, sizeof (chain),
                                         tmp_const, sizeof (tmp_const),
                                          start_fvk, sizeof (fvk),
                                         le_i, sizeof (le_i), tmp);
        }
        memcpy(key, tmp,  32);
        memcpy(chain, tmp + 32,  32);

        // update ask and nsk
        uint8_t ask_cur_bytes[ASK_SIZE] = {0};
        uint8_t nsk_cur_bytes[NSK_SIZE] = {0};
        uint8_t buffer[64]={0};

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_bn_lock(32, 0);
        cx_bn_t rM; CX_THROW(cx_bn_alloc(&rM, 32));
        cx_bn_init(rM, fr_m, 32);
        init_mont(fq_m);

        cx_bn_t temp; CX_THROW(cx_bn_alloc(&temp, 32));
#endif
        uint8_t ask_cur_const[] = {0x13};
        prf_expand(key, sizeof(key), ask_cur_const, sizeof(ask_cur_const), buffer);
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        from_bytes_wide(temp, buffer, rM);
        cx_bn_export(temp, ask_cur_bytes, ASK_SIZE);
        cx_bn_t ask_cur; CX_THROW(cx_bn_alloc(&ask_cur, ASK_SIZE));
        cx_bn_init(ask_cur, ask_cur_bytes, ASK_SIZE);
#else
        rust_from_bytes_wide(ask_cur_bytes, buffer);
#endif

        MEMZERO(buffer, sizeof(buffer));

        uint8_t nsk_cur_const[] = {0x14};
        prf_expand(key, sizeof(key), nsk_cur_const, sizeof(nsk_cur_const), buffer);
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        from_bytes_wide(temp, buffer, rM);
        cx_bn_export(temp, nsk_cur_bytes, NSK_SIZE);
        cx_bn_t nsk_cur; CX_THROW(cx_bn_alloc(&nsk_cur, NSK_SIZE));
        cx_bn_init(nsk_cur, nsk_cur_bytes, NSK_SIZE);

        cx_bn_destroy(&temp);
#else
        rust_from_bytes_wide(nsk_cur_bytes, buffer);
#endif
        MEMZERO(buffer, sizeof(buffer));

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_bn_mod_add_fixed(ask, ask, ask_cur, M); // ask = ask + ask_cur
        cx_bn_mod_add_fixed(nsk, nsk, nsk_cur, M); // nsk = nsk + nsk_cur
#else
        rust_fr_add(ask_bytes, ask_cur_bytes, ask_bytes);
        rust_fr_add(nsk_bytes, nsk_cur_bytes, nsk_bytes);
#endif
        // Update expanded spending key
        // ask and nsk
        derive_dummy_ask_and_nsk(key, expandedSpendingKey.ask, expandedSpendingKey.nsk);
        uint8_t tmp_const_ovk[] = {0x15};
        // ovk
        masp_blake2b_expand_vec_two(key, sizeof (key),
                                    tmp_const_ovk, sizeof (tmp_const_ovk),
                                    expandedSpendingKey.ovk, OVK_SIZE,
                                    buffer);
        memcpy(expandedSpendingKey.ovk, buffer, OVK_SIZE);
        MEMZERO(buffer, sizeof(buffer));

        // dk
        uint8_t tmp_const_dk[] = {0x16};

        masp_blake2b_expand_vec_two(key, sizeof (key),
                                    tmp_const_dk, sizeof (tmp_const_dk),
                                    expandedSpendingKey.dk, DK_SIZE,
                                    buffer);
        memcpy(expandedSpendingKey.dk, buffer, DK_SIZE);
        MEMZERO(buffer, sizeof(buffer));
    }
    ask_to_ak(ask_bytes, out->ak);
    nsk_to_nk(nsk_bytes, out->nk);
    memcpy(out->ovk, expandedSpendingKey.ovk, OVK_SIZE);
    memcpy(out->dk, expandedSpendingKey.dk, DK_SIZE);
}


void get_expanded_spending_key_from_seed(uint8_t *seed, expanded_spending_key_t* out){
    uint8_t master_spending_key[64] = {0};
    derive_master_spending_key_from_seed(seed, (uint8_t *) master_spending_key);
    uint8_t key[32] = {0};
    memcpy(key, master_spending_key, 32);

    // derive the first layer of keys
    // ask, nsk are scalars obtained by hashing into 512 bit integer and then reducing mod R
    derive_dummy_ask_and_nsk(key, out->ask, out->nsk);

    // ovk, dk are the first 256 bits of the 512 bit hash
    uint8_t buffer[64]={0};
    uint8_t const_ovk[] = {0x02};
    prf_expand(key, sizeof(key), const_ovk, sizeof(const_ovk), buffer);
    memcpy(out->ovk, buffer, OVK_SIZE);

    MEMZERO(buffer, sizeof(buffer));

    uint8_t const_dk[] = {0x10};
    prf_expand(key, sizeof(key), const_dk, sizeof(const_dk), buffer);
    memcpy(out->dk, buffer, DK_SIZE);
}

#ifdef __cplusplus
}
#endif