#pragma once

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
#include <lcx_math.h>
#endif

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#include "../coin.h"

/**
 * Work around an issue on the ST33K1M5 chip
 * Adding two numbers can result in a number greater than the modulus
 * We reduce it by subtracting 0
*/
#ifdef MOD_ADD_FIX
#define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m); cx_bn_mod_sub(a, a, zero, m)
#else
#define cx_bn_mod_add_fixed(a, b, c, m) cx_bn_mod_add(a, b, c, m)
#endif

typedef uint8_t fr_t[32];
typedef uint8_t fq_t[32];

typedef uint8_t fp_t[32];
typedef uint8_t fv_t[32];

/// Modulus of Pasta base field
/// p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
static const uint8_t fp_m[32] = {
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b, 
  0x99, 0x2d, 0x30, 0xed, 0x00, 0x00, 0x00, 0x01,
};

/// Modulus of Pasta scalar field
/// v = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
static const uint8_t fv_m[32] = {
  0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x22, 0x46, 0x98, 0xfc, 0x09, 0x94, 0xa8, 0xdd, 
  0x8c, 0x46, 0xeb, 0x21, 0x00, 0x00, 0x00, 0x01,
};

/// @brief Reverse bytes of data
/// @param data pointer to the beginning of the array
/// @param len length of the array
void swap_endian(uint8_t *data, int8_t len);

/// @brief Reverse each byte bit by bit (does not reverse the bytes themselves)
/// @param data pointer to the beginning of the array
/// @param len length of the array
void swap_bit_endian(uint8_t *data, int8_t len);

#ifdef TEST
void print_bn_internal(const char *label, cx_bn_t bn);
#define print_bn(label, bn) print_bn_internal(label, bn)
#else
#define print_bn(label, bn)
#endif

int ff_is_zero(uint8_t *v);

// Generate a random jubjub scalar (Fr)
void random_fr(uint8_t *alpha_ptr);

#define BN_DEF(a) cx_bn_t a; CX_THROW(cx_bn_alloc(&a, 32));

