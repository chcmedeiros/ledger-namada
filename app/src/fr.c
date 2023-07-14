/*****************************************************************************
 *   Zcash Ledger App.
 *   (c) 2022 Hanh Huynh Huu.
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
 *****************************************************************************/

#include <stdint.h>   // uint*_t
#include <string.h>   // memset, explicit_bzero
#include <stdbool.h>  // bool
#include <os.h>       // sprintf

#include "lcx_rng.h"
#include "fr.h"

#include <stdint.h>

typedef struct {
    uint64_t limbs[4];
} jubjub_fr;

// Generate a random jubjub scalar (Fr)
void random_fr(uint8_t* alpha_ptr) {
    jubjub_fr fr;
    uint64_t rng_1;
    uint64_t rng_2;
    cx_rng_no_throw((uint8_t*)&rng_1, sizeof (uint64_t));
    cx_rng_no_throw((uint8_t*)&rng_2, sizeof (uint64_t));
    // Generate random values for each limb
    for (int i = 0; i < 4; i++) {
        fr.limbs[i] = rng_1 | (rng_2 << 32);
    }

    // Copy the generated scalar to the output pointer
    memcpy(alpha_ptr, &fr, sizeof(jubjub_fr));
}


void swap_endian(uint8_t *data, int8_t len) {
    for (int8_t i = 0; i < len / 2; i++) {
        uint8_t t = data[len - i - 1];
        data[len - i - 1] = data[i];
        data[i] = t;
    }
}

void swap_bit_endian(uint8_t *data, int8_t len) {
    for (int i = 0; i < len; i++) {
        uint8_t b = data[i];
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
        data[i] = b;
    }
}

#ifdef TEST
void print_bn_internal(const char *label, cx_bn_t bn) {
    uint8_t v[32];
    cx_bn_export(bn, v, 32);
    PRINTF(">> %s %.*H\n", label, 32, v);
}
#endif
