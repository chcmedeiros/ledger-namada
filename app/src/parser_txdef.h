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
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include "parser_types.h"
#include "coin.h"

typedef struct {
    uint8_t address[ADDRESS_LEN_TESTNET];
    const char *symbol;
} tokens_t;

typedef struct {
    uint8_t hash[SHA256_SIZE];
    const char *text;
} vp_types_t;
// -----------------------------------------------------------------
typedef struct {
    bytes_t hash;
    bytes_t r;
    bytes_t s;
    bytes_t pubKey;
} signature_section_t;

typedef struct {
    bytes_t bytes;
    fees_t fees;
    bytes_t pubkey;
    uint64_t epoch;
    uint64_t gasLimit;
    bytes_t dataHash;
    bytes_t codeHash;
} header_t;

typedef struct {
    uint8_t discriminant;
    bytes_t salt;
    bytes_t bytes;
} section_t;

typedef struct {
    uint32_t sectionLen;
    section_t data;
    section_t extraData;
    section_t code;
    signature_section_t signatures[3];
} sections_t;
typedef struct {
    bytes_t timestamp;
    header_t header;
    sections_t sections;
} transaction_t;


typedef struct{
    transaction_type_e typeTx;
    union {
        tx_bond_t bond;
        tx_transfer_t transfer;
        tx_init_account_t initAccount;
        tx_withdraw_t withdraw;
        tx_init_validator_t initValidator;
        tx_update_vp_t updateVp;
    };

    transaction_t transaction;

} parser_tx_t;


#ifdef __cplusplus
}
#endif
