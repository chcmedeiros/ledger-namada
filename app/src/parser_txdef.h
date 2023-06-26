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

// Sapling constants
#define DIVERSIFIER_LENGTH      11
#define SAPLING_OUTPUT_INFO_LEN 725


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
    bytes_t asset_type_id;
    uint64_t value;
} amount_t;

typedef struct {
    bytes_t cv; // 32 bytes: Extended Point, i.e. 5 elements in Fq, each of which are represented by 32 bytes
    bytes_t anchor; // 32 bytes: bls12_381::Scalar
    bytes_t nullifier; // 32 bytes:  [u8; 32]
    bytes_t rk; // 32 bytes: Extended Point, i.e. 5 elements in Fq, each of which are represented by 32
    bytes_t zkproof; // [u8; GROTH_PROOF_SIZE] where GROTH_PROOF_SSIZE = 48 + 96 + 48 = 192
    bytes_t spend_auth_sig; // 64 bytes:    rbar: [u8; 32], sbar: [u8; 32],
} spend_description_t; //

typedef struct {
    bytes_t ask; // jubjub Fr, i.e. [u64; 4] -> 32 bytes
    bytes_t nsk; // jubjub Fr, i.e. [u64; 4] -> 32 bytes
    bytes_t ovk; // [u8; 32]
} expanded_spending_key_t;

typedef struct {
    uint8_t depth;
    bytes_t parent_fvk_tag; // [u8; 4]
    uint8_t child_index_type; // 0 = NonHardened, 1 = Hardened
    uint32_t child_index;
    bytes_t chain_code; // [u8; 32]
    expanded_spending_key_t expsk;
    bytes_t dk; // [u8; 32]
} extended_spending_key_t; // 74 + 96 = 170

typedef struct {
    bytes_t asset_type; // [u8;32]
    uint64_t value; // 8 bytes
    bytes_t g_d; // 32 bytes
    bytes_t pk_d; // 32 bytes
    uint8_t rseed_type; // enum : 1 BeforeZip212(jubjub::Fr), 2 AfterZip212([u8; 32]),
    bytes_t rseed; // [u8;32]
} note_t; // 137

typedef struct {
    bytes_t cv; // 32 bytes
    bytes_t anchor; // 32 bytes: bls12_381::Scalar
    bytes_t zkproof; // [u8; 192]
} convert_description_t;

typedef struct {
    uint32_t num_auth_path;
    bytes_t auth_path; // Vec<33 bytes>: auth_path is a vec of Node (which is a [u8; 32]) and bool
    bytes_t generator; // 160 bytes: Extended Point, i.e. 5 elements in Fq, each of which are represented by 32 bytes
} merkle_path_t;

typedef struct {
    extended_spending_key_t extsk; //  170 bytes
    bytes_t diversifier; // [u8;DIVERSIFIER_LENGTH]
    note_t note; // 137 bytes
    bytes_t alpha; // jubjub Fr, i.e. [u64; 4],
    merkle_path_t merkle_path; // depends
} spend_description_info_t; //

typedef struct{
    bytes_t diversifier; // [u8;DIVERSIFIER_LENGTH]
    bytes_t pk_d; // jubjub::SubgroupPoint -> 160 bytes as Extended Point
} sapling_payment_address_t;

typedef struct {
    uint8_t has_ovk;
    bytes_t ovk; // [u8; 32]
    sapling_payment_address_t to; // 43 bytes
    note_t note; // 137
    bytes_t memo_bytes; // [0u8; 512]
} sapling_output_info; // fixed length: 725 bytes

typedef struct {
    bytes_t cv; // 160 bytes: Jubjub Extended Point, i.e. 5 elements in Fq, each of which are represented by 32 bytes
    bytes_t cmu; // 32 bytes: bls12_381::Scalar
    bytes_t ephemeral_key; // 32 bytes:  [u8; 32]
    bytes_t enc_ciphertext; // [u8; 580 + 32],
    bytes_t out_ciphertext; // [u8; 80],
    bytes_t zkproof; //Proof, [u8; 192]
} output_description_t; // 224 bytes

typedef struct {
    uint8_t num_of_shielded_spends;
    spend_description_t shielded_spends[3];
    uint8_t num_of_shielded_converts;
    convert_description_t shielded_converts[3];
    uint8_t num_of_shielded_outputs;
    output_description_t shielded_outputs[3];
    amount_t value_balance;
    bytes_t authorization_proof; // GrothProofBytes
    bytes_t authorization_sig_rbar; // redjubjub::Signature rbar
    bytes_t authorization_sig_sbar; // redjubjub::Signature sbar
    // nothing? or (unauth) a Vec<TransparentInputInfo>
    // for shielded a redjubjub::Signature
} masp_sapling_bundle_t;

typedef struct{
    bytes_t asset_type_id; // [u8;32]
    int64_t value; // 8 bytes
    bytes_t transparent_address; // [u8;20]
    //bytes_t transparent_sig; // this seems to always be empty
} masp_vin_t;

// https://github.com/anoma/masp/blob/0d7dc07d24b878e9162c25260ed744265dd2f748/masp_primitives/src/transaction/components/transparent.rs#L32
typedef struct {
    uint8_t num_of_vin;
    masp_vin_t vin[5];
    uint8_t num_of_vout;
    bytes_t vout;
    bytes_t authorization; // nothing if Auth;  for unauth a Vec<TransparentInputInfo>
} masp_transparent_bundle_t;

// For masp TxData definition, see:
// https://github.com/anoma/masp/blob/0d7dc07d24b878e9162c25260ed744265dd2f748/masp_primitives/src/transaction.rs#L189-L190
typedef struct {
    uint32_t tx_version; // const MASPV5_TX_VERSION: u32 = 2;
    uint32_t version_group_id; // const MASPV5_VERSION_GROUP_ID: u32 = 0x26A7270A;
    uint32_t consensus_branch_id; // this is an enum with at the moment only 0 -> MASP
    uint32_t lock_time;
    uint32_t expiry_height;
    uint8_t has_transparent_bundle;
    masp_transparent_bundle_t transparent_bundle;
    uint8_t has_sapling_bundle;
    masp_sapling_bundle_t sapling_bundle;
} masp_tx_data_t;

typedef struct {
    uint8_t discriminant;
    bytes_t tx_id; // [u8;32]
    masp_tx_data_t data;
} masp_tx_section_t;

typedef struct {
    bytes_t spend_indices;
    bytes_t convert_indices;
    bytes_t output_indices;
} sapling_metadata_t;

typedef struct {
    amount_t amount;
    bytes_t generator; // 160 bytes: Extended Point, i.e. 5 elements in Fq, each of which are represented by 32 bytes
} allowed_conversion_t;

typedef struct {
    allowed_conversion_t allowed;
    uint64_t value;
    merkle_path_t merkle_path;
} convert_description_info_t;


typedef struct {
    uint8_t has_spend_anchor;
    bytes_t spend_anchor; // 32 bytes: bls12_381::Scalar
    uint32_t target_height;
    bytes_t value_balance_asset_type;
    uint64_t value_balance_amount;
    uint8_t has_convert_anchor;
    bytes_t convert_anchor;
    uint32_t num_of_spends;
    spend_description_info_t spends[5];
    uint32_t num_of_converts;
    convert_description_info_t converts[5];
    uint32_t num_of_outputs;
    sapling_output_info outputs[5];
} sapling_builder_t;

typedef struct {
    bytes_t inputs;
    bytes_t vout;
} transparent_builder_t;

typedef struct {
    uint32_t target_height;
    uint32_t expiry_height;
    transparent_builder_t transparent_builder;
    sapling_builder_t sapling_builder;
    uint8_t has_progress_notifier;
    bytes_t progress_notifier;
} builder_t;

typedef struct {
    uint8_t discriminant;
    bytes_t target;  // [u8;32]
    bytes_t asset_types; // HashSet<(Address, Epoch)>
    sapling_metadata_t metadata;
    builder_t builder;
} masp_builder_section_t;

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
    section_t ciphertext; // todo: if we need to parse this in future, it will not be a section_t
    masp_tx_section_t maspTx;
    masp_builder_section_t maspBuilder; // todo: if we need to parse this in future, it will not be a section_t
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
        tx_custom_t custom;
        tx_transfer_t transfer;
        tx_init_account_t initAccount;
        tx_init_proposal_t initProposal;
        tx_vote_proposal_t voteProposal;
        tx_reveal_pubkey_t revealPubkey;
        tx_withdraw_t withdraw;
        tx_commission_change_t commissionChange;
        tx_init_validator_t initValidator;
        tx_update_vp_t updateVp;
    };

    transaction_t transaction;

} parser_tx_t;


#ifdef __cplusplus
}
#endif
