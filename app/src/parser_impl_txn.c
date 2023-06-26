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
#include "parser_impl_common.h"
#include "parser_txdef.h"
#include "leb128.h"
#include "bech32.h"
#include "stdbool.h"

#define ADDRESS_LEN_BYTES   45

#define DISCRIMINANT_DATA 0x00
#define DISCRIMINANT_EXTRA_DATA 0x01
#define DISCRIMINANT_CODE 0x02
#define DISCRIMINANT_SIGNATURE 0x03
#define DISCRIMINANT_CIPHERTEXT 0x04
#define DISCRIMINANT_MASP_TX 0x05
#define DISCRIMINANT_MASP_BUILDER 0x06


static const uint8_t hash_bond[] = {0xc5, 0xaf, 0x31, 0x37, 0x28, 0xe2, 0x81, 0xc2, 0x57, 0x8b, 0x4b, 0xd8, 0xcb, 0xc9, 0xcb, 0xbf, 0xb0, 0x20, 0x9d, 0x07, 0x85, 0x73, 0x4b, 0x46, 0x2c, 0x44, 0xb9, 0xa6, 0x31, 0x01, 0x29, 0x00 };
static const uint8_t hash_unbond[] = {0x7c, 0x18, 0x51, 0x53, 0x4a, 0x76, 0xb7, 0xb3, 0x35, 0x16, 0xeb, 0x48, 0x97, 0x54, 0x8b, 0xc5, 0x45, 0x73, 0xe1, 0xc4, 0x79, 0x2d, 0xb1, 0xe6, 0x95, 0x96, 0x7a, 0x19, 0xa8, 0xc6, 0x48, 0x48};
static const uint8_t hash_custom[] = {0x1c, 0x3e, 0x0c, 0x79, 0x1a, 0xa8, 0xa4, 0x33, 0x00, 0xe0, 0x8a, 0x5e, 0x54, 0x08, 0xdf, 0x66, 0xe6, 0x7e, 0xed, 0x26, 0x72, 0x1f, 0x3f, 0x48, 0x97, 0xb0, 0x17, 0xed, 0xdf, 0xc8, 0xcc, 0x78};
static const uint8_t hash_init_account[] = {0xfb, 0xd9, 0xe6, 0x6c, 0xe6, 0x6f, 0xc8, 0xae, 0x92, 0x57, 0x87, 0x8a, 0x60, 0xc6, 0xaf, 0xfe, 0x50, 0x46, 0xf3, 0xfc, 0xb4, 0x14, 0x8f, 0x39, 0x4a, 0x6e, 0xfa, 0x57, 0x89, 0xd8, 0xef, 0x72};
static const uint8_t hash_init_proposal[] ={0x65, 0x9f, 0xaa, 0xd0, 0xbf, 0x46, 0xb6, 0x89, 0xce, 0xa0, 0x6b, 0x4d, 0x31, 0x04, 0x0c, 0xa2, 0x30, 0xdb, 0x1b, 0x00, 0x96, 0xe8, 0x64, 0x0e, 0x40, 0xad, 0x57, 0x43, 0x4c, 0x9d, 0x4b, 0x16};
static const uint8_t hash_vote_proposal[] = {0x26, 0x9e, 0xd9, 0x2f, 0xd7, 0xe6, 0x8a, 0xf0, 0x06, 0xb9, 0x5f, 0x1f, 0x4b, 0x9a, 0x91, 0x1c, 0x0c, 0xf5, 0x1a, 0x2d, 0x60, 0x56, 0xb3, 0xc0, 0x61, 0x9e, 0x10, 0xe8, 0xfd, 0x0e, 0xe2, 0x72};
static const uint8_t hash_init_validator[] = {0x47, 0x03, 0x71, 0x62, 0x33, 0x73, 0x8e, 0xe2, 0x0e, 0x16, 0x1d, 0x5b, 0x8f, 0x1a, 0xe8, 0x56, 0xf7, 0x09, 0x6f, 0x51, 0x42, 0xe2, 0x8b, 0xbd, 0x79, 0xe5, 0xed, 0xe9, 0xb8, 0x6f, 0x9c, 0x56};
static const uint8_t hash_reveal_pubkey[] ={0xcc, 0xd2, 0xd3, 0xcf, 0x7e, 0xb3, 0x6a, 0xf9, 0x65, 0xe5, 0x2e, 0x10, 0xb3, 0x00, 0x52, 0x3e, 0x79, 0x6b, 0x7c, 0x55, 0x17, 0x27, 0x8a, 0x07, 0x03, 0xc4, 0x29, 0xd6, 0x70, 0xff, 0xf4, 0x79};
static const uint8_t hash_transfer[] = {0x22, 0x59, 0x91, 0xdd, 0xf8, 0x8d, 0x81, 0xb7, 0xa5, 0x87, 0xe9, 0x8f, 0xc4, 0x5d, 0x4e, 0xfe, 0x6d, 0xf3, 0xb3, 0xbc, 0x62, 0xd9, 0xba, 0x94, 0x6a, 0x82, 0x9b, 0x7a, 0x2d, 0x00, 0x25, 0xed};
static const uint8_t hash_update_vp[] = {0x8d, 0x00, 0xc0, 0xf6, 0xb7, 0x15, 0x11, 0xfd, 0x48, 0xda, 0x76, 0x67, 0x9f, 0x3f, 0x9a, 0x5b, 0x41, 0x10, 0x3b, 0x93, 0x16, 0x1a, 0x71, 0xb0, 0xc9, 0x7b, 0x21, 0x29, 0x06, 0xa7, 0x1d, 0xbb};
static const uint8_t hash_withdraw[] = {0xf7, 0xa3, 0xac, 0xf0, 0x46, 0xf3, 0xc2, 0x16, 0xea, 0xf4, 0xc6, 0x82, 0x7a, 0x3f, 0x91, 0x43, 0x3d, 0xac, 0x58, 0x05, 0xd8, 0x2f, 0x2d, 0x6a, 0xd7, 0xbd, 0xf1, 0x57, 0x4d, 0x50, 0x41, 0x40};
static const uint8_t hash_commission_change[] = {0x63, 0x31, 0x87, 0x82, 0x47, 0x80, 0x28, 0xc3, 0xa4, 0x69, 0x51, 0x04, 0xff, 0x4a, 0xab, 0x62, 0x08, 0xf0, 0xfc, 0x07, 0x52, 0x82, 0x8d, 0x4a, 0xb4, 0x86, 0x27, 0x6c, 0x69, 0xcf, 0xd4, 0x6c};

// Update VP types
static const vp_types_t vp_user = {
        {0xa4, 0x64, 0xa5, 0xb9, 0x3a, 0x58, 0x27, 0xe2, 0xc0, 0xee, 0xa0, 0xed, 0xb3, 0x7b, 0x16, 0xc8, 0x29, 0x67, 0x6f, 0xe7, 0x87, 0x9f, 0xcc, 0x36, 0xe8, 0x72, 0xc4, 0xa4, 0x0b, 0xad, 0xf1, 0x0d},
        "User"
};

// Add blindsigning code hash

#define NAM_TOKEN(_address, _symbol) { \
        .address  = _address, \
        .symbol = _symbol, \
    }

static const tokens_t nam_tokens[] = {
    NAM_TOKEN("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5", "NAM "),
    NAM_TOKEN("atest1v4ehgw36xdzryve5gsc52veeg5cnsv2yx5eygvp38qcrvd29xy6rys6p8yc5xvp4xfpy2v694wgwcp", "BTC "),
    NAM_TOKEN("atest1v4ehgw36xqmr2d3nx3ryvd2xxgmrq33j8qcns33sxezrgv6zxdzrydjrxveygd2yxumrsdpsf9jc2p", "ETH "),
    NAM_TOKEN("atest1v4ehgw36gg6nvs2zgfpyxsfjgc65yv6pxy6nwwfsxgungdzrggeyzv35gveyxsjyxymyz335hur2jn", "DOT "),
    NAM_TOKEN("atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt", "Schnitzel "),
    NAM_TOKEN("atest1v4ehgw36gfryydj9g3p5zv3kg9znyd358ycnzsfcggc5gvecgc6ygs2rxv6ry3zpg4zrwdfeumqcz9", "Apfel "),
    NAM_TOKEN("atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90", "Kartoffel "),
};

static const char* prefix_implicit = "imp::";
static const char* prefix_established = "est::";
static const char* prefix_internal = "int::";

parser_error_t readToken(const bytes_t *token, const char **symbol) {
    if (token == NULL || symbol == NULL) {
        return parser_unexpected_value;
    }

    // Convert token to address
    char address[110] = {0};
    CHECK_ERROR(readAddress(*token, address, sizeof(address)))

    const uint16_t tokenListLen = sizeof(nam_tokens) / sizeof(nam_tokens[0]);
    for (uint16_t i = 0; i < tokenListLen; i++) {
        if (!memcmp(&address, &nam_tokens[i].address, ADDRESS_LEN_TESTNET)) {
            *symbol = (char*) PIC(nam_tokens[i].symbol);
            return parser_ok;
        }
    }

    return parser_unexpected_value;
}

parser_error_t readVPType(const bytes_t *vp_type_hash, const char **vp_type_text) {
    if (vp_type_hash == NULL || vp_type_text == NULL) {
        return parser_unexpected_value;
    }

    // Type is User
    if (!memcmp(vp_type_hash->ptr, vp_user.hash, SHA256_SIZE))
    {
        *vp_type_text = (char*) PIC(vp_user.text);
    }
    else {
        *vp_type_text = (char*) PIC("Unknown VP hash");
    }

    return parser_ok;
}

parser_error_t readAddress(bytes_t pubkeyHash, char *address, uint16_t addressLen) {
    const uint8_t addressType = *pubkeyHash.ptr++;
    const char* prefix = NULL;

    switch (addressType) {
        case 0:
            prefix = PIC(prefix_established);
            break;
        case 1:
            prefix = PIC(prefix_implicit);
            break;
        case 2:
            prefix = PIC(prefix_internal);
            break;

        default:
            return parser_value_out_of_range;
    }

    uint32_t hashLen = 0;
    MEMCPY(&hashLen, pubkeyHash.ptr, sizeof(uint32_t));
    pubkeyHash.ptr += sizeof(uint32_t);
    if (hashLen != PK_HASH_LEN) {
        return parser_unexpected_value;
    }

    uint8_t tmpBuffer[FIXED_LEN_STRING_BYTES] = {0};
    snprintf((char*) tmpBuffer, sizeof(tmpBuffer), "%s", prefix);
    MEMCPY(tmpBuffer + strnlen(prefix, 5), pubkeyHash.ptr, PK_HASH_LEN);

    const char *hrp = "atest";
    const zxerr_t err = bech32EncodeFromBytes(address,
                                addressLen,
                                hrp,
                                tmpBuffer,
                                FIXED_LEN_STRING_BYTES,
                                0,
                                BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    return parser_ok;
}

parser_error_t readPaymentAddress(sapling_payment_address_t *paymentAddress, char *formattedAddress, uint16_t addressLen) {

    uint8_t tmpBuffer[DIVERSIFIER_LENGTH + HASH_LEN] = {0};
    MEMCPY(tmpBuffer , paymentAddress->diversifier.ptr, DIVERSIFIER_LENGTH);
    MEMCPY(tmpBuffer + DIVERSIFIER_LENGTH, paymentAddress->pk_d.ptr, HASH_LEN);

    const char *hrp = "patest";
    const zxerr_t err = bech32EncodeFromBytes(formattedAddress,
                                              addressLen,
                                              hrp,
                                              tmpBuffer,
                                              DIVERSIFIER_LENGTH + HASH_LEN,
                                              0,
                                              BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    return parser_ok;
}

static parser_error_t readTransactionType(bytes_t codeHash, transaction_type_e *type) {
    if (type == NULL) {
         return parser_unexpected_error;
    }

    // Bond
    if (!memcmp(codeHash.ptr, hash_bond, SHA256_SIZE)) {
        *type = Bond;
        return parser_ok;
    }
    // Unbond
    if (!memcmp(codeHash.ptr, hash_unbond, SHA256_SIZE)) {
        *type = Unbond;
        return parser_ok;
    }
    // Custom
    if (!memcmp(codeHash.ptr, hash_custom, SHA256_SIZE)) {
        *type = Custom;
        return parser_ok;
    }

    // Transfer
    if (!memcmp(codeHash.ptr, hash_transfer, SHA256_SIZE)) {
        *type = Transfer;
        return parser_ok;
    }

    // Init account
    if (!memcmp(codeHash.ptr, hash_init_account, SHA256_SIZE)) {
        *type = InitAccount;
        return parser_ok;
    }


    // Init proposal
    if(!memcmp(codeHash.ptr, hash_init_proposal, SHA256_SIZE)){
        *type = InitProposal;
        return parser_ok;
    }

    // Vote proposal
    if(!memcmp(codeHash.ptr, hash_vote_proposal, SHA256_SIZE)){
        *type = VoteProposal;
        return parser_ok;
    }

    // Init validator
    if (!memcmp(codeHash.ptr, hash_init_validator, SHA256_SIZE)) {
        *type = InitValidator;
        return parser_ok;
    }

    // Reveal pubkey
    if(!memcmp(codeHash.ptr, hash_reveal_pubkey, SHA256_SIZE)){
        *type = RevealPubkey;
        return parser_ok;
    }

    // Withdraw
    if (!memcmp(codeHash.ptr, hash_withdraw, SHA256_SIZE)) {
        *type = Withdraw;
        return parser_ok;
    }

    // Change Commission
    if (!memcmp(codeHash.ptr, hash_commission_change, SHA256_SIZE)) {
        *type = CommissionChange;
        return parser_ok;
    }

    // Update VP
    if (!memcmp(codeHash.ptr,hash_update_vp,SHA256_SIZE))
    {
        *type = UpdateVP;
        return parser_ok;
    }

    *type = Unknown;
    return parser_unexpected_method;
}

static parser_error_t readInitValidatorTxn(bytes_t *data,const bytes_t *extra_data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    parser_context_t extra_data_ctx = {.buffer = extra_data->ptr,
            .bufferLen = extra_data->len,
            .offset = 0,
            .tx_obj = NULL};

    v->initValidator.account_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.account_key.ptr, v->initValidator.account_key.len))

    v->initValidator.consensus_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.consensus_key.ptr, v->initValidator.consensus_key.len))

    v->initValidator.protocol_key.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.protocol_key.ptr, v->initValidator.protocol_key.len))

    v->initValidator.dkg_key.len = 100; //Check this size. Is fixed?
    CHECK_ERROR(readBytes(&ctx, &v->initValidator.dkg_key.ptr, v->initValidator.dkg_key.len))

    // Commission rate
    CHECK_ERROR(readDecimal(&ctx, &v->initValidator.commission_rate));

    // Max commission rate change
    CHECK_ERROR(readDecimal(&ctx, &v->initValidator.max_commission_rate_change));

    // VP code hash
    v->initValidator.vp_type_hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&extra_data_ctx, &v->initValidator.vp_type_hash.ptr, v->initValidator.vp_type_hash.len))
    // Get text from hash
    CHECK_ERROR(readVPType(&v->initValidator.vp_type_hash, &v->initValidator.vp_type_text))

    // Skip the rest of the fields
    ctx.offset = ctx.bufferLen;

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readInitAccountTxn(const bytes_t *data,const bytes_t *extra_data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};
    parser_context_t extra_data_ctx = {.buffer = extra_data->ptr,
            .bufferLen = extra_data->len,
            .offset = 0,
            .tx_obj = NULL};
    // Pubkey
    v->initAccount.pubkey.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->initAccount.pubkey.ptr, v->initAccount.pubkey.len))

    // Skip leftover bytes
    ctx.offset = ctx.bufferLen;

    // VP code hash
    v->initAccount.vp_type_hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&extra_data_ctx, &v->initAccount.vp_type_hash.ptr, v->initAccount.vp_type_hash.len))
    // Get text from hash
    CHECK_ERROR(readVPType(&v->initAccount.vp_type_hash, &v->initAccount.vp_type_text))


    if ((ctx.offset != ctx.bufferLen)|| (extra_data_ctx.offset != extra_data_ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readInitProposalTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Check if the proposal has an ID
    CHECK_ERROR(readByte(&ctx, &v->initProposal.has_id))
    if (v->initProposal.has_id){
        CHECK_ERROR(readUint32(&ctx, &v->initProposal.proposal_id.len));
        CHECK_ERROR(readBytes(&ctx, &v->initProposal.proposal_id.ptr, v->initProposal.proposal_id.len))
    }

    // Read content hash
    v->initProposal.content.len = SHA256_SIZE;
    CHECK_ERROR(readBytes(&ctx, &v->initProposal.content.ptr, v->initProposal.content.len))

    // Author, should be of length ADDRESS_LEN_BYTES
    v->initProposal.author.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->initProposal.author.ptr, v->initProposal.author.len))

    // Proposal type
    v->initProposal.has_proposal_code = 0;
    uint8_t proposal_type;
    CHECK_ERROR(readByte(&ctx, &proposal_type))
    // Proposal type 0 is Default(Option<Vec<u8>>),
    // where Vec<u8> is the proposal code (of 32 bytes)
    // Other proposal types have no data associated to the enum
    if (proposal_type==0){
        CHECK_ERROR(readByte(&ctx, &v->initProposal.has_proposal_code))
        if (v->initProposal.has_proposal_code){
            v->initProposal.proposal_code.len = SHA256_SIZE;
            CHECK_ERROR(readBytes(&ctx, &v->initProposal.proposal_code.ptr, v->initProposal.proposal_code.len))
        }
    }

    // Voting start epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.voting_start_epoch))

    // Voting end epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.voting_end_epoch))

    // Grace epoch
    CHECK_ERROR(readUint64(&ctx, &v->initProposal.grace_epoch))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}


static parser_error_t readVoteProposalTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Proposal ID
    CHECK_ERROR(readUint64(&ctx, &v->voteProposal.proposal_id))

    // Proposal vote
    CHECK_ERROR(readByte(&ctx, &v->voteProposal.proposal_vote))

    if (v->voteProposal.proposal_vote == Yay){
        CHECK_ERROR(readByte(&ctx, &v->voteProposal.vote_type))
        switch (v->voteProposal.vote_type) {
            case Default:
                break;
            // PGFCouncil(HashSet<Council>)
            case Council:
            {
                // Get the number of councils that are in the hash set:
                CHECK_ERROR(readUint32(&ctx, &v->voteProposal.number_of_councils))
                uint32_t number_read = (v->voteProposal.number_of_councils < MAX_COUNCILS)?
                       v->voteProposal.number_of_councils : MAX_COUNCILS;
                 // A council consists of an Address (45 bytes) and an Amount (uint64)
                for (uint32_t i = 0; i < number_read; ++i) {
                    v->voteProposal.councils[i].council_address.len =  ADDRESS_LEN_BYTES;
                    CHECK_ERROR(readBytes(&ctx,
                                          &v->voteProposal.councils[i].council_address.ptr,
                                          v->voteProposal.councils[i].council_address.len))
                    CHECK_ERROR(readUint64(&ctx,&v->voteProposal.councils[i].amount))
                }
                ctx.offset += (v->voteProposal.number_of_councils - number_read)
                              * (ADDRESS_LEN_BYTES + sizeof(uint64_t));
                break;
                }

            // ETHBridge(Signature)
            case EthBridge:
            {
                uint8_t signature_type = 0;
                CHECK_ERROR(readByte(&ctx, &signature_type))
                if(signature_type == 0){
                    // Ed25519 the signature consists of r (32 bytes), s (32 bytes)
                    v->voteProposal.eth_bridge_signature.len = SIG_ED25519_LEN;
                    CHECK_ERROR(readBytes(&ctx,
                                          &v->voteProposal.eth_bridge_signature.ptr,
                                          v->voteProposal.eth_bridge_signature.len))
                }
                else if (signature_type == 1){
                    // Secp256k1 the signature consists of r [u32; 8], s [u32; 8]
                    // and the RecoveryId (1 byte)
                    v->voteProposal.eth_bridge_signature.len = 65;
                    CHECK_ERROR(readBytes(&ctx,
                                          &v->voteProposal.eth_bridge_signature.ptr,
                                          v->voteProposal.eth_bridge_signature.len))
                } else return parser_unexpected_value;
                break;
            }
            default:
                return parser_unexpected_value;
        }
    }

    // Voter, should be of length ADDRESS_LEN_BYTES
    v->voteProposal.voter.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->voteProposal.voter.ptr, v->voteProposal.voter.len))

    // Delegators
    v->voteProposal.number_of_delegations = 0;
    CHECK_ERROR(readUint32(&ctx, &v->voteProposal.number_of_delegations))
    v->voteProposal.delegations.len = 0;
    if (v->voteProposal.number_of_delegations > 0 ){
        v->voteProposal.delegations.len = ADDRESS_LEN_BYTES*v->voteProposal.number_of_delegations;
        CHECK_ERROR(readBytes(&ctx, &v->voteProposal.delegations.ptr, v->voteProposal.delegations.len))
    }

    if ((ctx.offset != ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readRevealPubkeyTxn(const bytes_t *data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Pubkey
    if (ctx.bufferLen != 33) {
        return parser_unexpected_value;
    }
    v->revealPubkey.pubkey.len = 33;
    CHECK_ERROR(readBytes(&ctx, &v->revealPubkey.pubkey.ptr, v->revealPubkey.pubkey.len))

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readWithdrawTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->withdraw.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->withdraw.validator.ptr, v->withdraw.validator.len))

    // Does this tx specify the source
    CHECK_ERROR(readByte(&ctx, &v->withdraw.has_source))

    // Source
    if (v->withdraw.has_source != 0) {
        v->withdraw.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->withdraw.source.ptr, v->withdraw.source.len))
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readCommissionChangeTxn(bytes_t *buffer, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = buffer->ptr, .bufferLen = buffer->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->commissionChange.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->commissionChange.validator.ptr, v->commissionChange.validator.len))

    // Read new commission rate
    CHECK_ERROR(readDecimal(&ctx, &v->commissionChange.new_rate));


    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}


static parser_error_t readUpdateVPTxn(const bytes_t *data,const bytes_t *extra_data, parser_tx_t *v) {
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    parser_context_t extra_data_ctx = {.buffer = extra_data->ptr,
                                       .bufferLen = extra_data->len,
                                       .offset = 0,
                                       .tx_obj = NULL};

    // Address
    v->updateVp.address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->updateVp.address.ptr, v->updateVp.address.len))

    // VP code hash
    v->updateVp.vp_type_hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(&extra_data_ctx, &v->updateVp.vp_type_hash.ptr, v->updateVp.vp_type_hash.len))
    // Get text from hash
    CHECK_ERROR(readVPType(&v->updateVp.vp_type_hash, &v->updateVp.vp_type_text))

    ctx.offset += 32; // Skip tx_code_path (?)

    if ((ctx.offset != ctx.bufferLen) || (extra_data_ctx.offset != extra_data_ctx.bufferLen)) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

static parser_error_t readTransferTxn(const bytes_t *data, const masp_builder_section_t* maspBuilder,parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/token.rs#L467-L482
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Source
    v->transfer.source_address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.source_address.ptr, v->transfer.source_address.len))

    // Target
    v->transfer.target_address.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.target_address.ptr, v->transfer.target_address.len))

    // Token
    v->transfer.token.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->transfer.token.ptr, v->transfer.token.len))
    // Get symbol from token
    CHECK_ERROR(readToken(&v->transfer.token, &v->transfer.symbol))

    // Subprefix, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_sub_prefix))
    if (v->transfer.has_sub_prefix){
        CHECK_ERROR(readUint32(&ctx, &v->transfer.sub_prefix.len))
        CHECK_ERROR(readBytes(&ctx, &v->transfer.sub_prefix.ptr, v->transfer.sub_prefix.len))
    }

    // Amount
    CHECK_ERROR(readUint64(&ctx, &v->transfer.amount))

    // Key, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_key))
    if (v->transfer.has_key){
        CHECK_ERROR(readUint32(&ctx, &v->transfer.key.len))
        // we are not displaying these bytes
        ctx.offset += v->transfer.key.len;
    }
    // shielded hash, check if it is there
    CHECK_ERROR(readByte(&ctx, &v->transfer.has_shielded_hash))
    if (v->transfer.has_shielded_hash){
        v->transfer.shielded_hash.len = SHA256_SIZE;
        // we are not displaying these bytes
        ctx.offset += v->transfer.shielded_hash.len;
        if (maspBuilder->builder.sapling_builder.num_of_outputs > 0){
            uint32_t outputs_len = maspBuilder->builder.sapling_builder.num_of_outputs * SAPLING_OUTPUT_INFO_LEN;

        }
    }



    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }

    return parser_ok;
}

static parser_error_t readBondUnbondTxn(const bytes_t *data, parser_tx_t *v) {
    // https://github.com/anoma/namada/blob/8f960d138d3f02380d129dffbd35a810393e5b13/core/src/types/transaction/pos.rs#L24-L35
    parser_context_t ctx = {.buffer = data->ptr, .bufferLen = data->len, .offset = 0, .tx_obj = NULL};

    // Validator
    v->bond.validator.len = ADDRESS_LEN_BYTES;
    CHECK_ERROR(readBytes(&ctx, &v->bond.validator.ptr, v->bond.validator.len))

    // Amount
    MEMCPY(&v->bond.amount, ctx.buffer + ctx.offset, sizeof(uint64_t));
    ctx.offset += sizeof(uint64_t);
    ctx.offset++;   // Skip last byte --> Check this

    // Source
    if (ctx.offset < ctx.bufferLen) {
        v->bond.source.len = ADDRESS_LEN_BYTES;
        CHECK_ERROR(readBytes(&ctx, &v->bond.source.ptr, v->bond.source.len))
        v->bond.has_source = 1;
    }

    if (ctx.offset != ctx.bufferLen) {
        return parser_unexpected_characters;
    }
    return parser_ok;
}

// WrapperTx header
parser_error_t readHeader(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    const uint16_t tmpOffset = ctx->offset;

    // Read length of chain_id
    uint32_t chain_id_len = 0;
    CHECK_ERROR(readUint32(ctx, &chain_id_len))

    ctx->offset += chain_id_len;

    // Check if an expiration is set
    uint8_t has_expiration = 0;
    CHECK_ERROR(readByte(ctx, &has_expiration))
    if (has_expiration){
        // If so, read the length of expiration, and skip it
        uint32_t expiration_len = 0;
        CHECK_ERROR(readUint32(ctx, &expiration_len))
        ctx->offset += expiration_len;
    }
    // Timestamp
    CHECK_ERROR(readUint32(ctx, &v->transaction.timestamp.len))
    CHECK_ERROR(readBytes(ctx, &v->transaction.timestamp.ptr, v->transaction.timestamp.len))

    // Code hash
    v->transaction.header.codeHash.len = SHA256_SIZE;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.codeHash.ptr, v->transaction.header.codeHash.len))

    // Data hash
    v->transaction.header.dataHash.len = SHA256_SIZE;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.dataHash.ptr, v->transaction.header.dataHash.len))

    v->transaction.header.bytes.ptr = ctx->buffer + ctx->offset;

    CHECK_ERROR(checkTag(ctx, 0x01))
    // Fee.amount
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.fees.amount))
    // Fee.address
    v->transaction.header.fees.address.len = 45;
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.fees.address.ptr, v->transaction.header.fees.address.len))
    // Pubkey
    v->transaction.header.pubkey.len = 33;   // Check first byte (0x00 | 0x01)
    CHECK_ERROR(readBytes(ctx, &v->transaction.header.pubkey.ptr, v->transaction.header.pubkey.len))
    // Epoch
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.epoch))
    // GasLimit
    CHECK_ERROR(readUint64(ctx, &v->transaction.header.gasLimit))

    // Check if a PoW solution is present (should only exist in mainnet)
    uint8_t pow_solution_provided = 0;
    CHECK_ERROR(readByte(ctx, &pow_solution_provided))
    if (pow_solution_provided){
        // A PoW solution consists of :
        // - challenge parameters = Difficulty (u8) and a Counter (u64)
        // - a SolutionValue (u64)
        // so we skip 17 bytes
        ctx->offset += 17;
    }

    v->transaction.header.bytes.len = ctx->offset - tmpOffset;

    return parser_ok;
}

static parser_error_t readSalt(parser_context_t *ctx, bytes_t *salt) {
    if (ctx == NULL || salt == NULL) {
        return parser_unexpected_error;
    }
    salt->len = SALT_LEN;
    CHECK_ERROR(readBytes(ctx, &salt->ptr, salt->len))

    return parser_ok;
}

static parser_error_t readExtraDataSection(parser_context_t *ctx, section_t *extraData) {
    if (ctx == NULL || extraData == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &extraData->discriminant))
    if (extraData->discriminant != DISCRIMINANT_EXTRA_DATA) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &extraData->salt))
    // TODO Check this byte
    uint8_t hashType = 0;
    CHECK_ERROR(readByte(ctx, &hashType))
    extraData->bytes.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &extraData->bytes.ptr, extraData->bytes.len))

    return parser_ok;
}

static parser_error_t readDataSection(parser_context_t *ctx, section_t *data) {
    if (ctx == NULL || data == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &data->discriminant))
    if (data->discriminant != DISCRIMINANT_DATA) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &data->salt))
    CHECK_ERROR(readUint32(ctx, &data->bytes.len))
    CHECK_ERROR(readBytes(ctx, &data->bytes.ptr, data->bytes.len))

    return parser_ok;
}

static parser_error_t readCodeSection(parser_context_t *ctx, section_t *code) {
    if (ctx == NULL || code == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &code->discriminant))
    if (code->discriminant != DISCRIMINANT_CODE) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readSalt(ctx, &code->salt))
    // Check this byte
    uint8_t hashType = 0;
    CHECK_ERROR(readByte(ctx, &hashType))
    code->bytes.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &code->bytes.ptr, code->bytes.len))

    return parser_ok;
}

static parser_error_t readSignature(parser_context_t *ctx, signature_section_t *signature) {
    (void) ctx;
    (void) signature;
#if 0
    if (ctx == NULL || signature == NULL) {
        return parser_unexpected_error;
    }
    // CHECK_ERROR(checkTag(ctx, 0x03))
    // CHECK_ERROR(readSalt(ctx))
    // Read hash 32 bytes
    // Read tag 0x00 -> ED25519
    // Read R 32 bytes
    // Read S 32 bytes
    // Read tag 0x00 -> ED25519
    // Read VerificationKey 32 bytes

    const uint8_t SIGNATURE_TAG = 0x03;
    const uint8_t ED25519_TAG = 0x00;

    CHECK_ERROR(checkTag(ctx, SIGNATURE_TAG))
    CHECK_ERROR(readSalt(ctx))
    signature->hash.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &signature->hash.ptr, signature->hash.len))

    CHECK_ERROR(checkTag(ctx, ED25519_TAG))
    signature->r.len = SIG_R_LEN;
    CHECK_ERROR(readBytes(ctx, &signature->r.ptr, signature->r.len))
    signature->s.len = SIG_S_LEN;
    CHECK_ERROR(readBytes(ctx, &signature->s.ptr, signature->s.len))

    CHECK_ERROR(checkTag(ctx, ED25519_TAG))
    signature->pubKey.len = PK_LEN_25519;
    CHECK_ERROR(readBytes(ctx, &signature->pubKey.ptr, signature->pubKey.len))
#endif
    return parser_ok;
}

static parser_error_t readCiphertext(parser_context_t *ctx, section_t *ciphertext) {
    (void) ctx;
    (void) ciphertext;
    return parser_ok;
}


static parser_error_t readMaspTxSection(parser_context_t *ctx, masp_tx_section_t *maspTx) {
    if (ctx == NULL || maspTx == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &maspTx->discriminant))
    if (maspTx->discriminant != DISCRIMINANT_MASP_TX) {
        return parser_unexpected_value;
    }

    CHECK_ERROR(readUint32(ctx, &maspTx->data.tx_version))
    CHECK_ERROR(readUint32(ctx, &maspTx->data.version_group_id))
    CHECK_ERROR(readUint32(ctx, &maspTx->data.consensus_branch_id))
    CHECK_ERROR(readUint32(ctx, &maspTx->data.lock_time))
    CHECK_ERROR(readUint32(ctx, &maspTx->data.expiry_height))

    // Transparent bundles
    // first read vector of vin
    CHECK_ERROR(readByte(ctx, &maspTx->data.transparent_bundle.num_of_vin))
    uint8_t tmp_offset = 0;
    for (int i = 0; i < maspTx->data.transparent_bundle.num_of_vin; ++i) {
        masp_vin_t *vin = &maspTx->data.transparent_bundle.vin[i];
        vin->asset_type_id.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx,
                              &vin->asset_type_id.ptr,
                              vin->asset_type_id.len))
        CHECK_ERROR(readUint64(ctx, &vin->value))
        vin->transparent_address.len = 20;
        CHECK_ERROR(readBytes(ctx,
                              &vin->transparent_address.ptr,
                              vin->transparent_address.len))
        tmp_offset+= vin->asset_type_id.len + sizeof(uint64_t) + vin->transparent_address.len;
    }
    CHECK_ERROR(readByte(ctx, &maspTx->data.transparent_bundle.num_of_vout))
    tmp_offset = 0;
    for (int i = 0; i < maspTx->data.transparent_bundle.num_of_vout; ++i) {
        // todo read vout
    }

    // Sapling bundles
    // first read shielded spends
    CHECK_ERROR(readByte(ctx, &maspTx->data.sapling_bundle.num_of_shielded_spends))
    tmp_offset = 0;
    for (int i = 0; i < maspTx->data.sapling_bundle.num_of_shielded_spends; ++i) {
        spend_description_t shielded_spend = *(&maspTx->data.sapling_bundle.shielded_spends[0]+tmp_offset);

        //  cv -> 32 bytes
        shielded_spend.cv.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &shielded_spend.cv.ptr, shielded_spend.cv.len))
        tmp_offset += shielded_spend.cv.len;

        //  anchor -> 32 bytes bls12_381::Scalar
        shielded_spend.anchor.len = 32;
        CHECK_ERROR(readBytes(ctx, &shielded_spend.anchor.ptr, shielded_spend.anchor.len))
        tmp_offset += shielded_spend.anchor.len;

        //  nullifier -> 32 bytes :  [u8; 32]
        shielded_spend.nullifier.len = 32;
        CHECK_ERROR(readBytes(ctx, &shielded_spend.nullifier.ptr, shielded_spend.nullifier.len))
        tmp_offset += shielded_spend.nullifier.len;

        //   rk -> 32 bytes: Extended Point, i.e. 5 elements in Fq, each of which are represented by 32
        shielded_spend.rk.len = 32;
        CHECK_ERROR(readBytes(ctx, &shielded_spend.rk.ptr, shielded_spend.rk.len))
        tmp_offset += shielded_spend.rk.len;

        //   zkproof -> 192 bytes
        shielded_spend.zkproof.len = 192;
        CHECK_ERROR(readBytes(ctx, &shielded_spend.zkproof.ptr, shielded_spend.zkproof.len))
        tmp_offset += shielded_spend.zkproof.len;

        //   spend_auth_sig -> 64 bytes:    rbar: [u8; 32], sbar: [u8; 32],
        shielded_spend.spend_auth_sig.len = 64;
        CHECK_ERROR(readBytes(ctx, &shielded_spend.spend_auth_sig.ptr, shielded_spend.spend_auth_sig.len))
        tmp_offset += shielded_spend.spend_auth_sig.len;

    }

    // second read shielded converts
    CHECK_ERROR(readByte(ctx, &maspTx->data.sapling_bundle.num_of_shielded_converts))
    tmp_offset = 0;
    for (int i = 0; i < maspTx->data.sapling_bundle.num_of_shielded_converts; ++i) {
        convert_description_t shielded_convert = *(&maspTx->data.sapling_bundle.shielded_converts[0]+tmp_offset);

        //  cv -> 32 bytes
        shielded_convert.cv.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &shielded_convert.cv.ptr, shielded_convert.cv.len))
        tmp_offset += shielded_convert.cv.len;

        //  anchor -> 32 bytes bls12_381::Scalar
        shielded_convert.anchor.len = 32;
        CHECK_ERROR(readBytes(ctx, &shielded_convert.anchor.ptr, shielded_convert.anchor.len))
        tmp_offset += shielded_convert.anchor.len;

        //   zkproof -> 192 bytes
        shielded_convert.zkproof.len = 192;
        CHECK_ERROR(readBytes(ctx, &shielded_convert.zkproof.ptr, shielded_convert.zkproof.len))
        tmp_offset += shielded_convert.zkproof.len;
    }

    // third read shielded outputs
    CHECK_ERROR(readByte(ctx, &maspTx->data.sapling_bundle.num_of_shielded_outputs))
    tmp_offset = 0;
    for (int i = 0; i < maspTx->data.sapling_bundle.num_of_shielded_outputs; ++i) {
        output_description_t *shielded_output = &maspTx->data.sapling_bundle.shielded_outputs[i];

        //  cv -> 32 bytes
        shielded_output->cv.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &shielded_output->cv.ptr, shielded_output->cv.len))
        tmp_offset += shielded_output->cv.len;

        //  cmu -> 32 bytes
        shielded_output->cmu.len = 32;
        CHECK_ERROR(readBytes(ctx, &shielded_output->cmu.ptr, shielded_output->cmu.len))
        tmp_offset += shielded_output->cmu.len;

        //  ephemeral_key -> 32 bytes
        shielded_output->ephemeral_key.len = 32;
        CHECK_ERROR(readBytes(ctx, &shielded_output->ephemeral_key.ptr, shielded_output->ephemeral_key.len))
        tmp_offset += shielded_output->ephemeral_key.len;

        //  enc_ciphertext -> [u8; 612]]
        shielded_output->enc_ciphertext.len = 612;
        CHECK_ERROR(readBytes(ctx, &shielded_output->enc_ciphertext.ptr, shielded_output->enc_ciphertext.len))
        tmp_offset += shielded_output->enc_ciphertext.len;

        //  out_ciphertext -> [u8; 80]]
        shielded_output->out_ciphertext.len = 80;
        CHECK_ERROR(readBytes(ctx, &shielded_output->out_ciphertext.ptr, shielded_output->out_ciphertext.len))
        tmp_offset += shielded_output->out_ciphertext.len;
    }

    // fourth read value balance
    uint8_t num_of_value_balances =0;
    CHECK_ERROR(readByte(ctx, &num_of_value_balances))
    if (num_of_value_balances > 1){
        // TODO CHECK THIS
        return parser_unexpected_value;
    }

    maspTx->data.sapling_bundle.value_balance.asset_type_id.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &maspTx->data.sapling_bundle.value_balance.asset_type_id.ptr,
                          maspTx->data.sapling_bundle.value_balance.asset_type_id.len))

    CHECK_ERROR(readUint64(ctx, &maspTx->data.sapling_bundle.value_balance.value))

    // fifth read authorization
    maspTx->data.sapling_bundle.authorization_proof.len = 192;
    CHECK_ERROR(readBytes(ctx, &maspTx->data.sapling_bundle.authorization_proof.ptr,
                          maspTx->data.sapling_bundle.authorization_proof.len))
    maspTx->data.sapling_bundle.authorization_sig_rbar.len = 32;
    CHECK_ERROR(readBytes(ctx, &maspTx->data.sapling_bundle.authorization_sig_rbar.ptr,
                          maspTx->data.sapling_bundle.authorization_sig_rbar.len))
    maspTx->data.sapling_bundle.authorization_sig_sbar.len = 32;
    CHECK_ERROR(readBytes(ctx, &maspTx->data.sapling_bundle.authorization_sig_sbar.ptr,
                          maspTx->data.sapling_bundle.authorization_sig_sbar.len))
    return parser_ok;

}

static parser_error_t readSaplingBuilder(parser_context_t *ctx, sapling_builder_t *saplingBuilder) {
    CHECK_ERROR(readByte(ctx, &saplingBuilder->has_spend_anchor))
    if(saplingBuilder->has_spend_anchor){
        // read anchor
        saplingBuilder->spend_anchor.len = 32;
        CHECK_ERROR(readBytes(ctx, &saplingBuilder->spend_anchor.ptr,
                              saplingBuilder->spend_anchor.len))
    }

    // 4.4.2 read target height
    CHECK_ERROR(readUint32(ctx, &saplingBuilder->target_height))

    // todo check this, is it the number of asset types?
    ctx->offset += 4;

    // 4.4.3 read asset type
    saplingBuilder->value_balance_asset_type.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &saplingBuilder->value_balance_asset_type.ptr,
                          saplingBuilder->value_balance_asset_type.len))
    // 4.3.4 read asset value
    CHECK_ERROR(readUint64(ctx, &saplingBuilder->value_balance_amount))

    // has convert_anchor:
    CHECK_ERROR(readByte(ctx, &saplingBuilder->has_convert_anchor))
    if(saplingBuilder->has_convert_anchor){
        // read convert_anchor
        saplingBuilder->convert_anchor.len=32;
        CHECK_ERROR(readBytes(ctx, &saplingBuilder->convert_anchor.ptr,
                              saplingBuilder->convert_anchor.len))
    }
    // read spends
    CHECK_ERROR(readUint32(ctx, &saplingBuilder->num_of_spends))
    uint8_t spends_offset = 0;
    for (uint32_t i = 0; i < saplingBuilder->num_of_spends; ++i) {
        spend_description_info_t* spend = &saplingBuilder->spends[0] + spends_offset;
        // read extended_spending_key
        CHECK_ERROR(readByte(ctx, &spend->extsk.depth))
        spends_offset += 1;
        spend->extsk.parent_fvk_tag.len = 4;
        CHECK_ERROR(readBytes(ctx, &spend->extsk.parent_fvk_tag.ptr,
                              spend->extsk.parent_fvk_tag.len))
        spends_offset += 4;

        CHECK_ERROR(readByte(ctx, &spend->extsk.child_index_type))
        spends_offset += 1;

        CHECK_ERROR(readUint32(ctx, &spend->extsk.child_index))
        spends_offset += 4;

        spend->extsk.chain_code.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->extsk.chain_code.ptr,
                              spend->extsk.chain_code.len))
        spends_offset += 32;

        spend->extsk.expsk.ask.len = 32;
        spend->extsk.expsk.nsk.len = 32;
        spend->extsk.expsk.ovk.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->extsk.expsk.ask.ptr,
                              spend->extsk.expsk.ask.len))
        CHECK_ERROR(readBytes(ctx, &spend->extsk.expsk.nsk.ptr,
                              spend->extsk.expsk.nsk.len))
        CHECK_ERROR(readBytes(ctx, &spend->extsk.expsk.ovk.ptr,
                              spend->extsk.expsk.ovk.len))
        spends_offset += spend->extsk.expsk.ask.len
                        + spend->extsk.expsk.nsk.len
                        + spend->extsk.expsk.ovk.len;

        spend->extsk.dk.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->extsk.dk.ptr,
                              spend->extsk.dk.len))
        spends_offset += spend->extsk.dk.len;

        // read diversifier
        spend->diversifier.len = DIVERSIFIER_LENGTH;
        CHECK_ERROR(readBytes(ctx, &spend->diversifier.ptr,
                              spend->diversifier.len))
        spends_offset += spend->diversifier.len;

        // read note
        spend->note.asset_type.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->note.asset_type.ptr,
                              spend->note.asset_type.len))
        spends_offset += spend->note.asset_type.len;

        CHECK_ERROR(readUint64(ctx, &spend->note.value))
        spends_offset += 8;

        spend->note.g_d.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->note.g_d.ptr,
                              spend->note.g_d.len))
        spends_offset += spend->note.g_d.len;

        spend->note.pk_d.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->note.pk_d.ptr,
                              spend->note.pk_d.len))
        spends_offset += spend->note.pk_d.len;

        spend->note.rseed.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->note.rseed.ptr,
                              spend->note.rseed.len))
        spends_offset += spend->note.rseed.len;

        // read alpha
        spend->alpha.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->alpha.ptr,
                              spend->alpha.len))
        spends_offset += spend->alpha.len;

        // read merkle path
        CHECK_ERROR(readUint32(ctx, &spend->merkle_path.num_auth_path))
        spends_offset += 4;

        spend->merkle_path.auth_path.len = spend->merkle_path.num_auth_path * 33;
        CHECK_ERROR(readBytes(ctx, &spend->merkle_path.auth_path.ptr,
                              spend->merkle_path.auth_path.len))
        spends_offset += spend->merkle_path.auth_path.len;

        spend->merkle_path.generator.len = 32;
        CHECK_ERROR(readBytes(ctx, &spend->merkle_path.generator.ptr,
                              spend->merkle_path.generator.len))
        spends_offset +=  spend->merkle_path.generator.len;
    }

    // read converts
    CHECK_ERROR(readUint32(ctx, &saplingBuilder->num_of_converts))
    uint8_t convert_offset = 0;
    for (uint32_t i = 0; i < saplingBuilder->num_of_converts; ++i) {
        convert_description_info_t* convert = &saplingBuilder->converts[0] + convert_offset;
        convert->allowed.amount.asset_type_id.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &convert->allowed.amount.asset_type_id.ptr,
                              convert->allowed.amount.asset_type_id.len))
        convert_offset +=  convert->allowed.amount.asset_type_id.len;

        CHECK_ERROR(readUint64(ctx, &convert->allowed.amount.value))
        convert_offset += sizeof(uint64_t);

        // TODO: check num bytes of generator
        convert->allowed.generator.len = 32;
        CHECK_ERROR(readBytes(ctx, &convert->allowed.generator.ptr,
                              convert->allowed.generator.len))
        convert_offset +=  convert->allowed.generator.len;
    }
    // read outputs
    CHECK_ERROR(readUint32(ctx, &saplingBuilder->num_of_outputs))
    uint8_t outputs_offset = 0;
    for (uint32_t i = 0; i < saplingBuilder->num_of_outputs; ++i) {
        sapling_output_info* outputInfo = &saplingBuilder->outputs[0] + i * SAPLING_OUTPUT_INFO_LEN;

        CHECK_ERROR(readByte(ctx, &outputInfo->has_ovk))
        outputs_offset +=1;
        if (outputInfo->has_ovk){
            outputInfo->ovk.len = 32;
            CHECK_ERROR(readBytes(ctx, &outputInfo->ovk.ptr, outputInfo->ovk.len))
            outputs_offset += outputInfo->ovk.len;
        }

        outputInfo->to.diversifier.len = DIVERSIFIER_LENGTH;
        CHECK_ERROR(readBytes(ctx, &outputInfo->to.diversifier.ptr,
                              outputInfo->to.diversifier.len))
        outputs_offset += outputInfo->to.diversifier.len;

        outputInfo->to.pk_d.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &outputInfo->to.pk_d.ptr,
                              outputInfo->to.pk_d.len))
        outputs_offset += outputInfo->to.pk_d.len;

        outputInfo->note.asset_type.len = 32;
        CHECK_ERROR(readBytes(ctx, &outputInfo->note.asset_type.ptr,
                              outputInfo->note.asset_type.len))
        outputs_offset += outputInfo->note.asset_type.len;

        CHECK_ERROR(readUint64(ctx, &outputInfo->note.value))
        outputs_offset += 8;

        outputInfo->note.g_d.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &outputInfo->note.g_d.ptr,
                              outputInfo->note.g_d.len))
        outputs_offset += outputInfo->note.g_d.len;

        outputInfo->note.pk_d.len = HASH_LEN;
        CHECK_ERROR(readBytes(ctx, &outputInfo->note.pk_d.ptr,
                              outputInfo->note.pk_d.len))
        outputs_offset += outputInfo->note.pk_d.len;

        CHECK_ERROR(readByte(ctx, &outputInfo->note.rseed_type))

        outputInfo->note.rseed.len = 32;
        CHECK_ERROR(readBytes(ctx, &outputInfo->note.rseed.ptr,
                              outputInfo->note.rseed.len))
        outputs_offset += outputInfo->note.rseed.len;

        // read memo bytes
        outputInfo->memo_bytes.len=512;
        CHECK_ERROR(readBytes(ctx, &outputInfo->memo_bytes.ptr,
                              outputInfo->memo_bytes.len))
        outputs_offset += outputInfo->memo_bytes.len;

    }
    return parser_ok;
}

static parser_error_t readMaspBuilderSection(parser_context_t *ctx, masp_builder_section_t *maspBuilder) {
    if (ctx == NULL || maspBuilder == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readByte(ctx, &maspBuilder->discriminant))
    if (maspBuilder->discriminant != DISCRIMINANT_MASP_BUILDER) {
        return parser_unexpected_value;
    }

    // 1. Read target
    maspBuilder->target.len = HASH_LEN;
    CHECK_ERROR(readBytes(ctx, &maspBuilder->target.ptr, maspBuilder->target.len))

    // 2. Read asset types
    uint32_t num_asset_types = 0;
    CHECK_ERROR(readUint32(ctx, &num_asset_types))

    // each asset_type consists of an address (45 bytes) and an epoch (uint46_t)
    maspBuilder->asset_types.len = num_asset_types * (ADDRESS_LEN_BYTES + sizeof(uint64_t) );
    CHECK_ERROR(readBytes(ctx, &maspBuilder->asset_types.ptr, maspBuilder->asset_types.len))

    // 3. Read Sapling metadata
    // first read the number of spend_indices
    uint32_t num_spend_indices = 0;
    CHECK_ERROR(readUint32(ctx, &num_spend_indices))
    // each index is a size_t
    maspBuilder->metadata.spend_indices.len = sizeof(size_t) * num_spend_indices;
    CHECK_ERROR(readBytes(ctx, &maspBuilder->metadata.spend_indices.ptr, maspBuilder->metadata.spend_indices.len))

    // second read the number of convert_indices
    uint32_t num_convert_indices = 0;
    CHECK_ERROR(readUint32(ctx, &num_convert_indices))
    // each index is a size_t
    maspBuilder->metadata.convert_indices.len = sizeof(size_t) * num_convert_indices;
    CHECK_ERROR(readBytes(ctx, &maspBuilder->metadata.convert_indices.ptr, maspBuilder->metadata.convert_indices.len))

    // finally read the number of output_indices
    uint32_t num_output_indices = 0;
    CHECK_ERROR(readUint32(ctx, &num_output_indices))
    // each index is a size_t
    maspBuilder->metadata.output_indices.len = sizeof(size_t) * num_output_indices;
    CHECK_ERROR(readBytes(ctx, &maspBuilder->metadata.output_indices.ptr, maspBuilder->metadata.output_indices.len))

    // 4. Read builder
    // 4.1. Read target height
    CHECK_ERROR(readUint32(ctx, &maspBuilder->builder.target_height))
    // 4.2. Read expiry height
    CHECK_ERROR(readUint32(ctx, &maspBuilder->builder.expiry_height))
    // 4.3. Read transparent builder
    // First read the number of TransparentInputInfo in inputs = Vec<TransparentInputInfo>
    uint32_t num_transparent_inputs = 0;
    CHECK_ERROR(readUint32(ctx, &num_transparent_inputs))
    // A TransparentInputInfo just consists of a TxOut,
    // A TxOut consists of :
    // - an asset type identifier (32 bytes),
    // - a value int64_t (8 bytes)
    // - a transparent address (20 bytes)
    maspBuilder->builder.transparent_builder.inputs.len = num_transparent_inputs * 60;
    CHECK_ERROR(readBytes(ctx, &maspBuilder->builder.transparent_builder.inputs.ptr,
                          maspBuilder->builder.transparent_builder.inputs.len))
    // Next read the number of TxOuts in vout: Vec<TxOut>
    uint32_t num_tx_outs = 0;
    CHECK_ERROR(readUint32(ctx, &num_tx_outs))
    maspBuilder->builder.transparent_builder.vout.len = num_tx_outs * 60;
    CHECK_ERROR(readBytes(ctx, &maspBuilder->builder.transparent_builder.vout.ptr,
                          maspBuilder->builder.transparent_builder.vout.len))

    // 4.4. Read sapling builder
    CHECK_ERROR(readSaplingBuilder(ctx, &maspBuilder->builder.sapling_builder))

    return parser_ok;
}

parser_error_t readSections(parser_context_t *ctx, parser_tx_t *v) {
    if (ctx == NULL || v == NULL) {
        return parser_unexpected_value;
    }
    CHECK_ERROR(readUint32(ctx, &v->transaction.sections.sectionLen))

    if (v->transaction.sections.sectionLen > 7) {
        return parser_unexpected_value;
    }

    for (uint32_t i = 0; i < v->transaction.sections.sectionLen; i++) {
        const uint8_t discriminant = *(ctx->buffer + ctx->offset);
        switch (discriminant) {
            case DISCRIMINANT_DATA:
                CHECK_ERROR(readDataSection(ctx, &v->transaction.sections.data))
                break;

            case DISCRIMINANT_EXTRA_DATA:
                CHECK_ERROR(readExtraDataSection(ctx, &v->transaction.sections.extraData))
                break;

            case DISCRIMINANT_CODE:
                CHECK_ERROR(readCodeSection(ctx, &v->transaction.sections.code))
                break;

            case DISCRIMINANT_SIGNATURE:
                CHECK_ERROR(readSignature(ctx, &v->transaction.sections.signatures[0]))
                break;

            case DISCRIMINANT_CIPHERTEXT:
                CHECK_ERROR(readCiphertext(ctx, &v->transaction.sections.ciphertext))
                break;

            case DISCRIMINANT_MASP_TX:
                CHECK_ERROR(readMaspTxSection(ctx, &v->transaction.sections.maspTx))
                break;

            case DISCRIMINANT_MASP_BUILDER:
                CHECK_ERROR(readMaspBuilderSection(ctx, &v->transaction.sections.maspBuilder))
                break;

            default:
                return parser_unexpected_field;
        }
    }

    return parser_ok;
}

parser_error_t validateTransactionParams(parser_tx_t *txObj) {
    if (txObj == NULL) {
        return parser_unexpected_error;
    }

    CHECK_ERROR(readTransactionType(txObj->transaction.sections.code.bytes, &txObj->typeTx))
    switch (txObj->typeTx) {
        case Bond:
        case Unbond:
            CHECK_ERROR(readBondUnbondTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case Custom:
            break;
        case Transfer:
            CHECK_ERROR(readTransferTxn(&txObj->transaction.sections.data.bytes, &txObj->transaction.sections.maspBuilder, txObj))
            break;
        case InitAccount:
             CHECK_ERROR(readInitAccountTxn(&txObj->transaction.sections.data.bytes,&txObj->transaction.sections.extraData.bytes, txObj))
             break;

        case InitProposal:
            CHECK_ERROR(readInitProposalTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;

        case VoteProposal:
            CHECK_ERROR(readVoteProposalTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case RevealPubkey:
            CHECK_ERROR(readRevealPubkeyTxn(&txObj->transaction.sections.data.bytes,  txObj))
            break;
        case Withdraw:
             CHECK_ERROR(readWithdrawTxn(&txObj->transaction.sections.data.bytes, txObj))
             break;
        case CommissionChange:
            CHECK_ERROR(readCommissionChangeTxn(&txObj->transaction.sections.data.bytes, txObj))
            break;
        case InitValidator:
             CHECK_ERROR(readInitValidatorTxn(&txObj->transaction.sections.data.bytes, &txObj->transaction.sections.extraData.bytes,txObj))
             break;
        case UpdateVP:
            CHECK_ERROR(readUpdateVPTxn(&txObj->transaction.sections.data.bytes, &txObj->transaction.sections.extraData.bytes, txObj))
            break;
        default:
            return parser_unexpected_method;
    }

    return  parser_ok;
}
