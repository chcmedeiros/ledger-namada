/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
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

#include "bech32.h"
#include "coin.h"
#include "constants.h"
#include "crypto.h"
#include "crypto_helper.h"
#include "fr.h"
#include "index_sapling.h"
#include "leb128.h"
#include "nvdata.h"
#include "parser_impl.h"
#include "sapling.h"
#include "zxmacros.h"
#include "zxformat.h"
#include "tx.h"

#include "cx.h"
#include "cx_sha256.h"
#include "lcx_rng.h"


#define SIGN_PREFIX_SIZE 11u
#define SIGN_PREHASH_SIZE (SIGN_PREFIX_SIZE + CX_SHA256_SIZE)

typedef struct {
    uint8_t salt[SALT_LEN];
    uint8_t hash[HASH_LEN];
    uint8_t pubkey[PK_LEN_25519];
    uint8_t signature[SIG_ED25519_LEN];
} crypto_signatures_t[3];

crypto_signatures_t NV_CONST
N_signatures_impl __attribute__ ((aligned(64)));
#define N_signatures (*(NV_VOLATILE crypto_signatures_t *)PIC(&N_signatures_impl))

typedef enum {
    signature_header = 0,
    signature_data,
    signature_code,
} signature_slot_e;


typedef enum {
    EXTRACT_SAPLING_E0 = 0xE0,
    EXTRACT_SAPLING_E1 = 0xE1,
    EXTRACT_SAPLING_E2 = 0xE2,
    EXTRACT_SAPLING_E3 = 0xE3,
    EXTRACT_SAPLING_E4 = 0xE4,
    EXTRACT_SAPLING_E5 = 0xE5,
    EXTRACT_SAPLING_E6 = 0xE6,
    EXTRACT_SAPLING_E7 = 0xE7,
    EXTRACT_SAPLING_E8 = 0xE8,
    EXTRACT_SAPLING_E9 = 0xE9,
    EXTRACT_SAPLING_EA = 0xEA,
    EXTRACT_SAPLING_EB = 0xEB,
    EXTRACT_SAPLING_EC = 0xEC,
    EXTRACT_SAPLING_ED = 0xED,
} extract_sapling_e;

typedef struct {
    uint8_t r[32];
    uint8_t s[32];
    uint8_t v;

    // DER signature max size should be 73
    // https://bitcoin.stackexchange.com/questions/77191/what-is-the-maximum-size-of-a-der-encoded-ecdsa-signature#77192
    uint8_t der_signature[73];

} __attribute__((packed)) rsv_signature_t;

static zxerr_t crypto_store_signature(const bytes_t *salt, const bytes_t *hash, const bytes_t *pubkey, const bytes_t *signature, signature_slot_e slot){
    if (salt == NULL || hash == NULL || pubkey == NULL || signature == NULL || slot > signature_code) {
        return zxerr_no_data;
    }

    if (salt->len != SALT_LEN || hash->len != HASH_LEN || pubkey->len != PK_LEN_25519 || signature->len != SIG_ED25519_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    MEMCPY_NV((void*) &N_signatures[slot].salt, (uint8_t*)salt->ptr, salt->len);
    MEMCPY_NV((void *)&N_signatures[slot].hash, (uint8_t*)hash->ptr, hash->len);
    MEMCPY_NV((void *)&N_signatures[slot].pubkey, (uint8_t*)pubkey->ptr, pubkey->len);
    MEMCPY_NV((void *)&N_signatures[slot].signature, (uint8_t*)signature->ptr, signature->len);

    return zxerr_ok;
}

zxerr_t crypto_getSignature(uint8_t *output, uint16_t outputLen, uint8_t slot) {
    const uint8_t minimum_output_len = SALT_LEN + HASH_LEN + PK_LEN_25519 + SIG_ED25519_LEN;
    if (output == NULL || outputLen < minimum_output_len || slot > signature_code) {
        return zxerr_out_of_bounds;
    }

    const uint8_t *saltPtr = (uint8_t *)&N_signatures[slot].salt;
    const uint8_t *hashPtr = (uint8_t *)&N_signatures[slot].hash;
    const uint8_t *pubkeyPtr = (uint8_t *)&N_signatures[slot].pubkey;
    const uint8_t *sigPtr = (uint8_t *)&N_signatures[slot].signature;

    MEMCPY(output, saltPtr, SALT_LEN);
    output += SALT_LEN;
    MEMCPY(output, hashPtr, HASH_LEN);
    output += HASH_LEN;
    MEMCPY(output, pubkeyPtr, PK_LEN_25519);
    output += PK_LEN_25519;
    MEMCPY(output, sigPtr, ED25519_SIGNATURE_SIZE);

    return zxerr_ok;
}


zxerr_t crypto_extractPublicKey_ed25519(uint8_t *pubKey, uint16_t pubKeyLen) {
    cx_ecfp_public_key_t cx_publicKey;
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519] = {0};

    if (pubKeyLen < PK_LEN_25519) {
        return zxerr_invalid_crypto_settings;
    }

    // Generate keys
    CATCH_CXERROR(os_derive_bip32_no_throw(CX_CURVE_Ed25519,
                                           hdPath,
                                           HDPATH_LEN_DEFAULT,
                                           privateKeyData, NULL))

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519, privateKeyData, SK_LEN_25519, &cx_privateKey))
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_Ed25519, NULL, 0, &cx_publicKey))
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_Ed25519, &cx_publicKey, &cx_privateKey, 1))
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, SK_LEN_25519);

    // Format pubkey
    for (unsigned int i = 0; i < PK_LEN_25519; i++) {
        pubKey[i] = cx_publicKey.W[64 - i];
    }
    if ((cx_publicKey.W[PK_LEN_25519] & 1) != 0) {
        pubKey[31] |= 0x80;
    }

    memcpy(pubKey, cx_publicKey.W, PK_LEN_25519);
    return zxerr_ok;

    catch_cx_error:
        MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
        MEMZERO(privateKeyData, SK_LEN_25519);
        return zxerr_unknown;
}

zxerr_t crypto_extractPublicKey_secp256k1(uint8_t *pubKey, uint16_t pubKeyLen)
{
    cx_ecfp_public_key_t cx_publicKey = {0};
    cx_ecfp_private_key_t cx_privateKey = {0};
    uint8_t privateKeyData[64] = {0};

    if (pubKeyLen < SECP256K1_PK_LEN) {
        return zxerr_invalid_crypto_settings;
    }

    CATCH_CXERROR(os_derive_bip32_no_throw(CX_CURVE_256K1,
                                           hdPath,
                                           HDPATH_LEN_DEFAULT,
                                           privateKeyData, NULL))

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_256K1, privateKeyData, SECP256K1_SK_LEN, &cx_privateKey))
    CATCH_CXERROR(cx_ecfp_init_public_key_no_throw(CX_CURVE_256K1, NULL, 0, &cx_publicKey))
    CATCH_CXERROR(cx_ecfp_generate_pair_no_throw(CX_CURVE_256K1, &cx_publicKey, &cx_privateKey, 1))
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, SECP256K1_SK_LEN);

    memcpy(pubKey, cx_publicKey.W, SECP256K1_PK_LEN);
    return zxerr_ok;

    catch_cx_error:
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, SECP256K1_SK_LEN);
    return zxerr_unknown;
}

zxerr_t crypto_sign_ed25519(uint8_t *signature, uint16_t signatureMaxLen, const uint8_t *message, uint16_t messageLen)
{
    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[SK_LEN_25519] = {0};

    // Generate keys
    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(
                    HDW_NORMAL,
                    CX_CURVE_Ed25519,
                    hdPath,
                    HDPATH_LEN_DEFAULT,
                    privateKeyData,
                    NULL,
                    NULL,
                    0))

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_Ed25519,
                                                    privateKeyData,
                                                    SCALAR_LEN_ED25519,
                                                    &cx_privateKey))

    // Sign
    CATCH_CXERROR(cx_eddsa_sign_no_throw(&cx_privateKey,
                          CX_SHA512,
                          message,
                          messageLen,
                          signature,
                          signatureMaxLen))

    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, SK_LEN_25519);

    return zxerr_ok;
    catch_cx_error:
        MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
        MEMZERO(privateKeyData, SK_LEN_25519);
        return zxerr_unknown;
}

zxerr_t crypto_sign_secp256k1(uint8_t *signature,
                    uint16_t signatureMaxLen,
                    uint16_t *sigSize) {
    if (signatureMaxLen < SIGN_PREHASH_SIZE + sizeof(rsv_signature_t)){
        return zxerr_buffer_too_small;
    }

    uint8_t messageDigest[CX_SHA256_SIZE];
    MEMZERO(messageDigest,sizeof(messageDigest));

    // Hash the message to be signed
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLen = tx_get_buffer_length();
    cx_hash_sha256(message, messageLen, messageDigest, CX_SHA256_SIZE);

    CHECK_APP_CANARY()

    cx_ecfp_private_key_t cx_privateKey;
    uint8_t privateKeyData[64];
    unsigned int info = 0;
    size_t signatureLength = 0;

    // Generate keys
    CATCH_CXERROR(os_derive_bip32_no_throw(CX_CURVE_SECP256K1,
                                       hdPath,
                                       HDPATH_LEN_DEFAULT,
                                       privateKeyData, NULL))

    CATCH_CXERROR(cx_ecfp_init_private_key_no_throw(CX_CURVE_SECP256K1, privateKeyData, SECP256K1_SK_LEN, &cx_privateKey))

    // Sign
    CATCH_CXERROR(cx_ecdsa_sign_no_throw(&cx_privateKey,
                                            CX_RND_RFC6979 | CX_LAST,
                                            CX_SHA256,
                                            messageDigest,
                                            CX_SHA256_SIZE,
                                            signature,
                                            &signatureLength,
                                            &info))
    MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
    MEMZERO(privateKeyData, SECP256K1_SK_LEN);

    *sigSize = signatureLength;

    return zxerr_ok;
    catch_cx_error:
        MEMZERO(&cx_privateKey, sizeof(cx_privateKey));
        MEMZERO(privateKeyData, SECP256K1_SK_LEN);
        signatureLength = 0;
        return zxerr_ledger_api_error;
}


typedef struct {
    uint8_t publicKey[PK_LEN_25519];
    uint8_t address[ADDRESS_LEN_TESTNET];
} __attribute__((packed)) ed25519_answer_t;

zxerr_t crypto_fillAddress_ed25519(uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen)
{
    zemu_log("crypto_fillAddress_ed25519");
    MEMZERO(buffer, bufferLen);
    uint8_t outLen = 0;
    ed25519_answer_t *const answer = (ed25519_answer_t *) buffer;

    if (bufferLen < PK_LEN_25519 + ADDRESS_LEN_TESTNET) {
        return zxerr_unknown;
    }
    CHECK_ZXERR(crypto_extractPublicKey_ed25519(answer->publicKey, sizeof_field(ed25519_answer_t, publicKey)))

    const bool isTestnet = hdPath[1] == HDPATH_1_TESTNET;
    outLen = crypto_encodePubkey_ed25519(answer->address, sizeof(answer->address), answer->publicKey, isTestnet);

    if (outLen == 0) {
        MEMZERO(buffer, bufferLen);
        return zxerr_encoding_failed;
    }

    *addrResponseLen = PK_LEN_25519 + outLen;
    return zxerr_ok;
}

zxerr_t crypto_fillAddress(signing_key_type_e addressKind, uint8_t *buffer, uint16_t bufferLen, uint16_t *addrResponseLen)
{
    zxerr_t err = zxerr_unknown;
    switch (addressKind) {
        case key_ed25519:
            err = crypto_fillAddress_ed25519(buffer, bufferLen, addrResponseLen);
            break;
        case key_secp256k1:
            // TODO
            break;
    }
    return err;
}


zxerr_t crypto_hashHeader(const header_t *header, uint8_t *output, uint32_t outputLen) {
    if (header == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }
    cx_hash_sha256(header->bytes.ptr, header->bytes.len, output, outputLen);
    return zxerr_ok;
}


zxerr_t crypto_hashDataSection(const section_t *data, uint8_t *output, uint32_t outputLen) {
    if (data == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
        return zxerr_no_data;
    }

    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    cx_sha256_update(&sha256, &data->discriminant, 1);
    cx_sha256_update(&sha256, data->salt.ptr, data->salt.len);
    cx_sha256_update(&sha256, (uint8_t*) &data->bytes.len, sizeof(data->bytes.len));
    cx_sha256_update(&sha256, data->bytes.ptr, data->bytes.len);
    cx_sha256_final(&sha256, output);

    return zxerr_ok;
}

zxerr_t crypto_hashCodeSection(const section_t *code, uint8_t *output, uint32_t outputLen) {
    if (code == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }

    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    cx_sha256_update(&sha256, &code->discriminant, 1);
    cx_sha256_update(&sha256, code->salt.ptr, code->salt.len);
    cx_sha256_update(&sha256, code->bytes.ptr, code->bytes.len);
    cx_sha256_final(&sha256, output);

    return zxerr_ok;
}

zxerr_t crypto_signHeader(const header_t *header, const bytes_t *pubkey) {
    if (header == NULL || pubkey == NULL) {
        return zxerr_no_data;
    }

    uint8_t hash[HASH_LEN] = {0};
    CHECK_ZXERR(crypto_hashHeader(header, hash, sizeof(hash)))

    uint8_t signature[SIG_ED25519_LEN] = {0};
    CHECK_ZXERR(crypto_sign_ed25519(signature, sizeof(signature), hash, sizeof(hash)))

    const bytes_t hash_bytes = {.ptr = hash, .len = HASH_LEN};
    const bytes_t signature_bytes = {.ptr = signature, .len = SIG_ED25519_LEN};

    const uint8_t salt[SALT_LEN] = {0};
    const bytes_t salt_bytes = {.ptr = salt, .len = sizeof(salt)};
    CHECK_ZXERR(crypto_store_signature(&salt_bytes, &hash_bytes, pubkey, &signature_bytes, signature_header))

    return zxerr_ok;
}

zxerr_t crypto_signDataSection(const section_t *data, const bytes_t *pubkey) {
    if (data == NULL || pubkey == NULL) {
        return zxerr_no_data;
    }

    uint8_t hash[HASH_LEN] = {0};
    CHECK_ZXERR(crypto_hashDataSection(data, hash, sizeof(hash)))

    uint8_t signature[SIG_ED25519_LEN] = {0};
    CHECK_ZXERR(crypto_sign_ed25519(signature, sizeof(signature), hash, sizeof(hash)))

    const bytes_t hash_bytes = {.ptr = hash, .len = HASH_LEN};
    const bytes_t signature_bytes = {.ptr = signature, .len = SIG_ED25519_LEN};
    CHECK_ZXERR(crypto_store_signature(&data->salt, &hash_bytes, pubkey, &signature_bytes, signature_data))

    return zxerr_ok;
}

zxerr_t crypto_signCodeSection(const section_t *code, const bytes_t *pubkey) {
    if (code == NULL || pubkey == NULL) {
        return zxerr_no_data;
    }

    uint8_t hash[HASH_LEN] = {0};
    CHECK_ZXERR(crypto_hashCodeSection(code, hash, sizeof(hash)))

    uint8_t signature[SIG_ED25519_LEN] = {0};
    CHECK_ZXERR(crypto_sign_ed25519(signature, sizeof(signature), hash, sizeof(hash)))

    const bytes_t hash_bytes = {.ptr = hash, .len = HASH_LEN};
    const bytes_t signature_bytes = {.ptr = signature, .len = SIG_ED25519_LEN};
    CHECK_ZXERR(crypto_store_signature(&code->salt, &hash_bytes, pubkey, &signature_bytes, signature_code))

    return zxerr_ok;
}

zxerr_t crypto_fillSaplingSeed(uint8_t *sk) {
    zemu_log_stack("crypto_fillSaplingSeed");

    // Generate randomness using a fixed path related to the device mnemonic
    const uint32_t path[HDPATH_LEN_DEFAULT] = {
            0x8000002c,
            0x80000085,
            MASK_HARDENED,
            MASK_HARDENED,
            MASK_HARDENED,
    };

    MEMZERO(sk, ED25519_SK_SIZE);

    CATCH_CXERROR(os_derive_bip32_with_seed_no_throw(HDW_NORMAL, CX_CURVE_Ed25519,
                                                     path, HDPATH_LEN_DEFAULT,
                                                     sk,
                                                     NULL,
                                                     NULL, 0))
    return zxerr_ok;
    catch_cx_error:
    return zxerr_unknown;
}


// handleGetKeyFVK: return the full viewing key (fvk = (ak, nk, ovk, dk)) for a given path
zxerr_t crypto_fvk_sapling(uint8_t *buffer, uint16_t bufferLen, uint32_t p, uint16_t *replyLen) {

    zemu_log_stack("crypto_fvk_sapling");
    MEMZERO(buffer, bufferLen);
    full_viewing_key_t *fvk_out = (full_viewing_key_t *) buffer;

    //the path in zip32 is [FIRST_VALUE, COIN_TYPE, p] where p is u32 and last part of hdPath
    uint8_t zip32_seed[ZIP32_SEED_SIZE] = {0};

    zxerr_t error = zxerr_ok;

    BEGIN_TRY
    {
        TRY
        {
            // Temporarily get sk from Ed25519
            error = crypto_fillSaplingSeed(zip32_seed);
            CHECK_APP_CANARY()

            // get full viewing key
            get_fvk(zip32_seed, p, fvk_out);
            CHECK_APP_CANARY()
        }
        FINALLY
        {
            MEMZERO(zip32_seed, sizeof(zip32_seed));
        }
    }
    END_TRY;
    CHECK_APP_CANARY()
    if(error != zxerr_ok){
        MEMZERO(buffer, bufferLen);
        *replyLen = 0;
        return error;
    }

    *replyLen = AK_SIZE + NK_SIZE + OVK_SIZE + DK_SIZE;
    return zxerr_ok;
}

// handleInitTX step 1/2
zxerr_t crypto_extracttx_sapling(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, const uint16_t txdatalen) {
    zemu_log_stack("crypto_extracttx_sapling");
    MEMZERO(buffer, bufferLen);
    uint8_t t_in_len = *txdata;
    uint8_t t_out_len = *(txdata + 1);
    uint8_t spend_len = *(txdata + 2);
    uint8_t output_len = *(txdata + 3);

    transaction_reset();

    if ((spend_len > 0 && output_len < 2) || (spend_len == 0 && output_len == 1)) {
        return (zxerr_t) EXTRACT_SAPLING_E0;
    }

    if (txdatalen < 4 || txdatalen - 4 !=
                         t_in_len * T_IN_INPUT_LEN + t_out_len * T_OUT_INPUT_LEN + spend_len * SPEND_INPUT_LEN +
                         output_len * OUTPUT_INPUT_LEN) {
        return (zxerr_t) EXTRACT_SAPLING_E1;
    }

    if (t_in_len == 0 && t_out_len == 0 && spend_len == 0 && output_len == 0) {
        return (zxerr_t) EXTRACT_SAPLING_E2;
    }

    uint8_t *start = (uint8_t *) txdata;
    start += 4;

    parser_context_t pars_ctx;
    parser_error_t pars_err;

    for (int i = 0; i < t_in_len; i++) {
        uint32_t *path = (uint32_t * )(start + INDEX_INPUT_TIN_PATH);
        uint8_t *script = (uint8_t * )(start + INDEX_INPUT_TIN_SCRIPT);

        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_TIN_VALUE;
        pars_ctx.bufferLen = 8;
        uint64_t v = 0;
        pars_err = _readUInt64(&pars_ctx, &v);
        if (pars_err != parser_ok) {
            return (zxerr_t) EXTRACT_SAPLING_E3;
        }
        zxerr_t err = t_inlist_append_item(path, script, v);
        if (err != zxerr_ok) {
            return (zxerr_t) EXTRACT_SAPLING_E4;
        }
        start += T_IN_INPUT_LEN;
    }

    for (int i = 0; i < t_out_len; i++) {
        uint8_t *addr = (uint8_t * )(start + INDEX_INPUT_TOUT_ADDR);
        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_TOUT_VALUE;
        pars_ctx.bufferLen = 8;
        uint64_t v = 0;
        pars_err = _readUInt64(&pars_ctx, &v);
        if (pars_err != parser_ok) {
            return (zxerr_t) EXTRACT_SAPLING_E5;
        }
        zxerr_t err = t_outlist_append_item(addr, v);
        if (err != zxerr_ok) {
            return (zxerr_t) EXTRACT_SAPLING_E6;
        }
        start += T_OUT_INPUT_LEN;
    }

    for (int i = 0; i < spend_len; i++) {
        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_SPENDPOS;
        pars_ctx.bufferLen = 4;
        uint32_t p = 0;
        pars_err = _readUInt32(&pars_ctx, &p);
        if (pars_err != parser_ok) {
            return (zxerr_t) EXTRACT_SAPLING_E7;
        }

        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_INPUTVALUE;
        pars_ctx.bufferLen = 8;
        uint64_t v = 0;
        pars_err = _readUInt64(&pars_ctx, &v);
        if (pars_err != parser_ok) {
            return (zxerr_t) EXTRACT_SAPLING_E8;
        }

        uint8_t *div = start + INDEX_INPUT_INPUTDIV;
        uint8_t *pkd = start + INDEX_INPUT_INPUTPKD;
        uint8_t rnd1[RND_SIZE];
        uint8_t rnd2[RND_SIZE];
        random_fr(rnd1);
        random_fr(rnd2);

        zxerr_t err = spendlist_append_item(p, v, div, pkd, rnd1, rnd2);
        if (err != zxerr_ok) {
            return (zxerr_t) EXTRACT_SAPLING_E9;
        }
        start += SPEND_INPUT_LEN;
    }

    for (int i = 0; i < output_len; i++) {
        uint8_t *div = start + INDEX_INPUT_OUTPUTDIV;
        uint8_t *pkd = start + INDEX_INPUT_OUTPUTPKD;

        pars_ctx.offset = 0;
        pars_ctx.buffer = start + INDEX_INPUT_OUTPUTVALUE;
        pars_ctx.bufferLen = 8;
        uint64_t v = 0;
        pars_err = _readUInt64(&pars_ctx, &v);
        if (pars_err != parser_ok) {
            return (zxerr_t) EXTRACT_SAPLING_EA;
        }

        uint8_t *memotype = start + INDEX_INPUT_OUTPUTMEMO;
        uint8_t *ovk = start + INDEX_INPUT_OUTPUTOVK;
        if (ovk[0] != 0x00 && ovk[0] != 0x01) {
            return (zxerr_t) EXTRACT_SAPLING_EB;
        }
        uint8_t hash_seed[OVK_SET_SIZE];
        if (ovk[0] == 0x00) {
            MEMZERO(hash_seed, OVK_SET_SIZE);
            cx_rng_no_throw(hash_seed + 1, OVK_SIZE);
            ovk = hash_seed;
        }

        uint8_t rnd1[RND_SIZE];
        uint8_t rnd2[RND_SIZE];
        random_fr(rnd1);
        cx_rng_no_throw(rnd2, RND_SIZE);
        zxerr_t err = outputlist_append_item(div, pkd, v, *memotype, ovk, rnd1, rnd2);
        if (err != zxerr_ok) {
            return (zxerr_t) EXTRACT_SAPLING_EC;
        }
        start += OUTPUT_INPUT_LEN;
    }

    uint64_t value_flash = get_totalvalue();
    if (value_flash != 1000) {
        return (zxerr_t) EXTRACT_SAPLING_ED;
    }

    if (spend_len > 0) {
        set_state(STATE_PROCESSED_INPUTS); //need both spend info and output info (as spend > 0 => output >= 2)
    } else if (output_len > 0) {
        set_state(STATE_PROCESSED_SPEND_EXTRACTIONS); //we can have shielded outputs only
    } else {
        set_state(STATE_PROCESSED_ALL_EXTRACTIONS); //We can have transparent inputs/outputs only
    }

    return zxerr_ok; //some code for all_good
}

// handleInitTX step 2/2 -- AND -- handleCheckandSign step 11/11
zxerr_t crypto_hash_messagebuffer(uint8_t *buffer, uint16_t bufferLen, const uint8_t *txdata, uint16_t txdataLen){
    if(bufferLen < CX_SHA256_SIZE){
        return zxerr_unknown;
    }
    cx_hash_sha256(txdata, txdataLen, buffer, CX_SHA256_SIZE);      // SHA256
    return zxerr_ok;
}

typedef struct {
    union {
        // STEP 1
        struct {
            uint8_t zip32_seed[ZIP32_SEED_SIZE];
            uint8_t sk[ED25519_SK_SIZE];
        } step1;

        struct {
            uint8_t ask[ASK_SIZE];
            uint8_t nsk[NSK_SIZE];
        } step2;
    };
} tmp_spendinfo_s;

// handleExtractSpendDataMASPTransfer
zxerr_t crypto_extract_spend_proof_key_and_rnd(uint8_t *buffer, uint16_t bufferLen){
    // First check that there a still items on the list of spends
    // for which spend data has not yet been extracted
    if(!spendlist_more_to_extract()){
        return zxerr_unknown;
    }

    // Ensure that the INS_INIT_MASP_TRANSFER has been called
    // and did not error.
    if(get_state() != STATE_PROCESSED_INPUTS){
        return zxerr_unknown;
    }

    uint8_t *out = (uint8_t *) buffer;
    MEMZERO(out, bufferLen);

    // Get the next item from the list of spends
    const spend_item_t *next = spendlist_extract_next();
    if (next == NULL){
        return zxerr_unknown;
    }

    tmp_spendinfo_s tmp = {0};

    zxerr_t error = crypto_fillSaplingSeed(tmp.step1.zip32_seed);
    CHECK_APP_CANARY()
    if(error != zxerr_ok){
        MEMZERO(buffer, bufferLen);
        return error;
    }

    // Get ak and nsk (the child proof key)
    get_child_proof_key(tmp.step1.zip32_seed, next->path, out, out + AK_SIZE);
    CHECK_APP_CANARY()

    MEMZERO(&tmp, sizeof(tmp_spendinfo_s));

    MEMCPY(out+AK_SIZE+NSK_SIZE, next->rcmvalue, RCM_SIZE);
    MEMCPY(out+AK_SIZE+NSK_SIZE+RCM_SIZE, next->alpha,ALPHA_SIZE);

    if(!spendlist_more_to_extract()){
        set_state(STATE_PROCESSED_SPEND_EXTRACTIONS);
    }

    return zxerr_ok;
}