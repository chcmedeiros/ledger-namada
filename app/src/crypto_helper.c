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
#include "crypto_helper.h"
#include "coin.h"
#include "bech32.h"
#include "zxformat.h"
#include "leb128.h"
#include "zxmacros.h"

#ifdef LEDGER_SPECIFIC
#include "bolos_target.h"
#endif

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX)
    #include "cx.h"
    #include "cx_sha256.h"
#else
    #include "picohash.h"
    #define CX_SHA256_SIZE 32
#endif

uint32_t hdPath[HDPATH_LEN_DEFAULT];

uint8_t bech32_hrp_len;
char bech32_hrp[MAX_BECH32_HRP_LEN + 1];

static zxerr_t crypto_publicKeyHash_ed25519(uint8_t *publicKeyHash, const uint8_t *pubkey){
    if (publicKeyHash == NULL || pubkey == NULL) {
        return zxerr_no_data;
    }

    // Step 1.  First borsh serialize pubkey (this prepends a 0 to the bytes of pubkey);
    uint8_t borshEncodedPubKey[PK_LEN_25519 + 1] = {0};
    memcpy(borshEncodedPubKey + 1, pubkey, PK_LEN_25519);

    // Step 2. Hash the serialized public key with sha256.
    uint8_t pkh[CX_SHA256_SIZE] = {0};
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX)
    cx_hash_sha256((const uint8_t*) borshEncodedPubKey, PK_LEN_25519 + 1, pkh, CX_SHA256_SIZE);
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, borshEncodedPubKey, PK_LEN_25519 + 1);
    picohash_final(&ctx, pkh);
#endif
    CHECK_APP_CANARY()

    // Step 3. Take the hex encoding of the hash (using upper-case);
    char hexPubKeyHash[2 * CX_SHA256_SIZE + 1] = {0};
    array_to_hexstr_uppercase(hexPubKeyHash, 2 * CX_SHA256_SIZE + 1, pkh, CX_SHA256_SIZE);

    // Prepend implicit address prefix
    publicKeyHash[0] = 0;

    // Step 4. The Public Key Hash consists of the first 40 characters of the hex encoding. ---> UPPERCASE
    MEMCPY(publicKeyHash + 1, pkh, PK_HASH_LEN);

    return zxerr_ok;
}

uint8_t crypto_encodePubkey_ed25519(uint8_t *buffer, uint16_t bufferLen, const uint8_t *pubkey) {
    if (buffer == NULL || pubkey == NULL) {
        return 0;
    }

    if (bufferLen < ADDRESS_LEN_TESTNET) {
        return 0;
    }

    // Step 1:  Compute the hash of the Ed25519 public key
    uint8_t publicKeyHash[21] = {0};
    crypto_publicKeyHash_ed25519(publicKeyHash, pubkey);

    // Step 2. Encode the public key hash with bech32m
    char addr_out[79] = {0};
    zxerr_t err = bech32EncodeFromBytes(addr_out,
                                        sizeof(addr_out),
                                        "tnam",
                                        publicKeyHash,
                                        sizeof(publicKeyHash),
                                        1,
                                        BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok){
        return 0;
    }

    memcpy(buffer, addr_out, ADDRESS_LEN_TESTNET);
    return ADDRESS_LEN_TESTNET;
}

zxerr_t crypto_sha256(const uint8_t *input, uint16_t inputLen, uint8_t *output, uint16_t outputLen) {
    if (input == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
        return zxerr_encoding_failed;
    }

    MEMZERO(output, outputLen);

#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX)
    cx_hash_sha256(input, inputLen, output, CX_SHA256_SIZE);
#else
    picohash_ctx_t ctx;
    picohash_init_sha256(&ctx);
    picohash_update(&ctx, input, inputLen);
    picohash_final(&ctx, output);
#endif
    return zxerr_ok;
}

zxerr_t crypto_hashExtraDataSection(const section_t *extraData, uint8_t *output, uint32_t outputLen) {
    if (extraData == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }

    const uint32_t extraDataTagLen = extraData->tag.len;
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX)
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    CHECK_CX_OK(cx_sha256_update(&sha256, &extraData->discriminant, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, extraData->salt.ptr, extraData->salt.len));
    CHECK_CX_OK(cx_sha256_update(&sha256, extraData->bytes.ptr, extraData->bytes.len));
    uint8_t has_tag = (extraData->tag.ptr == NULL) ? 0 : 1;
    CHECK_CX_OK(cx_sha256_update(&sha256, &has_tag, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &extraDataTagLen, has_tag*sizeof(extraDataTagLen)));
    CHECK_CX_OK(cx_sha256_update(&sha256, extraData->tag.ptr, has_tag*extraDataTagLen));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
#else
    picohash_ctx_t sha256 = {0};
    picohash_init_sha256(&sha256);
    picohash_update(&sha256, &extraData->discriminant, 1);
    picohash_update(&sha256, extraData->salt.ptr, extraData->salt.len);
    picohash_update(&sha256, extraData->bytes.ptr, extraData->bytes.len);
    uint8_t has_tag = (extraData->tag.ptr == NULL) ? 0 : 1;
    picohash_update(&sha256, &has_tag, 1);
    picohash_update(&sha256, (uint8_t*) &extraDataTagLen, has_tag*sizeof(extraDataTagLen));
    picohash_update(&sha256, extraData->tag.ptr, has_tag*extraDataTagLen);
    picohash_final(&sha256, output);
#endif

    return zxerr_ok;
}

zxerr_t crypto_hashDataSection(const section_t *data, uint8_t *output, uint32_t outputLen) {
    if (data == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
        return zxerr_no_data;
    }

    const uint32_t dataBytesLen = data->bytes.len;
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX)
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    CHECK_CX_OK(cx_sha256_update(&sha256, &data->discriminant, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, data->salt.ptr, data->salt.len));
    CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &dataBytesLen, sizeof(dataBytesLen)));
    CHECK_CX_OK(cx_sha256_update(&sha256, data->bytes.ptr, dataBytesLen));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
#else
    picohash_ctx_t sha256 = {0};
    picohash_init_sha256(&sha256);
    picohash_update(&sha256, &data->discriminant, 1);
    picohash_update(&sha256, data->salt.ptr, data->salt.len);
    picohash_update(&sha256, (uint8_t*) &dataBytesLen, sizeof(dataBytesLen));
    picohash_update(&sha256, data->bytes.ptr, dataBytesLen);
    picohash_final(&sha256, output);
#endif

    return zxerr_ok;
}

zxerr_t crypto_hashCodeSection(const section_t *code, uint8_t *output, uint32_t outputLen) {
    if (code == NULL || output == NULL || outputLen < CX_SHA256_SIZE) {
         return zxerr_invalid_crypto_settings;
    }

    const uint32_t codeTagLen = code->tag.len;
#if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX) || defined(TARGET_STAX)
    cx_sha256_t sha256 = {0};
    cx_sha256_init(&sha256);
    CHECK_CX_OK(cx_sha256_update(&sha256, &code->discriminant, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, code->salt.ptr, code->salt.len));
    CHECK_CX_OK(cx_sha256_update(&sha256, code->bytes.ptr, code->bytes.len));
    uint8_t has_tag = (code->tag.ptr == NULL) ? 0 : 1;
    CHECK_CX_OK(cx_sha256_update(&sha256, &has_tag, 1));
    CHECK_CX_OK(cx_sha256_update(&sha256, (uint8_t*) &codeTagLen, has_tag*sizeof(codeTagLen)));
    CHECK_CX_OK(cx_sha256_update(&sha256, code->tag.ptr, has_tag*codeTagLen));
    CHECK_CX_OK(cx_sha256_final(&sha256, output));
#else
    picohash_ctx_t sha256 = {0};
    picohash_init_sha256(&sha256);
    picohash_update(&sha256, &code->discriminant, 1);
    picohash_update(&sha256, code->salt.ptr, code->salt.len);
    picohash_update(&sha256, code->bytes.ptr, code->bytes.len);
    uint8_t has_tag = (code->tag.ptr == NULL) ? 0 : 1;
    picohash_update(&sha256, &has_tag, 1);
    picohash_update(&sha256, (uint8_t*) &codeTagLen, has_tag*sizeof(codeTagLen));
    picohash_update(&sha256, code->tag.ptr, has_tag*codeTagLen);
    picohash_final(&sha256, output);
#endif

    return zxerr_ok;
}

zxerr_t crypto_serializeCodeHash(uint8_t *buffer, uint16_t bufferLen) {
    if (bufferLen < 2) {
        return zxerr_buffer_too_small;
    }

    MEMZERO(buffer, bufferLen);
    buffer[0] = 10;
    buffer[1] = CX_SHA256_SIZE;

    return zxerr_ok;
}

zxerr_t crypto_serializeData(const uint64_t dataSize, uint8_t *buffer, uint16_t bufferLen, uint8_t *dataInfoSize) {
    if (bufferLen < 11) {
        return zxerr_buffer_too_small;
    }

    MEMZERO(buffer, bufferLen);
    buffer[0] = 18;
    CHECK_ZXERR(encodeLEB128(dataSize, buffer + 1, MAX_LEB128_OUTPUT, dataInfoSize))

    (*dataInfoSize)++;
    return zxerr_ok;
}
