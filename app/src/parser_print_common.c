/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
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
#include "parser_print_common.h"
#include "parser_impl_common.h"

#include <stdbool.h>
#include <zxformat.h>
#include "zxerror.h"
#include "timeutils.h"

#include "coin.h"
#include "bech32.h"

#define PREFIX "yay with councils:\n"
#define PREFIX_COUNCIL "Council: "
#define PREFIX_SPENDING "spending cap: "


#define CHECK_PTR_BOUNDS(count, dstLen)    \
    if((count + 1) >= dstLen) {             \
        return parser_decimal_too_big;     \
    }

__Z_INLINE bool isAllZeroes(const void *buf, size_t n) {
    uint8_t *p = (uint8_t *) buf;
    for (size_t i = 0; i < n; ++i) {
        if (p[i]) {
            return false;
        }
    }
    return true;
}

parser_error_t uint256_to_str(char *output, uint16_t outputLen, const uint256_t *value) {
    if (output == NULL || value == NULL) {
        return parser_unexpected_error;
    }
    MEMZERO(output, outputLen);

    uint16_t n[16] = {0};
    // Copy and right-align the number
    memcpy((uint8_t *) n, value, sizeof(*value));

    // Special case when value is 0
    if (isAllZeroes(n, sizeof(n))) {
        if (outputLen < 2) {
            // Not enough space to hold "0" and \0.
            return parser_decimal_too_big;
        }
        strncpy(output, "0", outputLen);
        return parser_ok;
    }

    int pos = outputLen;
    while (!isAllZeroes(n, sizeof(n))) {
        if (pos == 0) {
          return parser_decimal_too_big;
        }
        pos--;
        unsigned int carry = 0;
        for (int i = 15; i >= 0; i--) {
            int rem = ((carry << 16) | n[i]) % 10;
            n[i] = ((carry << 16) | n[i]) / 10;
            carry = rem;
        }
        output[pos] = '0' + carry;
    }
    memmove(output, output + pos, outputLen - pos);
    output[outputLen - pos] = 0;
    return parser_ok;
}

parser_error_t printAddress( bytes_t pubkeyHash,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {

    char address[110] = {0};
    CHECK_ERROR(readAddress(pubkeyHash, address, sizeof(address)))
    pageString(outVal, outValLen, (const char*) address, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t printCodeHash(bytes_t *codeHash,
                             char *outKey, uint16_t outKeyLen,
                             char *outVal, uint16_t outValLen,
                             uint8_t pageIdx, uint8_t *pageCount) {

    char hexString[65] = {0};
    snprintf(outKey, outKeyLen, "Code hash");
    array_to_hexstr((char*) hexString, sizeof(hexString), codeHash->ptr, codeHash->len);
    pageString(outVal, outValLen, (const char*) hexString, pageIdx, pageCount);

    return parser_ok;
}

static parser_error_t printTimestamp(const bytes_t timestamp,
                                     char *outVal, uint16_t outValLen,
                                     uint8_t pageIdx, uint8_t *pageCount) {


    // Received         "2023-04-19T14:19:38.114481351+00:00"
    // Expected         "2023-04-19 14:19:38.114481351 UTC"
    if (timestamp.len > 35 || timestamp.len < 25) {
        return parser_unexpected_value;
    }

    char date[50] = {0};
    uint32_t offset = timestamp.len - 6;
    memcpy(date, timestamp.ptr, timestamp.len - 6);
    snprintf(date + offset, sizeof(date) - offset, " UTC");
    if (date[10] == 'T') date[10] = ' ';

    pageString(outVal, outValLen, date, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t printAmount( const uint256_t *amount, uint8_t amountDenom, const char* symbol,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount) {

    char strAmount[90] = {0};
    CHECK_ERROR(uint256_to_str(strAmount, sizeof(strAmount), amount))
    if (intstr_to_fpstr_inplace(strAmount, sizeof(strAmount), amountDenom) == 0) {
        return parser_unexpected_error;
    }

    z_str3join(strAmount, sizeof(strAmount), symbol, "");
    number_inplace_trimming(strAmount, 1);
    pageString(outVal, outValLen, strAmount, pageIdx, pageCount);

    return parser_ok;
}

static parser_error_t printAmount64( uint64_t amount, uint8_t amountDenom, const char* symbol,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount) {

    char strAmount[33] = {0};
    if (uint64_to_str(strAmount, sizeof(strAmount), amount) != NULL) {
        return parser_unexpected_error;
    }
    if (intstr_to_fpstr_inplace(strAmount, sizeof(strAmount), amountDenom) == 0) {
        return parser_unexpected_error;
    }

    z_str3join(strAmount, sizeof(strAmount), symbol, "");
    number_inplace_trimming(strAmount, 1);
    pageString(outVal, outValLen, strAmount, pageIdx, pageCount);

    return parser_ok;
}

parser_error_t printPublicKey( const bytes_t *pubkey,
                            char *outVal, uint16_t outValLen,
                            uint8_t pageIdx, uint8_t *pageCount) {
    char bech32String[79] = {0};
    const zxerr_t err = bech32EncodeFromBytes(bech32String,
                        sizeof(bech32String),
                        "tpknam",
                        (uint8_t*) pubkey->ptr,
                        pubkey->len,
                        1,
                        BECH32_ENCODING_BECH32M);

    if (err != zxerr_ok) {
        return parser_unexpected_error;
    }
    pageString(outVal, outValLen, (const char*) &bech32String, pageIdx, pageCount);
    return parser_ok;
}

parser_error_t printExpert( const parser_context_t *ctx,
                                   uint8_t displayIdx,
                                   char *outKey, uint16_t outKeyLen,
                                   char *outVal, uint16_t outValLen,
                                   uint8_t pageIdx, uint8_t *pageCount) {

    if(displayIdx >= 5 && ctx->tx_obj->transaction.header.fees.symbol != NULL) {
        displayIdx++;
    }

    switch (displayIdx) {
        case 0:
            snprintf(outKey, outKeyLen, "Timestamp");
            CHECK_ERROR(printTimestamp(ctx->tx_obj->transaction.timestamp,
                                       outVal, outValLen, pageIdx, pageCount))
            break;
        case 1: {
            const bytes_t *pubkey = &ctx->tx_obj->transaction.header.pubkey;
            snprintf(outKey, outKeyLen, "Pubkey");
            CHECK_ERROR(printPublicKey(pubkey, outVal, outValLen, pageIdx, pageCount));
            break;
        }
        case 2:
            snprintf(outKey, outKeyLen, "Epoch");
            if (uint64_to_str(outVal, outValLen, ctx->tx_obj->transaction.header.epoch) != NULL) {
                return parser_unexpected_error;
            }
            break;
        case 3: {
            snprintf(outKey, outKeyLen, "Gas limit");
            CHECK_ERROR(printAmount64(ctx->tx_obj->transaction.header.gasLimit, COIN_AMOUNT_DECIMAL_PLACES, "",
                                    outVal, outValLen, pageIdx, pageCount));
            break;
        }
        case 4: {
            if(ctx->tx_obj->transaction.header.fees.symbol != NULL) {
                snprintf(outKey, outKeyLen, "Fees/gas unit");
                CHECK_ERROR(printAmount(&ctx->tx_obj->transaction.header.fees.amount, COIN_AMOUNT_DECIMAL_PLACES,
                                    ctx->tx_obj->transaction.header.fees.symbol,
                                    outVal, outValLen, pageIdx, pageCount))
            } else {
                snprintf(outKey, outKeyLen, "Fee token");
                CHECK_ERROR(printAddress(ctx->tx_obj->transaction.header.fees.address, outVal, outValLen, pageIdx, pageCount))
            }
            break;
        }
        case 5: {
            snprintf(outKey, outKeyLen, "Fees/gas unit");
            CHECK_ERROR(printAmount(&ctx->tx_obj->transaction.header.fees.amount, COIN_AMOUNT_DECIMAL_PLACES,
                                    "",
                                    outVal, outValLen, pageIdx, pageCount))
            break;
        }
        default:
            return parser_display_idx_out_of_range;
    }

    return parser_ok;
}
