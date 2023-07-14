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

#include <stdio.h>


#include <zxtypes.h>
//#include <os_io_seproxyhal.h>

#include "nvdata.h"
#include "parser_common.h"
#include "parser_impl.h"
#include "parser.h"

#include "crypto.h"
#include "crypto_helper.h"

#include "parser_print_common.h"
#include "view.h"

parser_error_t parser_init_context(parser_context_t *ctx,
                                   const uint8_t *buffer,
                                   uint16_t bufferSize) {
    ctx->offset = 0;
    ctx->buffer = NULL;
    ctx->bufferLen = 0;

    if (bufferSize == 0 || buffer == NULL || ctx->tx_obj == NULL) {
        // Not available, use defaults
        return parser_init_context_empty;
    }

    ctx->buffer = buffer;
    ctx->bufferLen = bufferSize;

    return parser_ok;
}

void view_tx_state() {
#if !defined(TARGET_STAX)
    uint8_t state = get_state();
    switch (state) {
        case STATE_PROCESSED_INPUTS:
        case STATE_PROCESSED_SPEND_EXTRACTIONS: {
            view_message_show("MASP", "Step [1/5]");
            break;
        }

        case STATE_PROCESSED_ALL_EXTRACTIONS: {
            view_message_show("MASP", "Step [2/5]");
            break;
        }

        case STATE_CHECKING_ALL_TXDATA: {
            view_message_show("MASP", "Step [3/5]");
            break;
        }

        case STATE_VERIFIED_ALL_TXDATA: {
            view_message_show("MASP", "Step [4/5]");
            break;
        }

        case STATE_SIGNED_TX: {
            view_message_show("MASP", "Step [5/5]");
            break;
        }

        default: {
            view_idle_show(0, NULL);
        }
    }
    // TODO: Uncomment this, need to #include <os_io_seproxyhal.h>
    //  but for some reason that is failing
    //  UX_WAIT_DISPLAYED();
#endif
    return;
}

parser_error_t parser_parse(parser_context_t *ctx,
                            const uint8_t *data,
                            size_t dataLen,
                            parser_tx_t *tx_obj) {
    ctx->tx_obj = tx_obj;
    CHECK_ERROR(parser_init_context(ctx, data, dataLen))
    return _read(ctx, tx_obj);
}

parser_error_t parser_validate(parser_context_t *ctx) {
    // Iterate through all items to check that all can be shown and are valid
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))

    char tmpKey[40];
    char tmpVal[40];

    for (uint8_t idx = 0; idx < numItems; idx++) {
        uint8_t pageCount = 0;
        CHECK_ERROR(parser_getItem(ctx, idx, tmpKey, sizeof(tmpKey), tmpVal, sizeof(tmpVal), 0, &pageCount))
    }
    return parser_ok;
}

parser_error_t parser_getNumItems(const parser_context_t *ctx, uint8_t *num_items) {
    return getNumItems(ctx, num_items);
}

static void cleanOutput(char *outKey, uint16_t outKeyLen,
                        char *outVal, uint16_t outValLen)
{
    MEMZERO(outKey, outKeyLen);
    MEMZERO(outVal, outValLen);
    snprintf(outKey, outKeyLen, "?");
    snprintf(outVal, outValLen, " ");
}

static parser_error_t checkSanity(uint8_t numItems, uint8_t displayIdx)
{
    if ( displayIdx >= numItems) {
        return parser_display_idx_out_of_range;
    }
    return parser_ok;
}

parser_error_t parser_getItem(const parser_context_t *ctx,
                              uint8_t displayIdx,
                              char *outKey, uint16_t outKeyLen,
                              char *outVal, uint16_t outValLen,
                              uint8_t pageIdx, uint8_t *pageCount) {

    *pageCount = 1;
    uint8_t numItems = 0;
    CHECK_ERROR(parser_getNumItems(ctx, &numItems))
    CHECK_APP_CANARY()

    CHECK_ERROR(checkSanity(numItems, displayIdx))
    cleanOutput(outKey, outKeyLen, outVal, outValLen);

    return printTxnFields(ctx, displayIdx, outKey, outKeyLen,
                          outVal, outValLen, pageIdx, pageCount);
}

parser_error_t parser_sapling_path(const uint8_t *data, size_t dataLen, uint32_t *p) {
    if (dataLen < 4) {
        return parser_context_unexpected_size;
    }
    parser_context_t pars_ctx;
    parser_error_t pars_err;
    pars_ctx.offset = 0;
    pars_ctx.buffer = data;
    pars_ctx.bufferLen = 4;
    pars_err = _readUInt32(&pars_ctx, p);
    if (pars_err != parser_ok) {
        return pars_err;
    }
    *p |= 0x80000000;
    return parser_ok;
}