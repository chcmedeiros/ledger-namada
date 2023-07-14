/*******************************************************************************
*   (c) 2018 - 2022 Zondax AG
*   (c) 2016 Ledger
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

#include "app_main.h"

#include <string.h>
#include <os_io_seproxyhal.h>
#include <os.h>

#include "actions.h"
#include "addr.h"
#include "crypto.h"
#include "coin.h"
#include "key.h"
#include "masp_apdu_errors.h"
#include "nvdata.h"
#include "parser.h"
#include "transparent.h"
#include "tx.h"
#include "view.h"
#include "view_internal.h"
#include "zxmacros.h"

static bool tx_initialized = false;

__Z_INLINE void extractHDPath(uint32_t rx, uint32_t offset) {
    ZEMU_LOGF(50, "Extract HDPath\n")
    tx_initialized = false;

    const uint8_t pathLength = G_io_apdu_buffer[offset];
    offset++;

    if (pathLength != HDPATH_LEN_DEFAULT || (rx - offset) != sizeof(uint32_t) * pathLength) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    memcpy(hdPath, G_io_apdu_buffer + offset, sizeof(uint32_t) * HDPATH_LEN_DEFAULT);

    const bool mainnet = hdPath[0] == HDPATH_0_DEFAULT &&
                         hdPath[1] == HDPATH_1_DEFAULT;

    const bool testnet = hdPath[0] == HDPATH_0_DEFAULT &&
                         hdPath[1] == HDPATH_1_TESTNET;

    if (!mainnet && !testnet) {
        THROW(APDU_CODE_DATA_INVALID);
    }
}

__Z_INLINE bool process_chunk(__Z_UNUSED volatile uint32_t *tx, uint32_t rx) {
    const uint8_t payloadType = G_io_apdu_buffer[OFFSET_PAYLOAD_TYPE];
    if (rx < OFFSET_DATA) {
        THROW(APDU_CODE_WRONG_LENGTH);
    }

    uint32_t added;
    switch (payloadType) {
        case P1_INIT:
            tx_initialize();
            tx_reset();
            extractHDPath(rx, OFFSET_DATA);
            tx_initialized = true;
            return false;
        case P1_ADD:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            return false;
        case P1_LAST:
            if (!tx_initialized) {
                THROW(APDU_CODE_TX_NOT_INITIALIZED);
            }
            added = tx_append(&(G_io_apdu_buffer[OFFSET_DATA]), rx - OFFSET_DATA);
            tx_initialized = false;
            if (added != rx - OFFSET_DATA) {
                tx_initialized = false;
                THROW(APDU_CODE_OUTPUT_BUFFER_TOO_SMALL);
            }
            tx_initialized = false;
            return true;
    }

    THROW(APDU_CODE_INVALIDP1P2);
}

__Z_INLINE void handleSignTransaction(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    ZEMU_LOGF(50, "handleSignTransaction\n")
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }
    CHECK_APP_CANARY()

    const char *error_msg = tx_parse();
    CHECK_APP_CANARY()

    if (error_msg != NULL) {
        int error_msg_length = strlen(error_msg);
        memcpy(G_io_apdu_buffer, error_msg, error_msg_length);
        *tx += (error_msg_length);
        THROW(APDU_CODE_DATA_INVALID);
    }

    CHECK_APP_CANARY()
    view_review_init(tx_getItem, tx_getNumItems, app_sign);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

__Z_INLINE void handleGetSignature(volatile uint32_t *tx) {
    ZEMU_LOGF(50, "HandleGetSignature")
    *tx = 0;
    const uint8_t slot = G_io_apdu_buffer[OFFSET_P2];

    const zxerr_t err = crypto_getSignature(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, slot);
    if (err == zxerr_ok){
        *tx = SALT_LEN + HASH_LEN + PK_LEN_25519 + SIG_ED25519_LEN;
        THROW(APDU_CODE_OK);
    } else {
        THROW(APDU_CODE_CONDITIONS_NOT_SATISFIED);
    }
}

// Process initial MASP transaction blob for later signing
__Z_INLINE void handleInitMASPTransfer(volatile uint32_t *flags,
                                volatile uint32_t *tx, uint32_t rx) {
    if (!process_chunk(tx, rx)) {
        THROW(APDU_CODE_OK);
    }

    zemu_log("----[handleInitMASPTransfer]\n");

    *tx = 0;
    const uint8_t *message = tx_get_buffer();
    const uint16_t messageLength = tx_get_buffer_length();

    zxerr_t err = crypto_extracttx_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok) {
        transaction_reset();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        G_io_apdu_buffer[0] = err;
        *tx = 1;
        THROW(APDU_CODE_EXTRACT_TRANSACTION_FAIL);
    }

    err = crypto_hash_messagebuffer(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 3, message, messageLength);
    if (err != zxerr_ok) {
        transaction_reset();
        MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
        G_io_apdu_buffer[0] = err;
        *tx = 1;
        THROW(APDU_CODE_HASH_MSG_BUF_FAIL);
    }

    view_review_init(tx_getItem, tx_getNumItems, app_reply_hash);

    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;

}

__Z_INLINE void handleExtractSpendDataMASPTransfer(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleExtractSpendDataMASPTransfer]\n");

    *tx = 0;
    if (rx != APDU_MIN_LENGTH || G_io_apdu_buffer[OFFSET_DATA_LEN] != 0) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }
    // TODO implement the following
    zxerr_t err = crypto_extract_spend_proof_key_and_rnd(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2);
    view_tx_state();
    if (err == zxerr_ok) {
        *tx = 128; //SPEND_EXTRACT_LEN
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }

}

__Z_INLINE void handleExtractOutputDataMASPTransfer(volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleExtractOutputData]\n");

    *tx = 0;
    if (rx != APDU_MIN_LENGTH || G_io_apdu_buffer[OFFSET_DATA_LEN] != 0) {
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint16_t replyLen = 0;
    zxerr_t err = crypto_extract_output_rnd(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, &replyLen);
    view_tx_state();
    if (err == zxerr_ok) {
        *tx = replyLen;
        THROW(APDU_CODE_OK);
    } else {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
}

// Get the sapling full viewing key fvk = (ak, nk, ovk, dk)
__Z_INLINE void handleGetKeyFVK(volatile uint32_t *flags,
                                volatile uint32_t *tx, uint32_t rx) {
    zemu_log("----[handleGetKeyFVK]\n");

    *tx = 0;
    if (rx < APDU_MIN_LENGTH ||  rx - APDU_MIN_LENGTH != DATA_LENGTH_GET_FVK
        || G_io_apdu_buffer[OFFSET_DATA_LEN] != DATA_LENGTH_GET_FVK
        || G_io_apdu_buffer[OFFSET_P1] == 0) {
        zemu_log("Wrong length!\n");
        THROW(APDU_CODE_COMMAND_NOT_ALLOWED);
    }

    uint32_t zip32path = 0;
    parser_error_t prserr = parser_sapling_path(G_io_apdu_buffer + OFFSET_DATA, DATA_LENGTH_GET_FVK,
                                                &zip32path);
    MEMZERO(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
    if (prserr != parser_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.kind = key_fvk;
    uint16_t replyLen = 0;

    zxerr_t err = crypto_fvk_sapling(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE - 2, zip32path, &replyLen);
    if (err != zxerr_ok) {
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    key_state.len = (uint8_t) replyLen;

    view_review_init(key_getItem, key_getNumItems, app_reply_key);
    view_review_show(REVIEW_TXN);
    *flags |= IO_ASYNCH_REPLY;
}

// For wrapper transactions, address is derived from Ed25519 pubkey
__Z_INLINE void handleGetAddr(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    zemu_log("handleGetAddr\n");
    extractHDPath(rx, OFFSET_DATA);
    *tx = 0;
    const uint8_t requireConfirmation = G_io_apdu_buffer[OFFSET_P1];

    zxerr_t zxerr = app_fill_address(key_ed25519);
    if(zxerr != zxerr_ok){
        *tx = 0;
        THROW(APDU_CODE_DATA_INVALID);
    }
    if (requireConfirmation) {
        view_review_init(addr_getItem, addr_getNumItems, app_reply_address);
        view_review_show(REVIEW_ADDRESS);
        *flags |= IO_ASYNCH_REPLY;
        return;
    }
    *tx = action_addrResponse.len;
    THROW(APDU_CODE_OK);
}

__Z_INLINE void handle_getversion(__Z_UNUSED volatile uint32_t *flags, volatile uint32_t *tx)
{
    G_io_apdu_buffer[0] = 0;

#if defined(APP_TESTING)
    G_io_apdu_buffer[0] = 0x01;
#endif

    G_io_apdu_buffer[1] = (LEDGER_MAJOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[2] = (LEDGER_MAJOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[3] = (LEDGER_MINOR_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[4] = (LEDGER_MINOR_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[5] = (LEDGER_PATCH_VERSION >> 8) & 0xFF;
    G_io_apdu_buffer[6] = (LEDGER_PATCH_VERSION >> 0) & 0xFF;

    G_io_apdu_buffer[7] = !IS_UX_ALLOWED;

    G_io_apdu_buffer[8] = (TARGET_ID >> 24) & 0xFF;
    G_io_apdu_buffer[9] = (TARGET_ID >> 16) & 0xFF;
    G_io_apdu_buffer[10] = (TARGET_ID >> 8) & 0xFF;
    G_io_apdu_buffer[11] = (TARGET_ID >> 0) & 0xFF;

    *tx += 12;
    THROW(APDU_CODE_OK);
}

#if defined(APP_TESTING)
void handleTest(__Z_UNUSED volatile uint32_t *flags, __Z_UNUSED volatile uint32_t *tx, __Z_UNUSED uint32_t rx) {
    THROW(APDU_CODE_OK);
}
#endif

void handleApdu(volatile uint32_t *flags, volatile uint32_t *tx, uint32_t rx) {
    volatile uint16_t sw = 0;

    BEGIN_TRY
    {
        TRY
        {
            if (G_io_apdu_buffer[OFFSET_CLA] != CLA) {
                THROW(APDU_CODE_CLA_NOT_SUPPORTED);
            }

            if (rx < APDU_MIN_LENGTH) {
                THROW(APDU_CODE_WRONG_LENGTH);
            }

            switch (G_io_apdu_buffer[OFFSET_INS]) {
                case INS_GET_VERSION: {
                    handle_getversion(flags, tx);
                    break;
                }

                case INS_GET_ADDR: {
                    CHECK_PIN_VALIDATED()
                    handleGetAddr(flags, tx, rx);
                    break;
                }

                case INS_SIGN: {
                    CHECK_PIN_VALIDATED()
                    handleSignTransaction(flags, tx, rx);
                    break;
                }

                case INS_GET_SIGNATURE: {
                    CHECK_PIN_VALIDATED()
                    handleGetSignature(tx);
                    break;
                }

                // MASP transactions
                // Get full viewing key fvk = (ak, nk, ovk, dk)
                case INS_GET_FVK: {
                    zemu_log("----[INS_GET_FVK]\n");
                    CHECK_PIN_VALIDATED()
                    handleGetKeyFVK(flags, tx, rx);
                    break;
                }

                // Step 1 in signing a MASP transaction:
                // the ledger receives an initial transaction blob
                // and stores relevant information in flash memory,
                // so that it can check consistency with what it signs later.
                case INS_INIT_MASP_TRANSFER: {
                    zemu_log("----[INS_INIT_MASP_TRANSFER]\n");
                    CHECK_PIN_VALIDATED()
                    handleInitMASPTransfer(flags, tx, rx);
                    break;
                }

                // If there are any spends (= shielded inputs) this is
                // Step 2 in signing a MASP transaction:
                // the clients requests information to build SpendDescriptions.
                // In particular, the ledger should answer with
                // a proof generating key (PGK) and randomness (rcv and alpha)
                // This APDU is called for each spend.
                case INS_EXTRACT_SPEND: {
                    CHECK_PIN_VALIDATED()
                    handleExtractSpendDataMASPTransfer(tx, rx);
                    break;
                }

                // If there are any shielded outputs this is
                // Step 3 in signing a MASP transaction:
                // the clients requests information to build OutputDescriptions.
                // In particular, the ledger should answer with
                // rcv,  rseed (after ZIP202) and optional Hash_Seed
                // This APDU is called for each shielded output.
                case INS_EXTRACT_OUTPUT: {
                    CHECK_PIN_VALIDATED()
                    handleExtractOutputDataMASPTransfer(tx, rx);
                    break;
                }


#if defined(APP_TESTING)
                    case INS_TEST: {
                    handleTest(flags, tx, rx);
                    THROW(APDU_CODE_OK);
                    break;
                }
#endif
                default:
                    THROW(APDU_CODE_INS_NOT_SUPPORTED);
            }
        }
        CATCH(EXCEPTION_IO_RESET)
        {
            THROW(EXCEPTION_IO_RESET);
        }
        CATCH_OTHER(e)
        {
            switch (e & 0xF000) {
                case 0x6000:
                case APDU_CODE_OK:
                    sw = e;
                    break;
                default:
                    sw = 0x6800 | (e & 0x7FF);
                    break;
            }
            G_io_apdu_buffer[*tx] = sw >> 8;
            G_io_apdu_buffer[*tx + 1] = sw & 0xFF;
            *tx += 2;
        }
        FINALLY
        {
        }
    }
    END_TRY;
}
