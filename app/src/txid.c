#include "txid.h"
#include "nvdata.h"
#include "index_sapling.h"
#include "coin.h"
#include "constants.h"

// TODO: THE FOLLOWING CONSTANTS SHOULD BE CHANGED FOR NAMADA, BUT WHAT DO THEY WANT?
//  probably the values can be found in the masp repo
// TxId transparent level 2 node personalization
#define MASP__PREVOUTS_HASH_PERSONALIZATION "ZTxIdPrevoutHash"
#define MASP__SEQUENCE_HASH_PERSONALIZATION "ZTxIdSequencHash"
#define MASP__OUTPUTS_HASH_PERSONALIZATION "ZTxIdOutputsHash"

void nu5_transparent_prevouts_hash(const uint8_t *input, uint8_t *output) {
    const uint8_t n = t_inlist_len();

    uint8_t personalization[16] = {0};
    MEMCPY(personalization, PIC(MASP__PREVOUTS_HASH_PERSONALIZATION), 16);

    #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_blake2b_t ctx;
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) personalization, 16);
    #else
        // todo: for testing need to use another library
    #endif

    if (n == 0) {
        #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
            cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_LEN);
        #else
            // todo: for testing need to use another library
        #endif
        return;
    }

    const uint8_t *data = input + INDEX_TIN_PREVOUT;
    for (uint8_t i = 0; i < n - 1; i++, data += T_IN_TX_LEN) {
        #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
            cx_hash_no_throw(&ctx.header, 0, data, PREVOUT_SIZE, NULL, 0);
        #else
            // todo: for testing need to use another library
        #endif
    }
    #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_hash_no_throw(&ctx.header, CX_LAST, data, PREVOUT_SIZE, output, HASH_LEN);
    #else
        // todo: for testing need to use another library
    #endif
}

void nu5_transparent_sequence_hash(const uint8_t *input, uint8_t *output) {
    zemu_log_stack("nu5_transparent_sequence_hash");

    const uint8_t n = t_inlist_len();

    uint8_t personalization[16] = {0};
    MEMCPY(personalization, PIC(MASP__SEQUENCE_HASH_PERSONALIZATION), 16);

    #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_blake2b_t ctx;
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) personalization, 16);
    #else
        // todo: for testing need to use another library
    #endif


    if (n == 0) {
        #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
            cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_LEN);
        #else
            // todo: for testing need to use another library
        #endif
        return;
    }

    const uint8_t *data = input + INDEX_TIN_SEQ;
    for (uint8_t i = 0; i < n - 1; i++, data += T_IN_TX_LEN) {
        #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
            cx_hash_no_throw(&ctx.header, 0, data, SEQUENCE_SIZE, NULL, 0);
        #else
            // todo: for testing need to use another library
        #endif
    }
    #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_hash_no_throw(&ctx.header, CX_LAST, data, SEQUENCE_SIZE, output, HASH_SIZE);
    #else
        // todo: for testing need to use another library
    #endif
}

/// Sequentially append the full serialized value of each transparent output
/// to a hash personalized by MASP__OUTPUTS_HASH_PERSONALIZATION.
/// In the case that no outputs are provided, this produces a default
/// hash from just the personalization string.
void nu5_transparent_outputs_hash(uint8_t *output) {
    const uint8_t n = t_outlist_len();

    uint8_t personalization[16] = {0};
    MEMCPY(personalization, PIC(MASP__OUTPUTS_HASH_PERSONALIZATION), 16);

    #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_blake2b_t ctx;
        cx_blake2b_init2_no_throw(&ctx, 256, NULL, 0, (uint8_t *) personalization, 16);
    #else
        // todo: for testing need to use another library
    #endif

    if (n == 0) {
    #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_hash_no_throw(&ctx.header, CX_LAST, 0, 0, output, HASH_LEN);
    #else
        // todo: for testing need to use another library
    #endif
        return;
    }

    uint8_t data[T_OUTPUT_SIZE];
    uint8_t i = 0;
    for (; i < n - 1; i++) {
        t_output_item_t *item = t_outlist_retrieve_item(i);
        MEMCPY(data, (uint8_t * ) & (item->value), 8);
        MEMCPY(data + 8, item->address, SCRIPT_SIZE);
        #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
            cx_hash_no_throw(&ctx.header, 0, data, sizeof(data), NULL, 0);
        #else
            // todo: for testing need to use another library
        #endif
    }
    t_output_item_t *item = t_outlist_retrieve_item(i);
    MEMCPY(data, (uint8_t * ) & (item->value), 8);
    MEMCPY(data + 8, item->address, SCRIPT_SIZE);
    #if defined(TARGET_NANOS) || defined(TARGET_NANOS2) || defined(TARGET_NANOX)
        cx_hash_no_throw(&ctx.header, CX_LAST, data, sizeof(data), output, HASH_SIZE);
    #else
        // todo: for testing need to use another library
    #endif
}

