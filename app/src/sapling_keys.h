#include <stdint.h>   // uint*_t

// SAPLING
#define AK_SIZE                 32
#define ASK_SIZE                32
#define DK_SIZE                 32
#define NK_SIZE                 32
#define NSK_SIZE                32
#define OVK_SIZE                32
#define OVK_SET_SIZE            1 + OVK_SIZE

typedef struct {
    uint8_t ask[ASK_SIZE];  // spend authorizing key
    uint8_t nsk[NSK_SIZE];  // nullifier private key
    uint8_t ovk[OVK_SIZE];  // outgoing viewing key
    uint8_t dk[DK_SIZE];    // diversifier key
} expanded_spending_key_t;

typedef struct {
    uint8_t ak[AK_SIZE];
    uint8_t nk[NK_SIZE];    // nullifier deriving key
    uint8_t ovk[OVK_SIZE];  // outgoing viewing key
    uint8_t dk[DK_SIZE];    // diversifier key
} full_viewing_key_t;

typedef struct {
    uint8_t ak[AK_SIZE];
    uint8_t ask[ASK_SIZE];
    uint8_t nk[NK_SIZE];    // nullifier deriving key
    uint8_t nsk[NSK_SIZE];
    uint8_t ovk[OVK_SIZE];  // outgoing viewing key
    uint8_t dk[DK_SIZE];    // diversifier key
} all_keys_t;