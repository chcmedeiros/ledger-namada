/*******************************************************************************
*  (c) 2018 - 2022 Zondax AG
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

#define VERSION_SIZE            2
#define CHECKSUM_SIZE           4
#define VERSION_P2SH            0x1CBD
#define VERSION_P2PKH           0x1CB8

#define ZIP32_SEED_SIZE         64

#define ED25519_SK_SIZE         64

#define MASK_HARDENED           0x80000000

#define CTX_EXPAND_SEED "MASP__ExpandSeed"
#define CTX_EXPAND_SEED_LEN 16
#define CTX_EXPAND_SEED_HASH_LEN 64