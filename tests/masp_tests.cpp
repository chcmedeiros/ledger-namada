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

#include "../build/googletest-src/googlemock/include/gmock/gmock.h"

#include <vector>
#include <cstring>
#include <hexutils.h>
#include "sapling.h"

void get_fvk(uint8_t *seed, uint32_t pos, full_viewing_key_t* out);

using namespace std;
struct FullViewingKeyTestcase {
        string seed;
        uint32_t zip32path;
        vector<uint8_t> expected_fvk;
};


TEST(FullViewingKey, NamadaEncodingTestnet) {
        vector<FullViewingKeyTestcase> testnet_fvks {
                {"d1b7bf436f5be86b1bd4bfeb69d6b89c3e5fb8b5a7fa1960f9444d1f230514a3",
                 0, {0x9B, 0x87, 0x9D, 0xE2, 0x05, 0x9B, 0x87, 0x9D, 0xE2, 0x05,0x9B, 0x87, 0x9D, 0xE2, 0x05}},
        };

        const uint8_t FVK_SIZE {128};
        for (const auto& testcase : testnet_fvks) {
                uint8_t seed[64] = {0};
                auto bufferLen = parseHexString(seed,
                                                sizeof(seed),
                                                testcase.seed.c_str());

                uint8_t actualFVK[FVK_SIZE] = {0};
                full_viewing_key_t fvk;
                get_fvk(seed, testcase.zip32path, &fvk);
                memcpy(actualFVK, fvk.ak, sizeof(actualFVK));

                const string namada_fvk(actualFVK, actualFVK + FVK_SIZE);
                EXPECT_TRUE(memcmp(testcase.expected_fvk.data(), &actualFVK, FVK_SIZE) == 0);
        }
}
