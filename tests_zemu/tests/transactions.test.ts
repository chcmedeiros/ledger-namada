/** ******************************************************************************
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
 ******************************************************************************* */

import Zemu from '@zondax/zemu'
import { NamadaApp, Signature } from '@zondax/ledger-namada'
import { models, hdpath, defaultOptions } from './common'

const sha256 = require('js-sha256')
const leb = require('leb128')

// @ts-ignore
import ed25519 from 'ed25519-supercop'


function hashSignatureSec(pubkeys: Buffer[], salt: Buffer, hashes: { [index: number]: Buffer }, indices: Buffer, signature: Buffer | null, prefix: Uint8Array | null) {
  let hash = sha256.create();
  if (prefix != null) {
    hash.update(prefix);
  }

  hash.update(new Uint8Array([indices.length, 0, 0, 0]));
  for (let i = 0; i < (indices.length); i ++) {
    hash.update(Buffer.from(hashes[indices[i]]));
  }

  // Signer::PubKeys
  hash.update(new Uint8Array([0x01]));

  //Pubkeys
  hash.update(new Uint8Array([pubkeys.length, 0, 0, 0]));
  for (let i = 0; i < (pubkeys.length); i ++) {
    hash.update(Buffer.from(pubkeys[i]));
  }

  if(signature != null) {
    // u32 representing length
    hash.update(new Uint8Array([1, 0, 0, 0]));
    // u8 representing key
    hash.update(new Uint8Array([0x00]));
    // common::Signature
    hash.update(signature);
  } else {
    // u32 representing length
    hash.update(new Uint8Array([0, 0, 0, 0]));
  }

  return Buffer.from(hash.array());
}

const TEST_DATA = [
  {
    name: 'bond',
    blob: Buffer.from('1e0000006532652d746573742e3034666165323161626338663330613866653336640023000000323032332d31302d32345431323a31363a30332e3531373433363135372b30303a3030ddc8e7f3a1463df54faae663873d8f46ca67d90a50eb6cace2cf44b707cba76addd167e7c54f7cb24c7c8231df0487b49d8fbfd5dfc51065406b50d2bbd8bf3e010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600995c47158272b094640f33e1be2e8ef48715ecce0e1307d4c7a71045e35d6a430000000000000000204e00000000000000000200000002e9099d618b01000000bec1efd37d88876be4176d1afc0b6fa784901efe18cf9ec30293313be855d81400e9099d618b0100004b00000000c3b0c3ac7ae423be6dfb63ef2c73ec5b2d30841800e9a435000000000000000000000000000000000000000000000000000000000100b9e8b32a0b14aa741134a95e0468588dd217645e', 'hex'),
    sectionHashes: {
      0: Buffer.from('5495ee5290ec771bb111b11eac340fb2ddfb09f332b13bfde7935096267c0e42', 'hex'),
      1: Buffer.from('ddc8e7f3a1463df54faae663873d8f46ca67d90a50eb6cace2cf44b707cba76a', 'hex'),
      2: Buffer.from('ddd167e7c54f7cb24c7c8231df0487b49d8fbfd5dfc51065406b50d2bbd8bf3e', 'hex'),
      0xff: Buffer.from('bfb8dee7cfb2d4887fa3ec8b5e2e928fd3b00c371c5ee0938f48557046a80613', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('1e0000006532652d746573742e3034666165323161626338663330613866653336640023000000323032332d31302d32345431323a31363a32302e3633353230303237332b30303a30300055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e60077ba64a6385ce0635625d4137596d969c67d02afcc7766dbb5339efd1296f6e30100000000000000204e00000000000000000400000001c94c9d618b010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e01c94c9d618b010000009ebd95ba9479625043b113445c949d78116a77e86011eec60abbfb41b89f880302de4c9d618b010000006f63dc0ee534b74cec728b9f76dae383388f7306df66b827fa940e210a7c11ca00de4c9d618b0100007000000000649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c0075bca173cf45b6945d0ee4a9985e55aaa7aea6bb000149510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e082640c0000000000000018000000000000001e00000000000000', 'hex'),
    sectionHashes: {
      0: Buffer.from('4c33e85bb44229a5961683873e4dc8bb0dd6cad7002eee26da213218004e8a29', 'hex'),
      1: Buffer.from('649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c', 'hex'),
      2: Buffer.from('49510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e08264', 'hex'),
      3: Buffer.from('0055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70', 'hex'),
      4: Buffer.from('b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606', 'hex'),
      0xff: Buffer.from('e41b5eb5e4e94c8e973848ae21165821a98e9425f7b7270a880fb6f358a5b970', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'init_validator',
    blob: Buffer.from('1e0000006532652d746573742e3034666165323161626338663330613866653336640023000000323032332d31302d32345431323a31373a33362e3637333934383336332b30303a3030d856401c57c3756bd9b7a8596b30bdbbdcd84ea1369082709085945a75593266bf1978c1d2c865cbd998c85270a41e91bf38370cdce5645c58b3936b29896733010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600995c47158272b094640f33e1be2e8ef48715ecce0e1307d4c7a71045e35d6a430100000000000000204e00000000000000000300000001a1759e618b010000003b9e4d777c9420bbbf730e1549252f1a091bc01535eb1f37e7a7e3d1bace757602a2759e618b01000000b3b48166976e0259db4eab1e72ace4c92368b34fd5a06f7ccd41b4ae4c88ca1d00a2759e618b0100006e0100000100000000995c47158272b094640f33e1be2e8ef48715ecce0e1307d4c7a71045e35d6a430100f773c1694fd69220bf1a6b71a6ae2af2e6944d0f43246c917a5e8c81b2afde2003bcd7fe0aaa2e25be62fa534195793f5b51d978e04d80e6cbf5381a23b2fedd6f0326db2fb8ef5fef81161189633a4a733a11780b9c010ce9eed3878d02234f986a003828f31d0f9a627e1fb95a39f85055e06118b646a4a37d95c0c2b930dc411d80600000003fdf4787a943f55e530fe56d7004f8597c02b6ad5e468552fc1a9d6b670d0070cf8c4c3dd7e1353972a2c3b5249cb01192d884219de86e801744431eff2f32ffc0380e6eb09360046bc3bd0be237f22716d372b9792462d2b530872a35df0c8200743ba40b00000000000000000000000000000000000000000000000000000000e40b5402000000000000000000000000000000000000000000000000000000b94b385c5bb780bccb7ed816a59209963ba92aeb37ff17bd17bac5439aa28bdf', 'hex'),
    sectionHashes: {
      0: Buffer.from('0b9772159d5a6760afad9c18e1837d7bdcb33428c886739bb47f4113c9ff8808', 'hex'),
      1: Buffer.from('b94b385c5bb780bccb7ed816a59209963ba92aeb37ff17bd17bac5439aa28bdf', 'hex'),
      2: Buffer.from('d856401c57c3756bd9b7a8596b30bdbbdcd84ea1369082709085945a75593266', 'hex'),
      3: Buffer.from('bf1978c1d2c865cbd998c85270a41e91bf38370cdce5645c58b3936b29896733', 'hex'),
      0xff: Buffer.from('2635e4198dd017e15766f80a76fd701fbe22409045ee30215adc762ed19f1ab6', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'update_vp',
    blob: Buffer.from('1e0000006532652d746573742e3034666165323161626338663330613866653336640023000000323032332d31302d32345431323a31373a32352e3833383135313936372b30303a303070b5e945f66af7c2ded580ce153616710e6e79bf7d30c69d0915e8c18d3f2bf37b5e32353abaa027c09297bf112b0722bd297c75dca19ccf9e958d8372be0440010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e600995c47158272b094640f33e1be2e8ef48715ecce0e1307d4c7a71045e35d6a430100000000000000204e000000000000000003000000017f4b9e618b010000003b9e4d777c9420bbbf730e1549252f1a091bc01535eb1f37e7a7e3d1bace7576027f4b9e618b01000000c3e25b73b94a226c3e9a5990fb91864c1515cf2bcb8e28e4b3e403c41a37093200804b9e618b0100003b00000000b9e8b32a0b14aa741134a95e0468588dd217645e01e666a12812cd9f8a2bd38973db21836fa6eeab3a915223f3e3ae3441a87369230000000000', 'hex'),
    sectionHashes: {
      0: Buffer.from('cc725ee2571dda7143662accd8cb6685c45ab704891f5aa1046a8ad7f4ba2f81', 'hex'),
      1: Buffer.from('e666a12812cd9f8a2bd38973db21836fa6eeab3a915223f3e3ae3441a8736923', 'hex'),
      2: Buffer.from('70b5e945f66af7c2ded580ce153616710e6e79bf7d30c69d0915e8c18d3f2bf3', 'hex'),
      3: Buffer.from('7b5e32353abaa027c09297bf112b0722bd297c75dca19ccf9e958d8372be0440', 'hex'),
      0xff: Buffer.from('8f36472221e8257cbca0093c8ffa50f5d209445b650351030f34d32c678610d4', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_pubkeys',
    blob: Buffer.from('1e0000006532652d746573742e3034666165323161626338663330613866653336640023000000323032332d31302d32345431323a31363a32302e3633353230303237332b30303a30300055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e60077ba64a6385ce0635625d4137596d969c67d02afcc7766dbb5339efd1296f6e30100000000000000204e00000000000000000500000001c94c9d618b010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e01c94c9d618b010000009ebd95ba9479625043b113445c949d78116a77e86011eec60abbfb41b89f880302de4c9d618b010000006f63dc0ee534b74cec728b9f76dae383388f7306df66b827fa940e210a7c11ca00de4c9d618b0100007000000000649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c0075bca173cf45b6945d0ee4a9985e55aaa7aea6bb000149510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e082640c0000000000000018000000000000001e000000000000000301000000e41b5eb5e4e94c8e973848ae21165821a98e9425f7b7270a880fb6f358a5b970010100000000d2bbc65a45539c4dc73fd03f896616e56ec326ae8e7f9de08bd4efcc3a506cb8010000000000b038cd9cdbf78dc239c5479b4cf0e00b8135600e308f51b3f2a2bf4efa25264925c2e881a76eac35f99fd918ee2d7b22d74bf11c18b0527519cbe5e1d208f203', 'hex'),
    sectionHashes: {
      0: Buffer.from('4c33e85bb44229a5961683873e4dc8bb0dd6cad7002eee26da213218004e8a29', 'hex'),
      1: Buffer.from('649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c', 'hex'),
      2: Buffer.from('49510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e08264', 'hex'),
      3: Buffer.from('0055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70', 'hex'),
      4: Buffer.from('b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606', 'hex'),
      5: Buffer.from('d6696623fc2de31730650870dd25ba2d8ba3d161c130294b9ad3640eda9a5d0b', 'hex'),
      0xff: Buffer.from('e41b5eb5e4e94c8e973848ae21165821a98e9425f7b7270a880fb6f358a5b970', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_address',
    blob: Buffer.from('1e0000006532652d746573742e3034666165323161626338663330613866653336640023000000323032332d31302d32345431323a31363a32302e3633353230303237332b30303a30300055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606010100000000000000000000000000000000000000000000000000000000000000004b88fb913a0766e30a00b2fb8aa2949a710e24e60077ba64a6385ce0635625d4137596d969c67d02afcc7766dbb5339efd1296f6e30100000000000000204e00000000000000000500000001c94c9d618b010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e01c94c9d618b010000009ebd95ba9479625043b113445c949d78116a77e86011eec60abbfb41b89f880302de4c9d618b010000006f63dc0ee534b74cec728b9f76dae383388f7306df66b827fa940e210a7c11ca00de4c9d618b0100007000000000649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c0075bca173cf45b6945d0ee4a9985e55aaa7aea6bb000149510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e082640c0000000000000018000000000000001e000000000000000301000000e41b5eb5e4e94c8e973848ae21165821a98e9425f7b7270a880fb6f358a5b970000030b32c33b5ddd220997c12bb0147165a9f7aa6c5010000000000b038cd9cdbf78dc239c5479b4cf0e00b8135600e308f51b3f2a2bf4efa25264925c2e881a76eac35f99fd918ee2d7b22d74bf11c18b0527519cbe5e1d208f203', 'hex'),
    sectionHashes: {
      0: Buffer.from('4c33e85bb44229a5961683873e4dc8bb0dd6cad7002eee26da213218004e8a29', 'hex'),
      1: Buffer.from('649fec9556db0c4a16c5d8bf6b5ab91ae6a66f84e2bf1e8245b0eedbbcbf607c', 'hex'),
      2: Buffer.from('49510642ab1a0b799b3f9afbba9f648a9d0b8c303277c4168cee973b66e08264', 'hex'),
      3: Buffer.from('0055805d692db09e0543ab4559d03867af8666e388a1236c2987c542341f2a70', 'hex'),
      4: Buffer.from('b35c02db7d217a355f8f1024de219cf3d9cf0dba1201daf788a2a079d5622606', 'hex'),
      5: Buffer.from('d953f2b8f418f44360b13b17e4f85710a84131180492033a0ea5b2231766d441', 'hex'),
      0xff: Buffer.from('e41b5eb5e4e94c8e973848ae21165821a98e9425f7b7270a880fb6f358a5b970', 'hex'),
    } as { [index: number]: Buffer },
  },
]

jest.setTimeout(120000)

describe.each(models)('Transactions', function (m) {
  test.concurrent.each(TEST_DATA)('Sign transaction', async function (data) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new NamadaApp(sim.getTransport())

      const resp_addr = await app.getAddressAndPubKey(hdpath)
      // console.log(resp_addr)

      const respRequest = app.sign(hdpath, data.blob)
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot(), 20000)
      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign-${data.name}`)

      const resp = await respRequest
      // console.log(resp, m.name, data.name)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('signature')

      const signature = resp.signature ?? new Signature()
      expect(signature.pubkey).toEqual(resp_addr.publicKey);

      // Verify raw signature
      const unsignedRawSigHash = hashSignatureSec([], signature.raw_salt, data.sectionHashes, signature.raw_indices, null, null)
      const rawSig = ed25519.verify(signature.raw_signature.subarray(1), unsignedRawSigHash, signature.pubkey.subarray(1))

      // Verify wrapper signature
      const prefix = new Uint8Array([0x03]);
      const rawHash: Buffer = hashSignatureSec([signature.pubkey], signature.raw_salt, data.sectionHashes, signature.raw_indices, signature.raw_signature, prefix);
      const tmpHashes = {...data.sectionHashes};

      tmpHashes[Object.keys(tmpHashes).length - 1] = rawHash;

      const unsignedWrapperSigHash = hashSignatureSec([], signature.wrapper_salt, tmpHashes, signature.wrapper_indices, null, null);
      const wrapperSig = ed25519.verify(signature.wrapper_signature.subarray(1), unsignedWrapperSigHash, resp_addr.publicKey.subarray(1));

      expect(wrapperSig && rawSig).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})
