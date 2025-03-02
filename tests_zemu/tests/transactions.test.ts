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
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431343a33313a31322e3030383437393437392b30303a303029e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be0101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca0048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d80300000000000000a861000000000000000200000002b3078bd88b010000007c7a739c83e943d4a56a0fd4e4c52a9edc0d66d9105324bcc909619857a6683b010c00000074785f626f6e642e7761736d00b3078bd88b0100004b00000000f2d1fbf5a690f8ab12cfa6166425bec4d7569bb400e9a435000000000000000000000000000000000000000000000000000000000100ba4c9645a23343896227110a902af84e7b4a4bb3', 'hex'),
    sectionHashes: {
      0: Buffer.from('5b693f86a6a8053b79effacd031e2367a1d35cc64988795768920b2965013742', 'hex'),
      1: Buffer.from('29e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58', 'hex'),
      2: Buffer.from('f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be', 'hex'),
      0xff: Buffer.from('c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e0', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'init_proposal',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431343a33313a32382e3130313832393531382b30303a3030036244dbf2c2d2fc6900e7c46a0d81e75a6e137c4900ee614cc8b1551543ce5d9e467e3e8db73280a50aac95b59e54ece4f670624e1a46388dd0c458e78076420101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75170500000000000000a86100000000000000030000000194468bd88b010000007e68fb834a7772c82a312c4e6e519d97282cce39507950c35fe89f1c347a4a2e000294468bd88b01000000d81ff4dba9b1316576360dc94fcd611f9b228b040eaefb5157819d692eb4ef50011500000074785f696e69745f70726f706f73616c2e7761736d0094468bd88b0100005000000000061a4caa2da23123adeb4ae80ba0dc5239bff64baa4aaf5f385dc6877ae22e2600282bcb6a66c770f23e7b2f068ae0ba025eccb2ec00000c0000000000000018000000000000001e00000000000000', 'hex'),
    sectionHashes: {
      0: Buffer.from('e86108905c4ba210c2c20289369b9cbcad3dfed25c601b9b6673ddef5573e3d4', 'hex'),
      1: Buffer.from('061a4caa2da23123adeb4ae80ba0dc5239bff64baa4aaf5f385dc6877ae22e26', 'hex'),
      2: Buffer.from('036244dbf2c2d2fc6900e7c46a0d81e75a6e137c4900ee614cc8b1551543ce5d', 'hex'),
      3: Buffer.from('9e467e3e8db73280a50aac95b59e54ece4f670624e1a46388dd0c458e7807642', 'hex'),
      0xff: Buffer.from('039a4d90beb2ead23ef48cecc0039104f865dd3c6c89ee12b90defbe8205c319', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'update_vp',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431343a33333a30352e3139313137373835302b30303a30305df9287d1f3b893eef4643c47a4d40a8838c9fc6a39bbda275e20c308f6bb0a290f781fd267026dfd1335d092f0a46d9cf00b8816c5997e55eaf88e0e5cbf3dc0101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75171400000000000000a861000000000000000500000001d2c18cd88b0100000053e9023f2edc55e90bdcf6024760140a91a7904cb4a529cb1707ea3d34ee685a010c00000076705f757365722e7761736d02d3c18cd88b0100000049a9b2023b4858255845bfa3949e314f241858949214950471b0b598febd7248011600000074785f7570646174655f6163636f756e742e7761736d00d3c18cd88b0100009f00000000ba4c9645a23343896227110a902af84e7b4a4bb301a911dbc336d7feab85e374e331542d94155fe25219bad6d7f497a2e5d9d6a41703000000009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a75170048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d80075c251407a7ed91b8114f90b6f454db9071a290458e2db36106b99daf4bf83b101020301000000ae19fb14011c761f61ea480a4d9fffd1abb049be4715f5344d6f60093470c0800000ba4c9645a23343896227110a902af84e7b4a4bb30100000000000d1cfc74bd04c329f14c466b7b17ac72b00818db85bb1069415a898bfa95cd21ae416cfc38e190ff2a631f1f9dd700556d5ad25eef92a5f5dffa5af3a723390c03050000009ac0dfc46072a5736aa2257015d54ecb5490f6811bf9ffee38662c38cecb1ea8a911dbc336d7feab85e374e331542d94155fe25219bad6d7f497a2e5d9d6a4175df9287d1f3b893eef4643c47a4d40a8838c9fc6a39bbda275e20c308f6bb0a290f781fd267026dfd1335d092f0a46d9cf00b8816c5997e55eaf88e0e5cbf3dc66f097755345c31d1ccf8b764bbbd8ff8b8496f7ac88a32f4967b98138b642aa0101000000009fd0df101ba3e91d24f555893ae1bf0b271bd98363d6d4c659876731fe4a7517010000000000e7c0e073a254bccce92bb5d6b35da86f6ee1b300fa6d3f54d1414a06745a895d32d5b86fe029e0ab456d2ade56f79d066f3e9c6dd80088c9fdc6e00a4a472f0a', 'hex'),
    sectionHashes: {
      0: Buffer.from('9ac0dfc46072a5736aa2257015d54ecb5490f6811bf9ffee38662c38cecb1ea8', 'hex'),
      1: Buffer.from('a911dbc336d7feab85e374e331542d94155fe25219bad6d7f497a2e5d9d6a417', 'hex'),
      2: Buffer.from('5df9287d1f3b893eef4643c47a4d40a8838c9fc6a39bbda275e20c308f6bb0a2', 'hex'),
      3: Buffer.from('90f781fd267026dfd1335d092f0a46d9cf00b8816c5997e55eaf88e0e5cbf3dc', 'hex'),
      4: Buffer.from('66f097755345c31d1ccf8b764bbbd8ff8b8496f7ac88a32f4967b98138b642aa', 'hex'),
      5: Buffer.from('521915f7e75cbde1d94d178a83f6c4ca51bc77640fcd3aaeb28b89ac16620d58', 'hex'),
      0xff: Buffer.from('ae19fb14011c761f61ea480a4d9fffd1abb049be4715f5344d6f60093470c080', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_pubkeys',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431343a33313a31322e3030383437393437392b30303a303029e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be0101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca0048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d80300000000000000a861000000000000000400000002b3078bd88b010000007c7a739c83e943d4a56a0fd4e4c52a9edc0d66d9105324bcc909619857a6683b010c00000074785f626f6e642e7761736d00b3078bd88b0100004b00000000f2d1fbf5a690f8ab12cfa6166425bec4d7569bb400e9a435000000000000000000000000000000000000000000000000000000000100ba4c9645a23343896227110a902af84e7b4a4bb30301000000c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e00000ba4c9645a23343896227110a902af84e7b4a4bb301000000000087d6e5a4617cce4c93120504a5f5db8c9ce1af0416e260c3fbe9066df3f3fdb2abfda0cac21b97b3e89b3c29013db345bd22548e8baf2df4e682bb4e1a041f0f03040000005b693f86a6a8053b79effacd031e2367a1d35cc64988795768920b296501374229e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897bed4bfd3e247c0ef6e2ab23983a793412fd94a78d9a08efaa94a3d6a977e3c601c01010000000048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d8010000000000cfcc82f327627fed72368dd168663db755478675d812365b9c8b92c36acaaebf1fe9a0494aaf9e675d4b4f041ffebc5234d9da012721b1bd5d1bbc819ed56f04', 'hex'),
    sectionHashes: {
      0: Buffer.from('5b693f86a6a8053b79effacd031e2367a1d35cc64988795768920b2965013742', 'hex'),
      1: Buffer.from('29e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58', 'hex'),
      2: Buffer.from('f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be', 'hex'),
      3: Buffer.from('d4bfd3e247c0ef6e2ab23983a793412fd94a78d9a08efaa94a3d6a977e3c601c', 'hex'),
      4: Buffer.from('ea7dd39da3e99c29ee2c51d7bc7cd14754010fa16531ff807988c5018fcccea4', 'hex'),
      0xff: Buffer.from('c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e0', 'hex'),
    } as { [index: number]: Buffer },
  },
  {
    name: 'multisig_address',
    blob: Buffer.from('1d0000006c6f63616c6e65742e6664633665356661643365356535326433662d300023000000323032332d31312d31365431343a33313a31322e3030383437393437392b30303a303029e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be0101000000000000000000000000000000000000000000000000000000000000000032fdd4e57f56519541491312d4e9089032244eca0048998ffa0340c473b72dad3604abd76581e71e4a334d0708ef754a0adcec66d80300000000000000a861000000000000000300000002b3078bd88b010000007c7a739c83e943d4a56a0fd4e4c52a9edc0d66d9105324bcc909619857a6683b010c00000074785f626f6e642e7761736d00b3078bd88b0100004b00000000f2d1fbf5a690f8ab12cfa6166425bec4d7569bb400e9a435000000000000000000000000000000000000000000000000000000000100ba4c9645a23343896227110a902af84e7b4a4bb30301000000c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e00001ed03655318474529449ed5f0bd81d2cbfa41d57a010000000000682203cfc3d10fd4bd2fbf57181012ca8f113e0b11ae6cd50621a2acf34e83b755fed6eeeb9f6f1c4f55765e2999ce8bd505fb48845e5f810ad57673fcb38e0d', 'hex'),
    sectionHashes: {
      0: Buffer.from('5b693f86a6a8053b79effacd031e2367a1d35cc64988795768920b2965013742', 'hex'),
      1: Buffer.from('29e3fd2d0a8c786d5318be88f0be06629152ac26628396e28350f7c5b81b1d58', 'hex'),
      2: Buffer.from('f09f9bf315fe3b244703f3695cafff63b67156f799dc5c0742d1612cdd4897be', 'hex'),
      3: Buffer.from('d05ef8971a0464a35ab4d08efea23d6c9c86aeeb5e1e6992956ed814d0a3d761', 'hex'),
      0xff: Buffer.from('c7fec5279e22792a9cad6346f8933c1b2249043e1a03c835030d4e71dfbac3e0', 'hex'),
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
