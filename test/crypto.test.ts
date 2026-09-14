// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { hexToBytes } from '@noble/hashes/utils.js'
import {
  commitment,
  depositSecrets,
  hash,
  isMnemonic,
  LeanIMT,
  masterKeys,
  mnemonicFromSignature,
  nullifierHash,
  precommitment,
  relayData,
  seedTypedData,
  withdrawalContext,
  withdrawalSecrets,
} from '../src/crypto.ts'

// Produced by 0xbow's own dependencies (viem, maci-crypto, @zk-kit/lean-imt)
const v = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'))
const n = BigInt

test('Poseidon matches circomlib', () => {
  assert.equal(hash([1n, 2n]), 0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189an)
  assert.equal(hash([1n]), 0x29176100eaa962bdc1fe6c654d6a3c130e96a4d1168b33848b897dc502820133n)
})

test('master keys, deposit and change notes match the 0xbow SDK', () => {
  assert.ok(v.k0_ge_p && v.k1_ge_p, 'vectors exercise keys above the field modulus')
  const k = masterKeys(v.mnemonic)
  assert.equal(k.masterNullifier, n(v.masterNullifier))
  assert.equal(k.masterSecret, n(v.masterSecret))
  const d0 = depositSecrets(k, n(v.scope), 0n)
  assert.deepEqual(d0, { nullifier: n(v.deposit0.nullifier), secret: n(v.deposit0.secret) })
  assert.deepEqual(depositSecrets(k, n(v.scope), 1n), {
    nullifier: n(v.deposit1.nullifier),
    secret: n(v.deposit1.secret),
  })
  assert.equal(precommitment(d0), n(v.deposit0.precommitment))
  assert.equal(commitment(n(v.value), n(v.label), d0), n(v.commitment0))
  assert.equal(nullifierHash(d0), n(v.nullifierHash0))
  const w0 = withdrawalSecrets(k, n(v.label), 0n)
  assert.deepEqual(w0, { nullifier: n(v.withdraw0.nullifier), secret: n(v.withdraw0.secret) })
})

test('LeanIMT roots and compressed proofs match zk-kit', () => {
  const tree = new LeanIMT(v.tree.leaves.map(n))
  assert.equal(tree.root, n(v.tree.root))
  assert.equal(tree.depth, v.tree.depth)
  for (const p of v.tree.proofs) {
    const got = tree.proof(p.i)
    assert.equal(got.index, p.index, `index of leaf ${p.i}`)
    assert.deepEqual(got.siblings, p.siblings.map(n), `siblings of leaf ${p.i}`)
  }
})

test('withdrawal context and relay data match viem', () => {
  const data = relayData(
    '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    '0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266',
    50000n,
  )
  assert.deepEqual(data, hexToBytes(v.context.data.slice(2)))
  assert.equal(withdrawalContext(v.context.entrypoint, data, n(v.scope)), n(v.context.value))
})

test('a wallet signature yields the website seed', () => {
  assert.equal(seedTypedData(v.seed.address).message.addressHash, v.seed.addressHash)
  const words = mnemonicFromSignature(v.seed.sig, v.seed.address)
  assert.equal(words, v.seed.mnemonic)
  assert.ok(isMnemonic(words))
})
