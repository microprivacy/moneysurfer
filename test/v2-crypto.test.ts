// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Known answers, all of them read off Ethereum mainnet: the vectors in
 * test/v2-vectors.json are real deposits, transacts, ragequits and keystore
 * registrations, so a hash that disagrees here disagrees with the contracts.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import {
  COMMITMENT_LEAF_TAG,
  commitmentLeaf,
  depositContext,
  hash,
  keystoreLeaf,
  LeanIMT,
  NULLIFIER_LEAF_TAG,
  nullifierLeaf,
  SNARK_FIELD,
} from '../src/v2/crypto.ts'

type Vectors = {
  deposit: { commitment: string; timestamp: string; leaf: string; hint: string; ciphertext: string; context: string }
  transact: { timestamp: string; commitments: string[]; nullifiers: string[]; leaves: string[] }
  ragequit: { nullifier: string; timestamp: string; leaf: string }
  keystore: { owner: string; nullifyingKeyHash: string; authDigest: string; leaf: string }
  stateTree: { leaves: string[]; root: string }
  keystoreTree: { leaves: string[]; root: string }
  aspSet: { leaves: string[]; root: string }
  aspSetProduction: { leaves: string[]; root: string }
}
const v: Vectors = JSON.parse(readFileSync(new URL('v2-vectors.json', import.meta.url), 'utf8'))
const n = (s: string) => BigInt(s)

test('poseidon is circomlib/maci-crypto', () => {
  // The two leaf tags, and the widths every V2 hash uses.
  assert.ok(COMMITMENT_LEAF_TAG < SNARK_FIELD && NULLIFIER_LEAF_TAG < SNARK_FIELD)
  assert.equal(hash([1n, 2n]), 7853200120776062878684798364095072458815029376092732009249414926327459813530n)
  assert.equal(hash([1n]), 18586133768512220936620570745912940619677854269274689475585506675881198879027n)
})

test('a deposit commitment becomes the leaf the pool inserted', () => {
  const { commitment, timestamp, leaf } = v.deposit
  assert.equal(commitmentLeaf(n(commitment), n(timestamp)), n(leaf))
})

test('a deposit context is keccak256(abi.encode(noteData)) mod r', () => {
  const { hint, ciphertext, context } = v.deposit
  assert.equal(depositContext(hint, Buffer.from(ciphertext.slice(2), 'hex')), n(context))
})

test('a transact inserts its commitments, then its nullifiers', () => {
  const { timestamp, commitments, nullifiers, leaves } = v.transact
  const built = [
    ...commitments.map((c) => commitmentLeaf(n(c), n(timestamp))),
    ...nullifiers.map((x) => nullifierLeaf(n(x), n(timestamp))),
  ]
  assert.deepEqual(built, leaves.map(n))
})

test('a ragequit inserts one nullifier leaf', () => {
  const { nullifier, timestamp, leaf } = v.ragequit
  assert.equal(nullifierLeaf(n(nullifier), n(timestamp)), n(leaf))
})

test('a keystore leaf is Poseidon(owner, nullifyingKeyHash, authDigest)', () => {
  const { owner, nullifyingKeyHash, authDigest, leaf } = v.keystore
  assert.equal(keystoreLeaf(owner, n(nullifyingKeyHash), n(authDigest)), n(leaf))
})

test('the LeanIMT rebuilds every root the chain published', () => {
  // each ASP set is the one that deployment's own ASP serves for its own
  // entrypoint; its root is the one that deployment's ASPRegistry.latestASPRoot()
  // returns, which is what the circuits check
  for (const [name, t] of [
    ['state', v.stateTree],
    ['keystore', v.keystoreTree],
    ['asp (staging)', v.aspSet],
    ['asp (production)', v.aspSetProduction],
  ] as const) {
    const tree = new LeanIMT(t.leaves.map(n))
    assert.equal(tree.root, n(t.root), `${name} tree root`)
  }
})

test('an inclusion proof recomputes the root it came from', () => {
  const tree = new LeanIMT(v.stateTree.leaves.map(n))
  for (const i of [0, 1, 7, tree.size - 1]) {
    const { index, siblings, leaf } = tree.proof(i)
    let node = leaf
    siblings.forEach((s, level) => {
      node = (index >> level) & 1 ? hash([s, node]) : hash([node, s])
    })
    assert.equal(node, tree.root, `leaf ${i}`)
  }
})
