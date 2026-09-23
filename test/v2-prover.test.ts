// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The ceremony's keys against the chain's own proofs. Real mainnet deposit,
 * ragequit and transact proofs are verified with the verification keys the
 * IPFS manifest points at, which is what makes both trustworthy at once: a
 * wrong key, or a public-signal order read wrong, fails the pairing.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { have, load, pinned, verificationKey } from '../src/v2/artifacts.ts'
import { commitment, generateSecret, label, NATIVE, noteAddressHash, precommitment } from '../src/v2/crypto.ts'
import { fromSolidityProof, prove, solidityProof, verifyProof } from '../src/v2/prover.ts'

type Recorded = { circuit: string; pA: string[]; pB: string[][]; pC: string[]; pubSignals: string[] }
const v = JSON.parse(readFileSync(new URL('v2-vectors.json', import.meta.url), 'utf8')) as {
  proofs: Record<string, Recorded>
}
const n = (s: string) => BigInt(s)
const ready = (c: string) => have(c, 'zkey') && have(c, 'wasm') && have(c, 'vkey')

// The artifacts are ~25 MB, so they are not in the repo: `setup` fetches them.
const downloaded = ['deposit', 'ragequit', 'transact_1x2'].filter((c) => have(c, 'vkey'))
const skip = downloaded.length === 0 && { skip: 'run `moneysurfer v2 setup` first' }

test('the manifest pins what the gateways served', { ...skip }, () => {
  for (const c of ['deposit', 'ragequit', 'transact_1x1']) {
    for (const kind of ['wasm', 'zkey', 'vkey'] as const) {
      if (!have(c, kind)) continue
      // load() re-hashes and throws unless it matches; reaching here is the assertion.
      assert.ok(load(c, kind).length > 0, `${c}.${kind}`)
      assert.match(pinned(c, kind), /^[0-9a-f]{64}$/)
    }
  }
})

test("the ceremony's keys verify the chain's own proofs", { ...skip }, () => {
  for (const name of downloaded) {
    const r = v.proofs[name]!
    const proof = fromSolidityProof(
      r.pA.map(n),
      r.pB.map((x) => x.map(n)),
      r.pC.map(n),
      r.pubSignals.map(n),
    )
    assert.equal(verificationKey(name).nPublic, r.pubSignals.length, `${name} nPublic`)
    assert.ok(verifyProof(name, proof), `${name} does not verify`)
    // the same signals in another order must not
    const shuffled = { ...proof, publicSignals: [...proof.publicSignals].reverse() }
    assert.ok(!verifyProof(name, shuffled), `${name} verifies with the signals reversed`)
  }
})

test('solidityProof round-trips a proof off the chain', { ...skip }, () => {
  const r = v.proofs.deposit!
  const proof = fromSolidityProof(
    r.pA.map(n),
    r.pB.map((x) => x.map(n)),
    r.pC.map(n),
    r.pubSignals.map(n),
  )
  const s = solidityProof(proof)
  assert.deepEqual(s.pA, r.pA.map(n))
  assert.deepEqual(
    s.pB,
    r.pB.map((x) => x.map(n)),
  )
  assert.deepEqual(s.pC, r.pC.map(n))
})

test('a deposit proof we build verifies, and its commitment is our own', {
  ...(ready('deposit') ? {} : { skip: 'run `moneysurfer v2 setup deposit` first' }),
}, async () => {
  const value = 10n ** 16n
  const noteSecret = generateSecret()
  const depositSecret = generateSecret()
  const ah = noteAddressHash('0x1111111111111111111111111111111111111111', noteSecret)
  const pre = precommitment(ah, NATIVE, value)
  const context = generateSecret()
  const proof = await prove('deposit', {
    depositSecret,
    noteAddressHash: ah,
    tokenId: BigInt(NATIVE),
    value,
    context,
  })
  assert.deepEqual(proof.publicSignals, [commitment(pre, label(pre, depositSecret)), BigInt(NATIVE), value, context])
  assert.ok(verifyProof('deposit', proof))
})
