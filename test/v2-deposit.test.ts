// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The transaction a deposit is. The known answer is the first mainnet deposit:
 * its calldata is in test/v2-vectors.json, and the encoder here has to reproduce
 * it byte for byte from its decoded parts. That settles the argument order, the
 * tuple layout and the `bytes` tails at once -- an ABI guess that is off by a
 * word cannot round-trip.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { Decoder } from 'micro-eth-signer/abi.js'
import { have } from '../src/v2/artifacts.ts'
import { decodeOpening, KEY_BYTES } from '../src/v2/asp.ts'
import { ENTRYPOINT, ENTRYPOINT_ABI } from '../src/v2/chain.ts'
import { NATIVE } from '../src/v2/config.ts'
import { depositContext, generateSecret, noteAddressHash } from '../src/v2/crypto.ts'
import { buildDeposit, msgValue, NO_NOTE } from '../src/v2/deposit.ts'

type Vectors = {
  deposit: {
    to: string
    input: string
    value: string
    msgValue: string
    tokenId: string
    vettingFeeBPS: string
    hint: string
    ciphertext: string
    context: string
  }
}
const v: Vectors = JSON.parse(readFileSync(new URL('v2-vectors.json', import.meta.url), 'utf8'))

const decoded = () => {
  const dec = new Decoder()
  dec.add(v.deposit.to, ENTRYPOINT_ABI)
  const r = dec.decode(v.deposit.to, hexToBytes(v.deposit.input.slice(2)))
  assert.ok(r && !Array.isArray(r), 'the calldata did not decode as one signature')
  assert.equal(r.name, 'deposit')
  return r.value as {
    proof: { pA: bigint[]; pB: bigint[][]; pC: bigint[]; pubSignals: bigint[] }
    noteData: { hint: Uint8Array; ciphertext: Uint8Array }
    aspCiphertext: Uint8Array
  }
}

test('the deposit calldata re-encodes to the bytes the chain saw', () => {
  const parts = decoded()
  assert.equal(`0x${bytesToHex(ENTRYPOINT.deposit.encodeInput(parts))}`, v.deposit.input.toLowerCase())
})

test('the real deposit carried the ASP opening as its third argument', () => {
  const { proof, noteData, aspCiphertext } = decoded()
  // the pool re-derives the context from the note data and the proof commits to it
  assert.equal(depositContext(`0x${bytesToHex(noteData.hint)}`, noteData.ciphertext), BigInt(v.deposit.context))
  assert.equal(proof.pubSignals[2], BigInt(v.deposit.value))
  assert.equal(proof.pubSignals[1], BigInt(v.deposit.tokenId))
  // and the opening obeys the length law for that value, unchanged by anything else
  assert.equal(aspCiphertext.length, 330 + BigInt(v.deposit.value).toString(16).length)
  assert.equal(aspCiphertext.slice(0, KEY_BYTES).length, KEY_BYTES)
})

test('msg.value is the deposit plus the vetting fee, not minus it', () => {
  const value = BigInt(v.deposit.value)
  assert.equal(msgValue(NATIVE, value, BigInt(v.deposit.vettingFeeBPS)), BigInt(v.deposit.msgValue))
  // production charges nothing, and an ERC-20 deposit sends no ether at all
  assert.equal(msgValue(NATIVE, value, 0n), value)
  assert.equal(msgValue('0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', value, 100n), 0n)
})

test('a deposit that tells nobody anything still binds a context', () => {
  // the pool accepts an empty note payload; the context is then a constant, and
  // the one the first mainnet deposit used is not it
  const context = depositContext(NO_NOTE.hint, NO_NOTE.ciphertext)
  assert.ok(context > 0n)
  assert.notEqual(context, BigInt(v.deposit.context))
})

test('a whole deposit: the proof, the opening and the calldata all agree', {
  ...(have('deposit', 'zkey') ? {} : { skip: 'run `moneysurfer2 setup deposit` first' }),
}, async () => {
  const asp = x25519.keygen()
  const owner = '0x1111111111111111111111111111111111111111'
  const noteSecret = generateSecret()
  const depositSecret = generateSecret()
  const value = 10n ** 16n
  const d = await buildDeposit({
    owner,
    noteSecret,
    depositSecret,
    value,
    vettingFeeBPS: 100n,
    aspPublicKey: `0x${bytesToHex(asp.publicKey)}`,
  })
  assert.equal(d.value, value + value / 100n)

  // what the ASP will read is the same note the proof is about
  assert.deepEqual(decodeOpening(d.aspCiphertext, asp.secretKey), {
    noteAddressHash: noteAddressHash(owner, noteSecret),
    tokenId: NATIVE.toLowerCase(),
    value,
    depositSecret,
  })

  // and the calldata carries exactly those bytes in the third argument
  const dec = new Decoder()
  dec.add(d.to, ENTRYPOINT_ABI)
  const r = dec.decode(d.to, d.data)
  assert.ok(r && !Array.isArray(r))
  const parts = r.value as { proof: { pubSignals: bigint[] }; aspCiphertext: Uint8Array }
  assert.deepEqual(parts.aspCiphertext, d.aspCiphertext)
  assert.equal(parts.proof.pubSignals[0], d.commitment)
  assert.equal(parts.proof.pubSignals[2], value)
  assert.equal(parts.proof.pubSignals[3], d.context)
})
