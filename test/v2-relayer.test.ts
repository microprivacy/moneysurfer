// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The relayer client, against replies shaped like 0xbow's production relayer.
 * Nothing here talks to it: `fetch` is replaced, and the one recorded reply is
 * a real committed quote for a withdrawal to 0x...dEaD on mainnet.
 */
import assert from 'node:assert/strict'
import { afterEach, test } from 'node:test'
import { bytesToHex } from '@noble/hashes/utils.js'
import { RELAY_ADDR } from '../src/v2/config.ts'
import { decodePayoutRouting, payoutRouting } from '../src/v2/crypto.ts'
import type { Proof } from '../src/v2/prover.ts'
import { quote, quoteGross, RELAY, wireProof } from '../src/v2/relayer.ts'

const NATIVE = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'
const DEAD = '0x000000000000000000000000000000000000dEaD'
const FEE_RECIPIENT = '0xfdece433a742f4c1b7020ad1731ffe24a47d9a2a'
const BASE = 'https://relayer.test'

/** POST /v1/quote/evm/1/receive for 0.01 ETH to 0x...dEaD, as the production relayer answered it. */
const RECORDED = {
  feeAmount: '163132541271000',
  gasPrice: '155364325',
  txCost: '1050000',
  processor: '0x01a8Fa4dbb60187aD8d3c3d08E7Fb8C14198A461',
  amountSent: '10163132541271000',
  amountReceived: '10000000000000000',
  feeCommitment: {
    feeAmount: '163132541271000',
    asset: NATIVE,
    recipient: DEAD,
    amountSent: '10163132541271000',
    amountReceived: '10000000000000000',
    data: '0x000000000000000000000000000000000000000000000000000000000000dead000000000000000000000000fdece433a742f4c1b7020ad1731ffe24a47d9a2a0000000000000000000000000000000000000000000000000000945e412c7bd80000000000000000000000000000000000000000000000000000000000000000',
    expiration: 1795088683564,
    signedRelayerCommitment:
      '0x44f1ea0f97bfa8a70b56e8760ffc6fbfad2542826f4f32e50f601caccb9e9f7d7c0d55ed213856bdcc769b3b77b7facb84ffb7fc93b099c48a351f95d970d93a1c',
  },
}

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})

/** Answer every request with `reply(body)`, and keep what was asked. */
function serve(reply: (body: Record<string, string>) => unknown) {
  const asked: Record<string, string>[] = []
  globalThis.fetch = (async (_url: string, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body ?? '{}'))
    asked.push(body)
    return new Response(JSON.stringify(reply(body)), { status: 201 })
  }) as typeof fetch
  return asked
}

/** A quote an honest relayer charging `fee(amount)` would give. */
function honest(fee: (amount: bigint) => bigint, o: { processor?: string; routing?: object } = {}) {
  return (b: Record<string, string>) => {
    const amount = BigInt(b.amount!)
    const f = fee(amount)
    const data = payoutRouting({
      recipient: b.recipient!,
      feeRecipient: FEE_RECIPIENT,
      feeAmount: f,
      nativeGas: 0n,
      ...o.routing,
    })
    const c = {
      feeAmount: String(f),
      asset: b.asset,
      recipient: b.recipient,
      amountSent: String(amount + f),
      amountReceived: String(amount),
      data: `0x${bytesToHex(data)}`,
      expiration: Date.now() + 60_000,
      signedRelayerCommitment: '0x01',
    }
    return { feeAmount: c.feeAmount, amountSent: c.amountSent, processor: o.processor ?? RELAY_ADDR, feeCommitment: c }
  }
}

test("the relay's selector is the one in PrivacyPoolRelay's bytecode", () => {
  const data = RELAY.relay.encodeInput({
    proof: {
      pA: [0n, 0n],
      pB: [
        [0n, 0n],
        [0n, 0n],
      ],
      pC: [0n, 0n],
      pubSignals: [],
    },
    transactParams: { processooor: RELAY_ADDR, data: new Uint8Array() },
    notes: [],
  })
  assert.equal(bytesToHex(data.slice(0, 4)), 'ace97342')
})

test('a recorded production quote reads back as the routing it signed', async () => {
  const asked = serve(() => RECORDED)
  const q = await quote(BASE, NATIVE, DEAD, 10_000_000_000_000_000n)
  assert.deepEqual(asked[0], {
    asset: NATIVE,
    commit: true,
    recipient: DEAD,
    extraGas: false,
    amount: '10000000000000000',
  })
  assert.equal(q.feeAmount, 163_132_541_271_000n)
  assert.equal(q.amountSent, 10_163_132_541_271_000n)
  assert.equal(q.routing.recipient.toLowerCase(), DEAD.toLowerCase())
  assert.equal(q.routing.feeRecipient, FEE_RECIPIENT)
  assert.equal(q.routing.nativeGas, 0n)
  // the routing round-trips: what is proven is exactly what the relayer signed
  assert.equal(bytesToHex(payoutRouting(decodePayoutRouting(q.data))), RECORDED.feeCommitment.data.slice(2))
  // handed back as the SDK hands it back, with extraGas made explicit
  assert.equal(q.commitment.signedRelayerCommitment, RECORDED.feeCommitment.signedRelayerCommitment)
  assert.equal(q.commitment.extraGas, false)
})

test('a quote that would pay anyone else, or anything else, is refused', async () => {
  const fee = () => 1000n
  serve(honest(fee, { processor: '0x2222222222222222222222222222222222222222' }))
  await assert.rejects(quote(BASE, NATIVE, DEAD, 10_000n), /submits through 0x2222.*not the PrivacyPoolRelay/)
  serve(honest(fee, { routing: { recipient: '0x3333333333333333333333333333333333333333' } }))
  await assert.rejects(quote(BASE, NATIVE, DEAD, 10_000n), /the routing pays 0x3333/)
  serve(honest(fee, { routing: { feeAmount: 5000n } }))
  await assert.rejects(quote(BASE, NATIVE, DEAD, 10_000n), /the routing takes 5000 while the fee quoted is 1000/)
  serve(honest(fee, { routing: { nativeGas: 1n } }))
  await assert.rejects(quote(BASE, NATIVE, DEAD, 10_000n), /native gas/)
})

test('a gross amount is what leaves the note, the fee included', async () => {
  // a fixed part and 10 bps, as BNB Chain's relayer charges
  const asked = serve(honest((amount) => 21_000n + amount / 1000n))
  const gross = 10_000_000n
  const q = await quoteGross(BASE, NATIVE, DEAD, gross)
  assert.ok(q.amountSent <= gross)
  assert.equal(q.amountSent, q.amount + q.feeAmount)
  // the fee shrinks with the net, so a sliver may stay behind -- never more than the bps on the fee
  assert.ok(gross - q.amountSent <= 1000n)
  assert.equal(asked[0]!.amount, String(gross))
})

test('a fee that eats the whole withdrawal is refused rather than quoted', async () => {
  serve(honest(() => 20_000n))
  await assert.rejects(quoteGross(BASE, NATIVE, DEAD, 10_000n), /leaves nothing/)
})

test('the proof goes to the relayer in snarkjs shape, every number hex', () => {
  const p = {
    proof: {
      pi_a: [1n, 2n, 1n],
      pi_b: [
        [3n, 4n],
        [5n, 6n],
        [1n, 0n],
      ],
      pi_c: [7n, 8n, 1n],
    },
    publicSignals: [255n, 0n],
  } as unknown as Proof
  assert.deepEqual(wireProof(p), {
    protocol: 'groth16',
    curve: 'bn128',
    pi_a: ['0x1', '0x2', '0x1'],
    pi_b: [
      ['0x3', '0x4'],
      ['0x5', '0x6'],
      ['0x1', '0x0'],
    ],
    pi_c: ['0x7', '0x8', '0x1'],
    publicSignals: ['0xff', '0x0'],
  })
})
