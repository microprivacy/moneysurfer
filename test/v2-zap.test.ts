// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The wrapping path: the slippage bound, the router's calldata and its errors.
 * The numbers here are off real mainnet transactions, so a change in how the
 * bound is computed or how the call is encoded fails loudly.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { bytesToHex } from '@noble/hashes/utils.js'
import { type Asset, pickAsset } from '../src/v2/chain.ts'
import { payoutRouting } from '../src/v2/crypto.ts'
import { explainRouterRevert, HEADROOM_PPM, ROUTER, ROUTER_ERRORS, withHeadroom } from '../src/v2/zap.ts'

const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
const PP_USDC = '0xC246aFb23482fF9596E9cee5f1f678eFe0EB1ad6'

test("the slippage bound is the SDK's, to the unit", () => {
  // From deposit 0x49a5b063dbeb164a68ae6bea11b2640783b255e623c80168dc380aaf68732215:
  // router.quote(...) at the block before inclusion returned 91831035, and the
  // calldata's maxUnderlyingIn was 91831127. One part per million, rounded up.
  assert.equal(withHeadroom(91_831_035n), 91_831_127n)
  assert.equal(HEADROOM_PPM, 1n)
  // Never zero slack, however small the amount: a bound equal to the quote
  // would revert on the first wei of index accrual.
  assert.equal(withHeadroom(1n), 2n)
  assert.equal(withHeadroom(0n), 1n)
  // --max-fee-percent widens it; 1% is 10_000 ppm.
  assert.equal(withHeadroom(10_000_000n, 10_000n), 10_100_000n)
})

test('depositExactShares encodes the selector the router dispatches on', () => {
  const proof = {
    pA: [1n, 2n] as [bigint, bigint],
    pB: [
      [3n, 4n],
      [5n, 6n],
    ] as [[bigint, bigint], [bigint, bigint]],
    pC: [7n, 8n] as [bigint, bigint],
    pubSignals: [9n, BigInt(PP_USDC), 10n, 11n] as never,
  }
  const args = { proof, noteData: { hint: new Uint8Array(32), ciphertext: new Uint8Array(0) } }
  const withCap = ROUTER.depositExactShares.encodeInput({
    ...args,
    aspCiphertext: new Uint8Array(0),
    maxUnderlyingIn: 12n,
  })
  const native = ROUTER.depositExactSharesNative.encodeInput({ ...args, aspCiphertext: new Uint8Array(0) })
  assert.equal(bytesToHex(withCap.slice(0, 4)), 'c63148e8')
  assert.equal(bytesToHex(native.slice(0, 4)), '31c09bb4')
  // The proof's twelve words sit inline right after the selector, so the
  // tokenId and value a reader checks are at fixed offsets.
  const word = (b: Uint8Array, i: number) => bytesToHex(b.slice(4 + i * 32, 4 + (i + 1) * 32))
  assert.equal(BigInt(`0x${word(withCap, 9)}`), BigInt(PP_USDC))
  assert.equal(BigInt(`0x${word(withCap, 10)}`), 10n)
})

test('PPRouter_SlippageExceeded carries two arguments, and says what they were', () => {
  // The zero-argument spelling hashes to 0x7d1389bb, which appears nowhere in
  // either router's bytecode. The real one is 0x46314e2c.
  assert.equal(ROUTER_ERRORS['0x7d1389bb'], undefined)
  const data = `0x46314e2c${92n.toString(16).padStart(64, '0')}${91n.toString(16).padStart(64, '0')}`
  const why = explainRouterRevert(data, 'USDC')!
  assert.match(why, /92 of USDC/)
  assert.match(why, /capped at 91/)
  assert.match(why, /nothing was spent/)
})

test('a stranded-shares revert is named, not swallowed', () => {
  assert.match(explainRouterRevert('0xf58dc788', 'USDC')!, /SharesStranded/)
  assert.match(explainRouterRevert('0x934a31a9', 'USDC')!, /PPRouter_ZeroValue/)
  // Something the routers never emit is left to the caller's own wording.
  assert.equal(explainRouterRevert('0xdeadbeef', 'USDC'), undefined)
  assert.equal(explainRouterRevert(undefined, 'USDC'), undefined)
})

test('payoutRouting is the four words a real transact carried', () => {
  // From transact 0xcde60af19e6bef3781d1d9dc4a6a6974cf0720629dd79b80bbeb6eecd9c87468:
  // recipient, feeRecipient, then an ABSOLUTE fee -- not V1's basis points --
  // and nativeGas, which this client always leaves at zero.
  const data = payoutRouting({
    recipient: '0x98addcc75931795eb66c52ca954541c18535e3c0',
    feeRecipient: '0x9e2f1b234953f46c6091636290e9035618ea3c07',
    feeAmount: 0x011f70b28e4f5258n,
    nativeGas: 0n,
  })
  assert.equal(
    bytesToHex(data),
    '00000000000000000000000098addcc75931795eb66c52ca954541c18535e3c0' +
      '0000000000000000000000009e2f1b234953f46c6091636290e9035618ea3c07' +
      '000000000000000000000000000000000000000000000000011f70b28e4f5258' +
      '0000000000000000000000000000000000000000000000000000000000000000',
  )
})

// ---------------------------------------------------------------------------
const asset = (o: Partial<Asset> & Pick<Asset, 'key' | 'tokenId' | 'enabled'>): Asset => ({
  symbol: o.key.toUpperCase(),
  decimals: 18,
  minAmount: 0n,
  vettingFeeBPS: 0n,
  maxRelayFee: 0n,
  ...o,
})

const PRODUCTION: Asset[] = [
  asset({ key: 'eth', tokenId: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', enabled: true }),
  asset({
    key: 'ppusdc',
    symbol: 'ppUSDC',
    tokenId: PP_USDC,
    enabled: true,
    router: { address: '0xe76E', underlying: USDC, underlyingSymbol: 'USDC', decimals: 6, native: false },
  }),
  // plain USDC is configured, but disabled -- it is the trap pickAsset avoids
  asset({ key: 'usdc', symbol: 'USDC', tokenId: USDC, decimals: 6, enabled: false }),
]

test('usdc names the route that works, not the disabled entry of the same name', () => {
  const hit = pickAsset(PRODUCTION, 'usdc')
  assert.equal(hit.key, 'ppusdc')
  assert.equal(hit.tokenId, PP_USDC)
  assert.equal(hit.enabled, true)
  // and the canonical key still resolves to the same asset
  assert.equal(pickAsset(PRODUCTION, 'ppusdc').tokenId, PP_USDC)
  // keys are matched case-insensitively, as V1 matches its pool keys
  assert.equal(pickAsset(PRODUCTION, 'USDC').tokenId, PP_USDC)
})

test('an enabled asset of that name wins over a wrapping route', () => {
  // If the Entrypoint ever re-enables plain USDC, `usdc` must mean plain USDC
  // again -- the route is a fallback, not an override.
  const reenabled = PRODUCTION.map((a) => (a.key === 'usdc' ? { ...a, enabled: true } : a))
  assert.equal(pickAsset(reenabled, 'usdc').tokenId, USDC)
})

test('an asset nobody configured is refused with the list of ones that are', () => {
  assert.throws(() => pickAsset(PRODUCTION, 'dai'), /no asset 'dai' -- eth, ppusdc/)
})
