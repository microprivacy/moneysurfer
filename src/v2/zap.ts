// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Depositing an asset the Entrypoint will not take.
 *
 * On production, plain USDC and USDT are **disabled** (`Entrypoint.assets()`
 * says so). What is enabled is the yield vaults' share tokens -- ppUSDC,
 * ppUSDT, ppETH -- and the way USDC reaches the pool is through a **PPRouter**,
 * one per asset, which in a single call:
 *
 *   1. quotes how much underlying `total = value + vettingFee` shares cost,
 *   2. pulls that underlying, supplies it to Aave and mints *exactly* `total`
 *      shares of the vault through its PPYieldTokenZap,
 *   3. approves the Entrypoint for them, and
 *   4. calls `Entrypoint.deposit(proof, noteData, aspCiphertext)` with the
 *      three arguments **byte-for-byte unchanged**.
 *
 * That last point is the whole trick and the reason this works at all: the
 * proof's `context` is `keccak256(abi.encode(noteData))`, and the router never
 * touches `noteData`, so a proof built for a plain `Entrypoint.deposit` stays
 * valid when the router makes the call instead. The proof is therefore built
 * against `tokenId = ppUSDC` and `value = shares`, exactly as if the depositor
 * already held the shares -- because by the time the Entrypoint sees it, the
 * router does.
 *
 * `depositExactShares` is **not** on the Entrypoint. The Entrypoint
 * implementation has eleven functions and this is not one of them; the call
 * goes to the router. See FINDINGS.md.
 *
 * Everything here was read off the deployed bytecode and confirmed against
 * real mainnet calldata; the error set comes from the routers' own PUSH32
 * constants.
 */
import { createContract } from 'micro-eth-signer/abi.js'
import type { RpcClient } from 'micro-eth-signer/net.js'
import { read } from '../shared/rpc.ts'
import { UsageError } from './config.ts'

const u256 = <N extends string>(name: N) => ({ name, type: 'uint256' }) as const

/** ProofLib's Groth16 struct as the deposit circuit sizes it. */
const DEPOSIT_PROOF = {
  name: 'proof',
  type: 'tuple',
  components: [
    { name: 'pA', type: 'uint256[2]' },
    { name: 'pB', type: 'uint256[2][2]' },
    { name: 'pC', type: 'uint256[2]' },
    { name: 'pubSignals', type: 'uint256[4]' },
  ],
} as const

const NOTE_DATA = {
  name: 'noteData',
  type: 'tuple',
  components: [
    { name: 'hint', type: 'bytes32' },
    { name: 'ciphertext', type: 'bytes' },
  ],
} as const

export const ROUTER_ABI = [
  {
    // 0xc63148e8 -- on every router
    type: 'function',
    name: 'depositExactShares',
    stateMutability: 'nonpayable',
    inputs: [DEPOSIT_PROOF, NOTE_DATA, { name: 'aspCiphertext', type: 'bytes' }, u256('maxUnderlyingIn')],
    // what it actually spent, at or under the cap -- confirmed by simulating a
    // whole deposit against the live router with only the allowance overridden
    outputs: [u256('underlyingIn')],
  },
  {
    // 0x31c09bb4 -- only on the ETH router, where msg.value *is* the bound
    type: 'function',
    name: 'depositExactSharesNative',
    stateMutability: 'payable',
    inputs: [DEPOSIT_PROOF, NOTE_DATA, { name: 'aspCiphertext', type: 'bytes' }],
    outputs: [u256('underlyingIn')],
  },
  {
    // 0xed1bd76c -- `total` is value + the Entrypoint's vetting fee, in shares;
    // `underlyingNeeded` is what minting that many costs right now
    type: 'function',
    name: 'quote',
    stateMutability: 'view',
    inputs: [u256('value')],
    outputs: [u256('underlyingNeeded'), u256('total')],
  },
  {
    type: 'function',
    name: 'quoteWithdraw',
    stateMutability: 'view',
    inputs: [u256('shares')],
    outputs: [u256('underlyingOut')],
  },
  { type: 'function', name: 'VAULT', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'address' }] },
  {
    type: 'function',
    name: 'UNDERLYING',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'ENTRYPOINT',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
  },
] as const

export const ROUTER = createContract(ROUTER_ABI)

/**
 * The vault's ERC-4626 side, used only to go the direction `quote` cannot:
 * from an amount of underlying to the shares it buys. `quote` then says what
 * those shares really cost, and that is the number the bound is built on.
 */
export const VAULT = createContract([
  {
    type: 'function',
    name: 'previewDeposit',
    stateMutability: 'view',
    inputs: [u256('assets')],
    outputs: [u256('shares')],
  },
  {
    type: 'function',
    name: 'convertToAssets',
    stateMutability: 'view',
    inputs: [u256('shares')],
    outputs: [u256('assets')],
  },
] as const)

/**
 * How much room over the quote the SDK leaves: one part per million, at least
 * one unit. It is small because the only thing that moves between quoting and
 * mining is Aave's liquidity index, which accrues by a few parts per billion a
 * block -- and a bound that is too generous is real money an adversarial
 * sequencer could take.
 */
export const HEADROOM_PPM = 1n

export const withHeadroom = (underlyingNeeded: bigint, ppm = HEADROOM_PPM): bigint => {
  const slack = (underlyingNeeded * ppm + 999_999n) / 1_000_000n
  return underlyingNeeded + (slack > 0n ? slack : 1n)
}

export type Quote = {
  /** the shares that land in the pool */
  value: bigint
  /** value plus the Entrypoint's vetting fee -- what the zap actually mints */
  total: bigint
  /** what minting `total` costs at this block */
  underlyingNeeded: bigint
  /** the most the router may spend, `underlyingNeeded` plus headroom */
  maxUnderlyingIn: bigint
}

/** What `value` shares will cost, and the bound to put on it. */
export async function quote(net: RpcClient, router: string, value: bigint, ppm?: bigint): Promise<Quote> {
  const q = await read(net, router, ROUTER.quote, value)
  return {
    value,
    total: q.total,
    underlyingNeeded: q.underlyingNeeded,
    maxUnderlyingIn: withHeadroom(q.underlyingNeeded, ppm),
  }
}

/** The shares an amount of underlying buys, which is the direction `quote` does not go. */
export const sharesFor = (net: RpcClient, vault: string, underlying: bigint): Promise<bigint> =>
  read(net, vault, VAULT.previewDeposit, underlying)

/**
 * The routers' own errors, by selector. The app decodes two of these; the rest
 * are here because a revert nobody can read is a bug report nobody can act on.
 * Every selector was taken from the deployed bytecode, not guessed -- note
 * that `PPRouter_SlippageExceeded` carries two arguments, so the zero-argument
 * spelling of it hashes to something that appears nowhere.
 */
export const ROUTER_ERRORS: Record<string, string> = {
  '0x46314e2c': 'PPRouter_SlippageExceeded(uint256 underlyingIn, uint256 maxUnderlyingIn)',
  '0xf58dc788': 'PPRouter_SharesStranded()',
  '0x443b96b8': 'PPRouter_SharesNotReceived()',
  '0x934a31a9': 'PPRouter_ZeroValue()',
  '0x120637b6': 'PPRouter_BelowMinUnderlying(uint256,uint256)',
  '0x09a64c28': 'PPRouter_FeeExceedsWithdrawal()',
  '0x31bae423': 'PPRouter_FeeExceedsMax()',
  '0x24b7e50c': 'PPRouter_NativeGasMismatch()',
  '0x6d2aa205': 'PPRouter_ZeroRecipient()',
  '0x5fa02c03': 'PPRouter_InvalidProcessor()',
  '0x79aaee89': 'PPRouter_ZeroWithdrawal()',
  '0x3d8c2936': 'PPRouter_AssetMismatch(address)',
  '0x4344a77b': 'PPRouter_DirectEthTransfer()',
  '0x093c7b6e': 'PPRouter_NotNativeMode()',
  '0x11297127': 'ProofLib_TokenIdNotCanonical(uint256)',
  '0x3ee5aeb5': 'ReentrancyGuardReentrantCall()',
  '0x5274afe7': 'SafeERC20FailedOperation(address)',
  '0xd6bda275': 'FailedCall()',
  '0x2c2f6301': 'PPYieldTokenZap_SlippageExceeded(uint256,uint256)',
  '0xb95dfddb': 'PPYieldTokenZap_InsufficientWrap(uint256,uint256)',
  '0x8abc2ca5': 'PPYieldTokenZap_ZeroAmount()',
}

const word = (data: string, i: number) => BigInt(`0x${data.slice(10 + i * 64, 10 + (i + 1) * 64)}` || '0x0')

/**
 * Turn a revert from the router into something worth reading. The two that
 * actually happen get a sentence of their own; the rest at least get a name.
 */
export function explainRouterRevert(data: string | undefined, underlyingSymbol: string): string | undefined {
  if (typeof data !== 'string' || data.length < 10) return undefined
  const selector = data.slice(0, 10).toLowerCase()
  const name = ROUTER_ERRORS[selector]
  if (!name) return undefined
  if (selector === '0x46314e2c') {
    const [needed, cap] = [word(data, 0), word(data, 1)]
    return (
      `the router would have spent ${needed} of ${underlyingSymbol} (base units) but was capped at ${cap}: ` +
      'the share price moved between the quote and the call. Raise --max-fee-percent, or try again -- ' +
      'nothing was spent'
    )
  }
  if (selector === '0xf58dc788') {
    return (
      'PPRouter_SharesStranded: the router minted the shares but the Entrypoint did not take them, ' +
      'so it refused to strand them. The deposit did not happen; check that the asset is still ' +
      'enabled and that the proof is for this exact value'
    )
  }
  return name
}

/** A router this client knows how to drive, checked against the chain before it is used. */
export async function assertRouter(net: RpcClient, router: string, vault: string, entrypoint: string): Promise<void> {
  const [gotVault, gotEntrypoint] = await Promise.all([
    read(net, router, ROUTER.VAULT),
    read(net, router, ROUTER.ENTRYPOINT),
  ])
  if (gotVault.toLowerCase() !== vault.toLowerCase()) {
    throw new UsageError(`router ${router} wraps into ${gotVault}, not ${vault} -- refusing to use it`)
  }
  if (gotEntrypoint.toLowerCase() !== entrypoint.toLowerCase()) {
    throw new UsageError(`router ${router} deposits into ${gotEntrypoint}, not ${entrypoint} -- refusing to use it`)
  }
}
