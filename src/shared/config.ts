// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * What both protocols agree on: which chains exist, where a Safe proposal
 * goes, where a wallet listens, and whether the operator named their own RPC.
 *
 * Anything a protocol decides for itself -- its contracts, its assets, its
 * artifacts, where its cache lives -- stays in that protocol's own config.
 */
import { homedir } from 'node:os'
import { join } from 'node:path'

/** A mistake in how the command was invoked -- printed without a stack trace. */
export class UsageError extends Error {}

/**
 * Where circuit artifacts and per-protocol state live. Each protocol takes a
 * subdirectory of its own where it needs one, so V1's and V2's caches and
 * seeds never meet.
 *
 * Artifacts sit beside the notes rather than in the checkout: installed from a
 * registry, the checkout is somebody's global node_modules -- often unwritable,
 * and emptied by the next upgrade.
 */
export const HOME_ROOT = process.env.MONEYSURFER_HOME ?? join(homedir(), '.local/share/moneysurfer')
export const ASSETS_ROOT = process.env.MONEYSURFER_ASSETS ?? join(HOME_ROOT, 'assets')

/**
 * Supported chains, each with the public RPC used unless --rpc-url is given:
 * ones that serve logs over wide block ranges without a key. `safe` is the
 * chain's EIP-3770 short name, which the Safe Transaction Service and app
 * address it by. V1 is on the first three; BNB Chain is V2's alone.
 *
 * BNB Chain has no `rpc`: none of its keyless RPCs serves eth_getLogs over
 * the blocks a sync reads. bsc-dataseed answers calls but not logs at all,
 * publicnode wants a token for anything old, the rest cap a range at 50-250
 * blocks, and NodeReal's chainlist key shares one quota with everyone using it.
 */
export const CHAINS: Record<number, { name: string; rpc?: string; safe: string }> = {
  1: { name: 'Ethereum', rpc: 'https://mainnet.gateway.tenderly.co', safe: 'eth' },
  10: { name: 'Optimism', rpc: 'https://optimism.gateway.tenderly.co', safe: 'oeth' },
  56: { name: 'BNB', safe: 'bnb' },
  42161: { name: 'Arbitrum', rpc: 'https://arbitrum.gateway.tenderly.co', safe: 'arb1' },
}

export const chainName = (id: number) => CHAINS[id]?.name ?? `chain ${id}`

/** The chain's EIP-3770 short name, for the Safe Transaction Service and app. */
export function safePrefix(chainId: number): string {
  const prefix = CHAINS[chainId]?.safe
  if (!prefix) throw new UsageError(`no Safe Transaction Service known for ${chainName(chainId)}`)
  return prefix
}

/** Where Safe proposals go; MONEYSURFER_SAFE_TX_SERVICE points at a self-hosted service. */
export const SAFE_TX_SERVICE = process.env.MONEYSURFER_SAFE_TX_SERVICE ?? 'https://api.safe.global/tx-service'

/** Frame's local JSON-RPC: the signer when neither a key nor --rpc-url is given. */
export const FRAME_RPC = 'http://127.0.0.1:1248'

/** A --chain value: a name (ethereum, optimism, bnb, arbitrum) or a chain id. */
export function parseChain(v: string): number {
  if (/^\d+$/.test(v)) return Number(v)
  const hit = Object.entries(CHAINS).find(([, c]) => c.name.toLowerCase() === v.toLowerCase())
  if (!hit) {
    const names = Object.values(CHAINS)
      .map((c) => c.name.toLowerCase())
      .join(', ')
    throw new UsageError(`unknown chain '${v}' -- ${names}, or a chain id`)
  }
  return Number(hit[0])
}

let rpcOverride: string | undefined

export function setRpcUrl(url: string | undefined): void {
  rpcOverride = url
}

/** Whether --rpc-url was given: if it was, it may be a wallet, and signer.ts asks it to sign. */
export const customRpc = () => rpcOverride !== undefined

/** --rpc-url, or undefined for the protocol's own default. */
export const rpcOverrideUrl = () => rpcOverride

/** The first eth_getLogs block range; a sync resizes it by what comes back. */
export const LOG_CHUNK = Number(process.env.MONEYSURFER_CHUNK ?? 50_000)
