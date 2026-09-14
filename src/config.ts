// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

/** A mistake in how the command was invoked -- printed without a stack trace. */
export class UsageError extends Error {}

export const ROOT = fileURLToPath(new URL('..', import.meta.url))
export const ASSETS = process.env.MONEYSURFER_ASSETS ?? join(ROOT, 'assets')
export const HOME = process.env.MONEYSURFER_HOME ?? join(homedir(), '.local/share/moneysurfer')

/**
 * The circuits' wasm and the trusted-setup keys, as privacypools.com serves
 * them, pinned by the sha256 0xbow's SDK pins
 * (privacy-pools-core packages/sdk/src/circuits/artifactHashes.ts).
 */
export const ARTIFACT_URL = 'https://privacypools.com/artifacts'
export const ARTIFACTS: Record<string, string> = {
  'withdraw.wasm': '36cda22791def3d520a55c0fc808369cd5849532a75fab65686e666ed3d55c10',
  'withdraw.zkey': '2a893b42174c813566e5c40c715a8b90cd49fc4ecf384e3a6024158c3d6de677',
  'commitment.wasm': '254d2130607182fd6fd1aee67971526b13cfe178c88e360da96dce92663828d8',
  'commitment.zkey': '494ae92d64098fda2a5649690ddc5821fcd7449ca5fe8ef99ee7447544d7e1f3',
}

/**
 * Supported chains, each with the public RPC used unless --rpc-url is given:
 * ones that serve logs over wide block ranges without a key.
 */
const CHAINS: Record<number, { name: string; rpc: string }> = {
  1: { name: 'Ethereum', rpc: 'https://mainnet.gateway.tenderly.co' },
  10: { name: 'Optimism', rpc: 'https://optimism.gateway.tenderly.co' },
  42161: { name: 'Arbitrum', rpc: 'https://arbitrum.gateway.tenderly.co' },
}

export const chainName = (id: number) => CHAINS[id]?.name ?? `chain ${id}`

/** Frame's local JSON-RPC: the signer when neither a key nor --rpc-url is given. */
export const FRAME_RPC = 'http://127.0.0.1:1248'

/** A --chain value: a name (ethereum, optimism, arbitrum) or a chain id. */
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

export const customRpc = () => rpcOverride !== undefined

/** --rpc-url if given, else the chain's default. */
export function rpcUrl(chain: number): string {
  if (rpcOverride !== undefined) return rpcOverride
  const url = CHAINS[chain]?.rpc
  if (!url) throw new UsageError(`no default RPC for ${chainName(chain)} -- pass --rpc-url`)
  return url
}

/**
 * The first eth_getLogs block range; sync resizes it by what comes back.
 */
export const LOG_CHUNK = Number(process.env.MONEYSURFER_CHUNK ?? 50_000)

/**
 * Gateways for the IPFS copy of the ASP's tree. Any of them may lie: the tree
 * is only used once its root equals the one on-chain.
 */
export const IPFS_GATEWAYS = [
  'https://gateway.pinata.cloud',
  'https://dweb.link',
  'https://ipfs.io',
  'https://w3s.link',
]

/** The ASP's own API, used only if no gateway serves the tree. Its answer is checked the same way. */
export const ASP_API = 'https://api.0xbow.io'

export type Pool = {
  chainId: number
  key: string
  symbol: string
  decimals: number
  /** 0xEeee...EEeE for the native coin */
  asset: string
  address: string
  deployedBlock: number
  entrypoint: string
}

export const NATIVE = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'

type ChainEntry = {
  entrypoint: string
  relayers: string[]
  pools: Record<string, Omit<Pool, 'chainId' | 'key' | 'entrypoint'>>
}

/** chain id -> the Entrypoint, its relayers and its pools. MONEYSURFER_POOLS points it elsewhere, e.g. a fork. */
function registry(): Record<string, ChainEntry> {
  return JSON.parse(readFileSync(process.env.MONEYSURFER_POOLS ?? join(ROOT, 'src/pools.json'), 'utf8'))
}

export const registryChains = () => Object.keys(registry()).map(Number)

function chainEntry(chainId: number): ChainEntry {
  const c = registry()[chainId]
  if (!c) {
    const known = registryChains()
      .map((id) => `${chainName(id)} (${id})`)
      .join(', ')
    throw new UsageError(`no pools on ${chainName(chainId)} -- supported: ${known}`)
  }
  return c
}

export function pools(chainId: number): Pool[] {
  const c = chainEntry(chainId)
  return Object.entries(c.pools).map(([key, p]) => ({ ...p, key, chainId, entrypoint: c.entrypoint }))
}

export function pool(chainId: number, key: string): Pool {
  const p = pools(chainId).find((x) => x.key === key.toLowerCase())
  if (!p) throw new UsageError(`no pool '${key}' on ${chainName(chainId)} (see: moneysurfer pools)`)
  return p
}

export const relayersFor = (chainId: number) => chainEntry(chainId).relayers
