// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ASSETS_ROOT, CHAINS, chainName, HOME_ROOT, ROOT, rpcOverrideUrl, UsageError } from '../shared/config.ts'

// The chain table, Safe service, wallet port and --rpc-url state are shared
// with V2; they are re-exported so this protocol's modules keep importing
// everything from one place.
export {
  chainName,
  customRpc,
  FRAME_RPC,
  LOG_CHUNK,
  parseChain,
  ROOT,
  SAFE_TX_SERVICE,
  safePrefix,
  setRpcUrl,
  UsageError,
} from '../shared/config.ts'

/** V1 keeps the artifact and state directories it always had. */
export const ASSETS = ASSETS_ROOT
export const HOME = HOME_ROOT

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

/** --rpc-url if given, else the chain's default. */
export function rpcUrl(chain: number): string {
  const override = rpcOverrideUrl()
  if (override !== undefined) return override
  const url = CHAINS[chain]?.rpc
  if (!url) throw new UsageError(`no default RPC for ${chainName(chain)} -- pass --rpc-url`)
  return url
}

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
  /** what commands call it: the token's symbol, lowercased */
  key: string
  symbol: string
  decimals: number
  /** 0xEeee...EEeE for the native coin */
  asset: string
  address: string
  /** where the Entrypoint registered it -- the pool has no events before */
  deployedBlock: number
  entrypoint: string
  /** taken off the Entrypoint: it takes no deposits and relays nothing, but its notes can still be ragequit */
  removed: boolean
}

export const NATIVE = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'

/** A chain's Entrypoint: its pools are whatever it has registered (chain.ts `pools`). */
export type Entrypoint = {
  chainId: number
  address: string
  deployedBlock: number
  /** the chain's coin, which names its native-asset pool */
  native: string
  relayers: string[]
}

/** chain id -> its Entrypoint and relayers. MONEYSURFER_ENTRYPOINTS points it elsewhere, e.g. a fork. */
function registry(): Record<string, Omit<Entrypoint, 'chainId'>> {
  return JSON.parse(readFileSync(process.env.MONEYSURFER_ENTRYPOINTS ?? join(ROOT, 'src/v1/entrypoints.json'), 'utf8'))
}

export const registryChains = () => Object.keys(registry()).map(Number)

export function entrypoint(chainId: number): Entrypoint {
  const e = registry()[chainId]
  if (!e) {
    const known = registryChains()
      .map((id) => `${chainName(id)} (${id})`)
      .join(', ')
    throw new UsageError(`no Privacy Pools on ${chainName(chainId)} -- supported: ${known}`)
  }
  return { ...e, chainId }
}
