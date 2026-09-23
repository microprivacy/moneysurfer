// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { ASSETS_ROOT, HOME_ROOT, ROOT, rpcOverrideUrl, UsageError } from '../shared/config.ts'

// Chains, the Safe service, the wallet port and --rpc-url are shared with V1.
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

/**
 * V2 keeps its artifacts and its state under a subdirectory of its own: the
 * two protocols' circuits happen not to share a name, but their seeds and
 * event caches are entirely different things and must never be confused.
 */
export const ASSETS = join(ASSETS_ROOT, 'v2')
export const HOME = join(HOME_ROOT, 'v2')

/**
 * The live Privacy Pools V2 deployment on Ethereum mainnet -- the one the app
 * at v2.privacypools.com deposits into, and the only one this client knows.
 *
 * Every role below was read back off the contracts themselves
 * (`pool.keystore()`, `pool.aspRegistry()`, `entrypoint.poolVault()`), not
 * taken from the app bundle. `deployedBlock` is the first block any of the
 * four had code, found by bisecting `eth_getCode`; the ASP's own `fromBlock`
 * is later -- it is the first *deposit* -- and starting there loses the
 * keystore registrations that came before it.
 *
 * An earlier mainnet deployment ("staging", behind `api-dev.0xbow.io`) is
 * still live but is no longer addressable from here. The recorded events it
 * produced survive as fixtures in test/v2-vectors.json, where they still pin
 * the ABI decoding and the public-signal order.
 */
export const CHAIN_ID = 1
export const POOL_ADDR = '0x0Eb42804BF897662aF851370eaeAdcDBEC1b97ed'
export const KEYSTORE_ADDR = '0x6E463391c79b7e1A88eF26E0B023f9A6C9938a71'
export const ASP_REGISTRY = '0x259C0BEa1d783c202509BD3b2688d23b8AEf58B0'
export const ENTRYPOINT_ADDR = '0xca1e072236D231130059eeA6Bfceb7F4e9a1F0C3'
export const ACCESS_ROUTER = '0x40a6bC296D87f71Ab31Ca3Bfb50513441fBD5160'
export const DEPOSIT_VERIFIER = '0x49Ab3f48Ff9fa603EE81E5f28eB4214798E29862'
export const RAGEQUIT_VERIFIER = '0x687059Fc9C2488f333e06aa72CBea7E4b1D05B57'
export const DEPLOYED_BLOCK = 25_884_231

/** The ASP serving this pool; it answers 404 for any other deployment's entrypoint. */
export const ASP_API = 'https://api-v2.0xbow.io'

/** The X25519 key this pool's deposit openings are encrypted to, from `GET /public-key`. */
export const ASP_PUBLIC_KEY = '0x3f651e2321b9b78c3690064b025b610942cbf755e28d44726378cf853cfd8f34'

/**
 * A relayer submits a `transact` for you, so the withdrawal is not linked to
 * an address of yours; it takes its fee out of `amountOut`. V1 kept this list
 * per Entrypoint; here there is one deployment, so one list.
 */
export const RELAYERS = ['https://relayer-v2-prod-149184580131.us-east1.run.app']

/**
 * The ASP's own API: public and unauthenticated, but every request must carry
 * both `chainId` and `entrypoint` -- the host serves several chains' pools and
 * answers for a different one (or 404s) without them.
 */
export const aspApi = () => process.env.MONEYSURFER_ASP ?? ASP_API

/** 0xEeee...EEeE, the asset id ETH carries. */
export const NATIVE = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'

export const isNative = (a: string) => a.toLowerCase() === NATIVE.toLowerCase()

/**
 * A PPRouter: the contract that turns an asset the Entrypoint will not take
 * into one it will. Each wraps exactly one underlying into exactly one yield
 * vault's share token, and `VAULT()`, `UNDERLYING()`, `ZAP()` and
 * `ENTRYPOINT()` on each of these addresses return precisely what is paired
 * with it here -- read off the chain, not the app (see FINDINGS.md).
 *
 * Keyed by the vault (the `tokenId` the PoolVault ends up recording).
 */
export type Router = {
  address: string
  /** what the depositor spends: an ERC-20, or NATIVE where `native` is set */
  underlying: string
  /** the router takes the coin itself and wraps it (ETH -> WETH -> ppETH) */
  native: boolean
}

const PP_ETH = '0x66051920D25af4E3596A8a46309F4D045F9D83B7'
const PP_USDC = '0xC246aFb23482fF9596E9cee5f1f678eFe0EB1ad6'
const PP_USDT = '0xA4cF419558Ef36CC6FfB666195684dC963910426'

export const ROUTERS: Record<string, Router> = {
  [PP_ETH.toLowerCase()]: {
    address: '0x77613D670BB9fD48A9898D0eac8ebf21B566F960',
    underlying: NATIVE,
    native: true,
  },
  [PP_USDC.toLowerCase()]: {
    address: '0xe76E793d776c1e207aD7a7fa7C57d27420d85110',
    underlying: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    native: false,
  },
  [PP_USDT.toLowerCase()]: {
    address: '0x13a0b86bac3e0C29bd64fED7BCD2EE84f371f41C',
    underlying: '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    native: false,
  },
}

export const routerFor = (tokenId: string): Router | undefined => ROUTERS[tokenId.toLowerCase()]

/**
 * Every asset the Entrypoint might have configured. There is no way to
 * enumerate them on chain -- `assets(address)` is a getter, not a list -- so
 * this is the candidate set and `Entrypoint.assets()` is the authority on
 * which of them are actually open. `chain.ts` reads each one's symbol and
 * decimals and derives its command-line key from the symbol.
 */
export const CANDIDATE_TOKENS: string[] = [
  NATIVE,
  PP_ETH,
  PP_USDC,
  PP_USDT,
  '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
  '0xdAC17F958D2ee523a2206206994597C13D831ec7',
]

/** LeanIMT depths the circuits are compiled for; the contracts cap the trees to match. */
export const STATE_DEPTH = 22
export const KEYSTORE_DEPTH = 18
export const ASP_DEPTH = 18

export const DEFAULT_RPC = process.env.MONEYSURFER_RPC ?? 'https://ethereum-rpc.publicnode.com'

/** --rpc-url if given, else the public default. */
export const rpcUrl = () => rpcOverrideUrl() ?? DEFAULT_RPC

/**
 * Gateways for the circuit artifacts. Any of them may lie: an artifact counts
 * only once its sha256 matches the manifest. ipfs.io and dweb.link were
 * rate-limiting every request at the time of writing; pinata was not.
 */
export const IPFS_GATEWAYS = [
  'https://gateway.pinata.cloud',
  'https://dweb.link',
  'https://ipfs.io',
  'https://w3s.link',
]

export type Artifact = {
  wasm: string
  wasmSha256: string
  provingKey: string
  provingKeySha256: string
  verificationKey: string
  /** not in the app's manifest: each file was checked against its CID, then pinned here */
  verificationKeySha256: string
}

/**
 * The 27 circuits' CIDs and sha256, as the web app's `IpfsCircuitArtifacts`
 * hardcodes them. `deposit`, `ragequit` and `transact_1x1` were fetched and
 * checked; see FINDINGS.md.
 */
export const CIRCUITS: Record<string, Artifact> = JSON.parse(
  readFileSync(join(ROOT, 'src/v2/circuit-artifacts.json'), 'utf8'),
)

export type Circuit = keyof typeof CIRCUITS & string

/** The `transact_NxM` variant for N inputs and M outputs. */
export function transactCircuit(inputs: number, outputs: number): Circuit {
  if (inputs < 1 || inputs > 5 || outputs < 1 || outputs > 5)
    throw new UsageError(`no transact circuit for ${inputs}x${outputs} -- both must be 1..5`)
  return `transact_${inputs}x${outputs}`
}

export function artifact(circuit: string): Artifact {
  const a = CIRCUITS[circuit]
  if (!a) throw new UsageError(`unknown circuit '${circuit}'`)
  return a
}
