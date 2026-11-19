// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import { join } from 'node:path'
import { ASSETS_ROOT, CHAINS, chainName, HOME_ROOT, rpcOverrideUrl, UsageError } from '../shared/config.ts'
import CIRCUIT_ARTIFACTS from './circuit-artifacts.json' with { type: 'json' }

// Chains, the Safe service, the wallet port and --rpc-url are shared with V1.
export {
  chainName,
  customRpc,
  FRAME_RPC,
  LOG_CHUNK,
  parseChain,
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
 * The production Privacy Pools V2 deployment -- the one the app at
 * privacypools.com deposits into. It was deployed deterministically, so these
 * addresses are the same on every chain it runs on; what differs per chain is
 * in `DEPLOYMENTS` below.
 *
 * Every role below was read back off the contracts themselves
 * (`pool.keystore()`, `pool.aspRegistry()`, `entrypoint.poolVault()`), not
 * taken from the app bundle.
 *
 * An earlier mainnet deployment ("staging", behind `api-dev.0xbow.io`) is
 * still live but is no longer addressable from here. The recorded events it
 * produced survive as fixtures in test/v2-vectors.json, where they still pin
 * the ABI decoding and the public-signal order.
 */
export const POOL_ADDR = '0x0Eb42804BF897662aF851370eaeAdcDBEC1b97ed'
export const KEYSTORE_ADDR = '0x6E463391c79b7e1A88eF26E0B023f9A6C9938a71'
export const ASP_REGISTRY = '0x259C0BEa1d783c202509BD3b2688d23b8AEf58B0'
export const ENTRYPOINT_ADDR = '0xca1e072236D231130059eeA6Bfceb7F4e9a1F0C3'
export const ACCESS_ROUTER = '0x40a6bC296D87f71Ab31Ca3Bfb50513441fBD5160'
export const DEPOSIT_VERIFIER = '0x49Ab3f48Ff9fa603EE81E5f28eB4214798E29862'
export const RAGEQUIT_VERIFIER = '0x687059Fc9C2488f333e06aa72CBea7E4b1D05B57'
/**
 * The PrivacyPoolRelay a relayed withdrawal names as its processor. The pool
 * pays the processor all of `amountOut` and this contract splits it by the
 * routing the proof binds, so a relayer that names any other is refused.
 */
export const RELAY_ADDR = '0x01a8Fa4dbb60187aD8d3c3d08E7Fb8C14198A461'

/** The ASP serving this pool on every chain; it answers 404 for any other deployment's entrypoint. */
export const ASP_API = 'https://api-v2.0xbow.io'

/** The X25519 key this pool's deposit openings are encrypted to, from `GET /public-key`. */
export const ASP_PUBLIC_KEY = '0x3f651e2321b9b78c3690064b025b610942cbf755e28d44726378cf853cfd8f34'

/**
 * A relayer submits a `transact` for you, so the withdrawal is not linked to
 * an address of yours; it takes its fee out of `amountOut`. V1 kept this list
 * per Entrypoint; 0xbow's relayer serves every chain, and says which under
 * `GET /v1/details`.
 */
export const RELAYERS = ['https://relayer-v2-prod-149184580131.us-east1.run.app']

/**
 * The ASP's own API: public and unauthenticated, but every request must carry
 * both `chainId` and `entrypoint` -- the host serves several chains' pools and
 * answers for a different one (or 404s) without them.
 */
export const aspApi = () => process.env.MONEYSURFER_ASP ?? ASP_API

/** 0xEeee...EEeE, the asset id the chain's own coin carries -- ETH, or BNB. */
export const NATIVE = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'

export const isNative = (a: string) => a.toLowerCase() === NATIVE.toLowerCase()

/**
 * A PPRouter: the contract that turns an asset the Entrypoint will not take
 * into one it will. Each wraps exactly one underlying into exactly one yield
 * vault's share token, and `VAULT()`, `UNDERLYING()`, `ZAP()` and
 * `ENTRYPOINT()` on each of these addresses return precisely what is paired
 * with it here -- read off the chain, not the app (see FINDINGS.md).
 */
export type Router = {
  address: string
  /** what the depositor spends: an ERC-20, or NATIVE where `native` is set */
  underlying: string
  /** the router takes the coin itself and wraps it (ETH -> WETH -> ppETH) */
  native: boolean
}

/**
 * What the deployment looks like on one chain.
 *
 * `deployedBlock` is the first block any of the core contracts had code,
 * found by bisecting `eth_getCode`; the ASP's own `fromBlock` is later -- it
 * is the first *deposit* -- and starting there loses the keystore
 * registrations that came before it.
 *
 * `tokens` is every asset the Entrypoint might have configured. There is no
 * way to enumerate them on chain -- `assets(address)` is a getter, not a list
 * -- so this is the candidate set and `Entrypoint.assets()` is the authority
 * on which of them are actually open. `chain.ts` reads each one's symbol and
 * decimals and derives its command-line key from the symbol.
 *
 * `routers` is keyed by the vault (the `tokenId` the PoolVault ends up
 * recording).
 */
export type Deployment = {
  deployedBlock: number
  /** the chain's own coin, which NATIVE stands for */
  native: string
  /** a public RPC that serves eth_getLogs from `deployedBlock` without a key, where there is one */
  rpc?: string
  tokens: string[]
  routers: Record<string, Router>
}

const PP_ETH = '0x66051920D25af4E3596A8a46309F4D045F9D83B7'
const PP_USDC = '0xC246aFb23482fF9596E9cee5f1f678eFe0EB1ad6'
const PP_USDT = '0xA4cF419558Ef36CC6FfB666195684dC963910426'
const USDC = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
const USDT = '0xdAC17F958D2ee523a2206206994597C13D831ec7'

const BNB_PP_USDT = '0x6C17bE9c864254CA4b2d36223f31AdE94B4d64c2'
const BNB_USDT = '0x55d398326f99059fF775485246999027B3197955'
const BNB_FDUSD = '0xc5f0f7b66764F6ec8C8Dff7BA683102295E16409'

/**
 * The chains this client serves. Citrea (4114) runs the same contracts, but
 * its ASP has never published a root, so nothing deposited there can be spent
 * privately -- only ragequit -- and it is left out until that changes.
 */
export const DEPLOYMENTS: Record<number, Deployment> = {
  1: {
    deployedBlock: 25_884_231,
    native: 'ETH',
    rpc: CHAINS[1]!.rpc,
    tokens: [NATIVE, PP_ETH, PP_USDC, PP_USDT, USDC, USDT],
    routers: {
      [PP_ETH.toLowerCase()]: {
        address: '0x77613D670BB9fD48A9898D0eac8ebf21B566F960',
        underlying: NATIVE,
        native: true,
      },
      [PP_USDC.toLowerCase()]: {
        address: '0xe76E793d776c1e207aD7a7fa7C57d27420d85110',
        underlying: USDC,
        native: false,
      },
      [PP_USDT.toLowerCase()]: {
        address: '0x13a0b86bac3e0C29bd64fED7BCD2EE84f371f41C',
        underlying: USDT,
        native: false,
      },
    },
  },
  56: {
    deployedBlock: 119_401_450,
    native: 'BNB',
    // FDUSD goes in directly: the Entrypoint takes it, and it has no router.
    tokens: [NATIVE, BNB_PP_USDT, BNB_FDUSD, BNB_USDT],
    routers: {
      [BNB_PP_USDT.toLowerCase()]: {
        address: '0x9929Ad2Edc2E0B5D59C3f5b2910812D0c8b84E16',
        underlying: BNB_USDT,
        native: false,
      },
    },
  },
}

let selected = 1

/** --chain, checked against the chains this client serves. Mainnet when not given. */
export function setChain(id: number): void {
  if (!DEPLOYMENTS[id]) {
    const known = Object.keys(DEPLOYMENTS)
      .map((k) => `${chainName(Number(k))} (${k})`)
      .join(', ')
    throw new UsageError(`no Privacy Pools V2 on ${chainName(id)} -- supported: ${known}`)
  }
  selected = id
}

export const chainId = () => selected
export const deployment = (): Deployment => DEPLOYMENTS[selected]!

export const routerFor = (tokenId: string): Router | undefined => deployment().routers[tokenId.toLowerCase()]

/** LeanIMT depths the circuits are compiled for; the contracts cap the trees to match. */
export const STATE_DEPTH = 22
export const KEYSTORE_DEPTH = 18
export const ASP_DEPTH = 18

/** --rpc-url if given, else MONEYSURFER_RPC, else the chain's public default. */
export function rpcUrl(): string {
  const url = rpcOverrideUrl() ?? process.env.MONEYSURFER_RPC ?? deployment().rpc
  if (url) return url
  throw new UsageError(
    `no public RPC on ${chainName(selected)} serves the logs a sync reads -- pass --rpc-url, or set\n` +
      '  MONEYSURFER_RPC, to a provider of your own (Alchemy, QuickNode, NodeReal with a key, ...)',
  )
}

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
export const CIRCUITS: Record<string, Artifact> = CIRCUIT_ARTIFACTS

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
