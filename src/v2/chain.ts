// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Everything Privacy Pools V2 keeps on-chain: the PoolVault's events, the
 * state tree they build, the Keystore's tree of registered accounts, and the
 * ASP's published roots. The ABI is recovered, not published -- the contracts
 * are unverified, so every signature here was read out of the deployed
 * bytecode and checked against real mainnet calldata (see FINDINGS.md).
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { bytesToNumberBE } from '@noble/curves/utils.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'
import { createContract, events } from 'micro-eth-signer/abi.js'
import type { RpcClient } from 'micro-eth-signer/net.js'
import { RangeLimitError, read } from '../shared/rpc.ts'
import { symbolKey, uniqueKeys } from '../shared/symbols.ts'
import {
  ASP_REGISTRY,
  aspApi,
  CANDIDATE_TOKENS,
  CHAIN_ID,
  DEPLOYED_BLOCK,
  ENTRYPOINT_ADDR,
  HOME,
  isNative,
  KEYSTORE_ADDR,
  LOG_CHUNK,
  POOL_ADDR,
  routerFor,
  UsageError,
} from './config.ts'
import { aspLeaf, LeanIMT } from './crypto.ts'

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------
const u256 = <N extends string>(name: N) => ({ name, type: 'uint256' }) as const
const addr = <N extends string>(name: N) => ({ name, type: 'address' }) as const

/** ProofLib's Groth16 struct, with the public signals sized per circuit. */
const proof = (signals: { name: string; type: string }) =>
  ({
    name: 'proof',
    type: 'tuple',
    components: [
      { name: 'pA', type: 'uint256[2]' },
      { name: 'pB', type: 'uint256[2][2]' },
      { name: 'pC', type: 'uint256[2]' },
      signals,
    ],
  }) as const

/** The `(bytes32 hint, bytes ciphertext)` the Note event carries. */
const NOTE_DATA = {
  name: 'noteData',
  type: 'tuple',
  components: [
    { name: 'hint', type: 'bytes32' },
    { name: 'ciphertext', type: 'bytes' },
  ],
} as const

export const POOL_ABI = [
  {
    type: 'function',
    name: 'deposit',
    stateMutability: 'payable',
    inputs: [proof({ name: 'pubSignals', type: 'uint256[4]' }), NOTE_DATA],
    outputs: [],
  },
  {
    type: 'function',
    name: 'ragequit',
    stateMutability: 'nonpayable',
    inputs: [proof({ name: 'pubSignals', type: 'uint256[7]' })],
    outputs: [],
  },
  {
    type: 'function',
    name: 'transact',
    stateMutability: 'nonpayable',
    inputs: [
      proof({ name: 'pubSignals', type: 'uint256[][]' }),
      {
        name: 'transactParams',
        type: 'tuple',
        components: [addr('processooor'), { name: 'data', type: 'bytes' }],
      },
      { ...NOTE_DATA, name: 'notes', type: 'tuple[]' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'commitments',
    stateMutability: 'view',
    inputs: [u256('commitment')],
    outputs: [u256('timestamp')],
  },
  {
    type: 'function',
    name: 'spentNullifiers',
    stateMutability: 'view',
    inputs: [u256('nullifier')],
    outputs: [u256('timestamp')],
  },
  {
    type: 'function',
    name: 'isKnownRoot',
    stateMutability: 'view',
    inputs: [u256('root')],
    outputs: [{ name: 'known', type: 'bool' }],
  },
  { type: 'function', name: 'keystore', stateMutability: 'view', inputs: [], outputs: [addr('keystore')] },
  { type: 'function', name: 'aspRegistry', stateMutability: 'view', inputs: [], outputs: [addr('aspRegistry')] },
  { type: 'function', name: 'depositVerifier', stateMutability: 'view', inputs: [], outputs: [addr('verifier')] },
  { type: 'function', name: 'ragequitVerifier', stateMutability: 'view', inputs: [], outputs: [addr('verifier')] },
  {
    type: 'function',
    name: 'verifiers',
    stateMutability: 'view',
    inputs: [{ name: 'key', type: 'bytes32' }],
    outputs: [addr('verifier'), { name: 'selector', type: 'bytes4' }],
  },
  { type: 'function', name: 'maxStateTreeSize', stateMutability: 'view', inputs: [], outputs: [u256('size')] },
  {
    type: 'function',
    name: 'paused',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: 'paused', type: 'bool' }],
  },
  {
    type: 'event',
    name: 'LeavesInserted',
    inputs: [{ name: 'leaves', type: 'uint256[]' }, u256('root'), u256('index')],
  },
  {
    type: 'event',
    name: 'Note',
    inputs: [
      { name: 'hint', type: 'bytes32', indexed: true },
      { name: 'ciphertext', type: 'bytes' },
    ],
  },
  {
    type: 'event',
    name: 'Deposited',
    inputs: [
      u256('commitment'),
      { ...addr('tokenId'), indexed: true },
      u256('value'),
      { ...addr('caller'), indexed: true },
    ],
  },
  {
    type: 'event',
    name: 'Ragequit',
    inputs: [
      { ...addr('ragequitter'), indexed: true },
      { ...addr('tokenId'), indexed: true },
      u256('value'),
      u256('commitment'),
      u256('nullifier'),
      u256('label'),
    ],
  },
  {
    type: 'event',
    name: 'Transacted',
    inputs: [
      { name: 'commitments', type: 'uint256[]' },
      { name: 'nullifiers', type: 'uint256[]' },
      { ...addr('tokenId'), indexed: true },
      u256('amountOut'),
      { ...addr('processooor'), indexed: true },
    ],
  },
] as const

export const ENTRYPOINT_ABI = [
  {
    type: 'function',
    name: 'deposit',
    stateMutability: 'payable',
    inputs: [proof({ name: 'pubSignals', type: 'uint256[4]' }), NOTE_DATA, { name: 'aspCiphertext', type: 'bytes' }],
    outputs: [],
  },
  { type: 'function', name: 'poolVault', stateMutability: 'view', inputs: [], outputs: [addr('vault')] },
  {
    type: 'function',
    name: 'assets',
    stateMutability: 'view',
    inputs: [addr('asset')],
    // the field names are the SDK's own, read out of the app bundle: the last
    // one caps a relay fee, it is not a deposit ceiling
    outputs: [{ name: 'enabled', type: 'bool' }, u256('minAmount'), u256('vettingFeeBPS'), u256('maxRelayFee')],
  },
  {
    type: 'event',
    name: 'Deposited',
    inputs: [
      { ...addr('tokenId'), indexed: true },
      { ...addr('depositor'), indexed: true },
      u256('value'),
      u256('fee'),
    ],
  },
] as const

export const KEYSTORE_ABI = [
  {
    type: 'function',
    name: 'setAuthPolicy',
    stateMutability: 'nonpayable',
    inputs: [u256('authDigest'), u256('nullifyingKeyHash')],
    outputs: [],
  },
  {
    type: 'function',
    name: 'setViewingKey',
    stateMutability: 'nonpayable',
    inputs: [{ name: 'viewingKey', type: 'bytes32' }],
    outputs: [],
  },
  {
    type: 'function',
    name: 'viewingKeys',
    stateMutability: 'view',
    inputs: [addr('account')],
    outputs: [{ name: 'viewingKey', type: 'bytes32' }],
  },
  {
    type: 'function',
    name: 'nullifyingKeys',
    stateMutability: 'view',
    inputs: [addr('account')],
    outputs: [u256('nullifyingKeyHash')],
  },
  { type: 'function', name: 'currentRoot', stateMutability: 'view', inputs: [], outputs: [u256('root')] },
  {
    type: 'function',
    name: 'isKnownRoot',
    stateMutability: 'view',
    inputs: [u256('root')],
    outputs: [{ name: 'known', type: 'bool' }],
  },
  { type: 'event', name: 'LeafInserted', inputs: [u256('leaf'), u256('root'), u256('index')] },
  {
    type: 'event',
    name: 'ViewingKeySet',
    inputs: [
      { ...addr('account'), indexed: true },
      { name: 'previous', type: 'bytes32' },
      { name: 'viewingKey', type: 'bytes32' },
    ],
  },
  {
    type: 'event',
    name: 'AuthPolicySet',
    inputs: [{ ...addr('account'), indexed: true }, u256('nullifyingKeyHash'), u256('authDigest')],
  },
] as const

export const ASP_ABI = [
  { type: 'function', name: 'latestASPRoot', stateMutability: 'view', inputs: [], outputs: [u256('root')] },
  {
    type: 'function',
    name: 'latestIPFSCID',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: 'cid', type: 'string' }],
  },
  {
    type: 'event',
    name: 'ASPRootUpdated',
    inputs: [
      { ...u256('root'), indexed: true },
      { name: 'ipfsCID', type: 'bytes' },
    ],
  },
] as const

export const ERC20_ABI = [
  { type: 'function', name: 'symbol', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'string' }] },
  { type: 'function', name: 'decimals', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'uint8' }] },
  { type: 'function', name: 'balanceOf', stateMutability: 'view', inputs: [addr('owner')], outputs: [u256('')] },
  {
    type: 'function',
    name: 'allowance',
    stateMutability: 'view',
    inputs: [addr('owner'), addr('spender')],
    outputs: [u256('')],
  },
  {
    type: 'function',
    name: 'approve',
    stateMutability: 'nonpayable',
    inputs: [addr('spender'), u256('value')],
    outputs: [{ name: '', type: 'bool' }],
  },
] as const

export const POOL = createContract(POOL_ABI)
export const ENTRYPOINT = createContract(ENTRYPOINT_ABI)
export const KEYSTORE = createContract(KEYSTORE_ABI)
export const ASP = createContract(ASP_ABI)
export const ERC20 = createContract(ERC20_ABI)

const POOL_EVENTS = events(POOL_ABI)
const KEYSTORE_EVENTS = events(KEYSTORE_ABI)
const ASP_EVENTS = events(ASP_ABI)

const topicOf = (signature: string) => `0x${bytesToHex(keccak_256(utf8ToBytes(signature)))}`
export const TOPIC = {
  LeavesInserted: topicOf('LeavesInserted(uint256[],uint256,uint256)'),
  Note: topicOf('Note(bytes32,bytes)'),
  Deposited: topicOf('Deposited(uint256,address,uint256,address)'),
  EntrypointDeposited: topicOf('Deposited(address,address,uint256,uint256)'),
  Ragequit: topicOf('Ragequit(address,address,uint256,uint256,uint256,uint256)'),
  Transacted: topicOf('Transacted(uint256[],uint256[],address,uint256,address)'),
  LeafInserted: topicOf('LeafInserted(uint256,uint256,uint256)'),
  ViewingKeySet: topicOf('ViewingKeySet(address,bytes32,bytes32)'),
  AuthPolicySet: topicOf('AuthPolicySet(address,uint256,uint256)'),
  ASPRootUpdated: topicOf('ASPRootUpdated(uint256,bytes)'),
  LabelRegistered: topicOf('LabelRegistered(bytes)'),
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------
type Log = {
  address: string
  topics: string[]
  data: string
  blockNumber: string
  transactionHash: string
  logIndex: string
}
const hexNum = (n: number) => `0x${n.toString(16)}`

/**
 * eth_getLogs over [from, to], in ranges sized by what comes back: doubled
 * while logs are sparse, halved when the provider says a range is too wide.
 * Several addresses go in one query where the provider takes a list, and one
 * query each where it does not -- Blockscout answers "invalid address" to a
 * list, which the spec allows and most providers accept.
 */
async function getLogs(
  net: RpcClient,
  address: string[],
  topics: (string | string[] | null)[] | undefined,
  from: number,
  to: number,
  progress?: (block: number) => void,
): Promise<Log[]> {
  let batched = address.length > 1
  const out: Log[] = []
  let span = LOG_CHUNK
  for (let start = from; start <= to; ) {
    const end = Math.min(start + span - 1, to)
    const query = (a: string | string[]) =>
      net.call('eth_getLogs', {
        address: a,
        fromBlock: hexNum(start),
        toBlock: hexNum(end),
        ...(topics && { topics }),
      }) as Promise<Log[]>
    let logs: Log[]
    try {
      if (batched) logs = await query(address)
      else {
        // one at a time, not in parallel: a provider that refuses a list is
        // usually the same one metering requests
        logs = []
        for (const a of address) logs.push(...(await query(a)))
      }
    } catch (e) {
      if (e instanceof RangeLimitError && span > 1) {
        span = Math.max(1, Math.floor(span / 2))
        continue
      }
      if (!batched) throw e
      // one address at a time, for the provider that will not take a list
      batched = false
      continue
    }
    out.push(...logs)
    start = end + 1
    progress?.(end)
    if (logs.length < 1000) span = Math.min(span * 2, 20_000_000)
  }
  // one address at a time comes back grouped by address, not by block
  return address.length > 1 && !batched
    ? out.sort((a, b) => Number(a.blockNumber) - Number(b.blockNumber) || Number(a.logIndex) - Number(b.logIndex))
    : out
}

/** How far back each sync re-reads, so a reorg since the last one cannot leave stale events. */
const REORG_BLOCKS = 2000

function writeCache(file: string, json: string) {
  mkdirSync(join(HOME, 'cache'), { recursive: true })
  writeFileSync(`${file}.tmp`, json)
  renameSync(`${file}.tmp`, file)
}

// ---------------------------------------------------------------------------
// The pool's events
// ---------------------------------------------------------------------------
type At = { block: number; tx: string }
export type Deposit = At & { commitment: bigint; tokenId: string; value: bigint }
export type Ragequit = At & {
  ragequitter: string
  tokenId: string
  value: bigint
  commitment: bigint
  nullifier: bigint
  label: bigint
}
export type Transact = At & {
  commitments: bigint[]
  nullifiers: bigint[]
  tokenId: string
  amountOut: bigint
  processooor: string
}
/** A Note event: a random hint in discoverable mode, Poseidon([paymentId]) against a payment request. */
export type Note = At & { hint: bigint; ciphertext: string }

export type PoolEvents = {
  /** synced through this block */
  block: number
  deposits: Deposit[]
  ragequits: Ragequit[]
  transacts: Transact[]
  notes: Note[]
  /** LeavesInserted flattened to [index, leaf], in insertion order */
  leaves: [number, bigint][]
  /** the Keystore's tree, same shape */
  keystoreLeaves: [number, bigint][]
  /** every ASP root the registry has published, oldest first */
  aspRoots: bigint[]
}

const empty = (): PoolEvents => ({
  block: DEPLOYED_BLOCK - 1,
  deposits: [],
  ragequits: [],
  transacts: [],
  notes: [],
  leaves: [],
  keystoreLeaves: [],
  aspRoots: [],
})

const cacheFile = () => join(HOME, 'cache', `${CHAIN_ID}-${POOL_ADDR.toLowerCase()}.json`)

const revive = (_k: string, v: unknown) => (typeof v === 'string' && /^\d+n$/.test(v) ? BigInt(v.slice(0, -1)) : v)
const replace = (_k: string, v: unknown) => (typeof v === 'bigint' ? `${v}n` : v)

function loadEvents(): PoolEvents {
  const file = cacheFile()
  if (!existsSync(file)) return empty()
  return JSON.parse(readFileSync(file, 'utf8'), revive)
}

/**
 * Bring the event cache up to the chain head, in one eth_getLogs pass over the
 * pool, the keystore and the ASP registry.
 */
export async function sync(net: RpcClient, log?: (s: string) => void): Promise<PoolEvents> {
  const head = Number(await net.call('eth_blockNumber'))
  const ev = loadEvents()
  const from = Math.max(DEPLOYED_BLOCK, ev.block - REORG_BLOCKS + 1)
  const keep = <T extends At>(xs: T[]) => xs.filter((x) => x.block < from)
  ev.deposits = keep(ev.deposits)
  ev.ragequits = keep(ev.ragequits)
  ev.transacts = keep(ev.transacts)
  ev.notes = keep(ev.notes)
  // Leaves carry no block, so what is re-read replaces everything at or above
  // the first index inserted from `from` on; the index in the event says where.
  const addresses = [POOL_ADDR, KEYSTORE_ADDR, ASP_REGISTRY].map((a) => a.toLowerCase())
  const shown = process.stderr.isTTY && head - from > LOG_CHUNK
  const logs = await getLogs(
    net,
    addresses,
    undefined,
    from,
    head,
    shown ? (b) => process.stderr.write(`\r\x1b[K  syncing: block ${b} / ${head}`) : undefined,
  )
  if (shown) process.stderr.write('\r\x1b[K')
  const leaves = new Map(ev.leaves)
  const keystoreLeaves = new Map(ev.keystoreLeaves)
  const aspRoots = new Set(ev.aspRoots)
  for (const l of logs) addEvent(ev, l, leaves, keystoreLeaves, aspRoots)
  const ordered = (m: Map<number, bigint>): [number, bigint][] => [...m].sort((a, b) => a[0] - b[0])
  ev.leaves = ordered(leaves)
  ev.keystoreLeaves = ordered(keystoreLeaves)
  ev.aspRoots = [...aspRoots]
  ev.block = head
  writeCache(cacheFile(), JSON.stringify(ev, replace))
  log?.(
    `${ev.deposits.length} deposits, ${ev.transacts.length} transacts, ${ev.ragequits.length} ragequits, ` +
      `${ev.leaves.length} leaves, ${ev.keystoreLeaves.length} accounts`,
  )
  return ev
}

function addEvent(
  ev: PoolEvents,
  l: Log,
  leaves: Map<number, bigint>,
  keystoreLeaves: Map<number, bigint>,
  aspRoots: Set<bigint>,
) {
  const at = { block: Number(l.blockNumber), tx: l.transactionHash }
  const [topic] = l.topics
  if (topic === TOPIC.LeavesInserted) {
    const e = POOL_EVENTS.LeavesInserted.decode(l.topics, l.data)
    for (const [i, leaf] of e.leaves.entries()) leaves.set(Number(e.index) + i, leaf)
  } else if (topic === TOPIC.Deposited && l.address.toLowerCase() === POOL_ADDR.toLowerCase()) {
    const e = POOL_EVENTS.Deposited.decode(l.topics, l.data)
    ev.deposits.push({ ...at, commitment: e.commitment, tokenId: e.tokenId, value: e.value })
  } else if (topic === TOPIC.Ragequit) {
    const e = POOL_EVENTS.Ragequit.decode(l.topics, l.data)
    ev.ragequits.push({ ...at, ...e })
  } else if (topic === TOPIC.Transacted) {
    const e = POOL_EVENTS.Transacted.decode(l.topics, l.data)
    ev.transacts.push({ ...at, ...e })
  } else if (topic === TOPIC.Note) {
    const e = POOL_EVENTS.Note.decode(l.topics, l.data)
    ev.notes.push({ ...at, hint: bytesToNumberBE(e.hint), ciphertext: bytesToHex(e.ciphertext) })
  } else if (topic === TOPIC.LeafInserted) {
    const e = KEYSTORE_EVENTS.LeafInserted.decode(l.topics, l.data)
    keystoreLeaves.set(Number(e.index), e.leaf)
  } else if (topic === TOPIC.ASPRootUpdated) {
    aspRoots.add(ASP_EVENTS.ASPRootUpdated.decode(l.topics, l.data).root)
  }
}

// ---------------------------------------------------------------------------
// The two trees
// ---------------------------------------------------------------------------
/** The pool's state tree, refusing to return one the pool does not recognise. */
export async function stateTree(net: RpcClient, ev: PoolEvents): Promise<LeanIMT> {
  return checked(net, POOL_ADDR, POOL.isKnownRoot, ev.leaves, 'state')
}

/** The keystore's tree of registered accounts. */
export async function keystoreTree(net: RpcClient, ev: PoolEvents): Promise<LeanIMT> {
  return checked(net, KEYSTORE_ADDR, KEYSTORE.isKnownRoot, ev.keystoreLeaves, 'keystore')
}

async function checked(
  net: RpcClient,
  to: string,
  method: { encodeInput: (a: bigint) => Uint8Array; decodeOutput: (b: Uint8Array) => boolean },
  entries: [number, bigint][],
  what: string,
): Promise<LeanIMT> {
  for (const [n, [i]] of entries.entries())
    if (i !== n) throw new Error(`the ${what} tree is missing leaf ${n} -- delete the cache and re-sync`)
  const tree = new LeanIMT(entries.map(([, leaf]) => leaf))
  const known = await read(net, to, method, tree.root)
  if (!known)
    throw new Error(`the ${what} tree we built has root 0x${tree.root.toString(16)}, which the contract does not know`)
  return tree
}

/** Where a commitment sits in the state tree, for a membership proof. */
export function leafIndexOf(tree: LeanIMT, leaf: bigint): number {
  const i = tree.levels[0]!.indexOf(leaf)
  if (i < 0) throw new UsageError(`leaf 0x${leaf.toString(16)} is not in the state tree`)
  return i
}

// ---------------------------------------------------------------------------
// The ASP's association set
// ---------------------------------------------------------------------------
export type AspSet = { root: bigint; tree: LeanIMT; source: string }

/**
 * The association set whose root the registry has published. Both `chainId`
 * and `entrypoint` are required: the ASP serves several pools and answers for
 * the wrong one without them. The set is trusted only once it hashes to the
 * root the registry holds, so the gateway cannot lie about membership.
 */
export async function aspSet(net: RpcClient): Promise<AspSet> {
  const root = await read(net, ASP_REGISTRY, ASP.latestASPRoot, undefined)
  const url = `${aspApi()}/association-set/leaves?chainId=${CHAIN_ID}&entrypoint=${ENTRYPOINT_ADDR}`
  const res = await fetch(url, { signal: AbortSignal.timeout(60_000) })
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`)
  const { leaves } = (await res.json()) as { leaves: string[] }
  const tree = new LeanIMT(leaves.map(BigInt))
  if (tree.root !== root)
    throw new Error(
      `the ASP's ${tree.size} leaves hash to 0x${tree.root.toString(16)}, but the registry published ` +
        `0x${root.toString(16)} -- the set is stale or is not this pool's`,
    )
  return { root, tree, source: url }
}

/** Where a label sits in the association set. A note is unspendable until it is there. */
export function aspIndexOf(set: AspSet, lbl: bigint): number {
  const i = set.tree.levels[0]!.indexOf(aspLeaf(lbl))
  if (i < 0)
    throw new UsageError(`label 0x${lbl.toString(16)} is not in the association set -- not attested yet, or rejected`)
  return i
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------
/**
 * An asset a command can name. V2 has **one PoolVault serving many assets**
 * rather than V1's pool per asset, so V1's `<pool>` key becomes a symbol here
 * and `tokenId` is what the vault records against the note.
 *
 * Two shapes reach the vault:
 *
 *  - *direct*: the Entrypoint takes the token itself, so `tokenId` is the
 *    token and `<amount>` is in its own decimals.
 *  - *wrapped* (`router` set): what the depositor holds is not what the vault
 *    records. The underlying goes to a PPRouter, which supplies it to Aave,
 *    mints the yield vault's shares and deposits *those*. `<amount>` is then
 *    in the underlying's decimals (USDC: 6) while the note's value is in
 *    shares (ppUSDC: 18). See zap.ts.
 */
export type Asset = {
  /** what commands call it: the symbol, lowercased and made typeable */
  key: string
  symbol: string
  /** what the PoolVault records, and what `Entrypoint.assets()` is keyed by */
  tokenId: string
  /** the tokenId's own decimals */
  decimals: number
  /** what actually leaves the wallet, where a router stands in between */
  router?: { address: string; underlying: string; underlyingSymbol: string; decimals: number; native: boolean }
  enabled: boolean
  /** in tokenId units -- for a wrapped asset that means shares, not underlying */
  minAmount: bigint
  vettingFeeBPS: bigint
  maxRelayFee: bigint
}

const ETH_TOKEN = { symbol: 'ETH', decimals: 18 }

/** A token's symbol and decimals; the native coin has neither on chain. */
async function tokenMeta(net: RpcClient, token: string): Promise<{ symbol: string; decimals: number }> {
  if (isNative(token)) return ETH_TOKEN
  const [symbol, decimals] = await Promise.all([read(net, token, ERC20.symbol), read(net, token, ERC20.decimals)])
  return { symbol, decimals: Number(decimals) }
}

/**
 * Every asset this client knows, with what the Entrypoint says about each.
 *
 * The set is not enumerable on chain -- `assets(address)` is a getter, not a
 * list -- so config.ts holds the candidates and the Entrypoint is the
 * authority on which are open. Keys come from the symbols by the same rule V1
 * names its pools with, so they are lowercase and typeable.
 */
export async function assets(net: RpcClient): Promise<Asset[]> {
  const found = await Promise.all(
    CANDIDATE_TOKENS.map(async (tokenId) => {
      const [meta, cfg] = await Promise.all([
        tokenMeta(net, tokenId),
        read(net, ENTRYPOINT_ADDR, ENTRYPOINT.assets, tokenId),
      ])
      const r = routerFor(tokenId)
      const router = r
        ? {
            ...r,
            ...(await tokenMeta(net, r.underlying).then((m) => ({ underlyingSymbol: m.symbol, decimals: m.decimals }))),
          }
        : undefined
      return { tokenId, meta, cfg, router }
    }),
  )
  // Enabled assets claim the bare name first, as V1 lets a live pool do.
  const ordered = [...found].sort((a, b) => Number(b.cfg.enabled) - Number(a.cfg.enabled))
  const keys = uniqueKeys(ordered, (a) => symbolKey(a.meta.symbol, a.tokenId))
  return found.map((a) => ({
    key: keys.get(a)!,
    symbol: a.meta.symbol,
    tokenId: a.tokenId,
    decimals: a.meta.decimals,
    router: a.router,
    enabled: a.cfg.enabled,
    minAmount: a.cfg.minAmount,
    vettingFeeBPS: a.cfg.vettingFeeBPS,
    maxRelayFee: a.cfg.maxRelayFee,
  }))
}

/** The key an asset's underlying answers to, where a router stands in between. */
export const underlyingKey = (a: Asset) =>
  a.router ? symbolKey(a.router.underlyingSymbol, a.router.underlying) : undefined

/**
 * The asset an `<asset>` argument names.
 *
 * A wrapped asset answers to its own key *and* to its underlying's, because
 * the underlying is what you actually spend: on production `usdc` and `ppusdc`
 * are one route. Plain USDC is also a configured asset in its own right, but a
 * disabled one, so an enabled route wins over it -- otherwise `deposit usdc`
 * would resolve to the entry that cannot take a deposit at all.
 */
export function pickAsset(all: Asset[], key: string): Asset {
  const want = key.toLowerCase()
  const hit =
    all.find((a) => a.enabled && a.key === want) ??
    all.find((a) => a.enabled && underlyingKey(a) === want) ??
    all.find((a) => a.key === want) ??
    all.find((a) => underlyingKey(a) === want)
  if (!hit) {
    const open = all.filter((a) => a.enabled).map((a) => a.key)
    throw new UsageError(`no asset '${key}' -- ${open.join(', ')} (see: moneysurfer v2 pools)`)
  }
  return hit
}
