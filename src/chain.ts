/**
 * Everything Privacy Pools keeps on-chain: the Entrypoint and pool
 * contracts, a cache of each pool's events synced from its deployment, the
 * state tree those events build, and the ASP's association set -- fetched
 * from the IPFS copy the ASP pins with every root, and trusted only once it
 * hashes to the root the Entrypoint holds.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils.js'
import { createContract, events } from 'micro-eth-signer/abi.js'
import type { RpcClient } from 'micro-eth-signer/net.js'
import { ASP_API, chainName, HOME, IPFS_GATEWAYS, LOG_CHUNK, type Pool } from './config.ts'
import { LeanIMT } from './crypto.ts'
import { RangeLimitError, read } from './rpc.ts'

// ---------------------------------------------------------------------------
// Contracts
// ---------------------------------------------------------------------------
const u256 = <N extends string>(name: N) => ({ name, type: 'uint256' }) as const

export const ENTRYPOINT_ABI = [
  {
    type: 'function',
    name: 'deposit',
    stateMutability: 'payable',
    inputs: [u256('_precommitment')],
    outputs: [u256('_commitment')],
  },
  {
    type: 'function',
    name: 'relay',
    stateMutability: 'nonpayable',
    inputs: [
      {
        name: '_withdrawal',
        type: 'tuple',
        components: [
          { name: 'processooor', type: 'address' },
          { name: 'data', type: 'bytes' },
        ],
      },
      {
        name: '_proof',
        type: 'tuple',
        components: [
          { name: 'pA', type: 'uint256[2]' },
          { name: 'pB', type: 'uint256[2][2]' },
          { name: 'pC', type: 'uint256[2]' },
          { name: 'pubSignals', type: 'uint256[8]' },
        ],
      },
      u256('_scope'),
    ],
    outputs: [],
  },
  { type: 'function', name: 'latestRoot', stateMutability: 'view', inputs: [], outputs: [u256('')] },
  {
    type: 'function',
    name: 'assetConfig',
    stateMutability: 'view',
    inputs: [{ name: '_asset', type: 'address' }],
    outputs: [
      { name: 'pool', type: 'address' },
      u256('minimumDepositAmount'),
      u256('vettingFeeBPS'),
      u256('maxRelayFeeBPS'),
    ],
  },
  {
    type: 'function',
    name: 'usedPrecommitments',
    stateMutability: 'view',
    inputs: [u256('')],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'event',
    name: 'RootUpdated',
    inputs: [
      { name: '_root', type: 'uint256', indexed: false },
      { name: '_ipfsCID', type: 'string', indexed: false },
      { name: '_timestamp', type: 'uint256', indexed: false },
    ],
  },
] as const

export const POOL_ABI = [
  { type: 'function', name: 'SCOPE', stateMutability: 'view', inputs: [], outputs: [u256('')] },
  { type: 'function', name: 'currentRoot', stateMutability: 'view', inputs: [], outputs: [u256('')] },
  { type: 'function', name: 'currentTreeSize', stateMutability: 'view', inputs: [], outputs: [u256('')] },
  { type: 'function', name: 'dead', stateMutability: 'view', inputs: [], outputs: [{ name: '', type: 'bool' }] },
  {
    type: 'function',
    name: 'nullifierHashes',
    stateMutability: 'view',
    inputs: [u256('')],
    outputs: [{ name: '', type: 'bool' }],
  },
  {
    type: 'function',
    name: 'depositors',
    stateMutability: 'view',
    inputs: [u256('')],
    outputs: [{ name: '', type: 'address' }],
  },
  {
    type: 'function',
    name: 'ragequit',
    stateMutability: 'nonpayable',
    inputs: [
      {
        name: '_p',
        type: 'tuple',
        components: [
          { name: 'pA', type: 'uint256[2]' },
          { name: 'pB', type: 'uint256[2][2]' },
          { name: 'pC', type: 'uint256[2]' },
          { name: 'pubSignals', type: 'uint256[4]' },
        ],
      },
    ],
    outputs: [],
  },
  {
    type: 'event',
    name: 'Deposited',
    inputs: [
      { name: '_depositor', type: 'address', indexed: true },
      { name: '_commitment', type: 'uint256', indexed: false },
      { name: '_label', type: 'uint256', indexed: false },
      { name: '_value', type: 'uint256', indexed: false },
      { name: '_precommitmentHash', type: 'uint256', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'Withdrawn',
    inputs: [
      { name: '_processooor', type: 'address', indexed: true },
      { name: '_value', type: 'uint256', indexed: false },
      { name: '_spentNullifier', type: 'uint256', indexed: false },
      { name: '_newCommitment', type: 'uint256', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'Ragequit',
    inputs: [
      { name: '_ragequitter', type: 'address', indexed: true },
      { name: '_commitment', type: 'uint256', indexed: false },
      { name: '_label', type: 'uint256', indexed: false },
      { name: '_value', type: 'uint256', indexed: false },
    ],
  },
  {
    type: 'event',
    name: 'LeafInserted',
    inputs: [
      { name: '_index', type: 'uint256', indexed: false },
      { name: '_leaf', type: 'uint256', indexed: false },
      { name: '_root', type: 'uint256', indexed: false },
    ],
  },
] as const

export const ENTRYPOINT = createContract(ENTRYPOINT_ABI)
export const POOL = createContract(POOL_ABI)
const POOL_EVENTS = events(POOL_ABI)
const ROOT_UPDATED = events(ENTRYPOINT_ABI).RootUpdated

const topicOf = (signature: string) => `0x${bytesToHex(keccak_256(utf8ToBytes(signature)))}`
const TOPIC = {
  Deposited: topicOf('Deposited(address,uint256,uint256,uint256,uint256)'),
  Withdrawn: topicOf('Withdrawn(address,uint256,uint256,uint256)'),
  Ragequit: topicOf('Ragequit(address,uint256,uint256,uint256)'),
  LeafInserted: topicOf('LeafInserted(uint256,uint256,uint256)'),
  RootUpdated: topicOf('RootUpdated(uint256,string,uint256)'),
}

// ---------------------------------------------------------------------------
// Logs
// ---------------------------------------------------------------------------
type Log = { topics: string[]; data: string; blockNumber: string; transactionHash: string; logIndex: string }
const hexNum = (n: number) => `0x${n.toString(16)}`

/**
 * eth_getLogs over [from, to], in ranges sized by what comes back: doubled
 * while logs are sparse, halved when the provider says a range is too wide.
 */
async function getLogs(
  net: RpcClient,
  address: string,
  topics: (string | null)[] | undefined,
  from: number,
  to: number,
  progress?: (block: number) => void,
): Promise<Log[]> {
  const out: Log[] = []
  let span = LOG_CHUNK
  for (let start = from; start <= to; ) {
    const end = Math.min(start + span - 1, to)
    let logs: Log[]
    try {
      logs = (await net.call('eth_getLogs', {
        address,
        fromBlock: hexNum(start),
        toBlock: hexNum(end),
        ...(topics && { topics }),
      })) as Log[]
    } catch (e) {
      if (!(e instanceof RangeLimitError) || span === 1) throw e
      span = Math.max(1, Math.floor(span / 2))
      continue
    }
    out.push(...logs)
    start = end + 1
    progress?.(end)
    if (logs.length < 1000) span = Math.min(span * 2, 20_000_000)
  }
  return out
}

// ---------------------------------------------------------------------------
// Pool events, cached per pool
// ---------------------------------------------------------------------------
type At = { block: number; tx: string }
export type Deposit = At & {
  depositor: string
  commitment: bigint
  label: bigint
  value: bigint
  precommitment: bigint
}
export type Withdrawal = At & { processooor: string; value: bigint; spentNullifier: bigint; newCommitment: bigint }
export type Ragequit = At & { ragequitter: string; commitment: bigint; label: bigint; value: bigint }
export type PoolEvents = {
  /** synced through this block */
  block: number
  deposits: Deposit[]
  withdrawals: Withdrawal[]
  ragequits: Ragequit[]
  /** LeafInserted as [index, leaf], in insertion order */
  leaves: [bigint, bigint][]
}

/** How far back each sync re-reads, so a reorg since the last one cannot leave stale events. */
const REORG_BLOCKS = 2000

const cacheFile = (p: Pool) => join(HOME, 'cache', `${p.chainId}-${p.address.toLowerCase()}.json`)

function loadEvents(p: Pool): PoolEvents {
  const file = cacheFile(p)
  if (!existsSync(file)) return { block: p.deployedBlock - 1, deposits: [], withdrawals: [], ragequits: [], leaves: [] }
  return JSON.parse(readFileSync(file, 'utf8'), (_k, v) =>
    typeof v === 'string' && /^\d+n$/.test(v) ? BigInt(v.slice(0, -1)) : v,
  )
}

function saveEvents(p: Pool, ev: PoolEvents) {
  mkdirSync(join(HOME, 'cache'), { recursive: true })
  const tmp = `${cacheFile(p)}.tmp`
  writeFileSync(
    tmp,
    JSON.stringify(ev, (_k, v) => (typeof v === 'bigint' ? `${v}n` : v)),
  )
  renameSync(tmp, cacheFile(p))
}

/** Bring a pool's event cache up to the chain head and return it. */
export async function syncPool(net: RpcClient, p: Pool, log?: (s: string) => void): Promise<PoolEvents> {
  const ev = loadEvents(p)
  const head = Number(await net.call('eth_blockNumber'))
  const from = Math.max(p.deployedBlock, ev.block - REORG_BLOCKS + 1)
  const keep = <T extends At>(xs: T[]) => xs.filter((x) => x.block < from)
  ev.deposits = keep(ev.deposits)
  ev.withdrawals = keep(ev.withdrawals)
  ev.ragequits = keep(ev.ragequits)
  // LeafInserted carries no block, so leaves are re-derived from what remains
  // below `from` plus what is read now: inserts are strictly ordered by index.
  const leavesBelow = ev.deposits.length + ev.withdrawals.length
  ev.leaves = ev.leaves.slice(0, leavesBelow)

  const label = `${p.key} on ${chainName(p.chainId)}`
  const logs = await getLogs(net, p.address, undefined, from, head, (b) =>
    process.stderr.write(`\r  syncing ${label}: block ${b} / ${head}   `),
  )
  if (logs.length || head > from) process.stderr.write('\n')
  for (const l of logs) {
    const at = { block: Number(l.blockNumber), tx: l.transactionHash }
    const [topic] = l.topics
    if (topic === TOPIC.Deposited) {
      const e = POOL_EVENTS.Deposited.decode(l.topics, l.data)
      ev.deposits.push({
        ...at,
        depositor: e._depositor,
        commitment: e._commitment,
        label: e._label,
        value: e._value,
        precommitment: e._precommitmentHash,
      })
    } else if (topic === TOPIC.Withdrawn) {
      const e = POOL_EVENTS.Withdrawn.decode(l.topics, l.data)
      ev.withdrawals.push({
        ...at,
        processooor: e._processooor,
        value: e._value,
        spentNullifier: e._spentNullifier,
        newCommitment: e._newCommitment,
      })
    } else if (topic === TOPIC.Ragequit) {
      const e = POOL_EVENTS.Ragequit.decode(l.topics, l.data)
      ev.ragequits.push({
        ...at,
        ragequitter: e._ragequitter,
        commitment: e._commitment,
        label: e._label,
        value: e._value,
      })
    } else if (topic === TOPIC.LeafInserted) {
      const e = POOL_EVENTS.LeafInserted.decode(l.topics, l.data)
      ev.leaves.push([e._index, e._leaf])
    }
  }
  ev.leaves.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
  ev.block = head
  saveEvents(p, ev)
  log?.(`${label}: ${ev.deposits.length} deposits, ${ev.withdrawals.length} withdrawals, ${ev.leaves.length} leaves`)
  return ev
}

/** The pool's state tree, rebuilt from its inserts and checked against the root the pool holds now. */
export async function stateTree(net: RpcClient, p: Pool, ev: PoolEvents): Promise<LeanIMT> {
  const tree = new LeanIMT(ev.leaves.map(([, leaf]) => leaf))
  const [root, size] = await Promise.all([
    read(net, p.address, POOL.currentRoot),
    read(net, p.address, POOL.currentTreeSize),
  ])
  if (BigInt(tree.size) !== size || tree.root !== root) {
    throw new Error(
      `the synced state tree (${tree.size} leaves) does not match the pool's (${size}) -- a deposit may have just landed; try again`,
    )
  }
  return tree
}

// ---------------------------------------------------------------------------
// The ASP's association set
// ---------------------------------------------------------------------------
export type AspSet = { root: bigint; tree: LeanIMT; labels: Set<bigint>; source: string }

const aspCache = (p: Pool, root: bigint) => join(HOME, 'cache', `asp-${p.chainId}-${root}.json`)

/** The tree whose root the Entrypoint holds, if `leaves` are its labels -- as given, or sorted. */
function matching(leaves: bigint[], root: bigint): LeanIMT | undefined {
  const tree = new LeanIMT(leaves)
  if (tree.root === root) return tree
  const sorted = new LeanIMT([...leaves].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)))
  return sorted.root === root ? sorted : undefined
}

/** The IPFS CID the ASP published with `root`, from the newest RootUpdated carrying it. */
async function rootCid(net: RpcClient, entrypoint: string, root: bigint): Promise<string> {
  const head = Number(await net.call('eth_blockNumber'))
  const topic = [TOPIC.RootUpdated]
  for (let end = head, span = 50_000; end > 0; end -= span, span = Math.min(span * 4, 50_000_000)) {
    const logs = await getLogs(net, entrypoint, topic, Math.max(0, end - span + 1), end)
    for (const l of logs.reverse()) {
      const e = ROOT_UPDATED.decode(l.topics, l.data)
      if (e._root === root) return e._ipfsCID
    }
  }
  throw new Error(`no RootUpdated event carries the current ASP root ${root}`)
}

/**
 * The association set behind Entrypoint.latestRoot(): the ASP's IPFS copy
 * (no contact with the ASP), else its API as a last resort -- either way
 * accepted only if it hashes to that root.
 */
export async function aspSet(net: RpcClient, p: Pool, scope: bigint, log?: (s: string) => void): Promise<AspSet> {
  const root = await read(net, p.entrypoint, ENTRYPOINT.latestRoot)
  const done = (tree: LeanIMT, source: string): AspSet => ({ root, tree, labels: new Set(tree.levels[0]), source })
  const file = aspCache(p, root)
  if (existsSync(file)) {
    const tree = matching((JSON.parse(readFileSync(file, 'utf8')) as string[]).map(BigInt), root)
    if (tree) return done(tree, 'cache')
  }
  const save = (tree: LeanIMT) => {
    mkdirSync(join(HOME, 'cache'), { recursive: true })
    writeFileSync(file, JSON.stringify(tree.levels[0]!.map(String)))
  }

  const cid = await rootCid(net, p.entrypoint, root)
  for (const gw of IPFS_GATEWAYS) {
    try {
      const res = await fetch(`${gw}/ipfs/${cid}`, { signal: AbortSignal.timeout(60_000) })
      if (!res.ok) continue
      const levels = (await res.json()) as string[][]
      const tree = matching(levels[0]!.map(BigInt), root)
      if (!tree) {
        log?.(`${gw} served ${cid}, but it does not hash to the ASP root -- ignored`)
        continue
      }
      save(tree)
      return done(tree, `IPFS ${cid} via ${gw}`)
    } catch {
      // next gateway
    }
  }
  log?.(`no IPFS gateway served ${cid}; asking the ASP's API instead (it sees your IP, not your notes)`)
  const res = await fetch(`${ASP_API}/${p.chainId}/public/mt-leaves`, {
    headers: { 'X-Pool-Scope': String(scope) },
    signal: AbortSignal.timeout(60_000),
  })
  if (res.ok) {
    const { aspLeaves } = (await res.json()) as { aspLeaves: string[] }
    const tree = matching(aspLeaves.map(BigInt), root)
    if (tree) {
      save(tree)
      return done(tree, `${ASP_API}`)
    }
  }
  throw new Error(`could not obtain an association set that hashes to the current ASP root ${root}`)
}
