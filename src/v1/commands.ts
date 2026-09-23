// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * moneysurfer -- a Privacy Pools client.
 *
 * TypeScript run directly by Node. Chain access and signing via
 * micro-eth-signer; Poseidon, BIP-32/39 and hashing via noble and scure;
 * witnesses from the circuits' own wasm and Groth16 proofs via
 * micro-zk-proofs. One mnemonic derives every note, so there is nothing else
 * to back up.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { setTimeout as sleep } from 'node:timers/promises'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { generateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { addr } from 'micro-eth-signer'
import type { RpcClient } from 'micro-eth-signer/net.js'
import { formatUnits, parseUnits } from 'micro-eth-signer/utils.js'
import { type Common, checksummed, type Flags } from '../shared/flags.ts'
import { assertChain, read, rpc } from '../shared/rpc.ts'
import {
  batch,
  nextNonce,
  proposeSafeTx,
  queuedWith,
  type SafeCall,
  type SafeQueue,
  safeQueue,
} from '../shared/safe.ts'
import { makeSigner, type Signer, type SignerOpts } from '../shared/signer.ts'
import { type Account, recover, spendable } from './account.ts'
import {
  type AspSet,
  aspSet,
  ENTRYPOINT,
  ERC20,
  POOL,
  type PoolEvents,
  pool,
  pools,
  stateTree,
  syncPool,
  syncPools,
  TOKEN_DEPOSIT,
} from './chain.ts'
import {
  ARTIFACT_URL,
  ARTIFACTS,
  ASSETS,
  chainName,
  entrypoint,
  HOME,
  NATIVE,
  type Pool,
  parseChain,
  registryChains,
  rpcUrl,
  UsageError,
} from './config.ts'
import {
  depositSecrets,
  isMnemonic,
  masterKeys,
  mnemonicFromSignature,
  nullifierHash,
  precommitment,
  relayData,
  seedTypedData,
  withdrawalContext,
  withdrawalSecrets,
} from './crypto.ts'
import { prove, snarkjsProof, solidityProof } from './prover.ts'

const log = (s: string) => process.stderr.write(`${s}\n`)
const out = (s: string) => process.stdout.write(`${s}\n`)
process.stdout.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EPIPE') process.exit(0)
  throw e
})
const hex = (b: Uint8Array) => `0x${bytesToHex(b)}`
const shortLabel = (label: bigint) => `0x${label.toString(16).padStart(64, '0').slice(0, 8)}`
const amountOf = (p: Pool, v: bigint) => `${formatUnits(v, p.decimals)} ${p.symbol}`

async function connect(chainId: number): Promise<RpcClient> {
  const net = rpc(rpcUrl(chainId))
  await assertChain(net, chainId)
  return net
}

// ---------------------------------------------------------------------------
// The mnemonic
// ---------------------------------------------------------------------------
const MNEMONIC_FILE = join(HOME, 'mnemonic')

function mnemonic(): string {
  const m =
    process.env.MONEYSURFER_MNEMONIC ?? (existsSync(MNEMONIC_FILE) ? readFileSync(MNEMONIC_FILE, 'utf8') : undefined)
  if (!m) throw new UsageError('no mnemonic -- run `moneysurfer init` first, or set MONEYSURFER_MNEMONIC')
  if (!isMnemonic(m)) throw new UsageError('the mnemonic is not a valid BIP-39 phrase')
  return m.trim()
}

function saveMnemonic(words: string) {
  mkdirSync(dirname(MNEMONIC_FILE), { recursive: true, mode: 0o700 })
  writeFileSync(MNEMONIC_FILE, `${words}\n`, { mode: 0o600, flag: 'wx' })
  log(`mnemonic saved to ${MNEMONIC_FILE} -- back it up. It is the only key to every deposit you make.`)
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY)
    throw new UsageError('pipe the mnemonic on stdin, e.g. `moneysurfer init --import < words.txt`')
  let s = ''
  for await (const chunk of process.stdin) s += chunk
  return s.trim().split(/\s+/).join(' ')
}

async function init(o: { import?: boolean; fromWallet?: boolean; chain?: number; sig: SignerOpts }) {
  if (existsSync(MNEMONIC_FILE)) throw new UsageError(`${MNEMONIC_FILE} exists already -- refusing to replace it`)
  if (o.import) {
    const words = await readStdin()
    if (!isMnemonic(words)) throw new UsageError('that is not a valid BIP-39 mnemonic')
    return saveMnemonic(words)
  }
  if (o.fromWallet) {
    // privacypools.com's "sign in with wallet": the seed is derived from a
    // signature, which must therefore be deterministic -- so ask for two.
    const chainId = o.chain ?? 1
    const signer = await makeSigner(await connect(chainId), chainId, o.sig)
    log(`asking ${signer.address} to sign the Privacy Pools seed message, twice ...`)
    const typed = seedTypedData(signer.address)
    const [a, b] = [await signer.signTyped(typed), await signer.signTyped(typed)]
    if (a !== b) throw new Error('the wallet signed the same message differently twice; it cannot derive a stable seed')
    saveMnemonic(mnemonicFromSignature(a, signer.address))
    return log(`this is the account privacypools.com derives for ${signer.address}`)
  }
  const words = generateMnemonic(wordlist, 256)
  saveMnemonic(words)
  out(words)
}

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------
async function setup() {
  mkdirSync(ASSETS, { recursive: true })
  for (const [name, want] of Object.entries(ARTIFACTS)) {
    const file = join(ASSETS, name)
    if (existsSync(file) && bytesToHex(sha256(readFileSync(file))) === want) {
      log(`have ${name}`)
      continue
    }
    log(`downloading ${name} ...`)
    const res = await fetch(`${ARTIFACT_URL}/${name}`)
    if (!res.ok) throw new Error(`${name}: HTTP ${res.status}`)
    const bytes = new Uint8Array(await res.arrayBuffer())
    const got = bytesToHex(sha256(bytes))
    if (got !== want) throw new Error(`${name}: sha256 ${got} does not match the pinned ${want} -- refusing it`)
    writeFileSync(file, bytes)
  }
}

// ---------------------------------------------------------------------------
// pools / balance
// ---------------------------------------------------------------------------
const chainsOf = (chain?: number) => (chain === undefined ? registryChains() : [chain])

async function poolsCmd(chain?: number) {
  out(
    `${'CHAIN'.padEnd(10)} ${'POOL'.padEnd(8)} ${'ADDRESS'.padEnd(42)} ${'MINIMUM'.padStart(16)} ${'FEE'.padStart(6)} ${'NOTES'.padStart(7)}`,
  )
  for (const chainId of chainsOf(chain)) {
    const net = await connect(chainId)
    for (const p of await pools(net, chainId)) {
      const [cfg, size, dead] = await Promise.all([
        read(net, p.entrypoint, ENTRYPOINT.assetConfig, p.asset),
        read(net, p.address, POOL.currentTreeSize),
        read(net, p.address, POOL.dead),
      ])
      const open = !p.removed && !dead
      const minimum = open ? amountOf(p, cfg.minimumDepositAmount) : '-'
      const fee = open ? `${Number(cfg.vettingFeeBPS) / 100}%` : '-'
      out(
        `${chainName(chainId).padEnd(10)} ${p.key.padEnd(8)} ${p.address.padEnd(42)} ${minimum.padStart(16)} ${fee.padStart(6)} ${String(size).padStart(7)}${p.removed ? '  removed' : dead ? '  wound down' : ''}`,
      )
    }
  }
}

type Loaded = { net: RpcClient; p: Pool; scope: bigint; ev: PoolEvents; accounts: Account[]; nextIndex: bigint }

async function load(net: RpcClient, p: Pool): Promise<Loaded> {
  const [scope, ev] = await Promise.all([read(net, p.address, POOL.SCOPE), syncPool(net, p)])
  const { accounts, nextIndex } = recover(masterKeys(mnemonic()), scope, ev)
  return { net, p, scope, ev, accounts, nextIndex }
}

async function loadPool(chainId: number, key: string): Promise<Loaded> {
  const net = await connect(chainId)
  return load(net, await pool(net, chainId, key))
}

const statusOf = (a: Account, asp: AspSet) =>
  a.ragequit ? 'ragequit' : a.note.value === 0n ? 'empty' : asp.labels.has(a.label) ? 'approved' : 'not approved yet'

async function balance(chain?: number) {
  let found = 0
  for (const chainId of chainsOf(chain)) {
    const net = await connect(chainId)
    const ps = await pools(net, chainId)
    const [evs, scopes] = await Promise.all([
      syncPools(net, ps),
      Promise.all(ps.map((p) => read(net, p.address, POOL.SCOPE))),
    ])
    const k = masterKeys(mnemonic())
    for (const [i, p] of ps.entries()) {
      const { accounts } = recover(k, scopes[i]!, evs[i]!)
      if (!accounts.length) continue
      const asp = await aspSet(net, p, scopes[i]!, log)
      out(`${chainName(chainId)} ${p.key}`)
      out(`  ${'#'.padEnd(4)} ${'DEPOSITED'.padStart(22)} ${'BALANCE'.padStart(22)}  ${'STATUS'.padEnd(17)} LABEL`)
      for (const a of accounts) {
        found++
        out(
          `  ${String(Number(a.index) + 1).padEnd(4)} ${amountOf(p, a.deposit.value).padStart(22)} ${amountOf(p, a.note.value).padStart(22)}  ${statusOf(a, asp).padEnd(17)} ${shortLabel(a.label)}`,
        )
      }
    }
  }
  if (!found) log('no deposits found for this mnemonic')
}

async function syncCmd(chain?: number) {
  for (const chainId of chainsOf(chain)) {
    const net = await connect(chainId)
    await syncPools(net, await pools(net, chainId), log)
  }
}

// ---------------------------------------------------------------------------
// deposit
// ---------------------------------------------------------------------------
/**
 * Let the Entrypoint take `amount` of the pool's token, which its deposit
 * pulls. Exactly that much, so nothing stays approved once it has.
 */
async function allow(net: RpcClient, signer: Signer, p: Pool, amount: bigint) {
  const allowance = await read(net, p.asset, ERC20.allowance, { owner: signer.address, spender: p.entrypoint })
  if (allowance >= amount) return
  const approve = (value: bigint) =>
    signer.send({ to: p.asset, data: ERC20.approve.encodeInput({ spender: p.entrypoint, value }) })
  // USDT, for one, refuses to change an allowance from one nonzero value to another.
  if (allowance > 0n) log(`reset the old allowance: ${await approve(0n)}`)
  log(`approving the Entrypoint to take ${amountOf(p, amount)} -- a transaction of its own, before the deposit`)
  log(`approved: ${await approve(amount)}`)
}

/**
 * Where a proposal spending account `a` goes in the Safe's queue: at the
 * nonce of one that spends it already -- both cannot execute, and queued
 * behind it this one could only revert -- else after everything queued.
 */
function spendNonce(q: SafeQueue, a: Account): bigint {
  const same = queuedWith(q, nullifierHash(a.note.secrets))
  if (!same) return nextNonce(q)
  log(`account #${a.index + 1n} has a proposal waiting at nonce ${same.nonce} already; this one takes its place`)
  return same.nonce
}

/** A deposit by a Safe, proposed to its owners: one SafeTx, with any approval a token needs batched in. */
async function proposeDeposit(
  net: RpcClient,
  p: Pool,
  safe: string,
  queue: SafeQueue,
  signer: Signer,
  call: SafeCall,
  amount: bigint,
  index: bigint,
) {
  const calls: SafeCall[] = []
  if (p.asset !== NATIVE) {
    const allowance = await read(net, p.asset, ERC20.allowance, { owner: safe, spender: p.entrypoint })
    const approve = (value: bigint): SafeCall => ({
      to: p.asset,
      value: 0n,
      data: ERC20.approve.encodeInput({ spender: p.entrypoint, value }),
    })
    // As from a wallet: exactly the amount, reset first where USDT would refuse.
    if (allowance < amount) calls.push(...(allowance > 0n ? [approve(0n)] : []), approve(amount))
  }
  calls.push(call)
  log(`proposing it to Safe ${safe} as ${signer.address}${calls.length > 1 ? ', batched with the approval' : ''}`)
  const nonce = nextNonce(queue)
  const proposed = await proposeSafeTx({
    net,
    chainId: p.chainId,
    safe,
    signer,
    call: calls.length > 1 ? batch(calls) : call,
    nonce,
  })
  log(`proposed ${proposed.safeTxHash} at nonce ${nonce}; the owners confirm and execute it at ${proposed.queue}`)
  log(
    `  it becomes account #${index + 1n} when executed. Until then a deposit into ${p.key} made outside this Safe would take the same number, and whichever lands second reverts`,
  )
}

async function deposit(
  key: string | undefined,
  amountArg: string | undefined,
  chainId: number,
  sig: SignerOpts,
  safe?: string,
) {
  if (!key || !amountArg) throw new UsageError('usage: moneysurfer deposit <pool> <amount>')
  const { net, p, scope, nextIndex } = await loadPool(chainId, key)
  const where = `${p.key} on ${chainName(chainId)}`
  const cfg = await read(net, p.entrypoint, ENTRYPOINT.assetConfig, p.asset)
  if (p.removed || cfg.pool.toLowerCase() !== p.address.toLowerCase()) {
    throw new UsageError(`${where} was taken off the Entrypoint and takes no deposits`)
  }
  if (await read(net, p.address, POOL.dead)) throw new UsageError(`${where} is wound down`)
  const amount = parseUnits(amountArg, p.decimals)
  if (amount < cfg.minimumDepositAmount) {
    throw new UsageError(`the minimum deposit is ${amountOf(p, cfg.minimumDepositAmount)}`)
  }
  const signer = await makeSigner(net, chainId, sig)
  // With --safe the Safe deposits -- and is then the depositor, the one
  // address that can ragequit. The signer only proposes.
  const queue = safe ? await safeQueue(net, chainId, safe) : undefined
  const from = safe ?? signer.address
  const token = p.asset !== NATIVE
  if (token) {
    const held = await read(net, p.asset, ERC20.balanceOf, from)
    if (held < amount) throw new UsageError(`${from} holds only ${amountOf(p, held)}`)
  }

  // The next unused deposit index; one whose precommitment is on the
  // Entrypoint already (a deposit still pending, say), or in a proposal in
  // the Safe's queue, is skipped.
  const k = masterKeys(mnemonic())
  let index = nextIndex
  let pre = precommitment(depositSecrets(k, scope, index))
  const taken = async (pre: bigint) =>
    (queue !== undefined && queuedWith(queue, pre) !== undefined) ||
    (await read(net, p.entrypoint, ENTRYPOINT.usedPrecommitments, pre))
  while (await taken(pre)) pre = precommitment(depositSecrets(k, scope, ++index))

  const fee = (amount * cfg.vettingFeeBPS) / 10_000n
  log(`depositing ${amountOf(p, amount)} into ${where} from ${from}`)
  log(
    `  the pool keeps ${amountOf(p, amount - fee)} after the ${Number(cfg.vettingFeeBPS) / 100}% vetting fee; account #${index + 1n}`,
  )
  const data = token
    ? TOKEN_DEPOSIT.encodeInput({ _asset: p.asset, _value: amount, _precommitment: pre })
    : ENTRYPOINT.deposit.encodeInput(pre)
  const value = token ? 0n : amount
  if (safe && queue)
    return proposeDeposit(net, p, safe, queue, signer, { to: p.entrypoint, value, data }, amount, index)
  if (token) await allow(net, signer, p, amount)
  try {
    await net.estimateGas({ from: signer.address, to: p.entrypoint, value: `0x${value.toString(16)}`, data: hex(data) })
  } catch (e) {
    throw new UsageError(`the deposit would fail, nothing was deposited: ${(e as Error).message}`)
  }
  let tx: string
  try {
    tx = await signer.send({ to: p.entrypoint, value, data })
  } catch (e) {
    throw new Error(
      `deposit failed or unconfirmed: ${(e as Error).message}\n  check with \`moneysurfer balance --chain ${chainName(chainId).toLowerCase()}\` before trying again`,
    )
  }
  log(`deposited: ${tx}`)
  const d = (await syncPool(net, p)).deposits.find((x) => x.precommitment === pre)
  if (d) log(`label ${shortLabel(d.label)}: the ASP reviews it before it can be withdrawn privately (up to 7 days)`)
}

// ---------------------------------------------------------------------------
// withdraw
// ---------------------------------------------------------------------------
type WithdrawOpts = SignerOpts & {
  id?: string
  relayer?: string
  self?: boolean
  safe?: string
  maxFeePercent: number
  dryRun?: boolean
  threads: number
}

function pickAccount(accounts: Account[], asp: AspSet, amount: bigint | 'all', id?: string): Account {
  if (id !== undefined) {
    const a = accounts.find((x) => String(Number(x.index) + 1) === id.replace(/^#/, ''))
    if (!a) throw new UsageError(`no account #${id} (see: moneysurfer balance)`)
    if (!spendable(a)) throw new UsageError(`account #${id} has nothing left to withdraw`)
    if (!asp.labels.has(a.label))
      throw new UsageError(`account #${id} is not approved by the ASP (yet) -- wait, or ragequit`)
    return a
  }
  const a = accounts.find(
    (x) => spendable(x) && asp.labels.has(x.label) && (amount === 'all' || x.note.value >= amount),
  )
  if (!a) throw new UsageError('no approved account holds that much (see: moneysurfer balance)')
  return a
}

type Quote = { base: string; feeRecipient: string; feeBPS: bigint }

/**
 * The first relayer that serves the pool's asset and quotes `value` --
 * without being told the recipient -- within both the pool's cap and
 * --max-fee-percent.
 */
async function pickRelayer(urls: string[], p: Pool, value: bigint, capBPS: bigint, maxPercent: number): Promise<Quote> {
  const refused: string[] = []
  for (const url of urls) {
    const base = url.replace(/\/$/, '')
    try {
      const details = (await (
        await fetch(`${base}/details?chainId=${p.chainId}&assetAddress=${p.asset}`, {
          signal: AbortSignal.timeout(30_000),
        })
      ).json()) as { feeReceiverAddress?: string }
      if (!details.feeReceiverAddress) {
        refused.push(`${base}: does not serve ${p.symbol}`)
        continue
      }
      const quote = await postJson(`${base}/quote`, { chainId: p.chainId, amount: String(value), asset: p.asset })
      const feeBPS = BigInt(String(quote.feeBPS))
      const asks = `asks ${Number(feeBPS) / 100}%`
      if (feeBPS > capBPS) refused.push(`${base}: ${asks}, above the pool's ${Number(capBPS) / 100}% cap`)
      else if (feeBPS > BigInt(Math.round(maxPercent * 100))) {
        refused.push(`${base}: ${asks}, above --max-fee-percent ${maxPercent}`)
      } else return { base, feeRecipient: checksummed(details.feeReceiverAddress), feeBPS }
    } catch (e) {
      refused.push(`${base}: ${(e as Error).message.replace(`${base}/`, '')}`)
    }
  }
  throw new UsageError(
    `no relayer takes this withdrawal:\n  ${refused.join('\n  ')}\n  raise --max-fee-percent, name one with --relayer, or pay the gas with --self`,
  )
}

const postJson = async (url: string, body: unknown) => {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(60_000),
  })
  const text = await res.text()
  let json: Record<string, unknown> = {}
  try {
    json = JSON.parse(text)
  } catch {
    // reported below
  }
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status} ${String(json.message ?? json.error ?? text).slice(0, 300)}`)
  return json
}

async function withdraw(
  key: string | undefined,
  amountArg: string | undefined,
  to: string | undefined,
  chainId: number,
  o: WithdrawOpts,
) {
  if (!key || !amountArg || !to) throw new UsageError('usage: moneysurfer withdraw <pool> <amount|all> <recipient>')
  if ([o.relayer, o.self, o.safe].filter(Boolean).length > 1) {
    throw new UsageError('--relayer, --self and --safe are exclusive')
  }
  const recipient = checksummed(to)
  const { net, p, scope, ev, accounts } = await loadPool(chainId, key)
  const amount = amountArg === 'all' ? 'all' : parseUnits(amountArg, p.decimals)
  // A --self or --safe signer, and the Safe, are resolved before syncing and
  // proving, so a misconfiguration fails in a second rather than after all that.
  const signer = (o.self || o.safe) && !o.dryRun ? await makeSigner(net, chainId, o) : undefined
  const queue = o.safe ? await safeQueue(net, chainId, o.safe) : undefined
  const asp = await aspSet(net, p, scope, log)
  const a = pickAccount(accounts, asp, amount, o.id)
  const nonce = queue && spendNonce(queue, a)
  const value = amount === 'all' ? a.note.value : amount
  if (value <= 0n || value > a.note.value) {
    throw new UsageError(`account #${a.index + 1n} holds ${amountOf(p, a.note.value)}`)
  }
  const cfg = await read(net, p.entrypoint, ENTRYPOINT.assetConfig, p.asset)

  // Who is paid what. Through a relayer: its fee, quoted without telling it the
  // recipient. Yourself (--self) or a Safe (--safe): no fee, and the sender pays the gas.
  const quote =
    o.self || o.safe
      ? undefined
      : await pickRelayer(
          o.relayer ? [o.relayer] : entrypoint(chainId).relayers,
          p,
          value,
          cfg.maxRelayFeeBPS,
          o.maxFeePercent,
        )
  const relayer = quote?.base
  const feeRecipient = quote?.feeRecipient ?? recipient
  const feeBPS = quote?.feeBPS ?? 0n
  if (quote) log(`relayer ${quote.base}: fee ${Number(feeBPS) / 100}% to ${feeRecipient}`)
  const fee = (value * feeBPS) / 10_000n
  log(`withdrawing ${amountOf(p, value)} from account #${a.index + 1n}: ${amountOf(p, value - fee)} to ${recipient}`)

  // The proof: the note is in the pool's state tree, its label in the ASP's set.
  const state = await stateTree(net, p, ev)
  const leaf = state.levels[0]!.indexOf(a.note.commitment)
  const labelAt = asp.tree.levels[0]!.indexOf(a.label)
  if (leaf < 0) throw new Error('the note is missing from the synced state tree')
  const sp = state.proof(leaf)
  const ap = asp.tree.proof(labelAt)
  const pad = (xs: bigint[]) => [...xs, ...Array<bigint>(32 - xs.length).fill(0n)]
  const data = relayData(recipient, feeRecipient, feeBPS)
  const next = withdrawalSecrets(masterKeys(mnemonic()), a.label, BigInt(a.withdrawals.length))
  log(`proving on ${o.threads} threads ...`)
  const proof = await prove(
    'withdraw',
    {
      withdrawnValue: value,
      stateRoot: state.root,
      stateTreeDepth: 32n,
      ASPRoot: asp.root,
      ASPTreeDepth: 32n,
      context: withdrawalContext(p.entrypoint, data, scope),
      label: a.label,
      existingValue: a.note.value,
      existingNullifier: a.note.secrets.nullifier,
      existingSecret: a.note.secrets.secret,
      newNullifier: next.nullifier,
      newSecret: next.secret,
      stateSiblings: pad(sp.siblings),
      stateIndex: BigInt(sp.index),
      ASPSiblings: pad(ap.siblings),
      ASPIndex: BigInt(ap.index),
    },
    o.threads,
  )
  const calldata = ENTRYPOINT.relay.encodeInput({
    _withdrawal: { processooor: p.entrypoint, data },
    _proof: solidityProof(proof) as never,
    _scope: scope,
  })
  // The whole relay, simulated: roots, context, nullifier, fee cap -- before anyone pays gas.
  const sim = await net.dryRun({
    from: o.safe ?? signer?.address ?? feeRecipient,
    to: p.entrypoint,
    data: hex(calldata),
  })
  if (!sim.success) throw new Error(`the withdrawal would revert: ${sim.reason}`)
  log('simulated: the Entrypoint accepts it')
  if (o.dryRun) {
    out(JSON.stringify({ entrypoint: p.entrypoint, recipient, fee: String(fee), calldata: hex(calldata) }, null, 2))
    return
  }
  if (o.safe && nonce !== undefined) {
    log(`proposing to Safe ${o.safe} as ${signer!.address}`)
    const proposed = await proposeSafeTx({
      net,
      chainId,
      safe: o.safe,
      signer: signer!,
      call: { to: p.entrypoint, value: 0n, data: calldata },
      nonce,
    })
    log(`proposed ${proposed.safeTxHash} at nonce ${nonce}; the owners confirm and execute it at ${proposed.queue}`)
    log(
      "  execute it soon: the proof holds only while the ASP root it names is the Entrypoint's latest, and its state root\n" +
        "  one of the pool's last 64. If either moves on first, the execution reverts, nothing lost -- propose again",
    )
    return
  }

  const spent = nullifierHash(a.note.secrets)
  if (relayer) {
    const reply = await postJson(`${relayer}/request`, {
      withdrawal: { processooor: p.entrypoint, data: hex(data) },
      publicSignals: proof.publicSignals.map(String),
      proof: snarkjsProof(proof),
      scope: String(scope),
      chainId,
    })
    log(`relayer accepted${reply.txHash ? `: ${reply.txHash}` : ''} -- waiting for the chain`)
  } else {
    log(`submitting from ${signer!.address} -- this links that address to the withdrawal`)
    try {
      log(`sent: ${await signer!.send({ to: p.entrypoint, data: calldata })}`)
    } catch (e) {
      throw new Error(
        `withdrawal failed or unconfirmed: ${(e as Error).message}\n  check with \`moneysurfer balance\` before trying again`,
      )
    }
  }
  // The chain, not the relayer, says when it is done.
  for (const deadline = Date.now() + 15 * 60_000; Date.now() < deadline; await sleep(4000)) {
    if (await read(net, p.address, POOL.nullifierHashes, spent)) {
      const w = (await syncPool(net, p)).withdrawals.find((x) => x.spentNullifier === spent)
      return log(`withdrawn${w ? `: ${w.tx}` : ''}`)
    }
  }
  throw new Error('not confirmed within 15 minutes -- check `moneysurfer balance` before trying again')
}

// ---------------------------------------------------------------------------
// ragequit
// ---------------------------------------------------------------------------
async function ragequit(
  key: string | undefined,
  chainId: number,
  o: SignerOpts & { id?: string; threads: number; safe?: string },
) {
  if (!key || o.id === undefined) throw new UsageError('usage: moneysurfer ragequit <pool> --id N')
  const { net, p, accounts } = await loadPool(chainId, key)
  const a = accounts.find((x) => String(Number(x.index) + 1) === o.id!.replace(/^#/, ''))
  if (!a) throw new UsageError(`no account #${o.id} (see: moneysurfer balance)`)
  if (!spendable(a)) throw new UsageError(`account #${o.id} has nothing left`)
  const signer = await makeSigner(net, chainId, o)
  const queue = o.safe ? await safeQueue(net, chainId, o.safe) : undefined
  const depositor = addr.addChecksum(await read(net, p.address, POOL.depositors, a.label))
  if (depositor.toLowerCase() !== (o.safe ?? signer.address).toLowerCase()) {
    throw new UsageError(
      `only the depositing address ${depositor} can ragequit this account${o.safe ? '' : ` -- if that is a Safe, pass --safe ${depositor}`}`,
    )
  }
  log(`proving on ${o.threads} threads ...`)
  const proof = await prove(
    'commitment',
    { value: a.note.value, label: a.label, nullifier: a.note.secrets.nullifier, secret: a.note.secrets.secret },
    o.threads,
  )
  const data = POOL.ragequit.encodeInput(solidityProof(proof) as never)
  if (o.safe && queue) {
    log(
      `proposing to Safe ${o.safe} as ${signer.address}: ${amountOf(p, a.note.value)} back to the Safe -- this is public`,
    )
    const nonce = spendNonce(queue, a)
    const proposed = await proposeSafeTx({
      net,
      chainId,
      safe: o.safe,
      signer,
      call: { to: p.address, value: 0n, data },
      nonce,
    })
    return log(
      `proposed ${proposed.safeTxHash} at nonce ${nonce}; the owners confirm and execute it at ${proposed.queue}`,
    )
  }
  const sim = await net.dryRun({ from: signer.address, to: p.address, data: hex(data) })
  if (!sim.success) throw new Error(`the ragequit would revert: ${sim.reason}`)
  log(`ragequitting ${amountOf(p, a.note.value)} back to ${signer.address} -- this is public`)
  try {
    log(`ragequit: ${await signer.send({ to: p.address, data })}`)
  } catch (e) {
    throw new Error(
      `ragequit failed or unconfirmed: ${(e as Error).message}\n  check with \`moneysurfer balance\` before trying again`,
    )
  }
}

// ---------------------------------------------------------------------------
export const HELP = `moneysurfer v1 -- Privacy Pools from the command line

  setup                              fetch the circuits, check their pinned sha256
  init                               make a new mnemonic (the one secret behind every note)
       --import                      ... or take one on stdin
       --from-wallet                 ... or derive privacypools.com's from your wallet's signature
  pools                              every pool the Entrypoints registered: minimum deposit, fee, size
  balance                            your accounts and what each holds
  sync                               pull every pool's events into the cache
  deposit <pool> <amount>            deposit from your wallet (a token is approved first, exactly)
  withdraw <pool> <amount|all> <to>  withdraw privately, through a relayer by default
       --id N                        from account #N (default: the first that can)
       --relayer URL | --self        a relayer of your choosing, or submit and pay gas yourself
       --safe SAFE                   ... or have that Safe submit it (see below)
       --max-fee-percent N           refuse a relayer fee above N% (default 1)
       --dry-run                     prove and simulate, but send nothing
  ragequit <pool> --id N             take an account back publicly, to the depositing address

  --chain NAME                       ethereum (default), optimism, arbitrum

env: MONEYSURFER_MNEMONIC, MONEYSURFER_ENTRYPOINTS`

/** The commands this protocol answers to; cli.ts dispatches on the names. */
export const COMMANDS = ['setup', 'init', 'pools', 'balance', 'sync', 'deposit', 'withdraw', 'ragequit'] as const

export async function run(cmd: string, rest: string[], v: Flags, c: Common): Promise<void> {
  const chain = v.chain === undefined ? undefined : parseChain(v.chain)
  const commands: Record<string, () => unknown> = {
    setup: () => setup(),
    init: () => init({ import: v.import, fromWallet: v['from-wallet'], chain, sig: c.sig }),
    pools: () => poolsCmd(chain),
    balance: () => balance(chain),
    sync: () => syncCmd(chain),
    deposit: () => deposit(rest[0], rest[1], chain ?? 1, c.sig, c.safe),
    withdraw: () =>
      withdraw(rest[0], rest[1], rest[2], chain ?? 1, {
        ...c.sig,
        id: v.id,
        relayer: v.relayer,
        self: v.self,
        safe: c.safe,
        maxFeePercent: c.maxFeePercent,
        dryRun: c.dryRun,
        threads: c.threads,
      }),
    ragequit: () => ragequit(rest[0], chain ?? 1, { ...c.sig, id: v.id, threads: c.threads, safe: c.safe }),
  }
  if (!Object.hasOwn(commands, cmd)) throw new UsageError(`unknown v1 command '${cmd}'\n\n${HELP}`)
  await commands[cmd]!()
}
