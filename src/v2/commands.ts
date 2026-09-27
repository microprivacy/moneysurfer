// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Privacy Pools V2 from the command line -- V1's commands against V2's
 * protocol. Where the two differ the difference is handled here rather than
 * papered over, and each one is called out in place:
 *
 *  - **one vault, many assets.** V1's `<pool>` is an `<asset>` symbol, and
 *    `Entrypoint.assets()` decides which symbols mean anything.
 *  - **the fee is added, not deducted.** V1 deposits `amount` and the pool
 *    keeps `amount - fee`; V2 deposits `value` and you pay `value + fee`.
 *  - **the Keystore.** An account must be registered before it can spend.
 *    V1 has no equivalent, so `register` is a command V2 adds.
 *  - **`transact`, not `withdraw`.** A private spend is an N-in/M-out
 *    joinsplit; `withdraw` is that with one unshielded output.
 *  - **wrapped assets.** USDC and USDT are disabled at the Entrypoint and
 *    reach the vault as yield-vault shares through a PPRouter (zap.ts).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { entropyToMnemonic, generateMnemonic, mnemonicToEntropy, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import type { RpcClient } from 'micro-eth-signer/net.js'
import { formatUnits, parseUnits } from 'micro-eth-signer/utils.js'
import { type Common, checksummed, type Flags } from '../shared/flags.ts'
import { assertChain, read, rpc } from '../shared/rpc.ts'
import { batch, nextNonce, prepareSafeTx, proposeSafeTx, queuedWith, type SafeCall, safeQueue } from '../shared/safe.ts'
import { makeSigner, type Signer } from '../shared/signer.ts'
import { type Account, recover, spendable } from './account.ts'
import { fetchArtifact, have, pinned, verificationKey } from './artifacts.ts'
import {
  ASP,
  type Asset,
  aspIndexOf,
  aspSet,
  ENTRYPOINT,
  ERC20,
  KEYSTORE,
  keystoreTree,
  leafIndexOf,
  POOL,
  pickAsset,
  assets as readAssets,
  stateTree,
  sync,
} from './chain.ts'
import {
  ASP_PUBLIC_KEY,
  ASP_REGISTRY,
  ASSETS,
  CHAIN_ID,
  CIRCUITS,
  DEPOSIT_VERIFIER,
  ENTRYPOINT_ADDR,
  HOME,
  isNative,
  KEYSTORE_ADDR,
  POOL_ADDR,
  rpcUrl,
  transactCircuit,
  UsageError,
} from './config.ts'
import {
  aspLeaf,
  authDigest,
  changeSecret,
  commitmentLeaf,
  commitment as commitmentOf,
  depositSecrets,
  deriveKeys,
  type Keys,
  label as labelOf,
  noteAddressHash,
  nullifier as nullifierOf,
  nullifyingKeyHash,
  payoutRouting,
  precommitment,
  rootSecretFromSignature,
  secretDerivationTypedData,
  transactContext,
} from './crypto.ts'
import { buildDeposit, NO_NOTE, queuedDeposits } from './deposit.ts'
import { ragequit as ragequitWitness, transact as transactWitness } from './notes.ts'
import { prove, solidityProof } from './prover.ts'
import { assertRouter, explainRouterRevert, HEADROOM_PPM, quote, ROUTER, sharesFor } from './zap.ts'

const log = (s: string) => process.stderr.write(`${s}\n`)
const out = (s: string) => process.stdout.write(`${s}\n`)
const hex = (b: Uint8Array) => `0x${bytesToHex(b)}`
const hex32 = (n: bigint) => `0x${n.toString(16).padStart(64, '0')}`
const shortLabel = (label: bigint) => hex32(label).slice(0, 10)

/** What `<amount>` is denominated in for an asset: the underlying where one is wrapped. */
const units = (a: Asset) => (a.router ? { decimals: a.router.decimals, symbol: a.router.underlyingSymbol } : a)
const amountOf = (a: Asset, v: bigint) => `${formatUnits(v, a.decimals)} ${a.symbol}`
const spendOf = (a: Asset, v: bigint) => `${formatUnits(v, units(a).decimals)} ${units(a).symbol}`

async function connect(): Promise<RpcClient> {
  const net = rpc(rpcUrl())
  await assertChain(net, CHAIN_ID)
  return net
}

// ---------------------------------------------------------------------------
// The seed
// ---------------------------------------------------------------------------
/**
 * V2's keys come from a wallet signature, not a BIP-39 seed -- but the first
 * thing that signature becomes is a 32-byte *root secret*, and 32 bytes is
 * exactly what 24 words carry. So the words this client stores **are** that
 * root secret, and `init --from-wallet` writes down the one the app would have
 * derived rather than a different secret that happens to sit beside it.
 */
const MNEMONIC_FILE = join(HOME, 'mnemonic')

function rootSecret(): Uint8Array {
  const m =
    process.env.MONEYSURFER_MNEMONIC ?? (existsSync(MNEMONIC_FILE) ? readFileSync(MNEMONIC_FILE, 'utf8') : undefined)
  if (!m) throw new UsageError('no seed -- run `moneysurfer v2 init` first, or set MONEYSURFER_MNEMONIC')
  if (!validateMnemonic(m.trim(), wordlist)) throw new UsageError('the seed is not a valid BIP-39 phrase')
  return mnemonicToEntropy(m.trim(), wordlist)
}

function saveMnemonic(words: string) {
  mkdirSync(dirname(MNEMONIC_FILE), { recursive: true, mode: 0o700 })
  writeFileSync(MNEMONIC_FILE, `${words}\n`, { mode: 0o600, flag: 'wx' })
  log(`seed saved to ${MNEMONIC_FILE} -- back it up. It is the only key to every note you make.`)
}

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) throw new UsageError('pipe the words on stdin, e.g. `moneysurfer v2 init --import < words`')
  let s = ''
  for await (const chunk of process.stdin) s += chunk
  return s.trim().split(/\s+/).join(' ')
}

async function init(o: { import?: boolean; fromWallet?: boolean; sig: Common['sig'] }) {
  if (existsSync(MNEMONIC_FILE)) throw new UsageError(`${MNEMONIC_FILE} exists already -- refusing to replace it`)
  if (o.import) {
    const words = await readStdin()
    if (!validateMnemonic(words, wordlist)) throw new UsageError('that is not a valid BIP-39 mnemonic')
    return saveMnemonic(words)
  }
  if (o.fromWallet) {
    // "Sign in with wallet": the root secret is HKDF of the signature's r, so
    // the signature must be deterministic -- ask for it twice and compare.
    const signer = await makeSigner(await connect(), CHAIN_ID, o.sig)
    log(`asking ${signer.address} to sign the secret-derivation message, twice ...`)
    const typed = secretDerivationTypedData(signer.address)
    const [a, b] = [await signer.signTyped(typed), await signer.signTyped(typed)]
    if (a !== b) throw new Error('the wallet signed the same message differently twice; it cannot derive a stable seed')
    saveMnemonic(entropyToMnemonic(rootSecretFromSignature(a, signer.address), wordlist))
    log(`these words carry the root secret v2.privacypools.com derives for ${signer.address}`)
    log('  UNVERIFIED: the derivation was recovered from the app bundle and has never been checked')
    log('  against an account the app itself made. Confirm `register` before funding anything.')
    return
  }
  const words = generateMnemonic(wordlist, 256)
  saveMnemonic(words)
  out(words)
}

/**
 * The account a command acts as: the keys from the seed, and the address they
 * are registered against. V2 binds a note to an owner address, so `--safe` and
 * `--from` change *which* notes are yours, not merely who signs.
 */
async function account(net: RpcClient, c: Common): Promise<{ keys: Keys; root: Uint8Array; owner: string }> {
  const root = rootSecret()
  const owner = c.safe ?? c.sig.from ?? (await makeSigner(net, CHAIN_ID, c.sig)).address
  return { keys: deriveKeys(root), root, owner: checksummed(owner) }
}

/**
 * The signer, unless this is a dry run -- in which case there is nothing to
 * sign and the owner address is all a simulation needs. V1 resolves its signer
 * the same way, so a missing wallet fails in a second rather than after a
 * minute of proving.
 */
const signerFor = (net: RpcClient, c: Common, owner: string) =>
  c.dryRun
    ? Promise.resolve({ address: owner, send: () => Promise.reject(new Error('dry run')) } as unknown as Signer)
    : makeSigner(net, CHAIN_ID, c.sig)

// ---------------------------------------------------------------------------
// setup
// ---------------------------------------------------------------------------
async function setup(which: string[]) {
  mkdirSync(ASSETS, { recursive: true })
  const circuits = which.length ? which : ['deposit', 'ragequit', 'transact_1x1']
  for (const c of circuits) {
    if (!CIRCUITS[c]) throw new UsageError(`unknown circuit '${c}'`)
    for (const kind of ['wasm', 'zkey', 'vkey'] as const) {
      if (have(c, kind)) {
        log(`have ${c}.${kind}`)
        continue
      }
      log(`downloading ${c}.${kind} ...`)
      const bytes = await fetchArtifact(c, kind)
      log(`  ${bytes.length} bytes, sha256 ${pinned(c, kind)} matches`)
    }
    out(`${c}: nPublic ${verificationKey(c).nPublic}`)
  }
}

// ---------------------------------------------------------------------------
// pools / balance / sync
// ---------------------------------------------------------------------------
async function poolsCmd() {
  const net = await connect()
  const all = await readAssets(net)
  const ev = await sync(net)
  const notes = (a: Asset) =>
    ev.deposits.filter((d) => d.tokenId.toLowerCase() === a.tokenId.toLowerCase()).length +
    ev.transacts
      .filter((t) => t.tokenId.toLowerCase() === a.tokenId.toLowerCase())
      .reduce((n, t) => n + t.commitments.length, 0)
  out(
    `${'ASSET'.padEnd(8)} ${'TOKENID'.padEnd(42)} ${'DEC'.padStart(3)} ${'MINIMUM'.padStart(18)} ${'FEE'.padStart(6)} ${'NOTES'.padStart(6)}  SPEND`,
  )
  for (const a of all) {
    const min = a.enabled ? amountOf(a, a.minAmount) : '-'
    const fee = a.enabled ? `${Number(a.vettingFeeBPS) / 100}%` : '-'
    const route = all.find(
      (x) => x.enabled && x.router && x.router.underlying.toLowerCase() === a.tokenId.toLowerCase(),
    )
    const how = !a.enabled
      ? `disabled${route ? ` -- deposit it as ${route.key}` : ''}`
      : a.router
        ? `${a.router.underlyingSymbol}, wrapped by ${a.router.address.slice(0, 10)}`
        : a.symbol
    out(
      `${a.key.padEnd(8)} ${a.tokenId.padEnd(42)} ${String(a.decimals).padStart(3)} ${min.padStart(18)} ${fee.padStart(6)} ${String(notes(a)).padStart(6)}  ${how}`,
    )
  }
  out('')
  out("MINIMUM is in the asset's own units. For a wrapped asset that is shares, not the underlying:")
  out('a 10 ppUSDC minimum costs a little over 10 USDC, because a share is worth more than a dollar.')
}

async function balance(c: Common) {
  const net = await connect()
  const { keys, root, owner } = await account(net, c)
  const all = await readAssets(net)
  const ev = await sync(net, log)
  const { accounts } = recover(keys, root, owner, [...new Set(all.map((a) => a.tokenId))], ev)
  if (!accounts.length) return log(`no notes found for this seed at ${owner}`)

  const asp = await aspSet(net)
  const registered = (await read(net, KEYSTORE_ADDR, KEYSTORE.nullifyingKeys, owner)) !== 0n
  out(`${owner}${registered ? '' : '   NOT REGISTERED -- `moneysurfer v2 register` before spending'}`)
  const byToken = new Map<string, Account[]>()
  for (const a of accounts) {
    const k = a.tokenId.toLowerCase()
    byToken.set(k, [...(byToken.get(k) ?? []), a])
  }
  for (const [tokenId, list] of byToken) {
    const asset = all.find((x) => x.tokenId.toLowerCase() === tokenId)!
    out(asset.key)
    out(`  ${'#'.padEnd(4)} ${'DEPOSITED'.padStart(24)} ${'BALANCE'.padStart(24)}  ${'STATUS'.padEnd(17)} LABEL`)
    for (const a of list) {
      const spent = await read(
        net,
        POOL_ADDR,
        POOL.spentNullifiers,
        nullifierOf(keys.privateNullifyingKey, a.note.commitment),
      )
      const status = a.ragequit
        ? 'ragequit'
        : a.lost
          ? 'unfollowable'
          : a.note.value === 0n
            ? 'empty'
            : spent !== 0n
              ? 'spent'
              : asp.tree.levels[0]!.includes(aspLeaf(a.label))
                ? 'approved'
                : 'not approved yet'
      out(
        `  ${String(Number(a.index) + 1).padEnd(4)} ${amountOf(asset, a.deposit.value).padStart(24)} ${amountOf(asset, a.note.value).padStart(24)}  ${status.padEnd(17)} ${shortLabel(a.label)}`,
      )
      if (a.lost) log(`  #${Number(a.index) + 1}: ${a.lost}`)
    }
  }
}

async function syncCmd() {
  const ev = await sync(await connect(), log)
  out(`synced through block ${ev.block}`)
}

// ---------------------------------------------------------------------------
// register -- V2 only
// ---------------------------------------------------------------------------
/**
 * The Keystore holds one leaf per account, `Poseidon(owner, nullifyingKeyHash,
 * authDigest)`, and every spend proves membership of it. Depositing does not
 * need it -- the deposit circuit has no keystore signal -- but `withdraw` and
 * `ragequit` both do, so a deposit made before registering is stuck until it
 * happens. `setViewingKey` is the other half: it publishes the X25519 key
 * other people encrypt notes to you with. Only `setAuthPolicy` writes the leaf.
 */
async function register(c: Common) {
  const net = await connect()
  const { keys, owner } = await account(net, c)
  const [viewing, nullifying] = await Promise.all([
    read(net, KEYSTORE_ADDR, KEYSTORE.viewingKeys, owner),
    read(net, KEYSTORE_ADDR, KEYSTORE.nullifyingKeys, owner),
  ])
  const wantViewing = hex(keys.viewingPublicKey)
  const wantNullifying = nullifyingKeyHash(keys.privateNullifyingKey)
  const haveViewing = hex(viewing as unknown as Uint8Array)
  out(`account      ${owner}`)
  out(`  viewingKey   ${wantViewing}${haveViewing === wantViewing ? '  (already set)' : ''}`)
  out(`  nullifying   ${hex32(wantNullifying)}${nullifying === wantNullifying ? '  (already set)' : ''}`)
  out(`  authDigest   ${hex32(authDigest(keys.privateRevocableKey))}`)
  const calls: SafeCall[] = []
  if (haveViewing !== wantViewing) {
    calls.push({ to: KEYSTORE_ADDR, value: 0n, data: KEYSTORE.setViewingKey.encodeInput(keys.viewingPublicKey) })
  }
  if (nullifying !== wantNullifying) {
    calls.push({
      to: KEYSTORE_ADDR,
      value: 0n,
      data: KEYSTORE.setAuthPolicy.encodeInput({
        authDigest: authDigest(keys.privateRevocableKey),
        nullifyingKeyHash: wantNullifying,
      }),
    })
  }
  if (!calls.length) return log('already registered; nothing to do')
  if (nullifying !== 0n && nullifying !== wantNullifying) {
    throw new UsageError(
      `${owner} is registered with a different nullifying key (${hex32(nullifying)}). ` +
        "That is another seed's account -- registering again would orphan its notes",
    )
  }
  log('this is public: it records that this address uses Privacy Pools, and nothing else')
  if (c.safe) return proposeCalls(net, c, calls, 'the registration')
  const signer = await signerFor(net, c, owner)
  for (const call of calls) {
    await simulate(net, signer.address, call)
    if (c.dryRun) {
      out(JSON.stringify({ to: call.to, data: hex(call.data), value: '0x0' }, null, 2))
      continue
    }
    log(`sent: ${await signer.send({ to: call.to, value: call.value, data: call.data })}`)
  }
}

// ---------------------------------------------------------------------------
// deposit
// ---------------------------------------------------------------------------
/**
 * Let `spender` take exactly `amount` of `token`, and no more. V1's rule,
 * kept: USDT refuses to move an allowance from one nonzero value to another,
 * so it is zeroed first.
 */
async function allow(net: RpcClient, signer: Signer, token: string, spender: string, amount: bigint, what: string) {
  const allowance = await read(net, token, ERC20.allowance, { owner: signer.address, spender })
  if (allowance >= amount) return
  const approve = (value: bigint) => signer.send({ to: token, data: ERC20.approve.encodeInput({ spender, value }) })
  if (allowance > 0n) log(`reset the old allowance: ${await approve(0n)}`)
  log(`approving ${spender} to take ${what} -- a transaction of its own, before the deposit`)
  log(`approved: ${await approve(amount)}`)
}

/** The same approval as a SafeCall, for batching into one SafeTx. */
async function allowCalls(net: RpcClient, safe: string, token: string, spender: string, amount: bigint) {
  const allowance = await read(net, token, ERC20.allowance, { owner: safe, spender })
  if (allowance >= amount) return []
  const approve = (value: bigint): SafeCall => ({
    to: token,
    value: 0n,
    data: ERC20.approve.encodeInput({ spender, value }),
  })
  return [...(allowance > 0n ? [approve(0n)] : []), approve(amount)]
}

async function deposit(key: string | undefined, amountArg: string | undefined, c: Common) {
  if (!key || !amountArg) throw new UsageError('usage: moneysurfer v2 deposit <asset> <amount>')
  const net = await connect()
  const all = await readAssets(net)
  const asset = pickAsset(all, key)
  if (!asset.enabled) {
    throw new UsageError(
      `${asset.key} is disabled at the Entrypoint${asset.router ? '' : ' and has no wrapping router -- it cannot be deposited'}`,
    )
  }
  if (await read(net, POOL_ADDR, POOL.paused)) throw new UsageError('the PoolVault is paused')

  const { keys, root, owner } = await account(net, c)
  const u = units(asset)
  const spendAmount = parseUnits(amountArg, u.decimals)
  if (spendAmount <= 0n) throw new UsageError('a deposit of nothing is not a deposit')

  // `value` is what lands in the pool, always in the tokenId's own units. For a
  // wrapped asset that is shares, and the amount the operator typed was
  // underlying -- so it has to be converted before the minimum can be checked
  // at all, or the check would compare two different denominations.
  const value = asset.router ? await sharesFor(net, asset.tokenId, spendAmount) : spendAmount
  if (value < asset.minAmount) {
    const floor = asset.router
      ? `${formatUnits((await quote(net, asset.router.address, asset.minAmount)).underlyingNeeded, u.decimals)} ${u.symbol}`
      : amountOf(asset, asset.minAmount)
    throw new UsageError(
      `the minimum deposit is ${amountOf(asset, asset.minAmount)}, which costs about ${floor} -- ` +
        `${spendUnitsNote(asset)}you asked for ${spendOf(asset, spendAmount)}`,
    )
  }

  // The next unused deposit index for this asset. The walk skips one whose
  // commitment the pool already holds (mined since the last sync), and one a
  // deposit waiting in the Safe's queue has claimed -- whatever its value, or
  // two deposits would share secrets and `recover` would find only one.
  const ev = await sync(net)
  const { nextIndex } = recover(keys, root, owner, [asset.tokenId], ev)
  const queue = c.safe ? await safeQueue(net, CHAIN_ID, c.safe) : undefined
  const waiting = queue ? queuedDeposits(queue, asset.tokenId) : []
  let index = nextIndex.get(asset.tokenId.toLowerCase()) ?? 0n
  for (;;) {
    const s = depositSecrets(root, asset.tokenId, index)
    const claimed = waiting.some((w) => commitmentAt(asset.tokenId, owner, s, w.value) === w.commitment)
    if (!claimed && (await read(net, POOL_ADDR, POOL.commitments, commitmentAt(asset.tokenId, owner, s, value))) === 0n)
      break
    index++
  }

  const fee = (value * asset.vettingFeeBPS) / 10_000n
  log(`depositing ${amountOf(asset, value)} from ${owner}`)
  // V2 adds the vetting fee on top of the deposit rather than taking it out of
  // it, which is the opposite of V1 -- say so in the numbers.
  if (fee > 0n)
    log(`  it costs ${amountOf(asset, value + fee)}: the ${Number(asset.vettingFeeBPS) / 100}% vetting fee is on top`)
  log(`  account #${index + 1n}`)

  const secrets = depositSecrets(root, asset.tokenId, index)
  const started = Date.now()
  log(`proving on ${c.threads} threads ...`)
  const dep = await buildDeposit({
    owner,
    noteSecret: secrets.noteSecret,
    depositSecret: secrets.depositSecret,
    tokenId: asset.tokenId,
    value,
    vettingFeeBPS: asset.vettingFeeBPS,
    threads: c.threads,
  })
  log(`proved in ${((Date.now() - started) / 1000).toFixed(1)}s`)
  log(`  label ${shortLabel(dep.label)}: the ASP reviews it before it can be spent privately`)

  const wrapped = asset.router ? await wrappedCall(net, asset, dep, value, c) : undefined
  const call = wrapped?.call ?? { to: ENTRYPOINT_ADDR, value: dep.value, data: dep.data }
  const routerSpend = wrapped?.maxUnderlyingIn ?? 0n
  const approvalToken = asset.router
    ? asset.router.native
      ? undefined
      : asset.router.underlying
    : isNative(asset.tokenId)
      ? undefined
      : asset.tokenId
  const approvalSpender = asset.router ? asset.router.address : ENTRYPOINT_ADDR
  const approvalAmount = asset.router ? routerSpend : value + fee

  if (c.safe) {
    const calls: SafeCall[] = []
    if (approvalToken) calls.push(...(await allowCalls(net, c.safe, approvalToken, approvalSpender, approvalAmount)))
    calls.push({ to: call.to, value: call.value, data: call.data })
    return proposeCalls(
      net,
      c,
      calls,
      `the deposit; it becomes account #${index + 1n} when executed`,
      nextNonce(queue!),
    )
  }

  const signer = await signerFor(net, c, owner)
  if (approvalToken && !c.dryRun) {
    const held = await read(net, approvalToken, ERC20.balanceOf, signer.address)
    if (held < approvalAmount) {
      throw new UsageError(`${signer.address} holds only ${formatUnits(held, u.decimals)} ${u.symbol}`)
    }
    await allow(
      net,
      signer,
      approvalToken,
      approvalSpender,
      approvalAmount,
      `${formatUnits(approvalAmount, u.decimals)} ${u.symbol}`,
    )
  }
  if (c.dryRun) {
    // The approval comes first in the real run, so simulating the deposit
    // before it is granted reports an allowance it is about to have. Say what
    // would be sent, then say what the chain made of it, and let the reader
    // tell the two apart.
    out(
      JSON.stringify(
        {
          approve: approvalToken && { token: approvalToken, spender: approvalSpender, amount: String(approvalAmount) },
          to: call.to,
          value: `0x${call.value.toString(16)}`,
          data: hex(call.data),
          commitment: hex32(dep.commitment),
          label: hex32(dep.label),
          account: Number(index) + 1,
        },
        null,
        2,
      ),
    )
    const sim = await net.dryRun({ from: owner, to: call.to, value: call.value, data: hex(call.data) })
    log(
      sim.success
        ? 'simulated: the chain accepts it'
        : `simulated against today's state it reverts: ${explainRouterRevert((sim as { data?: string }).data, units(asset).symbol) ?? sim.reason}` +
            (approvalToken ? '\n  (expected before the approval above has been made)' : ''),
    )
    return
  }
  await simulate(net, signer.address, call, asset)
  log('simulated: the chain accepts it')
  try {
    log(`deposited: ${await signer.send({ to: call.to, value: call.value, data: call.data })}`)
  } catch (e) {
    throw new Error(
      `deposit failed or unconfirmed: ${(e as Error).message}\n  check with \`moneysurfer v2 balance\` before trying again`,
    )
  }
}

/** The commitment an index would produce, for probing whether it is already used. */
function commitmentAt(tokenId: string, owner: string, s: { noteSecret: bigint; depositSecret: bigint }, value: bigint) {
  const pre = precommitment(noteAddressHash(owner, s.noteSecret), tokenId, value)
  return commitmentOf(pre, labelOf(pre, s.depositSecret))
}

const spendUnitsNote = (a: Asset) => (a.router ? `amounts for ${a.key} are in ${units(a).symbol} -- ` : '')

/**
 * The PPRouter call that stands in for a plain deposit. The proof, the note
 * data and the ASP opening go through untouched -- that is what keeps the
 * proof's context valid -- and the only thing added is the cap on what the
 * router may spend.
 */
async function wrappedCall(
  net: RpcClient,
  asset: Asset,
  dep: Awaited<ReturnType<typeof buildDeposit>>,
  value: bigint,
  c: Common,
): Promise<{ call: { to: string; value: bigint; data: Uint8Array }; maxUnderlyingIn: bigint }> {
  const r = asset.router!
  await assertRouter(net, r.address, asset.tokenId, ENTRYPOINT_ADDR)
  // --max-fee-percent caps the premium over the quote, as it caps a relayer's
  // fee on the way out. Unset, it is the SDK's one part per million -- V1's
  // default of 1% for a relayer fee would be far too generous a bound here.
  const ppm = c.maxFeePercent === undefined ? HEADROOM_PPM : BigInt(Math.max(1, Math.round(c.maxFeePercent * 10_000)))
  const q = await quote(net, r.address, value, ppm)
  const u = units(asset)
  log(`  wrapping: ${formatUnits(q.underlyingNeeded, u.decimals)} ${u.symbol} buys ${amountOf(asset, q.total)}`)
  log(
    `  at most  ${formatUnits(q.maxUnderlyingIn, u.decimals)} ${u.symbol} will be taken (${Number(ppm) / 10_000}% over the quote);`,
  )
  log('    above that the router reverts and nothing moves')
  const args = {
    proof: solidityProof(dep.proof),
    noteData: { hint: hexToBytes(dep.noteData.hint.slice(2)), ciphertext: dep.noteData.ciphertext },
    aspCiphertext: dep.aspCiphertext,
  }
  const call = r.native
    ? { to: r.address, value: q.maxUnderlyingIn, data: ROUTER.depositExactSharesNative.encodeInput(args) }
    : {
        to: r.address,
        value: 0n,
        data: ROUTER.depositExactShares.encodeInput({ ...args, maxUnderlyingIn: q.maxUnderlyingIn }),
      }
  return { call, maxUnderlyingIn: q.maxUnderlyingIn }
}

/** eth_call the whole thing before anyone signs, and say what a revert meant. */
async function simulate(
  net: RpcClient,
  from: string,
  call: { to: string; value: bigint; data: Uint8Array },
  asset?: Asset,
) {
  const sim = await net.dryRun({ from, to: call.to, value: call.value, data: hex(call.data) })
  if (sim.success) return
  const why = (asset?.router && explainRouterRevert((sim as { data?: string }).data, units(asset).symbol)) ?? sim.reason
  throw new UsageError(`it would revert, nothing was sent: ${why}`)
}

/**
 * Where a proposal spending account `a` goes in the Safe's queue: after
 * everything waiting, even one that spends the account already. Two of those
 * cannot both execute, so say so rather than quietly take the other's nonce.
 */
async function spendNonce(net: RpcClient, safe: string, a: Account, privateNullifyingKey: bigint): Promise<bigint> {
  const q = await safeQueue(net, CHAIN_ID, safe)
  const same = queuedWith(q, nullifierOf(privateNullifyingKey, a.note.commitment))
  if (same) {
    log(
      `account #${a.index + 1n} has a proposal waiting at nonce ${same.nonce} already; both spend the account, so whichever the owners execute first leaves the other to revert -- reject that one in the Safe app to clear its nonce`,
    )
  }
  return nextNonce(q)
}

/**
 * Sign a SafeTx and hand it to the Safe's owners. The Safe is then the
 * depositor and the owner of every note -- V1's rule, and in V2 it also means
 * the Keystore registration has to be the Safe's.
 */
async function proposeCalls(net: RpcClient, c: Common, calls: SafeCall[], what: string, at?: bigint) {
  const safe = c.safe!
  // After everything already waiting, unless the caller placed it: a proposal
  // queued behind one that has not executed yet would only revert.
  const nonce = at ?? nextNonce(await safeQueue(net, CHAIN_ID, safe))
  const call = calls.length > 1 ? batch(calls) : calls[0]!
  // prepareSafeTx simulates the call as the Safe would run it, so a dry run
  // still proves the batch executes -- it just never asks anyone to sign.
  if (c.dryRun) {
    const { safeTxHash } = await prepareSafeTx(net, CHAIN_ID, safe, call, nonce)
    out(JSON.stringify({ safe, safeTxHash, to: call.to, value: String(call.value), data: hex(call.data) }, null, 2))
    return
  }
  const signer = await makeSigner(net, CHAIN_ID, c.sig)
  log(`proposing ${what} to Safe ${safe} as ${signer.address}${calls.length > 1 ? ', batched with the approval' : ''}`)
  const { safeTxHash, queue } = await proposeSafeTx({ net, chainId: CHAIN_ID, safe, signer, call, nonce })
  log(`proposed ${safeTxHash} at nonce ${nonce}; the owners confirm and execute it at ${queue}`)
}

// ---------------------------------------------------------------------------
// withdraw -- a transact with one unshielded output
// ---------------------------------------------------------------------------
function pickNote(accounts: Account[], amount: bigint | 'all', id?: string): Account {
  if (id !== undefined) {
    const a = accounts.find((x) => String(Number(x.index) + 1) === id.replace(/^#/, ''))
    if (!a) throw new UsageError(`no account #${id} (see: moneysurfer v2 balance)`)
    if (!spendable(a)) throw new UsageError(`account #${id} has nothing left to withdraw`)
    return a
  }
  const a = accounts.find((x) => spendable(x) && (amount === 'all' || x.note.value >= amount))
  if (!a) throw new UsageError('no account holds that much (see: moneysurfer v2 balance)')
  return a
}

async function withdraw(
  key: string | undefined,
  amountArg: string | undefined,
  to: string | undefined,
  v: Flags,
  c: Common,
) {
  if (!key || !amountArg || !to) throw new UsageError('usage: moneysurfer v2 withdraw <asset> <amount|all> <recipient>')
  if ([v.relayer, v.self, c.safe].filter(Boolean).length > 1) {
    throw new UsageError('--relayer, --self and --safe are exclusive')
  }
  if (v.relayer || !(v.self || c.safe)) {
    // V1 goes through a relayer by default. V2's relayer protocol is only
    // partly recovered -- /v1/details and /v1/quote are known, the submit body
    // is not -- so this client does not pretend to speak it. See FINDINGS.md.
    throw new UsageError(
      "a relayed withdrawal is not implemented: V2's relayer submit protocol is not fully recovered.\n" +
        '  Pass --self to submit and pay gas yourself (this links that address to the withdrawal),\n' +
        '  or --safe SAFE to have a Safe submit it.',
    )
  }
  const recipient = checksummed(to)
  const net = await connect()
  const all = await readAssets(net)
  const asset = pickAsset(all, key)
  const { keys, root, owner } = await account(net, c)
  if ((await read(net, KEYSTORE_ADDR, KEYSTORE.nullifyingKeys, owner)) === 0n) {
    throw new UsageError(`${owner} is not in the Keystore -- run \`moneysurfer v2 register\` first`)
  }
  const ev = await sync(net, log)
  const { accounts } = recover(keys, root, owner, [asset.tokenId], ev)
  const amount = amountArg === 'all' ? 'all' : parseUnits(amountArg, asset.decimals)
  const a = pickNote(accounts, amount, v.id)
  const value = amount === 'all' ? a.note.value : amount
  if (value <= 0n || value > a.note.value) {
    throw new UsageError(`account #${a.index + 1n} holds ${amountOf(asset, a.note.value)}`)
  }

  const [state, ks, asp] = await Promise.all([stateTree(net, ev), keystoreTree(net, ev), aspSet(net)])
  const timestamp = await read(net, POOL_ADDR, POOL.commitments, a.note.commitment)
  if (timestamp === 0n) throw new Error('the pool does not hold this note -- re-sync, or it was never mined')
  const note = {
    owner,
    noteSecret: a.note.noteSecret,
    tokenId: asset.tokenId,
    value: a.note.value,
    label: a.label,
    timestamp,
  }
  // Membership is checked here rather than in the prover, so an unapproved
  // label says so in words instead of failing an assert deep in the witness.
  leafIndexOf(state, commitmentLeaf(a.note.commitment, timestamp))
  aspIndexOf(asp, a.label)

  // The signer submits, so it is the processooor; no relayer, so no fee.
  const signer = await signerFor(net, c, owner)
  const processor = c.safe ?? signer.address
  const routing = { recipient, feeRecipient: recipient, feeAmount: 0n, nativeGas: 0n }
  const data = payoutRouting(routing)
  const notes = [NO_NOTE]
  const context = transactContext(processor, data, notes)

  // One input, one output: the change. Its value is settled by the event, which
  // is what lets `balance` follow the lineage afterwards without decrypting
  // anything.
  const change = a.note.value - value
  const outputs = [
    { owner, noteSecret: changeSecret(root, a.label, BigInt(a.spends.length)), value: change, label: a.label },
  ]
  log(`withdrawing ${amountOf(asset, value)} from account #${a.index + 1n} to ${recipient}`)
  if (change > 0n) log(`  ${amountOf(asset, change)} stays in the pool as a new note`)
  log(`proving ${transactCircuit(1, 1)} on ${c.threads} threads ...`)
  const t = transactWitness(
    { owner, privateNullifyingKey: keys.privateNullifyingKey, privateRevocableKey: keys.privateRevocableKey },
    [note],
    outputs,
    { state, keystore: ks, asp: asp.tree },
    { amountOut: value, context },
  )
  const proof = await prove(t.circuit, t.input, c.threads)
  const s = solidityProof(proof)
  const calldata = POOL.transact.encodeInput({
    proof: { pA: s.pA, pB: s.pB, pC: s.pC, pubSignals: groupTransact(proof.publicSignals, 1, 1) },
    transactParams: { processooor: processor, data },
    notes: notes.map((n) => ({ hint: hexToBytes(n.hint.slice(2)), ciphertext: n.ciphertext })),
  })
  const call = { to: POOL_ADDR, value: 0n, data: calldata }
  if (c.safe)
    return proposeCalls(net, c, [call], 'the withdrawal', await spendNonce(net, c.safe, a, keys.privateNullifyingKey))
  await simulate(net, signer.address, call, asset)
  log('simulated: the pool accepts it')
  if (c.dryRun) {
    out(JSON.stringify({ to: call.to, data: hex(calldata), recipient, amountOut: String(value) }, null, 2))
    return
  }
  log(`submitting from ${signer.address} -- this links that address to the withdrawal`)
  log(`sent: ${await signer.send(call)}`)
}

/**
 * `transact`'s public signals go on the wire grouped, one sub-array per bullet:
 * nullifiers, commitments, then a singleton each for stateRoot, keystoreRoot,
 * aspRoot, amountOut, tokenIdOut and context.
 */
function groupTransact(signals: bigint[], n: number, m: number): bigint[][] {
  const tail = n + m
  return [signals.slice(0, n), signals.slice(n, tail), ...signals.slice(tail, tail + 6).map((x) => [x])]
}

// ---------------------------------------------------------------------------
// ragequit
// ---------------------------------------------------------------------------
async function ragequit(key: string | undefined, v: Flags, c: Common) {
  if (!key || v.id === undefined) throw new UsageError('usage: moneysurfer v2 ragequit <asset> --id N')
  const net = await connect()
  const all = await readAssets(net)
  const asset = pickAsset(all, key)
  const { keys, root, owner } = await account(net, c)
  const ev = await sync(net, log)
  const { accounts } = recover(keys, root, owner, [asset.tokenId], ev)
  const a = accounts.find((x) => String(Number(x.index) + 1) === v.id!.replace(/^#/, ''))
  if (!a) throw new UsageError(`no account #${v.id} (see: moneysurfer v2 balance)`)
  if (!spendable(a)) throw new UsageError(`account #${v.id} has nothing left`)
  const ks = await keystoreTree(net, ev)
  const timestamp = await read(net, POOL_ADDR, POOL.commitments, a.note.commitment)
  if (timestamp === 0n) throw new Error('the pool does not hold this note')

  log(`proving on ${c.threads} threads ...`)
  const witness = ragequitWitness(
    { owner, privateNullifyingKey: keys.privateNullifyingKey, privateRevocableKey: keys.privateRevocableKey },
    { owner, noteSecret: a.note.noteSecret, tokenId: asset.tokenId, value: a.note.value, label: a.label, timestamp },
    { keystore: ks },
  )
  const proof = await prove('ragequit', witness, c.threads)
  const s = solidityProof(proof)
  const data = POOL.ragequit.encodeInput({ pA: s.pA, pB: s.pB, pC: s.pC, pubSignals: s.pubSignals as never })
  const call = { to: POOL_ADDR, value: 0n, data }
  log(`ragequitting ${amountOf(asset, a.note.value)} back to ${owner} -- this is public`)
  if (c.safe)
    return proposeCalls(net, c, [call], 'the ragequit', await spendNonce(net, c.safe, a, keys.privateNullifyingKey))
  const signer = await signerFor(net, c, owner)
  await simulate(net, signer.address, call, asset)
  if (c.dryRun) return out(JSON.stringify({ to: call.to, data: hex(data) }, null, 2))
  log(`ragequit: ${await signer.send(call)}`)
}

// ---------------------------------------------------------------------------
// status -- what the deployment looks like right now
// ---------------------------------------------------------------------------
async function status() {
  const net = await connect()
  out(`pool         ${POOL_ADDR}`)
  out(`  keystore     ${await read(net, POOL_ADDR, POOL.keystore)}`)
  out(`  aspRegistry  ${await read(net, POOL_ADDR, POOL.aspRegistry)}`)
  out(`  depositVk    ${await read(net, POOL_ADDR, POOL.depositVerifier)} (expected ${DEPOSIT_VERIFIER})`)
  out(`  paused       ${await read(net, POOL_ADDR, POOL.paused)}`)
  out(`entrypoint   ${ENTRYPOINT_ADDR}`)
  out(`  poolVault    ${await read(net, ENTRYPOINT_ADDR, ENTRYPOINT.poolVault)}`)
  out(`keystore     ${KEYSTORE_ADDR}`)
  out(`  currentRoot  ${hex32(await read(net, KEYSTORE_ADDR, KEYSTORE.currentRoot))}`)
  out(`aspRegistry  ${ASP_REGISTRY}`)
  out(`  latestRoot   ${hex32(await read(net, ASP_REGISTRY, ASP.latestASPRoot))}`)
  out(`asp          ${ASP_PUBLIC_KEY} (X25519)`)
}

async function trees() {
  const net = await connect()
  const ev = await sync(net, log)
  const state = await stateTree(net, ev)
  out(`state tree     ${state.size} leaves, depth ${state.depth}, root ${hex32(state.root)}  (the pool knows it)`)
  const ks = await keystoreTree(net, ev)
  out(`keystore tree  ${ks.size} leaves, depth ${ks.depth}, root ${hex32(ks.root)}  (the keystore knows it)`)
  const asp = await aspSet(net)
  out(`association    ${asp.tree.size} leaves, root ${hex32(asp.root)}  (the registry published it)`)
}

// ---------------------------------------------------------------------------
export const HELP: string = `moneysurfer v2 -- Privacy Pools V2 from the command line

  v2 setup [circuit...]              fetch the circuits, check their pinned sha256
  v2 init                            make a new seed (the one secret behind every note)
       --import                      ... or take one on stdin
       --from-wallet                 ... or derive v2.privacypools.com's from your wallet
  v2 register                        put this address in the Keystore -- required before spending
  v2 pools                           every asset the Entrypoint takes: minimum, fee, notes
  v2 balance                         your notes and what each holds
  v2 sync                            pull the pool, keystore and ASP events into the cache
  v2 deposit <asset> <amount>        deposit from your wallet (a token is approved first, exactly)
  v2 withdraw <asset> <amount|all> <to>   spend privately: a transact with one unshielded output
       --id N                        from account #N (default: the first that can)
       --self | --safe SAFE          submit and pay gas yourself, or have a Safe submit it
  v2 ragequit <asset> --id N         take a note back publicly, to the owning address
  v2 status | trees                  the deployment, and both trees rebuilt from logs

  --max-fee-percent N                on deposit, how far over the wrapping quote you will go
                                     (default 0.0001, one part per million)

amounts are human units of what you spend. For a wrapped asset (usdc, usdt) a deposit spends
the underlying, while the note's value is in the yield vault's shares -- and a share is worth
more than a dollar, so 10 USDC buys under 10 ppUSDC and falls below the minimum. About
10.02 usdc is the real floor; the error says so with the number of the day. A withdrawal
spends the note, so its amount is in shares, and shares are what it pays out.

Ethereum mainnet only, one deployment, no --chain.

env: MONEYSURFER_MNEMONIC, MONEYSURFER_RPC, MONEYSURFER_ASP`

export const COMMANDS = [
  'setup',
  'init',
  'register',
  'pools',
  'balance',
  'sync',
  'deposit',
  'withdraw',
  'ragequit',
  'status',
  'trees',
] as const

export async function run(cmd: string, rest: string[], v: Flags, c: Common): Promise<void> {
  const commands: Record<string, () => unknown> = {
    setup: () => setup(rest),
    init: () => init({ import: v.import, fromWallet: v['from-wallet'], sig: c.sig }),
    register: () => register(c),
    pools: () => poolsCmd(),
    balance: () => balance(c),
    sync: () => syncCmd(),
    deposit: () => deposit(rest[0], rest[1], c),
    withdraw: () => withdraw(rest[0], rest[1], rest[2], v, c),
    ragequit: () => ragequit(rest[0], v, c),
    status: () => status(),
    trees: () => trees(),
  }
  if (!Object.hasOwn(commands, cmd)) throw new UsageError(`unknown v2 command '${cmd}'\n\n${HELP}`)
  await commands[cmd]!()
}
