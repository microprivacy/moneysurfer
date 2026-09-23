// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Key derivation and note recovery.
 *
 * **These tests pin what was recovered; they do not confirm it.** The
 * derivation constants and the EIP-712 payload came out of the app's own
 * bundle, but no account the app made has ever been checked against them --
 * there is no offline oracle for that, only a wallet signature whose keys are
 * already in a Keystore. What is tested here is that the ladder is the one
 * de-minified (shape, widths, clamping, index encoding) and that it cannot
 * drift silently. See FINDINGS.md, gap 2.
 *
 * Recovery, by contrast, is fully testable: the notes are this client's own,
 * so a round trip through synthetic events proves it.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { symbolKey, uniqueKeys } from '../src/shared/symbols.ts'
import { recover, spendable } from '../src/v2/account.ts'
import type { Deposit, PoolEvents, Transact } from '../src/v2/chain.ts'
import {
  APP_IDENTIFIER,
  changeSecret,
  commitment,
  depositSecrets,
  deriveKeys,
  label as labelOf,
  noteAddressHash,
  nullifier,
  precommitment,
  rootSecretFromSignature,
  SNARK_FIELD,
  secretDerivationTypedData,
} from '../src/v2/crypto.ts'

const SEED = hexToBytes('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff')
const OWNER = '0x1111111111111111111111111111111111111111'
const TOKEN = '0xC246aFb23482fF9596E9cee5f1f678eFe0EB1ad6'

// ---------------------------------------------------------------------------
test('the EIP-712 payload is the one the app asks a wallet to sign', () => {
  const typed = secretDerivationTypedData(OWNER)
  assert.equal(typed.primaryType, 'SecretDerivation')
  assert.equal(typed.domain.name, 'Standardized Secret Derivation')
  assert.equal(typed.domain.version, '1')
  assert.equal(typed.domain.verifyingContract, '0x0000000000000000000000000000000000000000')
  // The domain has no chainId -- one account, every chain -- and its salt is
  // the app identifier hashed, which is what separates this app's keys from
  // any other built on the same scheme.
  assert.equal(APP_IDENTIFIER, 'TODO-privacy-pools-v2')
  assert.equal(typed.domain.salt, '0xee8b26979e200ad660eafc892b7846a5003a1aa9cc786183c9ebae06edf10fb7')
  assert.match(typed.message.purpose, /^This signature is used to deterministically derive/)
  assert.equal(typed.message.addressHash, '0xe2c07404b8c1df4c46226425cac68c28d27a766bbddce62309f36724839b22c0')
})

test('the key ladder is deterministic, in range, and clamped', () => {
  const k = deriveKeys(SEED)
  const again = deriveKeys(SEED)
  assert.equal(k.privateNullifyingKey, again.privateNullifyingKey)
  assert.equal(k.privateRevocableKey, again.privateRevocableKey)
  // The spending keys are 48 bytes reduced into the scalar field, so they are
  // always usable as circuit inputs.
  assert.ok(k.privateNullifyingKey > 0n && k.privateNullifyingKey < SNARK_FIELD)
  assert.ok(k.privateRevocableKey > 0n && k.privateRevocableKey < SNARK_FIELD)
  // The viewing key is an X25519 scalar, so it is clamped rather than reduced.
  assert.equal(k.viewingPrivateKey.length, 32)
  assert.equal(k.viewingPrivateKey[0]! & 7, 0)
  assert.equal(k.viewingPrivateKey[31]! & 0x80, 0)
  assert.equal(k.viewingPrivateKey[31]! & 0x40, 0x40)
  assert.equal(bytesToHex(k.viewingPublicKey), bytesToHex(x25519.getPublicKey(k.viewingPrivateKey)))
})

test('rotating the revocable key leaves every note alone', () => {
  // AUTH0:REVOCABLE is suffixed with the index as eight big-endian bytes, and
  // only the revocable key hangs off it -- so a rotation cannot orphan notes.
  const a = deriveKeys(SEED, 0n)
  const b = deriveKeys(SEED, 1n)
  assert.notEqual(a.privateRevocableKey, b.privateRevocableKey)
  assert.equal(a.privateNullifyingKey, b.privateNullifyingKey)
  assert.equal(bytesToHex(a.viewingPrivateKey), bytesToHex(b.viewingPrivateKey))
  assert.equal(b.revocableKeyIndex, 1n)
})

test("the root secret is HKDF of the signature's r, and nothing else of it", () => {
  const sig = `0x${'11'.repeat(32)}${'22'.repeat(32)}1b`
  const other = `0x${'11'.repeat(32)}${'33'.repeat(32)}1c`
  // s and v differ, r does not: the same account either way. That is what lets
  // a wallet that rotates its nonce still derive a stable seed.
  assert.equal(bytesToHex(rootSecretFromSignature(sig, OWNER)), bytesToHex(rootSecretFromSignature(other, OWNER)))
  // The address is the salt, so two wallets never share an account.
  assert.notEqual(
    bytesToHex(rootSecretFromSignature(sig, OWNER)),
    bytesToHex(rootSecretFromSignature(sig, '0x2222222222222222222222222222222222222222')),
  )
  assert.equal(rootSecretFromSignature(sig, OWNER).length, 32)
})

test('note secrets come from the seed, so nothing else needs backing up', () => {
  const a = depositSecrets(SEED, TOKEN, 0n)
  assert.notEqual(a.noteSecret, a.depositSecret)
  // Indices, assets and lineages are all separated.
  assert.notEqual(a.noteSecret, depositSecrets(SEED, TOKEN, 1n).noteSecret)
  assert.notEqual(a.noteSecret, depositSecrets(SEED, '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', 0n).noteSecret)
  assert.notEqual(changeSecret(SEED, 7n, 0n), changeSecret(SEED, 7n, 1n))
  assert.notEqual(changeSecret(SEED, 7n, 0n), changeSecret(SEED, 8n, 0n))
  for (const s of [a.noteSecret, a.depositSecret, changeSecret(SEED, 7n, 0n)]) {
    assert.ok(s > 0n && s < SNARK_FIELD)
  }
})

// ---------------------------------------------------------------------------
const at = { block: 1, tx: '0x' }

/** The deposit event this seed's index-th deposit of `value` would produce. */
function depositEvent(index: bigint, value: bigint): Deposit {
  const { noteSecret, depositSecret } = depositSecrets(SEED, TOKEN, index)
  const pre = precommitment(noteAddressHash(OWNER, noteSecret), TOKEN, value)
  return { ...at, tokenId: TOKEN, value, commitment: commitment(pre, labelOf(pre, depositSecret)) }
}

const events = (o: Partial<PoolEvents>): PoolEvents => ({
  block: 1,
  deposits: [],
  ragequits: [],
  transacts: [],
  notes: [],
  leaves: [],
  keystoreLeaves: [],
  aspRoots: [],
  ...o,
})

test('a deposit this seed made is found again from the log alone', () => {
  const keys = deriveKeys(SEED)
  const ev = events({ deposits: [depositEvent(0n, 100n), depositEvent(2n, 300n)] })
  const { accounts, nextIndex } = recover(keys, SEED, OWNER, [TOKEN], ev)
  assert.deepEqual(
    accounts.map((a) => [a.index, a.note.value]),
    [
      [0n, 100n],
      [2n, 300n],
    ],
  )
  // index 1 was never used, so it is where the next deposit goes
  assert.equal(nextIndex.get(TOKEN.toLowerCase()), 1n)
  assert.ok(accounts.every(spendable))
})

test("someone else's deposit is not mistaken for ours", () => {
  const keys = deriveKeys(SEED)
  const theirs: Deposit = { ...at, tokenId: TOKEN, value: 100n, commitment: 12345n }
  const { accounts } = recover(keys, SEED, OWNER, [TOKEN], events({ deposits: [theirs] }))
  assert.equal(accounts.length, 0)
  // ... and neither is our own deposit read at the wrong owner address
  const mine = events({ deposits: [depositEvent(0n, 100n)] })
  assert.equal(recover(keys, SEED, '0x2222222222222222222222222222222222222222', [TOKEN], mine).accounts.length, 0)
})

test('a spend is followed to the change note it left', () => {
  const keys = deriveKeys(SEED)
  const d = depositEvent(0n, 1000n)
  const { noteSecret } = depositSecrets(SEED, TOKEN, 0n)
  const pre = precommitment(noteAddressHash(OWNER, noteSecret), TOKEN, 1000n)
  const label = labelOf(pre, depositSecrets(SEED, TOKEN, 0n).depositSecret)
  // withdraw 400, leaving 600 as the first change note under the same label
  const change = changeSecret(SEED, label, 0n)
  const changeCommitment = commitment(precommitment(noteAddressHash(OWNER, change), TOKEN, 600n), label)
  const t: Transact = {
    ...at,
    tokenId: TOKEN,
    amountOut: 400n,
    nullifiers: [nullifier(keys.privateNullifyingKey, d.commitment)],
    commitments: [changeCommitment],
    processooor: OWNER,
  }
  const { accounts } = recover(keys, SEED, OWNER, [TOKEN], events({ deposits: [d], transacts: [t] }))
  assert.equal(accounts.length, 1)
  assert.equal(accounts[0]!.note.value, 600n)
  assert.equal(accounts[0]!.note.child, 0)
  assert.equal(accounts[0]!.note.commitment, changeCommitment)
  assert.equal(accounts[0]!.deposit.value, 1000n)
  assert.equal(accounts[0]!.lost, undefined)
  assert.ok(spendable(accounts[0]!))
})

test('a spend whose change this seed cannot derive is reported, not skipped', () => {
  const keys = deriveKeys(SEED)
  const d = depositEvent(0n, 1000n)
  const t: Transact = {
    ...at,
    tokenId: TOKEN,
    amountOut: 400n,
    nullifiers: [nullifier(keys.privateNullifyingKey, d.commitment)],
    commitments: [999n], // not ours: another client, or several notes at once
    processooor: OWNER,
  }
  const { accounts } = recover(keys, SEED, OWNER, [TOKEN], events({ deposits: [d], transacts: [t] }))
  assert.equal(accounts.length, 1)
  assert.match(accounts[0]!.lost!, /change this seed does not derive/)
  assert.equal(spendable(accounts[0]!), false)
})

test('a ragequit account is not spendable', () => {
  const keys = deriveKeys(SEED)
  const d = depositEvent(0n, 1000n)
  const { noteSecret, depositSecret } = depositSecrets(SEED, TOKEN, 0n)
  const label = labelOf(precommitment(noteAddressHash(OWNER, noteSecret), TOKEN, 1000n), depositSecret)
  const ev = events({
    deposits: [d],
    ragequits: [
      { ...at, ragequitter: OWNER, tokenId: TOKEN, value: 1000n, commitment: d.commitment, nullifier: 1n, label },
    ],
  })
  const { accounts } = recover(keys, SEED, OWNER, [TOKEN], ev)
  assert.equal(accounts.length, 1)
  assert.ok(accounts[0]!.ragequit)
  assert.equal(spendable(accounts[0]!), false)
})

// ---------------------------------------------------------------------------
test("asset keys are typeable, and Tether's symbol survives it", () => {
  assert.equal(symbolKey('ppUSDC', '0xC246aFb2'), 'ppusdc')
  assert.equal(symbolKey('ETH', '0xEeee'), 'eth')
  // Tether writes its symbol with U+20AE, and USD₮0 on several chains.
  assert.equal(symbolKey('USD₮', '0xdAC1'), 'usdt')
  assert.equal(symbolKey('USD₮0', '0xdAC1'), 'usdt0')
  // A symbol nothing survives falls back to the head of the address.
  assert.equal(symbolKey('🙂', '0xABCDEF0123'), '0xabcdef')
})

test('the first claimant of a name keeps it bare', () => {
  const items = [{ s: 'USDC' }, { s: 'USDC' }, { s: 'USDC' }]
  assert.deepEqual([...uniqueKeys(items, (i) => symbolKey(i.s, '0x0')).values()], ['usdc', 'usdc-2', 'usdc-3'])
})
