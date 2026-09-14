import assert from 'node:assert/strict'
import { test } from 'node:test'
import { recover, spendable } from '../src/account.ts'
import type { Deposit, PoolEvents, Ragequit, Withdrawal } from '../src/chain.ts'
import {
  commitment,
  depositSecrets,
  masterKeys,
  nullifierHash,
  precommitment,
  withdrawalSecrets,
} from '../src/crypto.ts'

const k = masterKeys('test test test test test test test test test test test junk')
const other = masterKeys(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
)
const scope = 42n
const at = { block: 1, tx: '0x' }
const ETH = 10n ** 18n

const deposit = (keys: typeof k, index: bigint, label: bigint, value: bigint): Deposit => {
  const s = depositSecrets(keys, scope, index)
  return {
    ...at,
    depositor: '0x0',
    commitment: commitment(value, label, s),
    label,
    value,
    precommitment: precommitment(s),
  }
}

test('recovery follows deposits, change notes and ragequits, and only this mnemonic', () => {
  // account 1: 1 ETH, then withdrawals of 0.3 and 0.2 leave two change notes
  const d0 = deposit(k, 0n, 100n, ETH)
  const c0 = withdrawalSecrets(k, 100n, 0n)
  const w0: Withdrawal = {
    ...at,
    processooor: '0x0',
    value: (3n * ETH) / 10n,
    spentNullifier: nullifierHash(depositSecrets(k, scope, 0n)),
    newCommitment: commitment((7n * ETH) / 10n, 100n, c0),
  }
  const w1: Withdrawal = {
    ...at,
    processooor: '0x0',
    value: (2n * ETH) / 10n,
    spentNullifier: nullifierHash(c0),
    newCommitment: commitment(ETH / 2n, 100n, withdrawalSecrets(k, 100n, 1n)),
  }
  // account 3, past a gap at index 1, taken back by ragequit
  const d2 = deposit(k, 2n, 200n, ETH / 20n)
  const r2: Ragequit = { ...at, ragequitter: '0x0', commitment: d2.commitment, label: 200n, value: ETH / 20n }
  // beyond 10 unused indices in a row: not found, as the SDK would not find it either
  const far = deposit(k, 13n, 300n, ETH)
  const ev: PoolEvents = {
    block: 1,
    deposits: [deposit(other, 0n, 999n, ETH), d0, d2, far],
    withdrawals: [w1, w0],
    ragequits: [r2],
    leaves: [],
  }

  const { accounts, nextIndex } = recover(k, scope, ev)
  assert.deepEqual(
    accounts.map((a) => a.index),
    [0n, 2n],
  )
  const [a, b] = accounts as [(typeof accounts)[0], (typeof accounts)[0]]
  assert.equal(a.note.value, ETH / 2n)
  assert.equal(a.note.child, 1)
  assert.equal(a.withdrawals.length, 2)
  assert.ok(spendable(a))
  assert.ok(b.ragequit)
  assert.ok(!spendable(b))
  assert.equal(nextIndex, 1n, 'the first unused index is the next deposit')
})

test('change this mnemonic cannot derive is reported, not skipped', () => {
  const d0 = deposit(k, 0n, 100n, ETH)
  const bad: Withdrawal = {
    ...at,
    processooor: '0x0',
    value: ETH / 2n,
    spentNullifier: nullifierHash(depositSecrets(k, scope, 0n)),
    newCommitment: 12345n,
  }
  assert.throws(
    () => recover(k, scope, { block: 1, deposits: [d0], withdrawals: [bad], ragequits: [], leaves: [] }),
    /does not derive/,
  )
})
