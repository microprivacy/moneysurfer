/**
 * A mnemonic's Privacy Pools accounts, recovered from chain data alone, the
 * way 0xbow's SDK recovers them (packages/sdk/src/core/account.service.ts):
 * walk the deposit indices a pool's scope derives until MISSES in a row find
 * nothing, then follow each account through its change notes by the
 * nullifier hashes its Withdrawn events spent.
 */
import type { Deposit, PoolEvents, Ragequit, Withdrawal } from './chain.ts'
import {
  commitment,
  depositSecrets,
  type MasterKeys,
  nullifierHash,
  precommitment,
  type Secrets,
  withdrawalSecrets,
} from './crypto.ts'

/** Unused deposit indices in a row that end the search -- the SDK's number. */
const MISSES = 10

export type Note = {
  secrets: Secrets
  value: bigint
  commitment: bigint
  /** which change note this is; -1 for the deposit itself */
  child: number
}

export type Account = {
  /** the deposit index within the pool's scope */
  index: bigint
  label: bigint
  deposit: Deposit
  withdrawals: Withdrawal[]
  ragequit?: Ragequit
  /** the account's live note: spendable while its value is non-zero and there was no ragequit */
  note: Note
}

export function recover(k: MasterKeys, scope: bigint, ev: PoolEvents): { accounts: Account[]; nextIndex: bigint } {
  const byPrecommitment = new Map(ev.deposits.map((d) => [d.precommitment, d]))
  const bySpentNullifier = new Map(ev.withdrawals.map((w) => [w.spentNullifier, w]))
  const ragequits = new Map(ev.ragequits.map((r) => [r.label, r]))
  const accounts: Account[] = []
  let nextIndex: bigint | undefined
  for (let i = 0n, misses = 0; misses < MISSES; i++) {
    const secrets = depositSecrets(k, scope, i)
    const d = byPrecommitment.get(precommitment(secrets))
    if (!d) {
      nextIndex ??= i
      misses++
      continue
    }
    misses = 0
    let note: Note = { secrets, value: d.value, commitment: d.commitment, child: -1 }
    const withdrawals: Withdrawal[] = []
    for (let j = 0; ; j++) {
      const w = bySpentNullifier.get(nullifierHash(note.secrets))
      if (!w) break
      const next = withdrawalSecrets(k, d.label, BigInt(j))
      const value = note.value - w.value
      const c = commitment(value, d.label, next)
      if (c !== w.newCommitment)
        throw new Error(`account ${i}: withdrawal ${j} left change this mnemonic does not derive`)
      withdrawals.push(w)
      note = { secrets: next, value, commitment: c, child: j }
    }
    accounts.push({ index: i, label: d.label, deposit: d, withdrawals, ragequit: ragequits.get(d.label), note })
  }
  return { accounts, nextIndex: nextIndex ?? 0n }
}

export const spendable = (a: Account) => a.note.value > 0n && !a.ragequit
