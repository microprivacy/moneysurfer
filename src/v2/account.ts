// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * A seed's Privacy Pools V2 accounts, recovered from chain data alone.
 *
 * V1 could do this because every note secret came from the mnemonic. The SDK
 * cannot: it draws note secrets at random and finds them again by decrypting
 * the `Note` ciphertext the deposit publishes. This client takes V1's road --
 * crypto.ts derives the secrets from the seed -- so recovery is once again a
 * walk over deposit indices with nothing to back up but the words, and a note
 * survives even if the Note payload was wrong or never published.
 *
 * The cost of that choice is stated plainly in README: a deposit made here is
 * recoverable here, but the web app will not list it unless the deposit also
 * published a Note the app can decrypt.
 *
 * An account in V2 is a pair, not a single key: the **owner address** (the one
 * registered in the Keystore, which the circuits take as `ownerAddress`) and
 * the keys the seed derives. Change the address and you change every note
 * hash, so `balance` needs to be told which address it is looking for.
 */
import type { Deposit, PoolEvents, Ragequit, Transact } from './chain.ts'
import {
  changeSecret,
  commitment as commitmentOf,
  depositSecrets,
  type Keys,
  label as labelOf,
  noteAddressHash,
  nullifier as nullifierOf,
  precommitment,
} from './crypto.ts'

/** Unused deposit indices in a row that end the search -- V1's number. */
const MISSES = 10

export type Note = {
  noteSecret: bigint
  tokenId: string
  value: bigint
  label: bigint
  commitment: bigint
  /** which change note this is; -1 for the deposit itself */
  child: number
}

export type Account = {
  /** the deposit index within this tokenId */
  index: bigint
  tokenId: string
  label: bigint
  deposit: Deposit
  /** the transacts that spent this lineage, oldest first */
  spends: Transact[]
  ragequit?: Ragequit
  /** the live note: spendable while its value is non-zero and there was no ragequit */
  note: Note
  /** set when the lineage ran into a spend this client cannot follow */
  lost?: string
}

export const spendable = (a: Account) => a.note.value > 0n && !a.ragequit && !a.lost

/** The commitment a note would have, from the parts the seed and the chain supply. */
export const noteCommitment = (owner: string, n: Omit<Note, 'commitment' | 'child'>) =>
  commitmentOf(precommitment(noteAddressHash(owner, n.noteSecret), n.tokenId, n.value), n.label)

/**
 * Every account this seed owns at `owner`, across the tokenIds given.
 *
 * A deposit is matched the way V1 matches a precommitment: the event supplies
 * `value` and `tokenId`, the seed supplies the two secrets, and the commitment
 * either comes out equal to the one in the log or it does not. Lineage is then
 * followed through `Transacted`: a spend of ours is one that names a nullifier
 * of ours, and its change note is the next secret under the same label.
 */
export function recover(
  keys: Keys,
  rootSecret: Uint8Array,
  owner: string,
  tokenIds: string[],
  ev: PoolEvents,
): { accounts: Account[]; nextIndex: Map<string, bigint> } {
  const ragequits = new Map(ev.ragequits.map((r) => [r.label, r]))
  const accounts: Account[] = []
  const nextIndex = new Map<string, bigint>()

  for (const tokenId of tokenIds) {
    const mine = ev.deposits.filter((d) => d.tokenId.toLowerCase() === tokenId.toLowerCase())
    let unused: bigint | undefined
    for (let i = 0n, misses = 0; misses < MISSES; i++) {
      const { noteSecret, depositSecret } = depositSecrets(rootSecret, tokenId, i)
      const ah = noteAddressHash(owner, noteSecret)
      const d = mine.find((x) => {
        const pre = precommitment(ah, tokenId, x.value)
        return commitmentOf(pre, labelOf(pre, depositSecret)) === x.commitment
      })
      if (!d) {
        unused ??= i
        misses++
        continue
      }
      misses = 0
      const label = labelOf(precommitment(ah, tokenId, d.value), depositSecret)
      accounts.push(follow(keys, rootSecret, owner, tokenId, i, label, d, ev, ragequits.get(label)))
    }
    nextIndex.set(tokenId.toLowerCase(), unused ?? 0n)
  }
  return { accounts, nextIndex }
}

/** Walk one lineage forward through the spends that touched it. */
function follow(
  keys: Keys,
  rootSecret: Uint8Array,
  owner: string,
  tokenId: string,
  index: bigint,
  label: bigint,
  deposit: Deposit,
  ev: PoolEvents,
  ragequit: Ragequit | undefined,
): Account {
  let note: Note = {
    noteSecret: depositSecrets(rootSecret, tokenId, index).noteSecret,
    tokenId,
    value: deposit.value,
    label,
    commitment: deposit.commitment,
    child: -1,
  }
  const spends: Transact[] = []
  let lost: string | undefined
  for (let child = 0; ; child++) {
    const spent = nullifierOf(keys.privateNullifyingKey, note.commitment)
    const t = ev.transacts.find((x) => x.nullifiers.includes(spent))
    if (!t) break
    spends.push(t)
    // Our own spends leave exactly one change note, so its value is settled by
    // the event: everything that went in, less what was unshielded. A spend
    // with several outputs was not made by this client and cannot be followed.
    const noteSecret = changeSecret(rootSecret, label, BigInt(child))
    const value = note.value - t.amountOut
    const guess = noteCommitment(owner, { noteSecret, tokenId, value, label })
    if (!t.commitments.includes(guess)) {
      lost =
        `the spend in ${t.tx} left change this seed does not derive -- it was made by another client, ` +
        'or from several notes at once. The note below is the last one this client can account for'
      break
    }
    note = { noteSecret, tokenId, value, label, commitment: guess, child }
    if (value === 0n) break
  }
  return { index, tokenId, label, deposit, spends, ragequit, note, ...(lost && { lost }) }
}
