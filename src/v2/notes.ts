// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import type { CircuitInput } from '../shared/circom.ts'
/**
 * Notes, and the witnesses that spend them. The circuits take one flat record
 * of signals per proof; everything here is about assembling that record from a
 * note, an account and the three trees, and getting the array widths right --
 * a circuit compiled for depth 22 wants 22 siblings whatever the tree's real
 * depth is, with `stateTreeDepth` saying how many of them count.
 */
import { ASP_DEPTH, KEYSTORE_DEPTH, STATE_DEPTH, transactCircuit, UsageError } from './config.ts'
import {
  aspLeaf,
  authDigest,
  commitment,
  commitmentLeaf,
  keystoreLeaf,
  type LeanIMT,
  label as labelOf,
  type MerkleProof,
  noteAddressHash,
  nullifier,
  nullifyingKeyHash,
  precommitment,
} from './crypto.ts'

/** Everything needed to spend one note. `timestamp` is when the pool inserted it. */
export type Note = {
  owner: string
  noteSecret: bigint
  tokenId: string
  value: bigint
  label: bigint
  timestamp: bigint
}

/** A note freshly deposited: its label comes from the deposit secret, and only then. */
export function depositNote(
  owner: string,
  noteSecret: bigint,
  depositSecret: bigint,
  tokenId: string,
  value: bigint,
  timestamp: bigint,
): Note {
  const pre = precommitment(noteAddressHash(owner, noteSecret), tokenId, value)
  return { owner, noteSecret, tokenId, value, label: labelOf(pre, depositSecret), timestamp }
}

/**
 * A note created by a spend rather than a deposit. It carries its parent's
 * label -- that inheritance is what keeps a whole lineage under one ASP
 * attestation, and it is why several notes can aggregate into one output.
 */
export const childNote = (
  owner: string,
  noteSecret: bigint,
  tokenId: string,
  value: bigint,
  label: bigint,
  timestamp: bigint,
): Note => ({
  owner,
  noteSecret,
  tokenId,
  value,
  label,
  timestamp,
})

export const noteCommitment = (n: Note) =>
  commitment(precommitment(noteAddressHash(n.owner, n.noteSecret), n.tokenId, n.value), n.label)

export const noteLeaf = (n: Note) => commitmentLeaf(noteCommitment(n), n.timestamp)

export const noteNullifier = (n: Note, privateNullifyingKey: bigint) =>
  nullifier(privateNullifyingKey, noteCommitment(n))

/** The three keys a spend proves knowledge of. */
export type Account = { owner: string; privateNullifyingKey: bigint; privateRevocableKey: bigint }

export const accountLeaf = (a: Account) =>
  keystoreLeaf(a.owner, nullifyingKeyHash(a.privateNullifyingKey), authDigest(a.privateRevocableKey))

/** An output the spend creates. Its label must be inherited from some input. */
export type Output = { owner: string; noteSecret: bigint; value: bigint; label: bigint }

export type Trees = { state: LeanIMT; keystore: LeanIMT; asp: LeanIMT }

const pad = (xs: bigint[], n: number) => {
  if (xs.length > n) throw new Error(`a proof of ${xs.length} siblings does not fit a circuit compiled for ${n}`)
  return [...xs, ...Array<bigint>(n - xs.length).fill(0n)]
}

/** Find a leaf and prove it is in the tree, or say which tree is missing it. */
function locate(tree: LeanIMT, leaf: bigint, what: string): MerkleProof {
  const i = tree.levels[0]!.indexOf(leaf)
  if (i < 0) throw new UsageError(`${what} 0x${leaf.toString(16)} is not in the tree`)
  return tree.proof(i)
}

export type Transact = {
  circuit: string
  input: CircuitInput
  nullifiers: bigint[]
  commitments: bigint[]
}

/**
 * The witness for `transact_NxM`. Value must balance: the inputs equal the
 * outputs plus `amountOut`, and every output label must come from some input,
 * both of which the circuit enforces before it will produce a witness at all.
 */
export function transact(
  account: Account,
  notes: Note[],
  outputs: Output[],
  trees: Trees,
  { amountOut = 0n, context }: { amountOut?: bigint; context: bigint },
): Transact {
  if (!notes.length) throw new UsageError('a transact spends at least one note')
  const tokenId = notes[0]!.tokenId
  if (notes.some((n) => n.tokenId !== tokenId)) throw new UsageError('every note in one transact shares a tokenId')
  const inValue = notes.reduce((a, n) => a + n.value, 0n)
  const outValue = outputs.reduce((a, o) => a + o.value, 0n)
  if (inValue !== outValue + amountOut)
    throw new UsageError(`value does not balance: ${inValue} in, ${outValue} out plus ${amountOut} withdrawn`)
  // ValueConservation is per label as well as global: a label's outputs may
  // not exceed its inputs, and every output label must come from some input.
  const perLabel = new Map<bigint, bigint>()
  for (const n of notes) perLabel.set(n.label, (perLabel.get(n.label) ?? 0n) + n.value)
  for (const o of outputs) {
    const left = perLabel.get(o.label)
    if (left === undefined)
      throw new UsageError(`output label 0x${o.label.toString(16)} is not inherited from an input`)
    if (o.value > left)
      throw new UsageError(
        `label 0x${o.label.toString(16)} has ${left} left across its inputs, but an output spends ${o.value}`,
      )
    perLabel.set(o.label, left - o.value)
  }

  const kp = locate(trees.keystore, accountLeaf(account), 'the account')
  const sp = notes.map((n) => locate(trees.state, noteLeaf(n), 'the note'))
  const ap = notes.map((n) => locate(trees.asp, aspLeaf(n.label), 'the label'))

  return {
    circuit: transactCircuit(notes.length, outputs.length),
    nullifiers: notes.map((n) => noteNullifier(n, account.privateNullifyingKey)),
    commitments: outputs.map((o) =>
      commitment(precommitment(noteAddressHash(o.owner, o.noteSecret), tokenId, o.value), o.label),
    ),
    input: {
      tokenId: BigInt(tokenId),
      context,
      value: notes.map((n) => n.value),
      noteSecret: notes.map((n) => n.noteSecret),
      label: notes.map((n) => n.label),
      timestamp: notes.map((n) => n.timestamp),
      ownerAddress: BigInt(account.owner),
      privateNullifyingKey: account.privateNullifyingKey,
      privateRevocableKey: account.privateRevocableKey,
      keystoreRoot: trees.keystore.root,
      keystoreLeafIndex: BigInt(kp.index),
      keystoreTreeDepth: BigInt(kp.siblings.length),
      keystoreSiblings: pad(kp.siblings, KEYSTORE_DEPTH),
      stateRoot: trees.state.root,
      stateLeafIndex: sp.map((p) => BigInt(p.index)),
      stateTreeDepth: sp.map((p) => BigInt(p.siblings.length)),
      stateSiblings: sp.flatMap((p) => pad(p.siblings, STATE_DEPTH)),
      associationSetRoot: trees.asp.root,
      associationSetLeafIndex: ap.map((p) => BigInt(p.index)),
      associationSetTreeDepth: ap.map((p) => BigInt(p.siblings.length)),
      associationSetSiblings: ap.flatMap((p) => pad(p.siblings, ASP_DEPTH)),
      amountOut,
      tokenIdOut: BigInt(tokenId),
      outputNoteAddressHash: outputs.map((o) => noteAddressHash(o.owner, o.noteSecret)),
      outputValue: outputs.map((o) => o.value),
      outputLabel: outputs.map((o) => o.label),
    },
  }
}

/** The witness for `deposit`: the only proof that does not spend anything. */
export function deposit(
  owner: string,
  noteSecret: bigint,
  depositSecret: bigint,
  tokenId: string,
  value: bigint,
  context: bigint,
): CircuitInput {
  return {
    depositSecret,
    noteAddressHash: noteAddressHash(owner, noteSecret),
    tokenId: BigInt(tokenId),
    value,
    context,
  }
}

/** The witness for `ragequit`: keystore membership, and nothing about the ASP. */
export function ragequit(account: Account, note: Note, trees: Pick<Trees, 'keystore'>): CircuitInput {
  const kp = locate(trees.keystore, accountLeaf(account), 'the account')
  return {
    tokenId: BigInt(note.tokenId),
    value: note.value,
    metadata: 0n,
    noteSecret: note.noteSecret,
    ownerAddress: BigInt(account.owner),
    label: note.label,
    privateNullifyingKey: account.privateNullifyingKey,
    privateRevocableKey: account.privateRevocableKey,
    keystoreRoot: trees.keystore.root,
    keystoreLeafIndex: BigInt(kp.index),
    keystoreTreeDepth: BigInt(kp.siblings.length),
    keystoreSiblings: pad(kp.siblings, KEYSTORE_DEPTH),
  }
}
