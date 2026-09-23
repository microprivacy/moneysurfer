// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * A whole deposit, assembled: the Groth16 proof, the note the depositor keeps,
 * the opening the ASP reads, and the `Entrypoint.deposit` calldata that carries
 * all three. Nothing here signs or sends anything -- what comes out is a
 * transaction someone else may choose to broadcast.
 *
 * The Entrypoint is the only way into the pool (it holds DEPOSITOR_ROLE), it
 * charges the asset's `vettingFeeBPS` on top of the deposited value, and it
 * forwards the third argument to the ASPRegistry untouched.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { encodeOpening } from './asp.ts'
import { ENTRYPOINT } from './chain.ts'
import { ASP_PUBLIC_KEY, ENTRYPOINT_ADDR, isNative, NATIVE, UsageError } from './config.ts'
import { commitment, depositContext, label as labelOf, noteAddressHash, precommitment } from './crypto.ts'
import { deposit as depositWitness } from './notes.ts'
import { type Proof, prove, solidityProof } from './prover.ts'

/** The `(bytes32 hint, bytes ciphertext)` a deposit publishes for the recipient. */
export type NoteData = { hint: string; ciphertext: Uint8Array }

/**
 * What a deposit that tells nobody anything carries. The pool takes it: the
 * Note event is how a *recipient* finds a note they did not create, and a
 * depositor who keeps their own note secret needs no such event. Encrypting a
 * real note payload needs the recipient's viewing key and the note ciphertext
 * format, which is still unrecovered -- see FINDINGS.md.
 */
export const NO_NOTE: NoteData = { hint: `0x${'00'.repeat(32)}`, ciphertext: new Uint8Array(0) }

export type DepositParams = {
  owner: string
  noteSecret: bigint
  depositSecret: bigint
  tokenId?: string
  value: bigint
  /** the asset's `vettingFeeBPS`, read off `Entrypoint.assets(tokenId)` */
  vettingFeeBPS: bigint
  /** the ASP's X25519 key; defaults to the one this deployment publishes */
  aspPublicKey?: string
  noteData?: NoteData
  threads?: number
}

export type Deposit = {
  /** the Entrypoint: a deposit sent straight to the pool reverts, it has no DEPOSITOR_ROLE */
  to: string
  data: Uint8Array
  /** msg.value -- the deposited value plus the vetting fee, or 0 for an ERC-20 */
  value: bigint
  /** what the depositor must keep: without these the note is unspendable and unragequittable */
  noteSecret: bigint
  depositSecret: bigint
  label: bigint
  commitment: bigint
  context: bigint
  noteData: NoteData
  aspCiphertext: Uint8Array
  /** the Groth16 proof itself, which a PPRouter deposit has to pass through unchanged */
  proof: Proof
}

/** What the Entrypoint takes for `value` wei of deposit: the fee is added on top, not deducted. */
export const msgValue = (tokenId: string, value: bigint, vettingFeeBPS: bigint) =>
  isNative(tokenId) ? value + (value * vettingFeeBPS) / 10_000n : 0n

/**
 * Build the whole thing. The proof binds the context, the context binds the
 * note data, and the ASP's opening binds the same `noteAddressHash`, `tokenId`,
 * `value` and `depositSecret` the proof is over -- so the three parts cannot be
 * mixed between deposits.
 */
export async function buildDeposit(p: DepositParams): Promise<Deposit> {
  const tokenId = p.tokenId ?? NATIVE
  if (p.value <= 0n) throw new UsageError('a deposit of nothing is not a deposit')
  const noteData = p.noteData ?? NO_NOTE
  const addressHash = noteAddressHash(p.owner, p.noteSecret)
  const pre = precommitment(addressHash, tokenId, p.value)
  const label = labelOf(pre, p.depositSecret)
  const context = depositContext(noteData.hint, noteData.ciphertext)

  const proof = await prove(
    'deposit',
    depositWitness(p.owner, p.noteSecret, p.depositSecret, tokenId, p.value, context),
    p.threads,
  )
  const out = commitment(pre, label)
  if (proof.publicSignals[0] !== out) throw new Error('the circuit disagrees with our own commitment')

  const aspCiphertext = encodeOpening(
    { noteAddressHash: addressHash, tokenId, value: p.value, depositSecret: p.depositSecret },
    p.aspPublicKey ?? ASP_PUBLIC_KEY,
  )
  return {
    to: ENTRYPOINT_ADDR,
    data: ENTRYPOINT.deposit.encodeInput({
      proof: solidityProof(proof),
      noteData: { hint: hexToBytes(noteData.hint.slice(2)), ciphertext: noteData.ciphertext },
      aspCiphertext,
    }),
    value: msgValue(tokenId, p.value, p.vettingFeeBPS),
    noteSecret: p.noteSecret,
    depositSecret: p.depositSecret,
    label,
    commitment: out,
    context,
    noteData,
    aspCiphertext,
    proof,
  }
}

/** The transaction, as an eth_call or eth_sendTransaction takes it. */
export const asTransaction = (d: Deposit, from: string) => ({
  from,
  to: d.to,
  data: `0x${bytesToHex(d.data)}`,
  value: `0x${d.value.toString(16)}`,
})
