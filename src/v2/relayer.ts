// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * A V2 relayer, spoken to the way the SDK's `RelayerInteractor` speaks to it
 * -- routes and bodies read out of the bundle privacypools.com serves, and
 * checked against 0xbow's production relayer.
 *
 * A withdrawal goes in three steps. `POST /v1/quote/evm/{chain}/receive`
 * names the asset, the recipient and what the recipient is to get; the
 * relayer answers with its fee and a signed `feeCommitment` whose `data` is
 * the PayoutRouting it will be paid by. That `data` is bound into the proof's
 * context, with the relayer's PrivacyPoolRelay as the processor, and
 * `POST /v1/relay/evm/{chain}/withdrawal` hands back the commitment, the proof
 * and the note data. The relayer sends `PrivacyPoolRelay.relay`, which calls
 * the pool and splits what it is paid between the recipient and the fee.
 *
 * Unlike V1's, the quote has to name the recipient: it is in the routing the
 * relayer signs. So the relayer learns where the money goes -- never where it
 * came from.
 */
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { createContract } from 'micro-eth-signer/abi.js'
import { POOL_ABI } from './chain.ts'
import { chainId, RELAY_ADDR } from './config.ts'
import { decodePayoutRouting, type Routing } from './crypto.ts'
import { type Proof, snarkjsProof } from './prover.ts'

const CHAIN_TYPE = 'evm'

/** PrivacyPoolRelay.relay takes exactly what PoolVault.transact does; it is payable for `nativeGas`. */
export const RELAY = createContract([{ ...POOL_ABI[2], name: 'relay', stateMutability: 'payable' }] as const)

async function request(url: string, body?: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(url, {
    ...(body !== undefined && {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
    signal: AbortSignal.timeout(60_000),
  })
  const text = await res.text()
  let json: Record<string, unknown> = {}
  try {
    json = JSON.parse(text)
  } catch {
    // reported below
  }
  if (!res.ok) {
    const why = json.message ?? json.error ?? text
    throw new Error(`HTTP ${res.status} ${(typeof why === 'string' ? why : JSON.stringify(why)).slice(0, 300)}`)
  }
  return json
}

export type Details = {
  /** the PrivacyPoolRelay it submits through, which a proof must name as its processor */
  relay: string
  /** the account that sends the transaction */
  relayerAddress: string
  /** the assets it will quote, lowercased */
  assets: Set<string>
}

/** What a relayer does on this chain, from `GET /v1/details/evm/{chain}`. */
export async function details(base: string): Promise<Details> {
  const d = (await request(`${base}/v1/details/${CHAIN_TYPE}/${chainId()}`)) as {
    id?: number
    contracts?: { relay?: string }
    relayerAddress?: string
    assets?: { address: string }[]
  }
  if (d.id !== chainId()) throw new Error(`answered for chain ${d.id}`)
  if (!d.contracts?.relay || !d.relayerAddress) throw new Error('its details name no relay contract')
  return {
    relay: d.contracts.relay,
    relayerAddress: d.relayerAddress,
    assets: new Set((d.assets ?? []).map((a) => a.address.toLowerCase())),
  }
}

export type Quote = {
  /** what the recipient is paid */
  amount: bigint
  feeAmount: bigint
  /** amount + fee: the transact's `amountOut` */
  amountSent: bigint
  /** the PayoutRouting the relayer signed, to be bound in the proof */
  data: Uint8Array
  routing: Routing
  /** unix ms after which the relayer refuses the commitment */
  expiration: number
  /** the signed commitment, handed back verbatim with the relay request */
  commitment: Record<string, unknown>
}

/**
 * A committed quote for paying `recipient` exactly `amount` of `asset`, and
 * proof that it says so: the routing it signed pays that recipient, takes the
 * fee it quoted and nothing else, and the relayer submits through the
 * PrivacyPoolRelay this client knows. The pool pays the whole `amountOut` to
 * the processor and leaves the split to it, so a relayer that named a
 * contract of its own there could keep everything.
 */
export async function quote(base: string, asset: string, recipient: string, amount: bigint): Promise<Quote> {
  const q = (await request(`${base}/v1/quote/${CHAIN_TYPE}/${chainId()}/receive`, {
    asset,
    commit: true,
    recipient,
    extraGas: false,
    amount: String(amount),
  })) as {
    feeAmount: string
    amountSent: string
    processor?: string
    feeCommitment: Record<string, unknown> & { asset: string; data: string; expiration: number; feeAmount: string }
  }
  const c = q.feeCommitment
  const feeAmount = BigInt(q.feeAmount)
  const data = hexToBytes(c.data.replace(/^0x/, ''))
  const routing = decodePayoutRouting(data)
  const wrong = [
    q.processor?.toLowerCase() !== RELAY_ADDR.toLowerCase() &&
      `it submits through ${q.processor}, not the PrivacyPoolRelay ${RELAY_ADDR}`,
    c.asset.toLowerCase() !== asset.toLowerCase() && `the fee is in ${c.asset}, not ${asset}`,
    routing.recipient.toLowerCase() !== recipient.toLowerCase() && `the routing pays ${routing.recipient}`,
    (routing.feeAmount !== feeAmount || BigInt(c.feeAmount) !== feeAmount) &&
      `the routing takes ${routing.feeAmount} while the fee quoted is ${feeAmount}`,
    routing.nativeGas !== 0n && `the routing asks for ${routing.nativeGas} of native gas`,
    BigInt(q.amountSent) !== amount + feeAmount && `amountSent ${q.amountSent} is not ${amount} + ${feeAmount}`,
  ].filter(Boolean)
  if (wrong.length) throw new Error(`its quote is not what was asked for: ${wrong.join('; ')}`)
  return {
    amount,
    feeAmount,
    amountSent: amount + feeAmount,
    data,
    routing,
    expiration: Number(c.expiration),
    commitment: { ...c, extraGas: false },
  }
}

/**
 * The quote under which `gross` leaves the note: the recipient gets what is
 * left after the fee, as V1 has it. The relayer quotes what the recipient
 * receives, and a fee in basis points moves with that, so the net is found
 * from the fee on the gross and walked down until the total fits.
 */
export async function quoteGross(base: string, asset: string, recipient: string, gross: bigint): Promise<Quote> {
  let q = await quote(base, asset, recipient, gross)
  for (let i = 0; i < 3; i++) {
    const net = gross - q.feeAmount
    if (net <= 0n) throw new Error(`its fee of ${q.feeAmount} leaves nothing of ${gross}`)
    q = await quote(base, asset, recipient, net)
    if (q.amountSent <= gross) return q
  }
  throw new Error(`its fee keeps moving; no quote fits within ${gross}`)
}

/** The proof as the relayer takes it: snarkjs's shape, every number 0x-hex, the public signals flat. */
export function wireProof(p: Proof) {
  const h = (s: string | bigint) => `0x${BigInt(s).toString(16)}`
  const s = snarkjsProof(p)
  return {
    ...s,
    pi_a: s.pi_a.map(h),
    pi_b: s.pi_b.map((xs) => xs.map(h)),
    pi_c: s.pi_c.map(h),
    publicSignals: p.publicSignals.map(h),
  }
}

/** Hand a proven withdrawal to the relayer; it answers with the transaction it sent. */
export async function relay(
  base: string,
  o: {
    quote: Quote
    proof: Proof
    notes: { hint: string; ciphertext: Uint8Array }[]
    inputs: number
  },
): Promise<string> {
  const reply = await request(`${base}/v1/relay/${CHAIN_TYPE}/${chainId()}/withdrawal`, {
    signedFeeCommitment: o.quote.commitment,
    proof: wireProof(o.proof),
    noteData: o.notes.map((n) => ({ hint: n.hint, data: `0x${bytesToHex(n.ciphertext)}` })),
    inputNullifierNumber: o.inputs,
    outputCommitmentNumber: o.notes.length,
  })
  if (typeof reply.txHash !== 'string')
    throw new Error(`the relayer answered without a transaction: ${JSON.stringify(reply)}`)
  return reply.txHash
}
