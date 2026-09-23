// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * V2's 27 circuits. Their artifacts are content-addressed on IPFS and pinned
 * by sha256 in circuit-artifacts.json, so artifacts.ts re-checks every file it
 * hands over; the proving itself is shared/prover.ts, the same engine V1 uses.
 *
 * Unlike V1, this ceremony publishes a verification key apart from the zkey.
 * That is the key the deployed verifiers were built from, so it is the one a
 * proof is checked against before anyone is asked to send it.
 */
import type { CircuitInput } from '../shared/circom.ts'
import { makeProver, type Proof, type VerificationKey } from '../shared/prover.ts'
import { load, verificationKey } from './artifacts.ts'

export { fromSolidityProof, type Proof, snarkjsProof, solidityProof } from '../shared/prover.ts'

const prover = makeProver((circuit) => ({
  wasm: load(circuit, 'wasm'),
  zkey: load(circuit, 'zkey'),
  vkey: verificationKey(circuit) as unknown as VerificationKey,
}))

export const prove = (circuit: string, input: CircuitInput, threads?: number): Promise<Proof> =>
  prover.prove(circuit, input, threads)

/** Check a proof against the ceremony's verification key, without proving. */
export const verifyProof = (circuit: string, proof: Proof): boolean =>
  prover.verifyProof(verificationKey(circuit) as unknown as VerificationKey, proof)
