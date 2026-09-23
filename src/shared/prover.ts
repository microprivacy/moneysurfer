// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Groth16 with micro-zk-proofs. Both protocols use the same proof system, the
 * same curve and the same encoding on the wire, so all of that lives here;
 * only *where the artifacts come from* differs, and that is the `Artifacts`
 * function each protocol binds in its own prover.ts.
 *
 * Witnesses come from the circuits' own wasm (circom.ts); proving keys are the
 * ceremonies' snarkjs .zkey files.
 */
import { availableParallelism } from 'node:os'
// The copy micro-zk-proofs' MSM workers load; package.json pins the same range.
import { bn254 } from '@noble/curves/bn254.js'
import { buildSnark, type GrothProof, type ProvingKey, type VerificationKey } from 'micro-zk-proofs'
import { initMSM } from 'micro-zk-proofs/msm.js'
import { getCoders } from 'micro-zk-proofs/witness.js'
import { type CircuitInput, witnessCalculator } from './circom.ts'

export type { VerificationKey }

/**
 * One circuit's bytes. `vkey` is the ceremony's own verification key where the
 * ceremony publishes one apart from the zkey -- V2 does, and it is the key the
 * chain was deployed against, so it is the one worth checking a proof with.
 * Where it is absent the zkey's embedded key is used instead.
 */
export type Artifacts = { wasm: Uint8Array; zkey: Uint8Array; vkey?: VerificationKey }

export type Proof = { proof: GrothProof; publicSignals: bigint[] }

type Loaded = { witness: (input: CircuitInput) => bigint[]; pkey: ProvingKey; vkey: VerificationKey }

/**
 * A prover bound to one source of artifacts. Parsing a zkey is slow and the
 * result is immutable, so each circuit is opened once and kept.
 */
export function makeProver(source: (circuit: string) => Artifacts) {
  const loaded = new Map<string, Loaded>()

  async function open(circuit: string): Promise<Loaded> {
    let c = loaded.get(circuit)
    if (!c) {
      const a = source(circuit)
      const { pkey, vkey } = getCoders(bn254).parseZKey(a.zkey)
      c = { witness: await witnessCalculator(a.wasm), pkey, vkey: a.vkey ?? vkey }
      loaded.set(circuit, c)
    }
    return c
  }

  return {
    async prove(circuit: string, input: CircuitInput, threads = availableParallelism()): Promise<Proof> {
      const { witness, pkey, vkey } = await open(circuit)
      const w = witness(input)
      const msm = threads > 1 ? initMSM() : undefined
      try {
        const { groth } = buildSnark(bn254, {
          ...(msm && {
            G1msm: (points) => msm.methods.bn254_msmG1(points, threads),
            G2msm: (points) => msm.methods.bn254_msmG2(points, threads),
          }),
        })
        const proof = await groth.createProof(pkey, w)
        // A proof the ceremony's own verifying key rejects is never worth sending.
        if (!groth.verifyProof(vkey, proof)) throw new Error(`${circuit}: the proof does not verify`)
        return proof
      } finally {
        msm?.terminate()
      }
    },
    /** Check a proof against the ceremony's verification key, without proving. */
    verifyProof(vkey: VerificationKey, proof: Proof): boolean {
      return buildSnark(bn254).groth.verifyProof(vkey, proof)
    },
  }
}

/** The ProofLib struct the contracts take; pB's coordinates swap for the EVM's pairing precompile. */
export function solidityProof({ proof: p, publicSignals }: Proof) {
  return {
    pA: [p.pi_a[0], p.pi_a[1]] as [bigint, bigint],
    pB: [
      [p.pi_b[0][1], p.pi_b[0][0]],
      [p.pi_b[1][1], p.pi_b[1][0]],
    ] as [[bigint, bigint], [bigint, bigint]],
    pC: [p.pi_c[0], p.pi_c[1]] as [bigint, bigint],
    pubSignals: publicSignals,
  }
}

/** Read a ProofLib struct back off calldata, undoing that swap. */
export function fromSolidityProof(pA: bigint[], pB: bigint[][], pC: bigint[], publicSignals: bigint[]): Proof {
  return {
    proof: {
      curve: 'bn254',
      protocol: 'groth16',
      pi_a: [pA[0]!, pA[1]!, 1n],
      pi_b: [
        [pB[0]![1]!, pB[0]![0]!],
        [pB[1]![1]!, pB[1]![0]!],
        [1n, 0n],
      ],
      pi_c: [pC[0]!, pC[1]!, 1n],
    } as unknown as GrothProof,
    publicSignals,
  }
}

/** snarkjs's JSON proof shape, as the relayer APIs take it. */
export function snarkjsProof({ proof: p }: Proof) {
  const s = String
  return {
    protocol: 'groth16',
    curve: 'bn128',
    pi_a: [s(p.pi_a[0]), s(p.pi_a[1]), '1'],
    pi_b: [
      [s(p.pi_b[0][0]), s(p.pi_b[0][1])],
      [s(p.pi_b[1][0]), s(p.pi_b[1][1])],
      ['1', '0'],
    ],
    pi_c: [s(p.pi_c[0]), s(p.pi_c[1]), '1'],
  }
}
