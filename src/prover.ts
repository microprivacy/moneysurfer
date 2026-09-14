/**
 * Groth16 proofs for Privacy Pools' two circuits with micro-zk-proofs:
 * `withdraw` (spend part of a note, leave change) and `commitment` (ragequit).
 * Witnesses come from the circuits' own wasm (circom.ts); proving keys are
 * the ceremony's snarkjs .zkey files, pinned by sha256 in config.ts.
 */
import { readFileSync } from 'node:fs'
import { availableParallelism } from 'node:os'
import { join } from 'node:path'
// The copy micro-zk-proofs' MSM workers load; package.json pins the same range.
import { bn254 } from '@noble/curves/bn254.js'
import { buildSnark, type GrothProof, type ProvingKey, type VerificationKey } from 'micro-zk-proofs'
import { initMSM } from 'micro-zk-proofs/msm.js'
import { getCoders } from 'micro-zk-proofs/witness.js'
import { type CircuitInput, witnessCalculator } from './circom.ts'
import { ASSETS } from './config.ts'

export type Circuit = 'withdraw' | 'commitment'

type Loaded = { witness: (input: CircuitInput) => bigint[]; pkey: ProvingKey; vkey: VerificationKey }
const loaded = new Map<Circuit, Loaded>()

async function load(circuit: Circuit): Promise<Loaded> {
  let c = loaded.get(circuit)
  if (!c) {
    const { pkey, vkey } = getCoders(bn254).parseZKey(readFileSync(join(ASSETS, `${circuit}.zkey`)))
    c = { witness: await witnessCalculator(readFileSync(join(ASSETS, `${circuit}.wasm`))), pkey, vkey }
    loaded.set(circuit, c)
  }
  return c
}

export type Proof = { proof: GrothProof; publicSignals: bigint[] }

export async function prove(circuit: Circuit, input: CircuitInput, threads = availableParallelism()): Promise<Proof> {
  const { witness, pkey, vkey } = await load(circuit)
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

/** snarkjs's JSON proof shape, as the relayer API takes it. */
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
