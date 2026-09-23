// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Privacy Pools' two circuits: `withdraw` (spend part of a note, leave change)
 * and `commitment` (ragequit). Their artifacts sit in ASSETS under those
 * names, pinned by the sha256 in config.ts and checked when `setup` fetches
 * them. The proving itself is shared/prover.ts; this only says where the bytes
 * come from, and narrows the circuit name to the two that exist.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { CircuitInput } from '../shared/circom.ts'
import { makeProver, type Proof } from '../shared/prover.ts'
import { ASSETS } from './config.ts'

export type Circuit = 'withdraw' | 'commitment'

export { fromSolidityProof, type Proof, snarkjsProof, solidityProof } from '../shared/prover.ts'

const prover = makeProver((circuit) => ({
  wasm: readFileSync(join(ASSETS, `${circuit}.wasm`)),
  zkey: readFileSync(join(ASSETS, `${circuit}.zkey`)),
}))

export const prove = (circuit: Circuit, input: CircuitInput, threads?: number): Promise<Proof> =>
  prover.prove(circuit, input, threads)
