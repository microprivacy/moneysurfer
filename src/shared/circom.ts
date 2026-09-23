// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Witness calculation for circom 2 circuits compiled to wasm -- the protocol
 * of the witness_calculator.js circom generates next to each .wasm, without
 * vendoring it. Field elements cross the boundary as 32-bit limbs in a shared
 * buffer, lowest limb first; an input is addressed by the FNV-1a hash of its
 * name, one call per element of an array.
 */
type Exports = {
  init(sanityCheck: number): void
  getFieldNumLen32(): number
  getRawPrime(): void
  readSharedRWMemory(i: number): number
  writeSharedRWMemory(i: number, v: number): void
  getInputSize(): number
  getInputSignalSize(hMSB: number, hLSB: number): number
  setInputSignal(hMSB: number, hLSB: number, i: number): void
  getWitnessSize(): number
  getWitness(i: number): void
  getMessageChar(): number
}

const ERRORS: Record<number, string> = {
  1: 'signal not found',
  2: 'too many signals set',
  3: 'signal already set',
  4: 'assert failed',
  5: 'not enough memory',
  6: 'input signal array access exceeds the size',
}

/** 64-bit FNV-1a of a signal name, split into the two halves the wasm takes. */
function signalHash(name: string): [number, number] {
  let h = 0xcbf29ce484222325n
  for (let i = 0; i < name.length; i++) h = ((h ^ BigInt(name.charCodeAt(i))) * 0x100000001b3n) & 0xffffffffffffffffn
  return [Number(h >> 32n), Number(h & 0xffffffffn)]
}

export type CircuitInput = Record<string, bigint | bigint[]>

/** Compile a circuit once; the result computes a full witness per call. */
export async function witnessCalculator(wasm: Uint8Array): Promise<(input: CircuitInput) => bigint[]> {
  let x: Exports
  let logged = ''
  const message = () => {
    let s = ''
    for (let c = x.getMessageChar(); c !== 0; c = x.getMessageChar()) s += String.fromCharCode(c)
    return s
  }
  const instance = await WebAssembly.instantiate(await WebAssembly.compile(wasm as BufferSource), {
    runtime: {
      exceptionHandler: (code: number) => {
        throw new Error(`circuit: ${ERRORS[code] ?? `error ${code}`}${logged ? `\n${logged}` : ''}`)
      },
      printErrorMessage: () => {
        logged += `${message()}\n`
      },
      writeBufferMessage: () => void message(), // the circuit's log(), not needed
      showSharedRWMemory: () => {},
    },
  })
  x = instance.exports as unknown as Exports
  const n32 = x.getFieldNumLen32()
  const read = () => {
    let v = 0n
    for (let j = n32 - 1; j >= 0; j--) v = (v << 32n) | BigInt(x.readSharedRWMemory(j) >>> 0)
    return v
  }
  x.getRawPrime()
  const prime = read()

  return (input) => {
    logged = ''
    x.init(0)
    let set = 0
    for (const [name, value] of Object.entries(input)) {
      const [hi, lo] = signalHash(name)
      const values = Array.isArray(value) ? value : [value]
      const size = x.getInputSignalSize(hi, lo)
      if (size < 0) throw new Error(`circuit has no input signal ${name}`)
      if (values.length !== size) throw new Error(`input ${name} takes ${size} values, got ${values.length}`)
      values.forEach((v, i) => {
        let limbs = ((v % prime) + prime) % prime
        for (let j = 0; j < n32; j++, limbs >>= 32n) x.writeSharedRWMemory(j, Number(limbs & 0xffffffffn))
        x.setInputSignal(hi, lo, i)
        set++
      })
    }
    if (set < x.getInputSize()) throw new Error(`only ${set} of ${x.getInputSize()} circuit inputs set`)
    const witness: bigint[] = []
    for (let i = 0, n = x.getWitnessSize(); i < n; i++) {
      x.getWitness(i)
      witness.push(read())
    }
    return witness
  }
}
