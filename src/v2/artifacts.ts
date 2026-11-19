// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The circuits' wasm and trusted-setup keys. What makes a file usable is its
 * sha256 matching the manifest, never where it came from, so the one host they
 * are fetched from is trusted with nothing but availability.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { ARTIFACTS_URL, ASSETS, artifact, UsageError } from './config.ts'

export type Kind = 'wasm' | 'zkey' | 'vkey'

/** Where a kind sits under ARTIFACTS_URL, by the app's own layout. */
const remote = (circuit: string, kind: Kind) =>
  kind === 'wasm'
    ? `${circuit}/${circuit}_js/${circuit}.wasm`
    : `${circuit}/${kind === 'zkey' ? 'groth16_pkey.zkey' : 'groth16_vkey.json'}`

/** The sha256 the manifest pins. */
export function pinned(circuit: string, kind: Kind): string {
  const a = artifact(circuit)
  return kind === 'wasm' ? a.wasmSha256 : kind === 'zkey' ? a.provingKeySha256 : a.verificationKeySha256
}

export const path = (circuit: string, kind: Kind) => join(ASSETS, `${circuit}.${kind}`)

export const have = (circuit: string, kind: Kind) => existsSync(path(circuit, kind))

/**
 * Whether the file on disk is the one pinned. A file from an earlier manifest
 * -- the first ceremony's keys, say -- is there but is not current.
 */
export const current = (circuit: string, kind: Kind) =>
  have(circuit, kind) && bytesToHex(sha256(readFileSync(path(circuit, kind)))) === pinned(circuit, kind)

/** Read an artifact off disk, refusing it if it no longer hashes to the manifest. */
export function load(circuit: string, kind: Kind): Uint8Array {
  const file = path(circuit, kind)
  if (!existsSync(file)) throw new UsageError(`${circuit}.${kind} is not downloaded -- run \`setup ${circuit}\``)
  const bytes = new Uint8Array(readFileSync(file))
  const want = pinned(circuit, kind)
  const got = bytesToHex(sha256(bytes))
  if (got !== want) {
    throw new UsageError(
      `${file} has sha256 ${got}, not the pinned ${want} -- it is from an older set; run \`moneysurfer v2 setup ${circuit}\``,
    )
  }
  return bytes
}

/** Fetch one artifact and keep it only if it hashes to what the manifest pins. */
export async function fetchArtifact(circuit: string, kind: Kind): Promise<Uint8Array> {
  const url = `${ARTIFACTS_URL}/${remote(circuit, kind)}`
  const want = pinned(circuit, kind)
  const res = await fetch(url, { signal: AbortSignal.timeout(300_000) })
  if (!res.ok) throw new Error(`could not fetch ${circuit}.${kind}: ${url}: HTTP ${res.status}`)
  const bytes = new Uint8Array(await res.arrayBuffer())
  const got = bytesToHex(sha256(bytes))
  if (got !== want) throw new Error(`${url} has sha256 ${got}, not the pinned ${want} -- refused`)
  mkdirSync(ASSETS, { recursive: true })
  const file = path(circuit, kind)
  writeFileSync(`${file}.tmp`, bytes)
  renameSync(`${file}.tmp`, file)
  return bytes
}

/** Everything a circuit needs to prove, downloading what is missing or out of date. */
export async function setup(circuit: string, kinds: Kind[] = ['wasm', 'zkey', 'vkey']): Promise<void> {
  for (const kind of kinds) if (!current(circuit, kind)) await fetchArtifact(circuit, kind)
}

/**
 * A constant as solc puts it in bytecode: PUSHn and the value's n bytes, with
 * no leading zeros -- a key point under 2^248 is a PUSH31, not a PUSH32.
 */
export function pushed(word: bigint): string {
  let hex = word.toString(16)
  if (hex.length % 2) hex = `0${hex}`
  return `${(0x5f + hex.length / 2).toString(16)}${hex}`
}

/** The constants that set one circuit's verifier apart, pushed as solc does. */
export function keyPushes(circuit: string): string[] {
  const j = JSON.parse(new TextDecoder().decode(load(circuit, 'vkey'))) as { vk_delta_2: string[][]; IC: string[][] }
  return [...j.vk_delta_2.slice(0, 2).flat(), ...j.IC.flatMap((p) => p.slice(0, 2))].map((w) => pushed(BigInt(w)))
}

/**
 * Whether a deployed verifier was built from this circuit's pinned key.
 * snarkjs's verifier carries the key's points as constants, so delta and
 * every IC point appear in its bytecode. Alpha, beta and gamma are left out:
 * they do not depend on the circuit's own setup, and match a verifier from
 * another ceremony just as well.
 */
export function builtFrom(code: string, circuit: string): boolean {
  const hay = code.toLowerCase()
  return keyPushes(circuit).every((p) => hay.includes(p))
}

export type VerificationKey = {
  protocol: string
  curve: string
  nPublic: number
  vk_alfa_1: bigint[]
  vk_beta_2: bigint[][]
  vk_gamma_2: bigint[][]
  vk_delta_2: bigint[][]
  IC: bigint[][]
}

/** snarkjs's verification_key.json in the shape micro-zk-proofs verifies with. */
export function verificationKey(circuit: string): VerificationKey {
  const j = JSON.parse(new TextDecoder().decode(load(circuit, 'vkey')))
  const g1 = (p: string[]) => p.map(BigInt)
  const g2 = (p: string[][]) => p.map(g1)
  return {
    protocol: j.protocol,
    curve: j.curve,
    nPublic: j.nPublic,
    vk_alfa_1: g1(j.vk_alpha_1),
    vk_beta_2: g2(j.vk_beta_2),
    vk_gamma_2: g2(j.vk_gamma_2),
    vk_delta_2: g2(j.vk_delta_2),
    IC: j.IC.map(g1),
  }
}
