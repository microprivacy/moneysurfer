// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The circuits' wasm and trusted-setup keys. They are content-addressed, so
 * any gateway will do: what makes a file usable is its sha256 matching the
 * manifest, never where it came from. The verification keys carry no sha256 --
 * their CID is the hash -- so those are trusted only as far as the CID.
 */
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { ASSETS, artifact, IPFS_GATEWAYS, UsageError } from './config.ts'

export type Kind = 'wasm' | 'zkey' | 'vkey'

const CID: Record<Kind, 'wasm' | 'provingKey' | 'verificationKey'> = {
  wasm: 'wasm',
  zkey: 'provingKey',
  vkey: 'verificationKey',
}

/** The sha256 the manifest pins, or undefined where it pins none. */
export function pinned(circuit: string, kind: Kind): string | undefined {
  const a = artifact(circuit)
  return kind === 'wasm' ? a.wasmSha256 : kind === 'zkey' ? a.provingKeySha256 : undefined
}

export const path = (circuit: string, kind: Kind) => join(ASSETS, `${circuit}.${kind}`)

export const have = (circuit: string, kind: Kind) => existsSync(path(circuit, kind))

/** Read an artifact off disk, refusing it if it no longer hashes to the manifest. */
export function load(circuit: string, kind: Kind): Uint8Array {
  const file = path(circuit, kind)
  if (!existsSync(file)) throw new UsageError(`${circuit}.${kind} is not downloaded -- run \`setup ${circuit}\``)
  const bytes = new Uint8Array(readFileSync(file))
  const want = pinned(circuit, kind)
  const got = bytesToHex(sha256(bytes))
  if (want && got !== want)
    throw new Error(`${file} has sha256 ${got}, not the pinned ${want} -- delete it and re-run setup`)
  return bytes
}

/**
 * Fetch one artifact and keep it only if it hashes to what the manifest pins.
 * Gateways are tried in turn: a 429 from one says nothing about the next.
 */
export async function fetchArtifact(circuit: string, kind: Kind): Promise<Uint8Array> {
  const cid = artifact(circuit)[CID[kind]]
  const want = pinned(circuit, kind)
  const failures: string[] = []
  for (const gateway of IPFS_GATEWAYS) {
    let bytes: Uint8Array
    try {
      const res = await fetch(`${gateway}/ipfs/${cid}`, { signal: AbortSignal.timeout(300_000) })
      if (!res.ok) {
        failures.push(`${gateway}: HTTP ${res.status}`)
        continue
      }
      bytes = new Uint8Array(await res.arrayBuffer())
    } catch (e) {
      failures.push(`${gateway}: ${(e as Error).message}`)
      continue
    }
    const got = bytesToHex(sha256(bytes))
    if (want && got !== want) {
      failures.push(`${gateway}: sha256 ${got}, want ${want}`)
      continue
    }
    mkdirSync(ASSETS, { recursive: true })
    const file = path(circuit, kind)
    writeFileSync(`${file}.tmp`, bytes)
    renameSync(`${file}.tmp`, file)
    return bytes
  }
  throw new Error(`could not fetch ${circuit}.${kind} (${cid}):\n  ${failures.join('\n  ')}`)
}

/** Everything a circuit needs to prove, downloading what is missing. */
export async function setup(circuit: string, kinds: Kind[] = ['wasm', 'zkey', 'vkey']): Promise<void> {
  for (const kind of kinds) if (!have(circuit, kind)) await fetchArtifact(circuit, kind)
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
