// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The opening a deposit hands the ASP -- the third `bytes` argument of
 * `Entrypoint.deposit`, forwarded to the ASPRegistry and re-emitted verbatim as
 * `LabelRegistered(bytes)`. It is the one part of a deposit nobody outside the
 * ASP can read, and it is what decides whether the deposit is ever attested:
 * get it wrong and the pool takes the money and the label never joins the
 * association set.
 *
 * The scheme is a sealed box. An ephemeral X25519 key is generated per message,
 * ECDH'd against the ASP's published key, and the shared secret hashed once
 * with sha256 into an XChaCha20-Poly1305 key; noble's `managedNonce` puts a
 * random 24-byte nonce in front of the ciphertext. So:
 *
 *   ephemeralPublicKey(32) || nonce(24) || ciphertext(n) || tag(16)
 *
 * and the plaintext is JSON, whose five fields are written in a fixed order
 * with two of them padded to a fixed width. See FINDINGS.md for where this
 * came from and how it was checked.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { managedNonce } from '@noble/ciphers/utils.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { UsageError } from './config.ts'

/** X25519 public key, XChaCha20 nonce, Poly1305 tag: what a sealed box costs on top of its plaintext. */
export const KEY_BYTES = 32
export const NONCE_BYTES = 24
export const TAG_BYTES = 16
export const OVERHEAD_BYTES = KEY_BYTES + NONCE_BYTES + TAG_BYTES

/** What the deposit tells the ASP. Everything else about the note stays private. */
export type Opening = {
  noteAddressHash: bigint
  tokenId: string
  value: bigint
  depositSecret: bigint
}

const hex64 = (n: bigint) => `0x${n.toString(16).padStart(64, '0')}`

/**
 * The exact plaintext, byte for byte. Field order is insertion order --
 * `JSON.stringify` keeps it -- and the widths are not cosmetic: the reader
 * rejects a `noteAddressHash` or `depositSecret` that is not 64 hex digits and
 * a `tokenId` that is not 40, while `value` is minimal hex with no padding at
 * all. `metadata` is the literal string "0x0", not a converted number; v2.0
 * has no other value for it.
 */
export function openingJson(o: Opening): string {
  const tokenId = o.tokenId.toLowerCase()
  if (!/^0x[0-9a-f]{40}$/.test(tokenId)) throw new UsageError(`tokenId ${o.tokenId} is not a 20-byte address`)
  if (o.noteAddressHash < 0n || o.noteAddressHash >= 1n << 256n) throw new UsageError('noteAddressHash does not fit')
  if (o.depositSecret < 0n || o.depositSecret >= 1n << 256n) throw new UsageError('depositSecret does not fit')
  if (o.value < 0n) throw new UsageError('value is negative')
  return JSON.stringify({
    noteAddressHash: hex64(o.noteAddressHash),
    tokenId,
    value: `0x${o.value.toString(16)}`,
    depositSecret: hex64(o.depositSecret),
    metadata: '0x0',
  })
}

/** The length a blob will have, without building one: 330 + the hex digits of `value`. */
export const openingLength = (o: Opening) => openingJson(o).length + OVERHEAD_BYTES

/**
 * One X25519 point, from either a 0x-string or raw bytes. The all-zero point
 * is refused here rather than later: it is what a low-order public key makes
 * ECDH produce, and it would encrypt to a key the sender does not control.
 */
function publicKey(key: string | Uint8Array): Uint8Array {
  const bytes = typeof key === 'string' ? hexToBytes(key.replace(/^0x/, '')) : key
  if (bytes.length !== KEY_BYTES) throw new UsageError(`an X25519 public key is 32 bytes, not ${bytes.length}`)
  if (bytes.every((b) => b === 0)) throw new UsageError('the all-zero X25519 point is not a public key')
  return bytes
}

/** sha256 of the ECDH output: the SDK hashes the shared secret once and takes 32 bytes. */
function sealKey(secret: Uint8Array, theirs: Uint8Array): Uint8Array {
  const shared = x25519.getSharedSecret(secret, theirs)
  if (shared.every((b) => b === 0)) throw new Error('ECDH produced an all-zero shared secret -- low-order public key')
  return sha256(shared).slice(0, KEY_BYTES)
}

/**
 * Seal bytes to an X25519 public key: a fresh ephemeral key per message, and a
 * fresh nonce per message inside that. Two seals of the same plaintext to the
 * same recipient share no bytes.
 */
export function seal(plaintext: Uint8Array, recipient: string | Uint8Array): Uint8Array {
  const theirs = publicKey(recipient)
  const { secretKey, publicKey: mine } = x25519.keygen()
  const box = managedNonce(xchacha20poly1305)(sealKey(secretKey, theirs))
  return concatBytes(mine, box.encrypt(plaintext))
}

/** Undo `seal` with the recipient's private key. Throws if the tag does not check out. */
export function unseal(blob: Uint8Array, secret: Uint8Array): Uint8Array {
  if (blob.length < OVERHEAD_BYTES + 1) throw new UsageError(`a sealed box is at least 73 bytes, not ${blob.length}`)
  const theirs = publicKey(blob.slice(0, KEY_BYTES))
  return managedNonce(xchacha20poly1305)(sealKey(secret, theirs)).decrypt(blob.slice(KEY_BYTES))
}

/** The `aspCiphertext` argument of a deposit. */
export const encodeOpening = (o: Opening, aspPublicKey: string | Uint8Array) =>
  seal(utf8ToBytes(openingJson(o)), aspPublicKey)

/**
 * What the ASP reads. Only the ASP's own private key opens a real blob -- this
 * is here so the encoder has an offline oracle, and so a client can check what
 * it is about to publish before it publishes it.
 */
export function decodeOpening(blob: Uint8Array, aspPrivateKey: Uint8Array): Opening {
  const json = new TextDecoder().decode(unseal(blob, aspPrivateKey))
  const p = JSON.parse(json) as Record<string, unknown>
  const field = (name: string, digits?: number) => {
    const v = p[name]
    if (typeof v !== 'string' || !/^0x[0-9a-fA-F]+$/.test(v)) throw new Error(`${name} is not a hex string: ${v}`)
    if (digits !== undefined && v.length - 2 !== digits)
      throw new Error(`${name} is ${v.length - 2} hex digits, not ${digits}`)
    return BigInt(v)
  }
  const tokenId = p.tokenId
  if (typeof tokenId !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(tokenId)) throw new Error('tokenId is not an address')
  if (p.metadata !== '0x0') throw new Error(`metadata is ${JSON.stringify(p.metadata)}, not "0x0"`)
  return {
    noteAddressHash: field('noteAddressHash', 64),
    tokenId,
    value: field('value'),
    depositSecret: field('depositSecret', 64),
  }
}

/** The ephemeral public key a blob leads with -- readable without any key at all. */
export const ephemeralKeyOf = (blob: Uint8Array) => `0x${bytesToHex(publicKey(blob.slice(0, KEY_BYTES)))}`
