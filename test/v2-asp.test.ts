// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The ASP's deposit opening. The blobs on chain are encrypted to a key only the
 * ASP holds, so they cannot be decrypted here -- but the scheme is a sealed box
 * to a *published* key, which means anyone can run it against a key they own
 * and check that what comes back is what went in. That round trip is the
 * oracle; the 39 real blobs then confirm the layout it produces is the layout
 * the real ones have.
 */
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { x25519 } from '@noble/curves/ed25519.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import {
  decodeOpening,
  encodeOpening,
  ephemeralKeyOf,
  KEY_BYTES,
  NONCE_BYTES,
  type Opening,
  OVERHEAD_BYTES,
  openingJson,
  openingLength,
  seal,
  TAG_BYTES,
  unseal,
} from '../src/v2/asp.ts'
import { NATIVE } from '../src/v2/config.ts'
import { generateSecret } from '../src/v2/crypto.ts'

type Vectors = {
  aspOpenings: {
    aspPublicKey: string
    blobs: { tx: string; value: string; tokenId: string; blob: string }[]
  }
}
const v: Vectors = JSON.parse(readFileSync(new URL('v2-vectors.json', import.meta.url), 'utf8'))

/** A recipient we hold both halves of, standing in for the ASP. */
const asp = x25519.keygen()

const opening = (value: bigint): Opening => ({
  noteAddressHash: generateSecret(),
  tokenId: NATIVE,
  value,
  depositSecret: generateSecret(),
})

test('a sealed opening decrypts back to exactly what went in', () => {
  const o = opening(10n ** 16n)
  const blob = encodeOpening(o, asp.publicKey)
  const back = decodeOpening(blob, asp.secretKey)
  assert.deepEqual(back, { ...o, tokenId: NATIVE.toLowerCase() })
  // and byte-exactly, not just field by field: the plaintext is a fixed string
  assert.equal(new TextDecoder().decode(unseal(blob, asp.secretKey)), openingJson(o))
})

test('the plaintext is the five fields in one fixed order', () => {
  const o: Opening = {
    noteAddressHash: 0x2an,
    tokenId: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
    value: 10n ** 16n,
    depositSecret: 0xffn,
  }
  assert.equal(
    openingJson(o),
    '{"noteAddressHash":"0x000000000000000000000000000000000000000000000000000000000000002a",' +
      '"tokenId":"0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",' +
      '"value":"0x2386f26fc10000",' +
      '"depositSecret":"0x00000000000000000000000000000000000000000000000000000000000000ff",' +
      '"metadata":"0x0"}',
  )
  // the two secrets are fixed-width and the value is not: that asymmetry is the
  // whole of the length law below
  assert.equal(openingJson(o).length, 258 + 14)
})

test('the envelope is ephemeral key, nonce, ciphertext, tag', () => {
  const blob = encodeOpening(opening(1n), asp.publicKey)
  assert.equal(OVERHEAD_BYTES, KEY_BYTES + NONCE_BYTES + TAG_BYTES)
  assert.equal(blob.length, openingJson(opening(1n)).length + OVERHEAD_BYTES)
  // the leading 32 bytes are a usable X25519 point: ECDH against it works
  const eph = blob.slice(0, KEY_BYTES)
  assert.equal(eph.length, 32)
  assert.ok(!eph.every((b) => b === 0))
  assert.doesNotThrow(() => x25519.getSharedSecret(asp.secretKey, eph))
  assert.equal(ephemeralKeyOf(blob).length, 66)
})

test('a fresh ephemeral key every time, so two identical openings differ', () => {
  const o = opening(10n ** 15n)
  const a = encodeOpening(o, asp.publicKey)
  const b = encodeOpening(o, asp.publicKey)
  assert.notEqual(ephemeralKeyOf(a), ephemeralKeyOf(b))
  assert.notDeepEqual(a, b)
  assert.deepEqual(decodeOpening(a, asp.secretKey), decodeOpening(b, asp.secretKey))
})

test('length is 330 + the hex digits of the value, whatever the value is', () => {
  const values = [
    1n, // one hex digit
    15n,
    16n, // two, the second of which is zero
    0xfffn, // an odd number of digits
    0x1000n, // an even number, top nibble 1
    0x0fffffn, // six digits with a zero top nibble once padded
    500_000n,
    10n ** 6n,
    10n ** 15n,
    10n ** 16n,
    2n ** 128n - 1n,
    2n ** 255n, // 64 digits, the widest a value can be
  ]
  for (const value of values) {
    const o = opening(value)
    const digits = value.toString(16).length
    const blob = encodeOpening(o, asp.publicKey)
    assert.equal(blob.length, 330 + digits, `value 0x${value.toString(16)} (${digits} digits)`)
    assert.equal(openingLength(o), blob.length)
    assert.equal(decodeOpening(blob, asp.secretKey).value, value)
  }
})

test('the two secrets are fixed width, so a small one does not shorten the blob', () => {
  // a noteAddressHash with a zero leading nibble is the case that would betray
  // a minimal-hex encoding; it must not change the length by a single byte
  const small = { ...opening(10n ** 16n), noteAddressHash: 1n, depositSecret: 2n }
  const big = { ...opening(10n ** 16n), noteAddressHash: 2n ** 255n, depositSecret: 2n ** 255n }
  assert.equal(encodeOpening(small, asp.publicKey).length, encodeOpening(big, asp.publicKey).length)
})

test('the wrong key, or a flipped bit, does not open it', () => {
  const blob = encodeOpening(opening(1n), asp.publicKey)
  assert.throws(() => decodeOpening(blob, x25519.keygen().secretKey))
  for (const i of [0, KEY_BYTES, KEY_BYTES + NONCE_BYTES, blob.length - 1]) {
    const bad = Uint8Array.from(blob)
    bad[i]! ^= 1
    assert.throws(() => decodeOpening(bad, asp.secretKey), Error, `byte ${i}`)
  }
})

test('a truncated blob is refused rather than half-parsed', () => {
  const blob = encodeOpening(opening(1n), asp.publicKey)
  assert.throws(() => unseal(blob.slice(0, OVERHEAD_BYTES), asp.secretKey), /at least 73 bytes/)
  assert.throws(() => seal(new Uint8Array(1), new Uint8Array(31)), /32 bytes/)
  assert.throws(() => seal(new Uint8Array(1), new Uint8Array(32)), /all-zero/)
})

// ---------------------------------------------------------------------------
// The 39 real blobs
// ---------------------------------------------------------------------------
test('every LabelRegistered blob on chain obeys the same length law', () => {
  const { blobs } = v.aspOpenings
  assert.equal(blobs.length, 39)
  for (const b of blobs) {
    const digits = BigInt(b.value).toString(16).length
    assert.equal((b.blob.length - 2) / 2, 330 + digits, `${b.tx} (value ${b.value})`)
  }
})

test("our own blobs are the same shape as the chain's, for the same values", () => {
  for (const b of v.aspOpenings.blobs) {
    const ours = encodeOpening(
      {
        noteAddressHash: generateSecret(),
        tokenId: b.tokenId,
        value: BigInt(b.value),
        depositSecret: generateSecret(),
      },
      v.aspOpenings.aspPublicKey,
    )
    assert.equal(ours.length, (b.blob.length - 2) / 2, `${b.tx} (value ${b.value})`)
  }
})

test('every real blob leads with a usable X25519 point and carries a full envelope', () => {
  const mine = x25519.keygen().secretKey
  const seen = new Set<string>()
  for (const b of v.aspOpenings.blobs) {
    const bytes = hexToBytes(b.blob.slice(2))
    const eph = bytes.slice(0, KEY_BYTES)
    assert.equal(eph.length, KEY_BYTES, b.tx)
    assert.ok(!eph.every((x) => x === 0), `${b.tx}: all-zero point`)
    // low-order and non-contributory points make ECDH return all zeroes
    assert.ok(
      !x25519.getSharedSecret(mine, eph).every((x) => x === 0),
      `${b.tx}: the leading 32 bytes are not a contributory point`,
    )
    // the rest must hold a nonce, at least a byte of ciphertext and a tag
    assert.ok(bytes.length - KEY_BYTES >= NONCE_BYTES + TAG_BYTES, b.tx)
    seen.add(b.blob.slice(2, 2 + 64))
  }
  assert.equal(seen.size, v.aspOpenings.blobs.length, 'an ephemeral key was reused')
})
