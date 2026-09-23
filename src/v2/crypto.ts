// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Privacy Pools V2's cryptography. The Poseidon and the LeanIMT are V1's, but
 * a note is no longer (nullifier, secret): it is owned by an address, its
 * nullifier comes from one account-wide nullifying key, and the pool's tree
 * holds tagged, timestamped leaves rather than bare commitments. Every shape
 * here is checked against mainnet in test/crypto.test.ts.
 */
import { grainGenConstants, poseidon } from '@noble/curves/abstract/poseidon.js'
import { bn254 } from '@noble/curves/bn254.js'
import { x25519 } from '@noble/curves/ed25519.js'
import { bytesToNumberBE } from '@noble/curves/utils.js'
import { hkdf, expand as hkdfExpand, extract as hkdfExtract } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { createContract } from 'micro-eth-signer/abi.js'

const Fr = bn254.fields.Fr
/** The BN254 scalar field every hash, label and context lives in. */
export const SNARK_FIELD = Fr.ORDER

// circomlib's Poseidon: 8 full rounds, partial rounds by width t, x^5 S-box,
// constants from the reference Grain generator.
const PARTIAL_ROUNDS = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]
const hashers = new Map<number, (state: bigint[]) => bigint[]>()

/** circomlib Poseidon of 1..16 field elements. */
export function hash(inputs: bigint[]): bigint {
  const t = inputs.length + 1
  let permute = hashers.get(t)
  if (!permute) {
    const opts = { Fp: Fr, t, roundsFull: 8, roundsPartial: PARTIAL_ROUNDS[t - 2]!, sboxPower: 5 }
    permute = poseidon({ ...opts, ...grainGenConstants(opts) })
    hashers.set(t, permute)
  }
  return permute([0n, ...inputs.map((x) => Fr.create(x))])[0]!
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------
/** 0xEeee...EEeE, the asset id ETH deposits carry. */
export const NATIVE = '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE'

export const addressToField = (a: string) => BigInt(a.toLowerCase())

/** A note's owner binding. The address is public; the secret is not. */
export const noteAddressHash = (owner: string, noteSecret: bigint) => hash([addressToField(owner), noteSecret])

/** What a deposit proves it knows, before the label exists. `metadata` is 0 in v2.0. */
export const precommitment = (addressHash: bigint, tokenId: string, value: bigint, metadata = 0n) =>
  hash([addressHash, addressToField(tokenId), value, metadata])

/** The lineage tag the ASP attests to: one per deposit, inherited by every note descended from it. */
export const label = (pre: bigint, depositSecret: bigint) => hash([pre, depositSecret])

/** A note's on-chain identifier. */
export const commitment = (pre: bigint, lbl: bigint) => hash([pre, lbl])

/** What the pool marks spent. One nullifying key covers every note an account owns. */
export const nullifier = (privateNullifyingKey: bigint, commit: bigint) => hash([privateNullifyingKey, commit])

// ---------------------------------------------------------------------------
// The two trees
// ---------------------------------------------------------------------------
/** src/utils/Constants.sol: the domain tags that keep the two leaf kinds apart in one tree. */
export const COMMITMENT_LEAF_TAG = 3791694183000795315792098099581407680958131641292811872617553086713867485913n
export const NULLIFIER_LEAF_TAG = 1480564842420020354887207755615370381236762558448265256256653429412951563031n

/**
 * What the pool actually inserts. Tagging keeps commitments and nullifiers in
 * one tree without colliding; the timestamp makes a leaf unreplayable into a
 * fork of the same pool.
 */
export const commitmentLeaf = (commit: bigint, timestamp: bigint) => hash([COMMITMENT_LEAF_TAG, commit, timestamp])
export const nullifierLeaf = (nul: bigint, timestamp: bigint) => hash([NULLIFIER_LEAF_TAG, nul, timestamp])

/** The keystore's leaf for a registered account. The viewing key is not in it. */
export const keystoreLeaf = (owner: string, nullifyingKeyHash: bigint, authDigest: bigint) =>
  hash([addressToField(owner), nullifyingKeyHash, authDigest])

export const nullifyingKeyHash = (privateNullifyingKey: bigint) => hash([privateNullifyingKey])

/**
 * What the ASP puts in its association set -- the label hashed once, not the
 * label itself. Confirmed against transact_1x1: the circuit's assert fails on a
 * raw label. It is also what `/labels/{hash}/status` is keyed by.
 */
export const aspLeaf = (lbl: bigint) => hash([lbl])

/** AUTH_TYPE_DIRECT_KEY = 0: the policy a first registration sets. */
export const authDigest = (privateRevocableKey: bigint) => hash([0n, privateRevocableKey])

// ---------------------------------------------------------------------------
// LeanIMT (zk-kit): a binary tree whose depth grows with its leaves, where a
// node with no right sibling moves up unchanged instead of pairing with a zero.
// ---------------------------------------------------------------------------
export type MerkleProof = { root: bigint; leaf: bigint; index: number; siblings: bigint[] }

export class LeanIMT {
  readonly levels: bigint[][]

  constructor(leaves: bigint[]) {
    this.levels = [leaves]
    for (let level = leaves; level.length > 1; ) {
      const up: bigint[] = []
      for (let i = 0; i < level.length; i += 2)
        up.push(i + 1 < level.length ? hash([level[i]!, level[i + 1]!]) : level[i]!)
      this.levels.push(up)
      level = up
    }
  }

  get depth() {
    return this.levels.length - 1
  }
  get size() {
    return this.levels[0]!.length
  }
  get root(): bigint {
    return this.levels[this.depth]![0] ?? 0n
  }

  /**
   * A proof in zk-kit's compressed form: levels without a sibling are left
   * out, and `index` holds one path bit per sibling kept, lowest level first
   * -- which is what the circuit's BinaryMerkleRoot reads.
   */
  proof(leafIndex: number): MerkleProof {
    const leaf = this.levels[0]![leafIndex]
    if (leaf === undefined) throw new Error(`no leaf ${leafIndex} in a tree of ${this.size}`)
    const siblings: bigint[] = []
    let index = 0
    for (let level = 0, i = leafIndex; level < this.depth; level++, i >>= 1) {
      const right = i & 1
      const sibling = this.levels[level]![right ? i - 1 : i + 1]
      if (sibling === undefined) continue
      index += right * 2 ** siblings.length
      siblings.push(sibling)
    }
    return { root: this.root, leaf, index, siblings }
  }
}

// ---------------------------------------------------------------------------
// Keys, from one wallet signature
//
// !! UNVERIFIED AGAINST A REAL ACCOUNT !!  Everything in this section was
// de-minified out of the app's own bundle -- the constants, the EIP-712
// payload and the HKDF ladder are the producer's, quoted rather than guessed
// -- but unlike the ASP opening there is no offline oracle for it. Confirming
// it needs a wallet signature whose derived keys are already registered in a
// Keystore, and this client has neither. If `register` writes a keystore leaf
// that the web app does not recognise as yours, this is the first thing to
// doubt. See FINDINGS.md, gap 2.
// ---------------------------------------------------------------------------
export type Keys = {
  privateNullifyingKey: bigint
  privateRevocableKey: bigint
  viewingPrivateKey: Uint8Array
  viewingPublicKey: Uint8Array
  revocableKeyIndex: bigint
}

/** `CryptoService`'s literals, verbatim. */
export const APP_IDENTIFIER = 'TODO-privacy-pools-v2'
export const ROOT_DERIVATION_INFO = 'Standardized-Secret-Derivation-v1-Root'
export const APP_DERIVATION_INFO = 'Standardized-Secret-Derivation-v1-App'
const PP_V2 = 'PP_V2'
const IDENTITY = 'IDENTITY'
const VIEWING = 'VIEWING'
const NULLIFYING = 'NULLIFYING'
const REVOCABLE = 'AUTH0:REVOCABLE'
const VIEWING_KEY = 'VIEWING_KEY'

/** The message the wallet signs. Only its `r` is used, so it must be deterministic. */
export const SECRET_DERIVATION_PURPOSE =
  'This signature is used to deterministically derive application-specific secrets from your master seed. ' +
  'It is not a transaction and will not cost any gas.'

/**
 * `buildSecretDerivationPayload`: the EIP-712 request behind "sign in with
 * wallet". The domain carries no chainId -- the account is the same on every
 * chain -- and its salt is the app identifier hashed, which is what keeps one
 * wallet's Privacy Pools keys apart from any other app's.
 */
export function secretDerivationTypedData(address: string) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'verifyingContract', type: 'address' },
        { name: 'salt', type: 'bytes32' },
      ],
      SecretDerivation: [
        { name: 'purpose', type: 'string' },
        { name: 'addressHash', type: 'bytes32' },
      ],
    },
    primaryType: 'SecretDerivation',
    domain: {
      name: 'Standardized Secret Derivation',
      version: '1',
      verifyingContract: '0x0000000000000000000000000000000000000000',
      salt: `0x${bytesToHex(keccak_256(utf8ToBytes(APP_IDENTIFIER)))}`,
    },
    message: {
      purpose: SECRET_DERIVATION_PURPOSE,
      addressHash: `0x${bytesToHex(keccak_256(hexToBytes(address.toLowerCase().slice(2))))}`,
    },
  }
}

/**
 * Stage one: the signature's `r`, HKDF'd with the signer's address as salt.
 * The result is a master seed that is *not* app-specific -- the same wallet
 * signature feeds other apps built on the same scheme -- which is why this
 * client stores it, and only it. 32 bytes, so it rides in a BIP-39 mnemonic.
 */
export function rootSecretFromSignature(signature: string, address: string): Uint8Array {
  const r = hexToBytes(signature.toLowerCase().replace(/^0x/, '')).slice(0, 32)
  const salt = hexToBytes(address.toLowerCase().slice(2))
  return hkdf(sha256, r, salt, utf8ToBytes(ROOT_DERIVATION_INFO), 32)
}

/** Stage two: this app's secret, keyed by the app identifier. */
export const appSecretFrom = (rootSecret: Uint8Array): Uint8Array =>
  hkdf(sha256, rootSecret, utf8ToBytes(APP_IDENTIFIER), utf8ToBytes(APP_DERIVATION_INFO), 32)

/** `AUTH0:REVOCABLE` is suffixed with the index as eight big-endian bytes. */
function revocableInfo(index: bigint): Uint8Array {
  const n = new Uint8Array(8)
  for (let i = 7; i >= 0; i--, index >>= 8n) n[i] = Number(index & 0xffn)
  return concatBytes(utf8ToBytes(REVOCABLE), n)
}

/** The usual X25519 clamp: the low three bits, the top bit, and bit 254 set. */
function clamp25519(b: Uint8Array): Uint8Array {
  const c = new Uint8Array(b)
  c[0]! &= 248
  c[31]! &= 127
  c[31]! |= 64
  return c
}

/**
 * Stage three, the SDK's `deriveKeys`: one extract under `PP_V2`, then two
 * branches. The spending keys hang off IDENTITY and are reduced into the
 * scalar field from 48 bytes; the viewing key hangs off VIEWING and is an
 * X25519 scalar, so it is clamped rather than reduced. `revocableKeyIndex`
 * only moves the revocable key -- rotating it leaves the nullifying key, and
 * therefore every note, alone.
 */
export function deriveKeys(rootSecret: Uint8Array, revocableKeyIndex = 0n): Keys {
  const appSecret = appSecretFrom(rootSecret)
  const prk = hkdfExtract(sha256, appSecret, utf8ToBytes(PP_V2))
  const identity = hkdfExpand(sha256, prk, utf8ToBytes(IDENTITY), 32)
  const viewing = hkdfExpand(sha256, prk, utf8ToBytes(VIEWING), 32)
  const viewingPrivateKey = clamp25519(hkdfExpand(sha256, viewing, utf8ToBytes(VIEWING_KEY), 32))
  return {
    privateNullifyingKey: reduce(hkdfExpand(sha256, identity, utf8ToBytes(NULLIFYING), 48)),
    privateRevocableKey: reduce(hkdfExpand(sha256, identity, revocableInfo(revocableKeyIndex), 48)),
    viewingPrivateKey,
    viewingPublicKey: x25519.getPublicKey(viewingPrivateKey),
    revocableKeyIndex,
  }
}

// ---------------------------------------------------------------------------
// Note secrets -- this client's own convention, not the SDK's
// ---------------------------------------------------------------------------
/**
 * The SDK draws `noteSecret` and `depositSecret` at random and relies on the
 * on-chain `Note` ciphertext to find them again. This client derives them from
 * the same seed instead, exactly as V1 derived its notes from the mnemonic, so
 * that the seed is once again the only thing to back up and a note is
 * recoverable from chain data alone even if the Note payload is wrong or
 * absent.
 *
 * The info strings are namespaced to this client so they cannot collide with
 * anything the SDK expands from the same secret. A note made this way is an
 * ordinary note -- the chain cannot tell -- but the web app will not find it
 * unless the deposit also published a Note it can decrypt.
 */
const NOTE_INFO = 'moneysurfer2/v1:'

function noteScalar(rootSecret: Uint8Array, what: string, a: bigint, b: bigint): bigint {
  const info = utf8ToBytes(`${NOTE_INFO}${what}:${a}:${b}`)
  return reduce(hkdf(sha256, appSecretFrom(rootSecret), utf8ToBytes(PP_V2), info, 48))
}

/** The `index`-th deposit this seed makes in `tokenId`. */
export const depositSecrets = (rootSecret: Uint8Array, tokenId: string, index: bigint) => ({
  noteSecret: noteScalar(rootSecret, 'note', addressToField(tokenId), index),
  depositSecret: noteScalar(rootSecret, 'deposit', addressToField(tokenId), index),
})

/** The note a spend leaves behind: the `index`-th change note under a label. */
export const changeSecret = (rootSecret: Uint8Array, label: bigint, index: bigint) =>
  noteScalar(rootSecret, 'change', label, index)

/** RFC 9380's hash-to-field reduction: 48 bytes down to a BN254 scalar, near-uniformly. */
export const reduce = (b: Uint8Array) => Fr.create(bytesToNumberBE(b))

/** 48 random bytes reduced the same way, for a note or deposit secret. */
export const generateSecret = () => reduce(crypto.getRandomValues(new Uint8Array(48)))

// ---------------------------------------------------------------------------
// What a proof binds
// ---------------------------------------------------------------------------
/** keccak256(abi.encode(NoteData{key, ciphertext})) mod r, as the pool recomputes it. */
export function depositContext(key: string, ciphertext: Uint8Array): bigint {
  return bytesToNumberBE(keccak_256(encodeNoteData(key, ciphertext))) % SNARK_FIELD
}

const word = (n: bigint) => hexToBytes(n.toString(16).padStart(64, '0'))

/** abi.encode of one `(bytes32, bytes)` struct: the head offset, then the tuple. */
function encodeNoteData(key: string, ciphertext: Uint8Array): Uint8Array {
  const pad = ((-ciphertext.length % 32) + 32) % 32
  return concatBytes(
    word(32n),
    hexToBytes(key.toLowerCase().slice(2)),
    word(64n),
    word(BigInt(ciphertext.length)),
    ciphertext,
    new Uint8Array(pad),
  )
}

/**
 * `transactParams.data`: who is paid what when a spend leaves the pool.
 *
 * `feeAmount` is an **absolute amount in the asset's own units**, not V1's
 * basis points -- which is also why `Entrypoint.assets()`'s fourth field
 * (`maxRelayFee`) reads as 0.5 ETH rather than a percentage. `nativeGas` lets
 * a relayer hand the recipient some of the chain's coin to move with; this
 * client always leaves it 0.
 */
const ROUTING = createContract([
  {
    type: 'function',
    name: 'payoutRouting',
    inputs: [
      {
        name: 'routing',
        type: 'tuple',
        components: [
          { name: 'recipient', type: 'address' },
          { name: 'feeRecipient', type: 'address' },
          { name: 'feeAmount', type: 'uint256' },
          { name: 'nativeGas', type: 'uint256' },
        ],
      },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'transactContext',
    inputs: [
      {
        name: 'transactParams',
        type: 'tuple',
        components: [
          { name: 'processor', type: 'address' },
          { name: 'data', type: 'bytes' },
        ],
      },
      {
        name: 'notes',
        type: 'tuple[]',
        components: [
          { name: 'hint', type: 'bytes32' },
          { name: 'data', type: 'bytes' },
        ],
      },
    ],
    outputs: [],
  },
] as const)

export type Routing = { recipient: string; feeRecipient: string; feeAmount: bigint; nativeGas: bigint }

/** abi.encode(PayoutRouting{recipient, feeRecipient, feeAmount, nativeGas}). */
export const payoutRouting = (r: Routing): Uint8Array => ROUTING.payoutRouting.encodeInput(r).slice(4)

/**
 * `keccak256(abi.encode(transactParams, noteData[]))`, as the pool recomputes
 * it -- the SDK's `computeTransactContext`, reduced into the scalar field the
 * way the deposit context is.
 */
export function transactContext(
  processor: string,
  data: Uint8Array,
  notes: { hint: string; ciphertext: Uint8Array }[],
): bigint {
  const encoded = ROUTING.transactContext
    .encodeInput({
      transactParams: { processor, data },
      notes: notes.map((n) => ({ hint: hexToBytes(n.hint.slice(2)), data: n.ciphertext })),
    })
    .slice(4)
  return bytesToNumberBE(keccak_256(encoded)) % SNARK_FIELD
}
