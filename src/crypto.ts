/**
 * Privacy Pools' cryptography, bit-for-bit with 0xbow's SDK
 * (privacy-pools-core packages/sdk/src/crypto.ts) and zk-kit's LeanIMT: the
 * test vectors in test/vectors.json come from running their code.
 */
import { grainGenConstants, poseidon } from '@noble/curves/abstract/poseidon.js'
import { bn254 } from '@noble/curves/bn254.js'
import { bytesToNumberBE } from '@noble/curves/utils.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { keccak_256 } from '@noble/hashes/sha3.js'
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { HDKey } from '@scure/bip32'
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { createContract } from 'micro-eth-signer/abi.js'

const Fr = bn254.fields.Fr
/** The BN254 scalar field every hash, label and scope lives in. */
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
  // Inputs are reduced mod r as maci-crypto does: a 256-bit private key
  // usually exceeds the field, and noble would refuse it otherwise.
  return permute([0n, ...inputs.map((x) => Fr.create(x))])[0]!
}

// ---------------------------------------------------------------------------
// Keys and notes
// ---------------------------------------------------------------------------
export type MasterKeys = { masterNullifier: bigint; masterSecret: bigint }
export type Secrets = { nullifier: bigint; secret: bigint }

export const isMnemonic = (m: string) => validateMnemonic(m.trim(), wordlist)

/**
 * The two master keys: Poseidon of the private keys at m/44'/60'/0'/0/0 and
 * m/44'/60'/1'/0/0, as viem's mnemonicToAccount({ accountIndex }) derives them.
 */
export function masterKeys(mnemonic: string): MasterKeys {
  const root = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic.trim()))
  const key = (account: number) => bytesToNumberBE(root.derive(`m/44'/60'/${account}'/0/0`).privateKey!)
  return { masterNullifier: hash([key(0)]), masterSecret: hash([key(1)]) }
}

/** The note for deposit number `index` into the pool with this scope. */
export const depositSecrets = (k: MasterKeys, scope: bigint, index: bigint): Secrets => ({
  nullifier: hash([k.masterNullifier, scope, index]),
  secret: hash([k.masterSecret, scope, index]),
})

/** The change note left by withdrawal number `index` from the account with this label. */
export const withdrawalSecrets = (k: MasterKeys, label: bigint, index: bigint): Secrets => ({
  nullifier: hash([k.masterNullifier, label, index]),
  secret: hash([k.masterSecret, label, index]),
})

export const precommitment = (s: Secrets) => hash([s.nullifier, s.secret])
export const commitment = (value: bigint, label: bigint, s: Secrets) => hash([value, label, precommitment(s)])
/** What a pool marks spent, and what a Withdrawn or Ragequit event names. */
export const nullifierHash = (s: Secrets) => hash([s.nullifier])

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
   * -- which is what the circuit's LeanIMTInclusionProof reads.
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
// Account seed from a wallet signature, as privacypools.com derives it
// (privacy-pools-website src/utils/walletSeed.ts, "v2")
// ---------------------------------------------------------------------------
const SEED_CONTEXT = 'privacy-pools/wallet-seed:v2'

/** The EIP-712 message the website asks the wallet to sign for an account seed. */
export function seedTypedData(address: string) {
  return {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
      ],
      DeriveSeed: [
        { name: 'action', type: 'string' },
        { name: 'context', type: 'string' },
        { name: 'addressHash', type: 'bytes32' },
      ],
    },
    primaryType: 'DeriveSeed',
    domain: { name: 'Privacy Pools', version: '1' },
    message: {
      action: 'Derive Account Seed',
      context: SEED_CONTEXT,
      addressHash: `0x${bytesToHex(keccak_256(hexToBytes(address.toLowerCase().slice(2))))}`,
    },
  }
}

/** 24 words: HKDF-SHA256(IKM = the signature's r, salt = the address, info = the context). */
export function mnemonicFromSignature(signature: string, address: string): string {
  const r = hexToBytes(signature.slice(2)).slice(0, 32)
  const salt = hexToBytes(address.toLowerCase().slice(2))
  return entropyToMnemonic(hkdf(sha256, r, salt, utf8ToBytes(SEED_CONTEXT), 32), wordlist)
}

// ---------------------------------------------------------------------------
// What a withdrawal proof binds
// ---------------------------------------------------------------------------
const ENCODERS = createContract([
  {
    type: 'function',
    name: 'context',
    inputs: [
      {
        name: 'withdrawal',
        type: 'tuple',
        components: [
          { name: 'processooor', type: 'address' },
          { name: 'data', type: 'bytes' },
        ],
      },
      { name: 'scope', type: 'uint256' },
    ],
    outputs: [],
  },
  {
    type: 'function',
    name: 'relayData',
    inputs: [
      { name: 'recipient', type: 'address' },
      { name: 'feeRecipient', type: 'address' },
      { name: 'relayFeeBPS', type: 'uint256' },
    ],
    outputs: [],
  },
] as const)

/** Entrypoint.relay's `data`: abi.encode(RelayData{recipient, feeRecipient, relayFeeBPS}). */
export const relayData = (recipient: string, feeRecipient: string, relayFeeBPS: bigint): Uint8Array =>
  ENCODERS.relayData.encodeInput({ recipient, feeRecipient, relayFeeBPS }).slice(4)

/** keccak256(abi.encode(Withdrawal{processooor, data}, scope)) mod r, as PrivacyPool checks it. */
export function withdrawalContext(processooor: string, data: Uint8Array, scope: bigint): bigint {
  const encoded = ENCODERS.context.encodeInput({ withdrawal: { processooor, data }, scope }).slice(4)
  return bytesToNumberBE(keccak_256(encoded)) % SNARK_FIELD
}
