import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { ARTIFACTS, ASSETS } from '../src/config.ts'
import {
  commitment,
  depositSecrets,
  LeanIMT,
  masterKeys,
  nullifierHash,
  relayData,
  withdrawalContext,
  withdrawalSecrets,
} from '../src/crypto.ts'
import { prove, solidityProof } from '../src/prover.ts'

const skip = !Object.keys(ARTIFACTS).every((f) => existsSync(join(ASSETS, f))) && 'run `moneysurfer setup` first'
const k = masterKeys('test test test test test test test test test test test junk')
const scope = 123456789n
const label = 987654321n
const pad = (xs: bigint[]) => [...xs, ...Array<bigint>(32 - xs.length).fill(0n)]

test('a withdrawal proves, verifies, and commits to what the contract checks', { skip }, async () => {
  const value = 10n ** 17n
  const withdrawn = 4n * 10n ** 16n
  const existing = depositSecrets(k, scope, 0n)
  const next = withdrawalSecrets(k, label, 0n)
  const state = new LeanIMT([11n, 22n, 33n, commitment(value, label, existing), 55n, 66n, 77n])
  const asp = new LeanIMT([5n, 6n, label, 8n, 9n])
  const sp = state.proof(3)
  const ap = asp.proof(2)
  const context = withdrawalContext(
    '0x44192215FEd782896BE2CE24E0Bfbf0BF825d15E',
    relayData('0x000000000000000000000000000000000000dEaD', '0x000000000000000000000000000000000000dEaD', 0n),
    scope,
  )
  const proof = await prove('withdraw', {
    withdrawnValue: withdrawn,
    stateRoot: state.root,
    stateTreeDepth: 32n,
    ASPRoot: asp.root,
    ASPTreeDepth: 32n,
    context,
    label,
    existingValue: value,
    existingNullifier: existing.nullifier,
    existingSecret: existing.secret,
    newNullifier: next.nullifier,
    newSecret: next.secret,
    stateSiblings: pad(sp.siblings),
    stateIndex: BigInt(sp.index),
    ASPSiblings: pad(ap.siblings),
    ASPIndex: BigInt(ap.index),
  })
  // ProofLib order: new commitment, spent nullifier hash, then the public inputs
  assert.deepEqual(proof.publicSignals, [
    commitment(value - withdrawn, label, next),
    nullifierHash(existing),
    withdrawn,
    state.root,
    32n,
    asp.root,
    32n,
    context,
  ])
  assert.equal(solidityProof(proof).pB[0][0], proof.proof.pi_b[0][1], 'G2 coordinates swapped for the EVM')
})

test('a ragequit proof commits to the note', { skip }, async () => {
  const s = depositSecrets(k, scope, 1n)
  const value = 5n * 10n ** 16n
  const proof = await prove('commitment', { value, label, nullifier: s.nullifier, secret: s.secret })
  assert.deepEqual(proof.publicSignals, [commitment(value, label, s), nullifierHash(s), value, label])
})
