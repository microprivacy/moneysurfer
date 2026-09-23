// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Spend witnesses. A witness the circuit accepts is the real test: the wasm
 * enforces every constraint the chain will, so generating one proves the
 * signal names, the array widths and the value rules are all right -- without
 * needing the (much larger) proving key.
 */
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { witnessCalculator } from '../src/shared/circom.ts'
import { have, load } from '../src/v2/artifacts.ts'
import { NATIVE, UsageError } from '../src/v2/config.ts'
import { aspLeaf, generateSecret, LeanIMT } from '../src/v2/crypto.ts'
import {
  type Account,
  accountLeaf,
  childNote,
  depositNote,
  noteLeaf,
  type Output,
  ragequit,
  transact,
} from '../src/v2/notes.ts'

const account: Account = {
  owner: '0x1111111111111111111111111111111111111111',
  privateNullifyingKey: generateSecret(),
  privateRevocableKey: generateSecret(),
}
const TS = 1788004607n

// Notes descended from one deposit share its label, which is what lets several
// of them aggregate into one output: conservation is enforced per label.
const scenario = (inputs: number, outputs: number) => {
  const first = depositNote(account.owner, generateSecret(), generateSecret(), NATIVE, 10n ** 16n, TS)
  const notes = [
    first,
    ...[...Array(inputs - 1)].map((_, i) =>
      childNote(account.owner, generateSecret(), NATIVE, 10n ** 16n * BigInt(i + 2), first.label, TS),
    ),
  ]
  const total = notes.reduce((a, n) => a + n.value, 0n)
  const outs: Output[] = [...Array(outputs)].map((_, i) => ({
    owner: account.owner,
    noteSecret: generateSecret(),
    value: i === 0 ? total - BigInt(outputs - 1) : 1n,
    label: notes[0]!.label,
  }))
  const trees = {
    state: new LeanIMT([...[...Array(5)].map(() => generateSecret()), ...notes.map(noteLeaf)]),
    keystore: new LeanIMT([...[...Array(3)].map(() => generateSecret()), accountLeaf(account)]),
    asp: new LeanIMT([...[...Array(4)].map(() => generateSecret()), ...notes.map((n) => aspLeaf(n.label))]),
  }
  return { notes, outs, trees }
}

for (const [n, m] of [
  [1, 1],
  [1, 2],
  [2, 1],
] as const) {
  const circuit = `transact_${n}x${m}`
  test(`${circuit}: the circuit accepts the witness we build`, {
    ...(have(circuit, 'wasm') ? {} : { skip: `run \`moneysurfer v2 setup ${circuit}\` first` }),
  }, async () => {
    const { notes, outs, trees } = scenario(n, m)
    const t = transact(account, notes, outs, trees, { context: generateSecret() })
    assert.equal(t.circuit, circuit)
    assert.equal(t.nullifiers.length, n)
    assert.equal(t.commitments.length, m)
    const w = await witnessCalculator(load(circuit, 'wasm'))
    const witness = w(t.input)
    // public signals come first in the witness, after the constant 1
    assert.equal(witness[0], 1n)
    assert.deepEqual(witness.slice(1, 1 + n), t.nullifiers)
    assert.deepEqual(witness.slice(1 + n, 1 + n + m), t.commitments)
  })
}

test('the ASP leaf is the hashed label, not the label', {
  ...(have('transact_1x1', 'wasm') ? {} : { skip: 'no wasm' }),
}, async () => {
  const { notes, outs, trees } = scenario(1, 1)
  const t = transact(account, notes, outs, trees, { context: generateSecret() })
  const w = await witnessCalculator(load('transact_1x1', 'wasm'))
  // the real tree holds aspLeaf(label); one holding the bare label must not verify
  const bare = new LeanIMT([...trees.asp.levels[0]!.slice(0, 4), notes[0]!.label])
  assert.throws(() => w({ ...t.input, associationSetRoot: bare.root }), /assert failed/)
})

test('a label cannot spend more than its own inputs', () => {
  const { notes, outs, trees } = scenario(1, 2)
  const other = depositNote(account.owner, generateSecret(), generateSecret(), NATIVE, 1n, TS)
  assert.throws(
    () => transact(account, notes, [{ ...outs[0]!, label: other.label }, outs[1]!], trees, { context: 0n }),
    UsageError,
  )
})

test('a spend that does not balance is refused before proving', () => {
  const { notes, outs, trees } = scenario(1, 1)
  const bad = [{ ...outs[0]!, value: outs[0]!.value + 1n }]
  assert.throws(() => transact(account, notes, bad, trees, { context: 0n }), UsageError)
})

test('an output label must be inherited from an input', () => {
  const { notes, outs, trees } = scenario(1, 1)
  const bad = [{ ...outs[0]!, label: generateSecret() }]
  assert.throws(() => transact(account, notes, bad, trees, { context: 0n }), UsageError)
})

test('ragequit needs the keystore and nothing else', {
  ...(have('ragequit', 'wasm') ? {} : { skip: 'no wasm' }),
}, async () => {
  const { notes, trees } = scenario(1, 1)
  const input = ragequit(account, notes[0]!, trees)
  const w = await witnessCalculator(load('ragequit', 'wasm'))
  const witness = w(input)
  assert.equal(witness[0], 1n)
  // outputs first: nullifierHash then commitment, then the five public inputs
  assert.equal(witness.length > 8, true)
})
