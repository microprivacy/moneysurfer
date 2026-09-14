// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { namePools, type PoolRegistry } from '../src/chain.ts'
import { type Entrypoint, NATIVE } from '../src/config.ts'

const e: Entrypoint = {
  chainId: 10,
  address: '0x44192215FEd782896BE2CE24E0Bfbf0BF825d15E',
  deployedBlock: 1,
  native: 'ETH',
  relayers: [],
}
const USDC = '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85'
const USDT0 = '0x01bFF41798a0BcF287b996046Ca68b395DbC1071'
const pool = (n: number) => `0x${n.toString(16).padStart(40, '0')}`
const tokens = {
  [NATIVE]: { symbol: 'ETH', decimals: 18 },
  [USDC]: { symbol: 'USDC', decimals: 6 },
  [USDT0]: { symbol: 'USD₮0', decimals: 6 },
}

test('pools are named by symbol, and a replaced pool hands its name to the live one', () => {
  const reg: PoolRegistry = {
    block: 100,
    logs: [
      { block: 10, removed: false, pool: pool(1), asset: NATIVE },
      { block: 20, removed: false, pool: pool(2), asset: USDC },
      { block: 30, removed: true, pool: pool(2), asset: USDC },
      { block: 40, removed: false, pool: pool(3), asset: USDC },
    ],
    tokens,
  }
  assert.deepEqual(
    namePools(e, reg).map((p) => [p.key, p.address, p.removed, p.deployedBlock, p.decimals]),
    [
      ['eth', pool(1), false, 10, 18],
      ['usdc-2', pool(2), true, 20, 6],
      ['usdc', pool(3), false, 40, 6],
    ],
  )
})

test('a pool registered again after removal is live, and dates from its first registration', () => {
  const reg: PoolRegistry = {
    block: 100,
    logs: [
      { block: 20, removed: false, pool: pool(2), asset: USDC },
      { block: 30, removed: true, pool: pool(2), asset: USDC },
      { block: 50, removed: false, pool: pool(2), asset: USDC },
    ],
    tokens,
  }
  assert.deepEqual(
    namePools(e, reg).map((p) => [p.key, p.removed, p.deployedBlock]),
    [['usdc', false, 20]],
  )
})

test('names are typeable, and a pool whose token could not be read is left out', () => {
  const reg: PoolRegistry = {
    block: 100,
    logs: [
      { block: 10, removed: false, pool: pool(1), asset: USDT0 },
      { block: 11, removed: false, pool: pool(2), asset: '0x000000000000000000000000000000000000dEaD' },
    ],
    tokens,
  }
  assert.deepEqual(
    namePools(e, reg).map((p) => [p.key, p.symbol]),
    [['usdt0', 'USD₮0']],
  )
})
