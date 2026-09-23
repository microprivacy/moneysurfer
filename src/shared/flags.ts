// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * The command line both protocols answer to. V2 is a different protocol, not a
 * different tool: it signs the same way, proposes to a Safe the same way, and
 * takes the same `--dry-run`, so the flags are declared once here and parsed
 * once in cli.ts.
 */
import { addr } from 'micro-eth-signer'
import { UsageError } from './config.ts'
import type { SignerOpts } from './signer.ts'

export const OPTIONS = {
  chain: { type: 'string' },
  'rpc-url': { type: 'string' },
  threads: { type: 'string' },
  import: { type: 'boolean' },
  'from-wallet': { type: 'boolean' },
  id: { type: 'string' },
  relayer: { type: 'string' },
  self: { type: 'boolean' },
  safe: { type: 'string' },
  'max-fee-percent': { type: 'string' },
  'dry-run': { type: 'boolean' },
  'private-key': { type: 'string' },
  account: { type: 'string' },
  keystore: { type: 'string' },
  from: { type: 'string' },
  help: { type: 'boolean', short: 'h' },
} as const

/** What `parseArgs` hands back for OPTIONS. */
export type Flags = {
  chain?: string
  'rpc-url'?: string
  threads?: string
  import?: boolean
  'from-wallet'?: boolean
  id?: string
  relayer?: string
  self?: boolean
  safe?: string
  'max-fee-percent'?: string
  'dry-run'?: boolean
  'private-key'?: string
  account?: string
  keystore?: string
  from?: string
  help?: boolean
}

/** The flags every command shares, resolved and checked once. */
export type Common = {
  threads: number
  /** propose to this Safe instead of sending; it is also the depositor and the owner */
  safe?: string
  sig: SignerOpts
  maxFeePercent: number
  dryRun: boolean
}

/** An address argument, refusing a mistyped one rather than acting on it. */
export function checksummed(a: string): string {
  if (!addr.isValid(a)) {
    const hexOnly = /^0x[0-9a-fA-F]{40}$/.test(a)
    throw new UsageError(hexOnly ? `${a} fails its EIP-55 checksum -- probably a typo` : `not an address: ${a}`)
  }
  return addr.addChecksum(a)
}
