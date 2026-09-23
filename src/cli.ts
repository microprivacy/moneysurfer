#!/usr/bin/env node
// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * moneysurfer -- a Privacy Pools client, for both protocols.
 *
 * TypeScript run directly by Node. Chain access and signing via
 * micro-eth-signer; Poseidon, BIP-32/39 and hashing via noble and scure;
 * witnesses from the circuits' own wasm and Groth16 proofs via
 * micro-zk-proofs. One seed derives every note, so there is nothing else to
 * back up.
 *
 * V1 and V2 are different protocols, not different tools: they sign the same
 * way, propose to a Safe the same way, and prove with the same engine. So the
 * flags are parsed once here and the protocol only decides which contracts the
 * commands talk to. `v1` is assumed when the command is one of V1's, which is
 * every invocation that worked before V2 existed.
 */
import { availableParallelism } from 'node:os'
import { parseArgs } from 'node:util'
import { setRpcUrl, UsageError } from './shared/config.ts'
import { type Common, checksummed, type Flags, OPTIONS } from './shared/flags.ts'
import * as v1 from './v1/commands.ts'
import * as v2 from './v2/commands.ts'

const out = (s: string) => process.stdout.write(`${s}\n`)
const log = (s: string) => process.stderr.write(`${s}\n`)
process.stdout.on('error', (e: NodeJS.ErrnoException) => {
  if (e.code === 'EPIPE') process.exit(0)
  throw e
})

/** A protocol's help, without its own title line, indentation kept. */
const section = (help: string) => help.split('\n').slice(2).join('\n').replace(/\s+$/, '')

const HELP = `moneysurfer -- Privacy Pools from the command line

  moneysurfer [v1|v2] <command> ...    v1 is assumed for a command only V1 has

${section(v1.HELP)}

${section(v2.HELP)}

shared by both:
  --safe SAFE                        propose to that Safe's owners instead of sending -- signed by
                                     an owner, or a proposer they added. The Safe is then the
                                     depositor, and the only address that can ragequit
  --rpc-url URL                      your own RPC instead of the public default
  --threads N                        prover threads (default: all cores)
  --dry-run                          prove and simulate, but send nothing

signing -- a local key, or else a wallet (Frame, or the one at --rpc-url):
  --private-key PK | MONEYSURFER_PRIVATE_KEY, --account NAME, --keystore FILE, --from ADDR

env: MONEYSURFER_HOME, MONEYSURFER_ASSETS, MONEYSURFER_SAFE_TX_SERVICE, MONEYSURFER_CHUNK,
     MONEYSURFER_PRIVATE_KEY, MONEYSURFER_KEYSTORE_PASSWORD`

/**
 * Flags a protocol has no use for. Refusing one is better than ignoring it:
 * a `--chain optimism` that quietly did nothing would read as a V2 deposit on
 * Optimism, which is not a thing.
 */
const REJECTS: Record<'v1' | 'v2', { flag: keyof Flags; why: string }[]> = {
  v1: [],
  v2: [{ flag: 'chain', why: 'V2 is one deployment on Ethereum mainnet' }],
}

try {
  const { values: v, positionals } = parseArgs({ allowPositionals: true, options: OPTIONS })
  let [head = 'help', ...rest] = positionals

  // `v1`/`v2` names the protocol; otherwise a command only V2 has picks V2 and
  // everything else falls to V1, so every V1 invocation keeps working.
  let protocol: 'v1' | 'v2' = 'v1'
  let explicit = false
  if (head === 'v1' || head === 'v2') {
    protocol = head
    explicit = true
    ;[head = 'help', ...rest] = rest
  } else if (!(v1.COMMANDS as readonly string[]).includes(head) && (v2.COMMANDS as readonly string[]).includes(head)) {
    protocol = 'v2'
  }

  // `moneysurfer v2 --help` narrows to that protocol; a bare --help covers both.
  if (v.help || head === 'help') {
    out(explicit ? (protocol === 'v2' ? v2.HELP : v1.HELP) : HELP)
    process.exit(0)
  }
  for (const { flag, why } of REJECTS[protocol]) {
    if (v[flag] !== undefined) throw new UsageError(`${protocol} takes no --${flag}: ${why}`)
  }

  setRpcUrl(v['rpc-url'])
  const threads = v.threads === undefined ? availableParallelism() : Number(v.threads)
  if (!Number.isInteger(threads) || threads < 1) throw new UsageError('--threads must be a positive integer')
  const maxFeePercent = v['max-fee-percent'] === undefined ? 1 : Number(v['max-fee-percent'])
  if (!(maxFeePercent >= 0 && maxFeePercent <= 10)) throw new UsageError('--max-fee-percent must be from 0 to 10')
  const common: Common = {
    threads,
    safe: v.safe === undefined ? undefined : checksummed(v.safe),
    maxFeePercent,
    dryRun: v['dry-run'] ?? false,
    sig: {
      privateKey: v['private-key'],
      account: v.account,
      keystore: v.keystore,
      from: v.from === undefined ? undefined : checksummed(v.from),
    },
  }
  await (protocol === 'v1' ? v1.run : v2.run)(head, rest, v, common)
} catch (e) {
  // Node's own errors carry string codes; JSON-RPC errors carry numbers (4001: rejected in the wallet).
  const code = (e as { code?: unknown }).code
  const usage = e instanceof UsageError || (typeof code === 'string' && code.startsWith('ERR_PARSE_ARGS'))
  log(`error: ${(e as Error).message}`)
  if (process.env.DEBUG) log((e as Error).stack ?? '')
  process.exit(usage ? 2 : 1)
}
