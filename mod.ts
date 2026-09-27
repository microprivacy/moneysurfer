// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * moneysurfer as a library: the two protocols' commands, and the flags they
 * both take.
 *
 * cli.ts is the other entry, and it is not re-exported here -- importing it
 * parses argv and exits the process, which is exactly what a library must not
 * do. What is left is the same thing the command line drives: `run(cmd, rest,
 * flags, common)` per protocol, so a caller builds `Common` itself and never
 * goes through `parseArgs`.
 *
 * V1 and V2 name many of the same things -- `Account`, `Note`, `recover` --
 * and mean different ones by them, so each protocol keeps its own namespace
 * rather than flattening into a single surface where one would shadow the
 * other.
 *
 * ```ts
 * import { v2, type Common } from '@microprivacy/moneysurfer'
 *
 * const common: Common = { threads: 4, dryRun: true, sig: { privateKey: '0x...' } }
 * await v2.run('balance', [], {}, common)
 * ```
 */

export * as v1 from './src/v1/commands.ts'
export * as v2 from './src/v2/commands.ts'
export { checksummed, OPTIONS } from './src/shared/flags.ts'
export type { Common, Flags } from './src/shared/flags.ts'
export { setRpcUrl, UsageError } from './src/shared/config.ts'
export type { Call, Signer, SignerOpts, TypedData } from './src/shared/signer.ts'
