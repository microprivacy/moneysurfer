// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Turning a token's symbol into something you can type. Both protocols name
 * things this way -- V1 its pools, V2 its assets -- and the awkward cases are
 * the same awkward cases, so the rule lives in one place.
 */

/**
 * A command-line key for a token: its symbol, lowercased and stripped to
 * characters a shell will not fight you over, falling back to the head of the
 * address for a token whose symbol survives none of that.
 *
 * The `₮` is not hypothetical: Tether writes its symbol USD₮, and USD₮0 on
 * many chains, so without this `usdt` would be untypeable.
 */
export const symbolKey = (symbol: string, address: string): string =>
  symbol
    .toLowerCase()
    .replace(/₮/g, 't')
    .replace(/[^a-z0-9._-]/g, '') || address.slice(0, 8).toLowerCase()

/**
 * Hand out one key per item, in the order given: the first claimant of a name
 * keeps it bare and the rest get -2, -3 and so on. Callers order the list so
 * that the one which should keep the bare name comes first -- for V1 that is
 * the live pool rather than a removed one.
 */
export function uniqueKeys<T>(items: T[], base: (item: T) => string): Map<T, string> {
  const taken = new Map<string, number>()
  const keys = new Map<T, string>()
  for (const item of items) {
    const b = base(item)
    const n = (taken.get(b) ?? 0) + 1
    taken.set(b, n)
    keys.set(item, n === 1 ? b : `${b}-${n}`)
  }
  return keys
}
