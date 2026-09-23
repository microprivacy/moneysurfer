// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * JSON-RPC transport, from Uragan: retries what is transient, never what a
 * wallet does, and recognises "that block range is too wide" in its many
 * wordings so log sync can split instead of repeating.
 */
import { STATUS_CODES } from 'node:http'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { isTransientRpcError, RpcClient, withRetry } from 'micro-eth-signer/net.js'
import { chainName, UsageError } from './config.ts'

export { isTransientRpcError }

/** A provider's eth_getLogs block-range cap. Carries no code, so it is never retried as transient. */
export class RangeLimitError extends Error {}

/**
 * A 503, or "unavailable", on eth_getLogs: mevblocker's wording for a range
 * too wide, and every provider's for being down. Retried briefly before it is
 * taken as a range limit, so an outage does not halve a sync down to nothing.
 */
class UnavailableError extends RangeLimitError {}
const UNAVAILABLE_RETRIES_MS = [1_000, 3_000]

/**
 * Known wordings of "that block range is too big". Checked before the retry
 * layer sees the error: some providers reuse code -32005 for both range and
 * rate limits, and a range error retried 9 times is 40 s wasted per chunk.
 */
const RANGE_LIMIT =
  /block range|blocks? range|ranges? over|range \d+ exceeds|more than \d+ (blocks|results)|query returned more than|log response size|limited to .*range/i

/** Never retried and never timed out: the wallet may already have signed, or may be waiting on a human. */
const NOT_IDEMPOTENT = new Set(['eth_sendTransaction', 'eth_signTypedData_v4', 'wallet_switchEthereumChain'])
const REQUEST_TIMEOUT_MS = 60_000

const urls = new WeakMap<RpcClient, string>()

/** The endpoint behind a client, for messages. */
export const urlOf = (net: RpcClient) => urls.get(net) ?? 'the RPC'

/**
 * JSON-RPC over fetch -- RpcClient only needs `call`. Errors throw; they never
 * read as a value. Transient failures (429s, dropped connections, 5xx) are
 * retried with backoff, except the wallet's own methods: a retry after the
 * wallet already acted would send a second transaction, or ask its user twice.
 * `retry: false` is for a local wallet, where a refused connection means it is
 * not running and backing off would only delay saying so.
 */
export function rpc(url: string, { retry = true } = {}): RpcClient {
  let id = 0
  const once = async (method: string, params: unknown[]) => {
    let res: Response
    let text: string
    try {
      res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: ++id, method, params }, (_k, v) =>
          typeof v === 'bigint' ? `0x${v.toString(16)}` : v,
        ),
        signal: NOT_IDEMPOTENT.has(method) ? undefined : AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      })
      text = await res.text()
    } catch (e) {
      if ((e as Error).name === 'TimeoutError') {
        const msg = `${method}: ETIMEDOUT after ${REQUEST_TIMEOUT_MS / 1000}s`
        // A log query that runs this long is too wide: split it, don't repeat it.
        if (method === 'eth_getLogs') throw new RangeLimitError(msg)
        // isTransientRpcError does not count a request timeout, but it is as
        // transient as a dropped connection -- say so in words it recognises.
        throw new Error(msg)
      }
      throw e
    }
    // A provider that times out a log query ("Request timeout on the free
    // plan", 408, 504) is saying the range is too heavy, not that it is down.
    const tooWide = (s: string, status?: number) =>
      RANGE_LIMIT.test(s) ||
      (method === 'eth_getLogs' && (status === 408 || status === 504 || /time[sd]? ?out/i.test(s)))
    const unavailable = (s: string, status?: number) =>
      method === 'eth_getLogs' && (status === 503 || /unavailable/i.test(s))
    if (!res.ok) {
      // The canonical reason phrase, not res.statusText: HTTP/2 has none, and
      // the retry layer recognises 502/503/504 by these words.
      const msg = `${method}: HTTP ${res.status} ${STATUS_CODES[res.status] ?? ''} ${text.slice(0, 200)}`
      if (tooWide(text, res.status)) throw new RangeLimitError(msg)
      throw unavailable(text, res.status) ? new UnavailableError(msg) : new Error(msg)
    }
    const body = JSON.parse(text) as {
      result?: unknown
      // the spec says an object; Blockscout answers with a bare string, and
      // says "Too many requests" in a top-level `message` with a null result
      error?: string | { message: string; code?: number; data?: unknown }
      message?: string
    }
    if (body.error || (body.result === null && body.message)) {
      const error = typeof body.error === 'string' ? { message: body.error } : (body.error ?? { message: '' })
      const msg = `${method}: ${error.message || body.message}`
      if (tooWide(msg)) throw new RangeLimitError(msg)
      if (unavailable(msg)) throw new UnavailableError(msg)
      throw Object.assign(new Error(msg), error)
    }
    return body.result
  }
  const patient = async (method: string, params: unknown[]) => {
    for (const wait of UNAVAILABLE_RETRIES_MS) {
      try {
        return await once(method, params)
      } catch (e) {
        if (!(e instanceof UnavailableError)) throw e
        await new Promise((r) => setTimeout(r, wait))
      }
    }
    return once(method, params)
  }
  const client = new RpcClient({
    call: (method: string, ...params: unknown[]) =>
      !retry || NOT_IDEMPOTENT.has(method)
        ? once(method, params)
        : withRetry(() => patient(method, params), undefined, method),
  })
  urls.set(client, url)
  return client
}

/**
 * Refuse to act through an RPC on another chain. The same pool address can
 * hold a different pool there, or nothing at all.
 */
export async function assertChain(net: RpcClient, chainId: number): Promise<void> {
  const got = Number(await net.chainId())
  if (got !== chainId) {
    throw new UsageError(`${urlOf(net)} is on ${chainName(got)} (${got}), not ${chainName(chainId)} -- use its RPC`)
  }
}

type ViewMethod<A, R> = { encodeInput: (args: A) => Uint8Array; decodeOutput: (b: Uint8Array) => R }

/** Call a view function and decode what it returns. */
export async function read<A, R>(net: RpcClient, to: string, method: ViewMethod<A, R>, args?: A): Promise<R> {
  const data = `0x${bytesToHex(method.encodeInput(args as A))}`
  const result = (await net.ethCall({ to, data })) as string
  return method.decodeOutput(hexToBytes(result.slice(2)))
}
