// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 v1rtl, moneysurfer: https://app.radicle.at/nodes/seed.radicle.at/rad:z3J1GzkKpv3WsrvvJ2vu8XP3PRDDr
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

/**
 * Transaction signing, the way `cast send` does it: either a local key, or a
 * wallet over JSON-RPC.
 *
 * Local key -- sign here and broadcast raw:
 *   --private-key PK             visible in /proc/<pid>/cmdline while running
 *                                and saved in shell history
 *   URAGAN_PRIVATE_KEY           the same key, kept out of argv
 *   --account NAME | --keystore  Web3 Secret Storage (V3) keystore -- the format
 *                                `cast wallet import` writes to ~/.foundry/keystores
 *
 * No key -- send eth_sendTransaction and let a wallet sign: the one at
 * --rpc-url (Frame, a hardware-wallet bridge, anvil), else Frame on its local
 * port, with reads and the wait for the receipt left on the public RPC.
 * --from picks the account; by default it is the wallet's first.
 */
import { openSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { ReadStream } from 'node:tty'
import { bytesToHex } from '@noble/hashes/utils.js'
import { addr, signTyped as signTypedWithKey, Transaction } from 'micro-eth-signer'
import { privFromLegacyKeystore } from 'micro-eth-signer/keystore.js'
import type { RpcClient } from 'micro-eth-signer/net.js'
import { chainName, customRpc, FRAME_RPC, UsageError } from './config.ts'
import { rpc, urlOf } from './rpc.ts'

export type Call = { to: string; value?: bigint; data?: Uint8Array }

/** EIP-712 typed data, as eth_signTypedData_v4 takes it (EIP712Domain included in `types`). */
export type TypedData = {
  types: Record<string, { name: string; type: string }[]>
  primaryType: string
  domain: Record<string, unknown>
  message: Record<string, unknown>
}

export type Signer = {
  address: string
  /** Send, wait for the receipt, and return the hash. Throws if it reverts. */
  send(call: Call): Promise<string>
  /** Sign EIP-712 typed data; a 65-byte r || s || v signature, as hex. */
  signTyped(typed: TypedData): Promise<string>
}

export type SignerOpts = { privateKey?: string; account?: string; keystore?: string; from?: string }

const hexData = (d?: Uint8Array) => (d ? `0x${bytesToHex(d)}` : '0x')

/**
 * Resolve the signer up front -- including the wallet's account and chain --
 * so a misconfiguration fails before anything is created or sent. `net` is
 * the command's RPC, on `chainId`.
 */
export async function makeSigner(net: RpcClient, chainId: number, o: SignerOpts): Promise<Signer> {
  const pk = o.privateKey ?? process.env.URAGAN_PRIVATE_KEY
  if (pk) return localSigner(net, pk.startsWith('0x') ? pk : `0x${pk}`)
  if (o.account || o.keystore) {
    const file = o.keystore ?? join(homedir(), '.foundry/keystores', o.account!)
    const keystore = JSON.parse(readFileSync(file, 'utf8'))
    try {
      // nonStrict: accept keystores whose JSON keys vary in case, as some tools write them
      return localSigner(net, await privFromLegacyKeystore(keystore, await password(file), true))
    } catch (e) {
      if (e instanceof UsageError) throw e
      throw new UsageError(`cannot decrypt ${file}: ${(e as Error).message}`)
    }
  }
  return walletSigner(customRpc() ? net : rpc(FRAME_RPC, { retry: false }), net, chainId, o.from)
}

/** Long enough for a congested block or two; past this the tx was likely dropped or replaced. */
const RECEIPT_TIMEOUT_MS = 15 * 60_000

async function confirm(net: RpcClient, hash: string): Promise<string> {
  const receipt = await net.waitForReceipt(hash, { timeoutMs: RECEIPT_TIMEOUT_MS }).catch((e: Error) => {
    throw new Error(
      `transaction ${hash} was not mined within ${RECEIPT_TIMEOUT_MS / 60_000} min -- it may have been ` +
        `dropped or replaced (e.g. "speed up" in a wallet), or may still land: ${e.message}`,
    )
  })
  if (!receipt.status) throw new Error(`transaction ${hash} reverted`)
  return hash
}

function localSigner(net: RpcClient, privateKey: string | Uint8Array): Signer {
  const address = addr.fromPrivateKey(privateKey)
  return {
    address,
    async send({ to, value = 0n, data }) {
      // micro-eth-signer fills nonce, gas and fees. 'ethers_v6' is only the name
      // of its fee formula (ethers is not involved): maxFee = 2 x base fee + tip.
      // The default formula caps at 1.2 x, which a couple of full blocks outgrow,
      // leaving the tx stuck. The cap is a ceiling -- you still pay base + tip.
      const prepared = await net.prepare({ from: address, to, value, data: hexData(data) }, 'ethers_v6')
      const tx = Transaction.prepare({
        ...prepared,
        gasLimit: (prepared.gasLimit * 12n) / 10n, // unused gas is refunded; an undershoot reverts
      }).signBy(privateKey)
      const hash = tx.hash
      try {
        await net.broadcast(tx)
      } catch (e) {
        // A broadcast retried after the node already took it fails -- "already
        // known" while pending, "nonce too low" once mined. Whatever the
        // wording: if the node has the transaction, wait for it.
        if (!(await net.call('eth_getTransactionByHash', hash).catch(() => null))) throw e
      }
      return confirm(net, hash)
    },
    async signTyped(typed) {
      return signTypedWithKey(typed as never, privateKey)
    },
  }
}

/** Sign with `wallet`; wait for receipts on `net`. The two are one client when --rpc-url is the wallet. */
async function walletSigner(wallet: RpcClient, net: RpcClient, chainId: number, from?: string): Promise<Signer> {
  // The same pool address can hold a different pool on another chain, or
  // nothing at all. The wallet's user can switch its chain at any time --
  // even while a withdrawal syncs and proves -- so it is asked to switch
  // (EIP-3326) whenever it is elsewhere, here and again just before sending,
  // and the transaction names its chain for wallets that refuse a mismatch
  // themselves.
  const want = `${chainName(chainId)} (${chainId})`
  const onChain = async () => {
    const was = Number(await wallet.chainId())
    if (was === chainId) return
    process.stderr.write(`asking the wallet at ${urlOf(wallet)} to switch from ${chainName(was)} to ${want}\n`)
    try {
      await wallet.call('wallet_switchEthereumChain', { chainId: `0x${chainId.toString(16)}` })
    } catch (e) {
      throw new UsageError(`the wallet at ${urlOf(wallet)} would not switch to ${want}: ${(e as Error).message}`)
    }
    const got = Number(await wallet.chainId())
    if (got !== chainId) {
      throw new UsageError(`the wallet at ${urlOf(wallet)} is still on ${chainName(got)} (${got}), not ${want}`)
    }
  }
  try {
    await onChain()
  } catch (e) {
    if (e instanceof UsageError) throw e
    const why = (e as { cause?: { code?: string } }).cause?.code ?? (e as Error).message
    throw new UsageError(
      `no key given, and no wallet answers at ${urlOf(wallet)} (${why}).\n` +
        '  start Frame, point --rpc-url at another wallet, or pass --private-key / --account / --keystore',
    )
  }
  let accounts: string[] = []
  try {
    accounts = ((await wallet.call('eth_accounts')) as string[]).map((a) => a.toLowerCase())
  } catch {
    // a plain node may not implement eth_accounts at all
  }
  const picked = from ?? accounts[0]
  // A wallet may list no accounts until it prompts, so --from is trusted.
  if (!picked) {
    throw new UsageError(`no key given, and ${urlOf(wallet)} lists no accounts to sign with -- pass --from, or a key`)
  }
  if (from && accounts.length && !accounts.includes(from.toLowerCase())) {
    throw new UsageError(`${urlOf(wallet)} does not hold ${from}; it has ${accounts.join(', ')}`)
  }
  const address = addr.addChecksum(picked)
  return {
    address,
    async send({ to, value = 0n, data }) {
      await onChain()
      // The wallet fills in nonce, gas and fees, and asks its user to approve.
      const hash = (await wallet.call('eth_sendTransaction', {
        from: address,
        to,
        value: `0x${value.toString(16)}`,
        data: hexData(data),
        chainId: `0x${chainId.toString(16)}`,
      })) as string
      return confirm(net, hash)
    },
    async signTyped(typed) {
      await onChain()
      const json = JSON.stringify(typed, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))
      return (await wallet.call('eth_signTypedData_v4', address, json)) as string
    },
  }
}

/** URAGAN_KEYSTORE_PASSWORD, else a no-echo prompt on /dev/tty (stdin may be carrying the note). */
async function password(file: string): Promise<string> {
  const env = process.env.URAGAN_KEYSTORE_PASSWORD
  if (env !== undefined) return env
  let tty: ReadStream
  try {
    tty = new ReadStream(openSync('/dev/tty', 'r'))
  } catch {
    throw new UsageError('no terminal for a password prompt; set URAGAN_KEYSTORE_PASSWORD')
  }
  process.stderr.write(`password for ${file}: `)
  tty.setRawMode(true)
  tty.setEncoding('utf8')
  return new Promise((ok, fail) => {
    let pass = ''
    tty.on('data', (chunk: string) => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') {
          tty.setRawMode(false)
          tty.destroy()
          process.stderr.write('\n')
          return ok(pass)
        }
        if (ch === '\u0003') {
          tty.setRawMode(false)
          tty.destroy()
          return fail(new UsageError('aborted'))
        }
        if (ch === '\u007f' || ch === '\b') pass = pass.slice(0, -1)
        else pass += ch
      }
    })
  })
}
