# moneysurfer

Lightweight CLI for [Privacy Pools](https://privacypools.com).

## Features

- Ethereum, Optimism and Arbitrum: every pool, ETH and tokens
- One mnemonic for every deposit, same keys as privacypools.com
- ASP set read from IPFS and checked on-chain; nothing is sent to the ASP
- Withdraw via a relayer, yourself, or a Safe; ragequit if unapproved
- Local prover in pure JS (~7 s), withdrawals simulated before sending
- Sign with Frame, a private key or a keystore
- No build step

## Install

Requires Node ≥ 22.18.

```sh
pnpm install
ln -s $PWD/src/cli.ts ~/.local/bin/moneysurfer
moneysurfer setup   # download circuits and keys, check their pinned sha256
moneysurfer init    # new mnemonic; or --import < words.txt, or --from-wallet
```

## Usage

```sh
moneysurfer pools
moneysurfer deposit usdc 100 --chain optimism
moneysurfer balance
moneysurfer withdraw usdc 50 0xRecipient --chain optimism
```

A deposit can be withdrawn once the ASP approves it (up to 7 days); until then `ragequit` returns it publicly.
Run `moneysurfer help` for all commands and options.

## License

MPL-2.0
