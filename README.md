# moneysurfer

Lightweight CLI for [Privacy Pools](https://privacypools.com).

## Features

- Ethereum, Optimism and Arbitrum ETH pools
- One mnemonic derives every note — nothing else to back up. Same keys as 0xbow's SDK, so accounts
  made on privacypools.com carry over, including wallet-derived ones (`init --from-wallet`)
- The ASP's association set comes from the IPFS copy it publishes with every root, checked against
  the root on-chain: nothing about your account is sent to the ASP
- Withdraw through a relayer (its fee is quoted without telling it the recipient), yourself, or
  take an unapproved deposit back with ragequit
- Local Groth16 prover in pure JS (~7 s); every withdrawal is simulated before it is sent
- Sign with Frame, a private key or a keystore
- No build step

## Install

Requires Node ≥ 22.18.

```sh
pnpm install
ln -s $PWD/src/cli.ts ~/.local/bin/moneysurfer
moneysurfer setup   # download the circuits and keys, check their pinned sha256
moneysurfer init    # or: init --import < words.txt, or init --from-wallet
```

## Usage

```sh
moneysurfer pools
moneysurfer deposit eth 0.1 --chain optimism
moneysurfer balance
moneysurfer withdraw eth 0.05 0xRecipient --chain optimism
```

A deposit can be withdrawn privately once the ASP approves it, which takes up to 7 days; ETH that
came out of Tornado Cash is held until you complete a proof of association. Until then — or if it is
declined — `ragequit` returns it publicly to the depositing address.

Not yet supported: ERC-20 pools, and accounts privacypools.com created before its key-derivation fix.
Run `moneysurfer help` for all commands and options.

## License

MIT
