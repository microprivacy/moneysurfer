# moneysurfer

Lightweight CLI for [Privacy Pools](https://privacypools.com).

## Features

- Every pool on Ethereum, Optimism and Arbitrum: ETH, USDC, USDT, DAI, USDS, sUSDS, wstETH, WBTC and
  the rest — read from the Entrypoints' own registrations, so new pools show up by themselves
- One mnemonic derives every note — nothing else to back up. Same keys as 0xbow's SDK, so accounts
  made on privacypools.com carry over, including wallet-derived ones (`init --from-wallet`)
- The ASP's association set comes from the IPFS copy it publishes with every root, checked against
  the root on-chain: nothing about your account is sent to the ASP
- Withdraw through a relayer (its fee is quoted without telling it the recipient), yourself, or
  take an unapproved deposit back with ragequit
- Local Groth16 prover in pure JS (~7 s); every withdrawal is simulated before it is sent
- Sign with Frame, a private key or a keystore, or propose to a Safe's owners (`--safe`): a deposit
  (a token's approval batched in), a withdrawal the Safe submits, or a ragequit of what it deposited
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
moneysurfer deposit usdc 100 --chain optimism
moneysurfer balance
moneysurfer withdraw usdc 50 0xRecipient --chain optimism
```

A token deposit is two transactions: an approval for exactly the amount, then the deposit.
Relayers price some tokens far above their gas cost (Fast Relay has quoted USDS and sUSDS at 10–56%);
`--max-fee-percent` (1% by default) refuses those, and `--self` withdraws without one.

With `--safe SAFE` the transaction goes to the Safe Transaction Service for the owners to confirm and
execute instead of being sent. A deposit made by a Safe can only be ragequit by it. A withdrawal must
be executed while the ASP root its proof names is still the latest; Ethereum's ASP publishes a new
one every hour or two, so propose there when the owners can act soon.

A deposit can be withdrawn privately once the ASP approves it, which takes up to 7 days; ETH that
came out of Tornado Cash is held until you complete a proof of association. Until then — or if it is
declined — `ragequit` returns it publicly to the depositing address.

Not yet supported: accounts privacypools.com created before its key-derivation fix.
Run `moneysurfer help` for all commands and options.

## License

MPL-2.0
