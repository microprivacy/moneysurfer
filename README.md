# moneysurfer

Lightweight CLI for [Privacy Pools](https://privacypools.com) V1 and V2.

```
moneysurfer [v1|v2] <command> ...
```

## Features

- Full V1 and V2 support: V1 on Ethereum, Optimism and Arbitrum; V2 on mainnet
- One seed per protocol
- Nothing is uploaded to the ASP: the set is read and checked against the on-chain root, and
  the opening it needs is sealed to its key inside the deposit. V1 reads the set from IPFS and
  asks the ASP's API only if no gateway serves it; V2 asks the API, which sees your IP
- Withdraw via a relayer (V1), yourself, or a Safe; ragequit if unapproved
- Local prover in pure JS, everything simulated before sending
- Sign with Frame, a private key or a keystore
- Minimal and security audited dependencies, bundled in: an install adds one package
- Node runs the sources as they are; only the published bundle is built

## Install

```sh
pnpm i -g moneysurfer
```

Then fetch the circuits and make a seed:

```sh
moneysurfer setup
moneysurfer init
```

## Usage

### V1

```sh
moneysurfer pools
moneysurfer deposit usdc 100 --chain optimism
moneysurfer balance
moneysurfer withdraw usdc 50 0xRecipient --chain optimism
```

A deposit can be withdrawn once the ASP approves it (up to 7 days); until then
`ragequit` returns it publicly.

### V2

Relayed withdrawals are not supported for v2 yet.

```sh
moneysurfer v2 setup
moneysurfer v2 init                # --from-wallet derives the seed the app would
moneysurfer v2 register            # a Keystore leaf; required before spending
moneysurfer v2 pools
moneysurfer v2 deposit usdc 10.02
moneysurfer v2 withdraw ppusdc 5 0xRecipient --self
```

Run `moneysurfer help` for all commands and options.

## License

MPL-2.0
