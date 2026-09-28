# moneysurfer

Lightweight CLI for [Privacy Pools](https://privacypools.com) V1 and V2.

```
moneysurfer [v1|v2] <command> ...
```

## Features

- Full V1 and V2 support: V1 on Ethereum, Optimism and Arbitrum; V2 on mainnet
- One seed per protocol
- Nothing is sent to the ASP
- Withdraw via a relayer, yourself, or a Safe; ragequit if unapproved
- Local prover in pure JS, everything simulated before sending
- Sign with Frame, a private key or a keystore
- No build step, minimal and security audited dependencies

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
