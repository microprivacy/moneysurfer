# Privacy Pools V2 - verified findings (handoff)

Everything below was verified directly (on-chain RPC, HTTP, the shipped JS bundle, or by
running the code in `src/`), not taken from marketing. Dates are UTC.
First pass 2026-09-21; second pass 2026-09-21 resolved every caveat the first one raised;
third pass 2026-09-22/23 **closed the ASP ciphertext gap** and added the production
deployment; fourth pass 2026-09-23 turned the proving harness into a client, and
**closed the key-derivation, transact-routing and share-wrapping gaps**; fifth pass
2026-11-19, after the public launch, **recovered the relayer protocol** and added BNB
Chain - see [Corrections](#corrections-to-the-earlier-passes).

**How to read this**: a claim is either *verified* (there is a reproducible check, named
here) or listed under [Gaps](#gaps-what-is-still-unverified). Nothing in between.

## Status

V2 is **launched**. `privacypools.com` now serves the V2 app (V1's moved to
`v1.privacypools.com`, artifacts included), and the docs at `docs.privacypools.com` list
production on Ethereum mainnet, BNB Chain and Citrea, all three at the same addresses. The
contracts are still **not** in any public repo (`privacy-pools-core` is V1 only) and the
SDK `@privacy-pools-v2/sdk` is still partner-gated; its quickstart targets Sepolia.

None of that blocks a third-party client. The circuits went through a **public trusted
setup**, the artifacts are content-addressed and hash-pinned, and `deposit`, `ragequit`
and `transact_NxM` proving were all reproduced end to end from scratch and accepted by
the deployed verifiers.

**Whole deposits now simulate green against the live production contracts**, by all
three routes the deployment offers:

| `moneysurfer v2 deposit ...` | goes to | `eth_call` |
|---|---|---|
| `eth 0.004` | `Entrypoint.deposit` | accepted |
| `ppeth 0.0041` | `PPRouter.depositExactSharesNative` | accepted |
| `usdc 10.02` | `PPRouter.depositExactShares` | accepted, with only the USDC allowance overridden |

Each carries a locally built Groth16 proof, the ASP opening, the note data and the
slippage bound. Nothing was signed or sent.

What is left is listed under [Gaps](#gaps-what-is-still-unverified). The one that matters
most is the **key derivation** - recovered from the producer, implemented, and still never
checked against an account the app itself made. The relayer protocol, half recovered
until the fifth pass, is now whole, and a withdrawal goes through a relayer by default.

## The mainnet deployment (chainId 1)

There is one deployment this client talks to: **production**, the pool the app deposits
into. An earlier mainnet deployment ("staging", behind `api-dev.0xbow.io`) is still live
but is no longer addressable from the command line - there is no `--deployment` flag and
no branch on it. The events it produced survive as static fixtures in
`test/v2-vectors.json`, where they still pin the ABI decoding, the public-signal order
and the circuit witness layout; production has far fewer examples to check against.
Those fixtures are **historical, from a retired target**, and nothing in the CLI can
send funds to it.

| Role | Address |
|---|---|
| PoolVault | `0x0Eb42804BF897662aF851370eaeAdcDBEC1b97ed` |
| Keystore | `0x6E463391c79b7e1A88eF26E0B023f9A6C9938a71` |
| ASPRegistry | `0x259C0BEa1d783c202509BD3b2688d23b8AEf58B0` |
| Entrypoint | `0xca1e072236D231130059eeA6Bfceb7F4e9a1F0C3` |
| AccessRouter | `0x40a6bC296D87f71Ab31Ca3Bfb50513441fBD5160` |
| DepositVerifier | `0x49Ab3f48Ff9fa603EE81E5f28eB4214798E29862` (at deployment; see below) |
| RagequitVerifier | `0x687059Fc9C2488f333e06aa72CBea7E4b1D05B57` (at deployment; see below) |
| PrivacyPoolRelay | `0x01a8Fa4dbb60187aD8d3c3d08E7Fb8C14198A461` |
| first block with code | 25,884,231 |
| ASP | `api-v2.0xbow.io` |
| ASP X25519 key | `0x3f651e23...cfd8f34` |

**Production was verified directly**, not copied from the ASP's entrypoint list:

- `entrypoint.poolVault()` returns `0x0eb42804...`, and `pool.keystore()`,
  `pool.aspRegistry()`, `pool.depositVerifier()`, `pool.ragequitVerifier()` and
  `pool.ACCESS_ROUTER()` return the rest of the table. All four are ERC-1967 proxies
  (141 bytes of code) whose implementations sit in the EIP-1967 slot:
  entrypoint `0xce641ed0...`, vault `0x5f89cd5c...`, keystore `0x7b915008...`,
  registry `0x04699131...`.
- The Entrypoint implementation's **complete** selector set is eleven functions:
  `deposit` `0x5dc67ea4`, `poolVault` `0x4b47002c`, `setPoolVault` `0x51cb9ad3`,
  `ACCESS_ROUTER` `0x67ad047b`, `sweep` `0xb8dc491b`, `assets` `0xf11b8188`,
  `setAssetConfiguration` `0xd3ed0048`, plus UUPS `upgradeToAndCall`, `proxiableUUID`,
  `initialize` and `UPGRADE_INTERFACE_VERSION`. This matters for the wrapping path:
  **`depositExactShares` is not one of them.**
- The deployment block was found by bisecting `eth_getCode`, not taken from the API. The
  ASP's own `fromBlock` (25,893,288) is the first *deposit*: two keystore registrations
  happened before it, so a scan starting there is missing leaf 0 and the keystore root
  does not match.
- `moneysurfer v2 trees` rebuilds both trees from logs and `pool.isKnownRoot` /
  `keystore.currentRoot()` confirm both. The newest `ASPRootUpdated` in the logs is
  `latestASPRoot()`.
- The **association set is verified**: `api-v2`'s leaves for this entrypoint hash as a
  LeanIMT to exactly `ASPRegistry.latestASPRoot()`.
- **The verifiers have been rotated since.** On 2026-11-19 `pool.depositVerifier()` reads
  `0xee96ca04...6fdf` and `pool.ragequitVerifier()` `0x5a065821...118f`, both 3,311 bytes of
  code like the originals; BNB Chain's deposit verifier is `0x60969d06...11c9`. The docs
  still list the deployment-time pair. They were built from a **second ceremony's keys**,
  which refused every proof this client made until it pinned them; see
  [Circuit artifacts](#circuit-artifacts---the-manifest-is-trustworthy). `v2 status` now
  checks each live verifier against the pinned key instead of against an address.

### Asset configuration, re-read 2026-09-23

`Entrypoint.assets(address)` returns `(bool enabled, uint256 minAmount,
uint256 vettingFeeBPS, uint256 maxRelayFee)`. Read directly against the production
Entrypoint:

| asset | address | dec | enabled | minAmount | vettingFeeBPS | maxRelayFee |
|---|---|---|---|---|---|---|
| ETH | `0xEeee...EEeE` | 18 | yes | 4e15 (0.004) | **0** | 5e17 |
| ppETH | `0x66051920...83B7` | 18 | yes | 4e15 (0.004) | **0** | 5e17 |
| ppUSDC | `0xC246aFb2...1ad6` | **18** | yes | 1e19 (10) | **0** | 1.2e21 |
| ppUSDT | `0xA4cF4195...0426` | **18** | yes | 1e19 (10) | **0** | 1.2e21 |
| USDC | `0xA0b8...eB48` | 6 | **no** | 1e7 | 0 | 1.2e9 |
| USDT | `0xdAC1...1ec7` | 6 | **no** | 1e7 | 0 | 1.2e9 |

Two things to keep straight. The `pp*` tokens are **18 decimals**, not their
underlyings' 6, so a `minAmount` of 1e19 is 10 *shares*. And `maxRelayFee` is an
**absolute amount in the asset's own units**, not basis points - which is why ETH shows
0.5 there. That reading is confirmed on the spend side, where `transactParams.data`
carries an absolute `feeAmount` (see [Spending](#spending-transact-and-what-it-binds)).

## BNB Chain (chainId 56), added 2026-11-19

The same deterministic deployment: every core address in the mainnet table, and the same
PrivacyPoolRelay, ASP and ASP key. What differs:

| | |
|---|---|
| first block with code | 119,401,450 (the Keystore; bisected, not the docs' 119,401,440) |
| BNB | `0xEeee...EEeE`, enabled, minAmount 0.02 |
| ppUSDT | `0x6C17bE9c...64c2`, enabled, over Aave's aBnbUSDT, router `0x9929Ad2E...4E16` |
| FDUSD | `0xc5f0f7b6...6409`, enabled directly, no router |
| USDT | `0x55d39832...7955`, **disabled**: it enters as ppUSDT |

Stablecoins on BNB Chain have 18 decimals, so nothing is assumed: `chain.ts` reads them.
The router answers `VAULT()`, `UNDERLYING()`, `ENTRYPOINT()` and `ZAP()` as listed, and
reverts on `NATIVE_MODE()` - the ERC-20 router build, like mainnet's ppUSDC and ppUSDT.
The relayer's `/v1/details/evm/56` lists all four plus FDUSD, which the docs said it did
not.

**No keyless RPC serves its logs.** bsc-dataseed answers calls but no `eth_getLogs`;
publicnode wants a token for anything not recent; 1rpc, 48.club and drpc cap a range at
50, 250 and 100 blocks; NodeReal's chainlist key served 50,000-block ranges, then ran out
of its shared quota partway through one sync. So `--chain bnb` asks for `--rpc-url` (or
`MONEYSURFER_RPC`) rather than defaulting to something that fails halfway.

**Note secrets are chain-scoped there.** A tokenId is not unique to a chain - both coins
are `0xEeee...EEeE` - so without the chain in the derivation one seed's first ETH deposit
and first BNB deposit of the same value would share a commitment, and then a nullifier,
in public. Mainnet keeps the info string it always had; see
[Note secrets](#note-secrets-this-clients-own-convention).

Citrea (4114) runs the same contracts too, but its ASP has never published a root, so a
deposit there can only be ragequit. It is left out until that changes.

### The retired staging deployment, and what still rests on it

**Not a target any more.** It is recorded because the fixtures in
`test/v2-vectors.json` come from it, and because several things below were established
there and have since had to be re-confirmed against production. Those are called out
as they arise; the ones still resting on staging alone are in
[Gaps](#gaps-what-is-still-unverified).

| Role | Proxy | Implementation (EIP-1967 slot) |
|---|---|---|
| PoolVault | `0x8884DC0c0DEcd2558F128ee00dD522ABfa21Dd52` | `0xf5dfdcdf302c4e9e309e8575cb007eb0f23b0038` |
| Keystore | `0x08806e1aD685FbF518dfa6795b90ca4c1F04Cd64` | `0x15bd39ef2184d92f71545a174ecb19904820346b` |
| ASPRegistry | `0x4BeCb4c0175Df3dA440A694E73Fd3c459B8dd422` | `0x17609567ddc214331e55e9c44d5328872f4410b3` |
| Entrypoint | `0x02a1E00294291d0E938eC92A8c2883044524ec4B` | `0xb96f13df76a13f712a372eda0dbc8a98a886268f` |

**The role labels are confirmed, not guessed.** The first pass read them positionally out
of the app bundle; they were re-derived two independent ways:

1. *Selectors.* Each implementation's bytecode was disassembled (`cast selectors`) and
   every selector resolved with `cast 4byte`. The 4byte database has the full V2 ABI, so
   the names come back directly: the pool has `transact`/`ragequit`/`spentNullifiers`, the
   keystore has `setViewingKey`/`setAuthPolicy`, the registry has `updateASPRoot`, the
   entrypoint has `poolVault`/`setAssetConfiguration`.
2. *Cross-references.* `pool.keystore()`, `pool.aspRegistry()` and `entrypoint.poolVault()`
   were called on-chain and each returns exactly the address labelled that way above.

Also discovered on-chain:

| | |
|---|---|
| AccessRouter | `0x641E395651bAB1195e14DfFaAe7534623B4B6973` (`pool.ACCESS_ROUTER()`) |
| DepositVerifier | `0x8240695D24746D6ED38E9a4EEF57EF78b33158f4` |
| RagequitVerifier | `0x15e2296513cC8d464c1388885E18325eA4fc936b` |
| Transact 1x1 verifier | `0x70b54A09e7d5fD73e56eAfe65455834F83f595A7`, selector `0xc9219a7a` |
| `maxStateTreeSize` | 4,194,304 = 2^22 |
| `maxKeystoreTreeSize` | 262,144 = 2^18 |
| `rootHistorySize` | 16 |
| `keystoreRootLiveness` | 1200 (seconds) |

Transact verifiers are routed through `pool.verifiers(bytes32)`, keyed by
`keccak256(abi.encode(uint8 N, uint8 M))`, returning `(address verifier, bytes4 selector)`.

Configured assets on the staging Entrypoint (`assets(address)`), all three set at deploy:
ETH (`0xEeee...EEeE`), USDC (`0xA0b8...eB48`), USDT (`0xdAC1...1ec7`) - each `enabled`,
`minAmount` 1 wei, `maxRelayFee` `type(uint256).max`, `vettingFeeBPS` 100 (1%).
The advertised $100 deposit cap is a frontend limit, not an on-chain one. The 1% fee
matches the first mainnet deposit exactly: 0.0101 ETH sent, 0.01 deposited, 0.0001 fee -
and it is added *on top* of the deposit, never deducted from it
(`msg.value = value + value * vettingFeeBPS / 10000`, and only for the native asset).

## Circuit artifacts - the manifest is trustworthy

**Superseded 2026-11-19: the verifiers now run a second ceremony's keys.** Every
verifier the pool points at - deposit, ragequit and the transact grid, on mainnet and BNB
Chain alike - was redeployed after the launch from a new phase-2 setup over the same
circuits. The wasm is byte for byte what it was; the zkeys and vkeys are not. A
snarkjs verifier carries its key as 32-byte constants, so this is checkable against
bytecode alone:

| verifier | first ceremony's key | the app's current key |
|---|---|---|
| deposit, mainnet `0x49Ab3f48...9862` (at deployment) | 24/24 constants | - |
| deposit, mainnet `0xee96ca04...6fdf` (now) | 4/24 | 24/24 |
| deposit, BNB `0x60969d06...11c9` | - | 24/24 |
| ragequit, mainnet `0x5a065821...118f` (now) | 4/30 | 30/30 |
| transact_1x1, mainnet `0x21347145...0042` (now) | 0/22 (delta, IC) | 22/22 |

The four that still match are alpha, beta and gamma, which phase 2 does not touch. Until
this was fixed every proof this client made was refused - a deposit reverted
`PoolVault_InvalidDepositProof()` in simulation - and recent production deposit,
ragequit and transact_1x1 proofs verify under the new keys and not the old
(`proofsProduction` in `test/v2-vectors.json`).

The SDK's IPFS manifest still names the first ceremony's keys. The app does not use it:
it fetches `artifacts.privacypools.com/artifacts/<ARTIFACTS_VERSION>/<circuit>/...`
(`groth16_pkey.zkey`, `groth16_vkey.json`, `<circuit>_js/<circuit>.wasm`), version
`0b62f6b7e5eb` at the time of writing, and so does this client now, pinning the sha256
of all 27. That host serves about 180 KB/s per connection. `v2 status` checks each
live verifier's bytecode against the pinned key, so the next rotation shows there
first. What follows is the first ceremony, as it was checked.

`./circuit-artifacts.json` had `wasm`/`provingKey`/`verificationKey` CIDs plus SHA-256
pins for all 27 circuits. The first pass could not download any bytes (every public
gateway returned HTTP 429). **They have now been downloaded and checked.**

`gateway.pinata.cloud` serves them; `ipfs.io`, `dweb.link`, `w3s.link`, `nftstorage.link`
and `gateway.ipfs.io` all still return 429 with the service-worker migration notice.
A local kubo 0.34.1 daemon is not a workaround - it segfaults in bitswap
(`boxo/bitswap/message.newMessageFromProto`, nil deref) within seconds of connecting.

Every pinned hash matched, byte for byte:

| circuit | wasm | zkey |
|---|---|---|
| deposit | 2,337,270 B OK | 1,031,707 B OK |
| ragequit | 3,085,620 B OK | 5,932,748 B OK |
| transact_1x1 | 3,239,462 B OK | 17,942,432 B OK |
| transact_1x2 | OK | (not fetched) |
| transact_2x1 | OK | (not fetched) |

All three zkeys parse with `micro-zk-proofs`' `parseZKey` (magic `7a6b6579`, v1) and
prove. The manifest pins **no** hash for the verification keys - their CID is the hash,
so they are trusted exactly as far as the CID is.

The strongest check is not the SHA-256 at all: **the verification keys from the manifest
successfully verify real mainnet proofs** pulled off `deposit`, `ragequit` and
`transact_1x2` transactions (`test/prover.test.ts`). A substituted key could not do that.

`nPublic` from the vkeys matches the contract ABI exactly, which independently confirms
the public-signal counts: deposit 4 (`uint256[4]`), ragequit 7 (`uint256[7]`),
transact_NxM = **N + M + 6**.

## Recovered ABI

Unverified, closed-source contracts; the signatures below come from selector extraction
plus `cast 4byte`, and every one was decoded against real mainnet calldata. The
PPRouter and PPYieldTokenZap are in
[their own section](#depositing-an-asset-the-entrypoint-refuses-the-pprouter).

```solidity
// PoolVault
deposit((uint256[2],uint256[2][2],uint256[2],uint256[4]), (bytes32,bytes))         0x37d38383
transact((uint256[2],uint256[2][2],uint256[2],uint256[][]), (address,bytes),
         (bytes32,bytes)[])                                                        0x85afaff4
ragequit((uint256[2],uint256[2][2],uint256[2],uint256[7]))                         0x769284c2
commitments(uint256) -> uint256    // block.timestamp of insertion, 0 if absent
spentNullifiers(uint256) -> uint256
isKnownRoot(uint256) -> bool ; roots(uint256) ; currentRootIndex() ; rootHistorySize()
keystore() ; aspRegistry() ; depositVerifier() ; ragequitVerifier() ; verifiers(bytes32)
maxStateTreeSize() ; paused() ; pause() ; unpause()

// Entrypoint  (holds DEPOSITOR_ROLE; the only way into the pool)
deposit((uint256[2],uint256[2][2],uint256[2],uint256[4]), (bytes32,bytes), bytes)   0x5dc67ea4
poolVault() ; assets(address) -> (bool,uint256,uint256,uint256) ; sweep(address,address)
setAssetConfiguration(address,(bool,uint256,uint256,uint256))

// Keystore
setAuthPolicy(uint256 authDigest, uint256 nullifyingKeyHash)                       0x735aeddc
setViewingKey(bytes32)                                                             0x73897d65
setAuthPolicyWithSig(address,uint256,uint256,uint256,bytes)
updateAuthPolicy(uint256,uint256,uint256[])
viewingKeys(address) ; nullifyingKeys(address) ; currentRoot() ; isKnownRoot(uint256)

// ASPRegistry
updateASPRoot(uint256 root, bytes ipfsCID)                                         0x5bced48c
latestASPRoot() ; latestIPFSCID() ; associationSets(uint256) ; registerLabel(bytes)
```

The Entrypoint's third `bytes` argument is the **encrypted opening for the ASP**: it is
forwarded to `ASPRegistry` and re-emitted verbatim as `LabelRegistered(bytes)`
(344 bytes in the observed deposit).

### Events (topic0 resolved with `cast 4byte-event`, indexed args read off real logs)

```solidity
// PoolVault
LeavesInserted(uint256[] leaves, uint256 root, uint256 index)   // no indexed args
Note(bytes32 indexed hint, bytes ciphertext)
Deposited(uint256 commitment, address indexed tokenId, uint256 value, address indexed caller)
Ragequit(address indexed ragequitter, address indexed tokenId, uint256 value,
         uint256 commitment, uint256 nullifier, uint256 label)
Transacted(uint256[] commitments, uint256[] nullifiers, address indexed tokenId,
           uint256 amountOut, address indexed processooor)
// Entrypoint
Deposited(address indexed tokenId, address indexed depositor, uint256 value, uint256 fee)
// Keystore
LeafInserted(uint256 leaf, uint256 root, uint256 index)
ViewingKeySet(address indexed account, bytes32 previous, bytes32 viewingKey)
AuthPolicySet(address indexed account, uint256 nullifyingKeyHash, uint256 authDigest)
RootSuperseded(uint256 indexed, uint256 indexed, uint256)
// ASPRegistry
ASPRootUpdated(uint256 indexed root, bytes ipfsCID)
LabelRegistered(bytes ciphertext)
```

## Protocol, verified against mainnet

Every hash below is checked in `test/crypto.test.ts` against values read off real
transactions (`test/vectors.json`).

```
noteAddressHash = Poseidon(ownerAddress, noteSecret)
precommitment   = Poseidon(noteAddressHash, tokenId, value, metadata)   // metadata = 0 in v2.0
label           = Poseidon(precommitment, depositSecret)
commitment      = Poseidon(precommitment, label)
nullifier       = Poseidon(privateNullifyingKey, commitment)
nullifyingKeyHash = Poseidon(privateNullifyingKey)
authDigest        = Poseidon(0, privateRevocableKey)       // 0 = AUTH_TYPE_DIRECT_KEY
keystoreLeaf      = Poseidon(ownerAddress, nullifyingKeyHash, authDigest)
```

**State tree** - LeanIMT (zk-kit), Poseidon, dynamic depth, circuit bound 22. It holds
*both* kinds of leaf, domain-separated and timestamped:

```
commitmentLeaf = Poseidon(COMMITMENT_LEAF_TAG, commitment, block.timestamp)
nullifierLeaf  = Poseidon(NULLIFIER_LEAF_TAG,  nullifier,  block.timestamp)
COMMITMENT_LEAF_TAG = 3791694183000795315792098099581407680958131641292811872617553086713867485913
NULLIFIER_LEAF_TAG  = 1480564842420020354887207755615370381236762558448265256256653429412951563031
```

The timestamp is recoverable without any extra call: `commitments(c)` and
`spentNullifiers(n)` *are* the insertion timestamps. Insertion order within one transact
is **all commitments, then all nullifiers**; a deposit inserts one commitment leaf, a
ragequit one nullifier leaf.

Rebuilding the tree from `LeavesInserted` logs reproduces the on-chain root exactly
(98 leaves, depth 7 at the time of writing), and `pool.isKnownRoot` confirms it. Same for
the keystore tree from `LeafInserted` (14 leaves, depth 4) against `keystore.currentRoot()`.

**Contexts** - `deposit` binds `uint256(keccak256(abi.encode(noteData))) % r` where
`noteData` is the `(bytes32 hint, bytes ciphertext)` struct; verified byte-exact against
the first mainnet deposit. `transact` binds `keccak256(abi.encode(transactParams, noteData))`
(per the docs; not re-derived here).

### Public signal order - confirmed by pairing, not by reading

The flattened public-input vector was confirmed by verifying real mainnet proofs; a
reordering fails, so this is not a guess:

```
deposit  [4]  outputCommitment, tokenId, value, context
ragequit [7]  nullifierHash, commitment, keystoreRoot, ownerAddress, value, tokenId, label
transact      nullifiers[N], commitments[M], stateRoot, keystoreRoot, aspRoot,
              amountOut, tokenIdOut, context
```

Circom puts outputs first, then public inputs - hence `nullifierHash, commitment` leading
ragequit. On the wire `transact`'s `uint256[][]` is **grouped**, one sub-array per bullet
above, in exactly that order. Which group is which was settled on-chain, not by inspection:
`spentNullifiers()` is non-zero for the first group's entries and `commitments()` for the
second's.

### Circuit input signals - recovered by probing the wasm

circom's witness calculator answers `getInputSignalSize` for any name, so the full input
list was recovered by FNV-1a probing (no source needed). Sizes for N inputs / M outputs:

| signal | deposit | ragequit | transact_NxM |
|---|---|---|---|
| `depositSecret`, `noteAddressHash` | 1 | - | - |
| `tokenId`, `context` | 1 | `tokenId` only | 1 |
| `value`, `noteSecret`, `label` | - | 1 | **N** |
| `metadata` | - | 1 | - (hard-coded 0) |
| `ownerAddress`, `privateNullifyingKey`, `privateRevocableKey` | - | 1 | 1 |
| `keystoreRoot`, `keystoreLeafIndex`, `keystoreTreeDepth` | - | 1 | 1 |
| `keystoreSiblings` | - | 18 | 18 |
| `stateRoot`, `amountOut`, `tokenIdOut`, `associationSetRoot` | - | - | 1 |
| `stateLeafIndex`, `stateTreeDepth`, `timestamp`, `associationSetLeafIndex` | - | - | **N** |
| `stateSiblings` | - | - | **22N** |
| `associationSetSiblings` | - | - | **18N** |
| `outputNoteAddressHash`, `outputValue`, `outputLabel` | - | - | **M** |

Totals: deposit 5 signals, ragequit 12 (29 elements), transact 26 signals
(81 elements at 1x1, 84 at 1x2, 129 at 2x1).

Ragequit carries **no** state-tree or ASP witness: the contract checks commitment
existence by direct `commitments()` lookup, and bypassing the ASP is the point.

## Keys

Three private keys plus one public viewing key, from one EIP-712 signature. The whole
ladder, the constants **and the EIP-712 payload** are now de-minified out of the app's
own bundle (`CryptoService` and `buildSecretDerivationPayload`), quoted rather than
guessed, and implemented in `src/v2/crypto.ts`.

```
rootSecret = HKDF(sha256, ikm=signature.r, salt=signerAddress, info=ROOT_DERIVATION_INFO, L=32)
appSecret  = HKDF(sha256, ikm=rootSecret,  salt=APP_IDENTIFIER, info=APP_DERIVATION_INFO, L=32)
(privateNullifyingKey, privateRevocableKey, viewingPrivateKey)
           = deriveKeys(appSecret, revocableKeyIndex)
viewingPublicKey = x25519.getPublicKey(viewingPrivateKey)
```

```
ROOT_DERIVATION_INFO = "Standardized-Secret-Derivation-v1-Root"
APP_IDENTIFIER       = "TODO-privacy-pools-v2"
APP_DERIVATION_INFO  = "Standardized-Secret-Derivation-v1-App"

deriveKeys(appSecret, revocableKeyIndex):
  prk       = hkdf-extract(sha256, ikm=appSecret, salt="PP_V2")
  identity  = hkdf-expand(sha256, prk,      info="IDENTITY",   32)
  viewing   = hkdf-expand(sha256, prk,      info="VIEWING",    32)
  privateNullifyingKey = hkdf-expand(sha256, identity, info="NULLIFYING", 48) mod r
  privateRevocableKey  = hkdf-expand(sha256, identity,
                           info="AUTH0:REVOCABLE" ‖ uint64be(revocableKeyIndex), 48) mod r
  viewingPrivateKey    = clamp25519(hkdf-expand(sha256, viewing, info="VIEWING_KEY", 32))
```

`clamp25519` is the usual `b[0] &= 248; b[31] &= 127; b[31] |= 64`. Only the revocable
key moves with `revocableKeyIndex`, so rotating it cannot orphan a note.

### The EIP-712 payload - recovered, no longer missing

The earlier passes recorded this as unpublished. It is `buildSecretDerivationPayload`,
verbatim:

```js
{
  domain: { name: 'Standardized Secret Derivation', version: '1',
            verifyingContract: '0x0000000000000000000000000000000000000000',
            salt: keccak256(toHex(APP_IDENTIFIER)) },
  types: { SecretDerivation: [{ name: 'purpose', type: 'string' },
                              { name: 'addressHash', type: 'bytes32' }] },
  primaryType: 'SecretDerivation',
  message: { purpose: 'This signature is used to deterministically derive ' +
                      'application-specific secrets from your master seed. ' +
                      'It is not a transaction and will not cost any gas.',
             addressHash: keccak256(toBytes(signerAddress)) }
}
```

The domain carries **no chainId** - one account on every chain - and its salt is
`keccak256("TODO-privacy-pools-v2")` = `0xee8b2697…edf10fb7`, which is what keeps this
app's keys apart from any other built on the same scheme. The handler asserts
`message.addressHash == keccak256(signerAddress)` and uses only the signature's `r`,
so `s` and `v` may differ between signings without changing the account.

### Still unverified, and this is the one that matters

**No account the app itself made has ever been checked against this.** Unlike the ASP
opening there is no offline oracle: confirming it needs a wallet signature whose derived
keys are *already* registered in a Keystore, and this client has neither. Everything
above is the producer's own code, and `test/v2-account.test.ts` pins its shape, widths,
clamping and index encoding so it cannot drift silently - but pinning a recovered
constant is not the same as confirming it.

The code says so too: `src/v2/crypto.ts` carries the warning at the top of the section,
and `moneysurfer v2 init --from-wallet` prints it before writing the seed. **The cheap
test is `register`**: derive keys, register, and see whether the web app recognises the
account as yours. That costs one small transaction and settles it.

### Note secrets: this client's own convention

The SDK draws `noteSecret` and `depositSecret` at random and finds them again by
decrypting the on-chain `Note` ciphertext. This client derives them from the seed
instead, the way V1 derived its notes from the mnemonic:

```
noteSecret(tokenId, i)    = HKDF(sha256, appSecret, salt="PP_V2",
                                 info="moneysurfer2/v1:note:<tokenId>:<i>", 48) mod r
depositSecret(tokenId, i) = ... info="moneysurfer2/v1:deposit:<tokenId>:<i>" ...
changeSecret(label, j)    = ... info="moneysurfer2/v1:change:<label>:<j>" ...
```

Off mainnet, `note` and `deposit` become `note@<chainId>` and `deposit@<chainId>`: every
chain's coin is `0xEeee...EEeE`, so the tokenId alone would give one seed the same notes
on every chain. Change secrets need no such suffix, since the label they hang off already
differs. Mainnet's strings are the ones it had before there was a second chain.

The info strings are namespaced so they cannot collide with anything the SDK expands
from the same secret. A note made this way is an ordinary note - nothing on chain can
tell - and `balance` recovers it from the `Deposited` and `Transacted` logs alone, with
nothing to back up but the words and no dependence on the Note payload being right.

The trade is stated in the README: **the web app will not list a deposit made here**
unless it also published a `Note` the app can decrypt, which this client does not do.

## ASP

Public, unauthenticated, and **every request must carry both `chainId` and
`entrypoint`**. This is the thing the first pass got wrong: without `entrypoint`
the API answers for a different pool, which is why its leaves looked unrelated.

```
GET {host}/association-set/leaves?chainId=1&entrypoint={entrypoint}
GET {host}/association-set/root?chainId=1&entrypoint={entrypoint}
GET {host}/1/public/event-snapshot/payload?entrypoint={entrypoint}
GET {host}/labels/{decimalPoseidonLabelHash}/status
GET {host}/public-key
GET {host}/global/public/entrypoints
```

**One ASP host per deployment.** `api-dev.0xbow.io` serves staging and answers
`404 No enabled pool found` for the production entrypoint; `api-v2.0xbow.io`
serves production and 404s for staging's. `api-v2`'s
`/global/public/entrypoints` lists production on three chains - mainnet
(fromBlock 25,893,288, the first deposit), 4114 and 56 - all behind the same
entrypoint and vault addresses. `api-dev`'s list has staging as poolId 6:
entrypoint `0x02a1e002…`, poolVault `0x8884dc0c…`, fromBlock 25,753,940 —
again the first deposit block.

**Both association sets are recovered and verified.** Staging: 182 leaves
hashing as a LeanIMT to `0x0882fded…d829`. Production: 380 leaves hashing to
`0x2bf0663b…90c8deee`. Each is exactly what that deployment's
`ASPRegistry.latestASPRoot()` returns. The set is per-pool, not global (Sepolia's
two pools return 568 and 12,131 leaves under different roots).

**The ASP leaf is `Poseidon(label)`, not the bare label.** Settled by the circuit
itself, not by inference: a `transact_1x1` witness built over a tree of bare
labels fails with `assert failed` in `ValueConservation`/`Transact`, and one
built over `Poseidon(label)` leaves is accepted. It matches the docs, which key
`/labels/{hash}/status` by the Poseidon hash of the label.

The snapshot endpoint returns the same view this client rebuilds from logs —
39 deposits, 20 transacts, 7 ragequits, 98 state leaves, 14 keystore leaves,
66 notes — which independently confirms the log scan. It also splits the Note
ciphertext into `ephemeralPubKey` (32 bytes) and `encryptedPayload`, so the
171-byte deposit blob is a 32-byte X25519 ephemeral public key followed by a
139-byte AEAD payload.

### The Note ciphertext, from the same bundle

Not implemented here, but no longer unknown, and it checks out against every
Note event on staging. `encryptAndWrap` is the **same sealed box** as the ASP
opening — ephemeral X25519, ECDH to the recipient's viewing public key,
sha256 to an XChaCha20-Poly1305 key, `managedNonce`, concatenated after the
ephemeral key — so `seal`/`unseal` in `src/asp.ts` already cover it. The hint is
32 random bytes in discoverable mode, or `Poseidon(sharedSecret, "0x0")` against
a payment request. The plaintext is RLP, not JSON:

```
RLP([ 0x02, 0x01, noteSecret, value, tokenId, label ])       // a note for its owner
RLP([ 0x02, 0x02, noteAddressHash, value, tokenId, label ])  // against a payment request
```

`0x02` is the payload version and the second byte is the kind. That predicts
`72 + 92 + bytelen(value)` bytes on the wire, and the 66 staging Note events
agree exactly: the 39 deposit self-notes are 167 B (21 of them, 3-byte values),
168 B (3, 4-byte) and 171 B (15, 7-byte), each matching its own deposit's value;
the 27 transact notes are a constant 196 B, which is the same formula with
`value` padded to 32 bytes — the transact path runs amounts through the SDK's
`DecimalRepresentationToHexSchema`, which pads, while the deposit path does not.
66 of 66, no exceptions.

### The deposit opening — recovered, implemented and tested

This is the gap the second pass called unclosable. It was wrong, for one
reason: **the app bundles the SDK core.** `v2.privacypools.com` ships 40
`bootstrap-part-*.js` chunks, and one of them (`675e66a4…`) contains
`encodeASPCipherText`, `decodeASPCipherText`, the whole `CryptoService`, the
deposit service that calls them and the zod schema the ASP parses with. It is
minified but not obfuscated. The second pass reasoned about the ciphertexts from
outside and never looked for the producer.

The ASP's key is public — the depositor has to encrypt to it:

```
GET https://api-v2.0xbow.io/public-key
  -> {"publicKey":"0x3f651e2321b9b78c3690064b025b610942cbf755e28d44726378cf853cfd8f34"}  (production)
GET https://api-dev.0xbow.io/public-key
  -> {"publicKey":"0x18656ba6d7862cb11d995afe20bf8761edee05ec28aa29bfbcf31ebd19dede71"}  (staging)
```

**The scheme is a sealed box**, de-minified from the bundle:

```js
encodeASPCipherText = (payload, { aspPublicKey }) => {
  const eph    = cryptoService.generateEphemeralKeyPair()          // x25519.keygen()
  const shared = cryptoService.ecdh(eph.privateKey, aspPublicKey)  // x25519.getSharedSecret
  const ct     = cryptoService.encrypt(utf8(JSON.stringify(payload)), shared)
  return '0x' + eph.publicKey.slice(2) + ct.slice(2)
}
// CryptoService
secretToKey(s) { return sha256(hexToBytes(s.slice(2))).slice(0, 32) }
encrypt(pt, secret) { return '0x' + bytesToHex(managedNonce(xchacha20poly1305)(secretToKey(secret)).encrypt(pt)) }
```

noble's `managedNonce` puts a random 24-byte nonce in front of what it encrypts,
so the wire format is

```
ephemeralPublicKey(32) ‖ nonce(24) ‖ ciphertext(n) ‖ Poly1305 tag(16)
```

and the ECDH output is hashed once with sha256 into the XChaCha20 key. Both
implementations refuse an all-zero shared secret (a low-order public key).

The **plaintext is JSON**, and the EVM deposit service builds it as

```js
generateASPCipherText({ noteAddressHash: witness.noteAddressHash, tokenId, value,
                        depositSecret, metadata: '0x0' })
```

so the five fields appear in that insertion order, which `JSON.stringify`
preserves. `metadata` is the literal string `"0x0"` — not a formatted zero.
The widths are not free: the reader's schema is
`{ noteAddressHash: Ir, tokenId: Ar, value: vr, depositSecret: Sr, metadata: vr }`
where `Ir`/`Sr` *require* 64 hex digits, `Ar` requires 40, and `vr` is any
non-empty `0x[0-9a-f]+`. The producers agree: `hashService.hash()` and
`generateSecret()` both return `'0x' + n.toString(16).padStart(64,'0')`, while
the app passes the amount through as `` `0x${amount.toString(16)}` `` — minimal
hex, no padding.

```json
{"noteAddressHash":"0x<64>","tokenId":"0x<40>","value":"0x<minimal>","depositSecret":"0x<64>","metadata":"0x0"}
```

That is `258 + hexdigits(value)` bytes of plaintext, `330 + hexdigits(value)` on
the wire — which is the length law the second pass measured, now explained: the
17 unexplained bytes are `,"metadata":"0x0"` plus the opening brace the earlier
count dropped.

**Beware the Sui path**, which the same bundle also contains: it pads *every*
field to 64 hex, `metadata` included, so its blobs are 61 bytes longer. The EVM
payload is the one above.

#### Fixed-width or minimal-hex: settled empirically, not just read

The source says `noteAddressHash` and `depositSecret` are fixed 64-digit fields.
The 39 on-chain `LabelRegistered` blobs say the same thing on their own, and
that check does not depend on trusting the bundle. Every one of the 39, paired
with the value of the deposit in the same transaction, satisfies
`len = 330 + hexdigits(value)` — **39 of 39, no exceptions** (`test/asp.test.ts`,
and the blobs are in `test/vectors.json`).

If those two fields were minimal-hex, a leading zero nibble would shorten the
blob. A Poseidon output and a reduced 48-byte secret are both near-uniform on
`[0, r)` with `r ≈ 0.3306 · 2^256`, so each has probability `2^252 / r ≈ 0.331`
of a zero top nibble. Over 78 fields the expected number of short blobs is
about **26**; the probability of seeing none is `(1 - 0.331)^78 ≈ 2.5 · 10^-14`.
Zero were short. Fixed width, with no ambiguity left to report.

The same 39 also pin `value` as minimal: the observed lengths run 335–344 and
track `hexdigits(value)` one for one. A padded value would make every blob a
constant 394 bytes.

#### What was checked, and what a round trip can and cannot prove

- **The offline oracle exists after all.** The box is sealed to a *published*
  key, so anyone can run the encoder against a keypair they hold and decrypt
  with the private half. `test/asp.test.ts` does exactly that: the recovered
  `Opening` is deep-equal to the input, and the recovered plaintext is
  byte-identical to the JSON. A wrong key, a flipped byte anywhere in the
  envelope, or a truncated blob all fail.
- **Structure of the real blobs.** All 39 lead with 32 bytes that are a usable,
  contributory X25519 point (ECDH against them does not yield zero), all 39
  ephemeral keys are distinct, and every remainder holds at least a nonce, a
  byte of ciphertext and a tag. The encoder's output is shape-identical for the
  same values.
- **The chain accepts it.** `moneysurfer2 build-deposit` assembles proof +
  opening + calldata + `msg.value` and `eth_call`s the live Entrypoint; both
  deployments return success. Tampering with one byte of the proof gives
  `PoolVault_InvalidDepositProof()`, a wrong `msg.value` gives
  `Entrypoint_InvalidETHAmount()`, and replaying an old deposit gives
  `PoolVault_CommitmentAlreadyUsed()` — so the simulation is doing real work.
- **What is still not proved.** Flipping a byte *inside* the ASP ciphertext
  changes nothing on chain: the Entrypoint forwards those bytes to the registry
  without looking at them, and no public signal commits to them. A deposit is
  therefore accepted on-chain whether the opening is right or not. The last
  step — the ASP actually decrypting it and attesting the label — can only be
  observed by making a funded deposit, which this client will not do. The round
  trip proves the *scheme*; only the ASP can confirm the *key exchange with the
  real ASP key*, and that is a one-line difference (whose public key) rather
  than a format question.

### Is the ASP bypassable?

Worth answering precisely, because the deposit-side opening is *not* validated
on chain (above) and that invites the wrong conclusion.

**For a private spend, no.** Two independent checks:

- *In the circuit.* `transact_NxM` takes `associationSetRoot` as a public signal
  and every input note must carry a Merkle inclusion proof of `Poseidon(label)`
  under it. This is enforced, not advisory: a witness built over a tree of bare
  labels fails with `assert failed`, and `associationSetSiblings` is a required
  `18N`-element input (`test/notes.test.ts`).
- *On chain.* The PoolVault implementation's runtime code contains the selector
  for `ASPRegistry.latestASPRoot()` (`0x36149de2`) on both deployments, so the
  pool reads the registry rather than taking the prover's word for the root.
  Empirically, all six staging transacts that call `pool.transact` directly (the
  other fourteen go through relay contracts) used an `aspRoot` the registry had
  published — 6 of 6, across three different historical roots.

So a spender cannot invent an association set: they would have to invent a root
the registry never published.

**For getting the money out, yes — and that is the design.** `ragequit` carries
no ASP witness at all; the contract checks commitment existence with a direct
`commitments()` lookup. But it is an exit, not a privacy bypass: the `Ragequit`
event publishes `ragequitter`, `tokenId`, `value`, `commitment`, `nullifier` and
`label` in the clear, so the depositor gets their own deposit back with zero
anonymity. Seven ragequits have happened on staging.

**The deposit side is unauthenticated but not exploitable in the depositor's
favour.** Garbage in the ASP opening produces a deposit the chain accepts and
the ASP can never attest, which leaves ragequit as the only way out. It is a
footgun, not a hole — and it is the reason this client round-trips the opening
before publishing it.

Not verified: the exact rule the pool applies to `aspRoot` — equality with
`latestASPRoot()`, or a history/liveness window like the keystore's
`keystoreRootLiveness`. `ASPRegistry.associationSets(uint256)` reverts with
Panic 0x32 (array out of bounds) on a large index, so it is a stored array of
historical sets, but its selector does **not** appear in the pool's code.

### Still open about the set

182 leaves against 39 deposits is unexplained — labels are per-deposit, so a
one-leaf-per-approved-deposit set should be at most 39. None of the 182 matches
any public on-chain value (deposit/transact commitments, nullifiers, state or
keystore leaves, note hints, ragequit labels: 0 of 182 explained), which is
consistent with leaves being hashes of private labels but leaves the surplus
unaccounted for. The published roots are also **not** prefixes of the set in the
order the API returns it — only the newest root is — so the API's ordering is
not insertion order, and historical sets cannot be reconstructed from it
(`?root=`, `?block=`, `?blockNumber=` are all ignored). None of this blocks a
client: a spender knows their own label, and finds `Poseidon(label)` in the
current set by search.

### Labels are not derivable from public data

Worth stating precisely, because it is the reason the set has to be fetched at
all. `label = Poseidon(precommitment, depositSecret)` and `depositSecret` is a
private 48-byte scalar, so a label cannot be recomputed by an observer. Tested
rather than assumed, against the 7 labels the `Ragequit` events publish:

- `Poseidon(scope, nonce)` and `keccak(scope, nonce) % r` for nonce 0..63 over
  seven scope candidates (pool address; `keccak`/`Poseidon` of
  pool‖chainId‖asset; pool‖asset; chainId; 0) — V1's label shape. No hits.
- `Poseidon` of every ordered pair drawn from the deposit's public values
  (commitment, value, tokenId, owner, deposit index, block) — no hits.
- ~6,300 candidates per label across all 7. **0 hits.**

Nor is any published root reachable from public data: single-leaf and
zero-padded fixed-depth trees over known labels (7 leaf forms × 18 roots), the
power-of-two LeanIMT append identity `root' = Poseidon(root, leaf)` over all 17
transitions, and LeanIMT prefixes of deposit commitments and known labels in
both orders — **0 hits** for every one.

## Spending: `transact` and what it binds

V2 has no `withdraw`. A private spend is `PoolVault.transact` - an N-in/M-out joinsplit -
and a withdrawal is that with a non-zero `amountOut`. The client maps V1's
`withdraw <asset> <amount|all> <to>` onto a **1x1 transact**: one input note, one change
note, and the withdrawn amount unshielded.

`transactParams` is `(address processor, bytes data)`, and `data` is
**`abi.encode(PayoutRouting{recipient, feeRecipient, feeAmount, nativeGas})`** - four
words. Recovered two ways that agree:

- the SDK's `getTransactParams` / `buildPayoutRoutingParams` encode exactly that tuple
  (`Si` in the bundle);
- decoding the `data` of real production transacts gives four words in that order.
  In `0xcde60af1…` (a `withdrawToUnderlying`) they are recipient `0x98addcc7…`,
  feeRecipient `0x9e2f1b23…`, `feeAmount` `0x011f70b28e4f5258`, `nativeGas` 0. A direct
  `pool.transact` (`0xf45e145c…`) has recipient = feeRecipient = the caller and both
  trailing words zero.

`test/v2-zap.test.ts` re-encodes the first of those byte-for-byte.

**The relay fee is an absolute amount, not basis points.** That is what
`feeAmount` holds, and it is the same denomination as `Entrypoint.assets().maxRelayFee` -
which independently explains why production shows 0.5 there for ETH rather than a
percentage. V1's `--max-fee-percent` is a percentage of the withdrawal, so the two are
not the same quantity; the client converts.

The context is `computeTransactContext`:

```
context = keccak256(abi.encode(transactParams, noteData[])) mod r
```

Recovered from the bundle rather than the docs this time, which closes the earlier
"taken from the docs, not re-derived" caveat on its *preimage*. It has **not** been
re-derived from calldata against a successful on-chain transact, so it remains a gap.

### The relayer

0xbow runs one relayer for every chain, `https://relayer-v2-prod-149184580131.us-east1.run.app`.
The earlier passes read the wrong client out of the bundle: the `proofBytes, n, m, gvkX,
coinType` body they found posts to `/v1/relay/withdrawal` and expects a `txDigest` back -
another chain's path, not this one. The SDK's own `RelayerInteractor` is in the bundle
`privacypools.com` serves now, with its zod schemas, and speaks this:

- `GET /v1/details/evm/{chainId}`: `contracts.relay` (the PrivacyPoolRelay), the
  `relayerAddress` that sends, and the `assets` it quotes.
- `POST /v1/quote/evm/{chainId}/receive` with `{asset, commit: true, recipient,
  extraGas, amount}`, where `amount` is what the **recipient** gets. It answers
  `feeAmount`, `amountSent` (= amount + fee, the transact's `amountOut`), `processor`,
  and a `feeCommitment` whose `data` is the ABI-encoded PayoutRouting `(recipient,
  feeRecipient, feeAmount, nativeGas)` and whose `signedRelayerCommitment` signs it. It
  lives about 60 seconds.
- `POST /v1/relay/evm/{chainId}/withdrawal` with `{signedFeeCommitment, proof,
  noteData, inputNullifierNumber, outputCommitmentNumber}`; `proof` is snarkjs's JSON
  with every number `0x`-hex and the flat `publicSignals` folded in, `noteData` is
  `[{hint, data}]`. It answers `{txHash}`.

The proof binds `processor = contracts.relay` and `data = feeCommitment.data`. A live
quote for 0.01 ETH to `0x...dEaD` decodes to exactly that routing, with the relayer's fee
recipient `0xfdece433...9a2a`. `PrivacyPoolRelay.relay` takes the same arguments as
`PoolVault.transact`; its selector `0xace97342` is in the contract's bytecode, so the
whole relay is simulated `from` the relayer before it is handed over.

The pool pays the processooor everything and leaves the split to it (see the last
section), so this client refuses a quote naming any processor but the PrivacyPoolRelay
it knows, and checks that the signed routing pays the recipient asked for, takes the fee
quoted, and asks for no native gas.

## Depositing an asset the Entrypoint refuses: the PPRouter

Plain USDC and USDT are disabled on production. They reach the vault as the yield
vaults' share tokens, through a **PPRouter** - one per asset. This is the whole of
Phase 2, and it is verified end to end.

**The call does not go to the Entrypoint.** `depositExactShares` (`0xc63148e8`) is not
among the Entrypoint implementation's eleven selectors; it is on the router.

| asset | PPRouter | PPYieldTokenZap | vault | underlying |
|---|---|---|---|---|
| USDC | `0xe76E793d776c1e207aD7a7fa7C57d27420d85110` | `0x9Ea986BcDF6784D85B518b15bEEE1E65b585817B` | ppUSDC | USDC (6) |
| USDT | `0x13a0b86bac3e0C29bd64fED7BCD2EE84f371f41C` | `0xDC3D922df81FC7B7f58229431ED91acB0482f3A5` | ppUSDT | USDT (6) |
| ETH | `0x77613D670BB9fD48A9898D0eac8ebf21B566F960` | `0x33c1eEf370bBb447414156CFc4fDABD434776EAf` | ppETH | WETH, `NATIVE_MODE()` true |

Each router's `VAULT()`, `UNDERLYING()`, `ZAP()`, `POOL()` (Aave v3
`0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2`), `A_TOKEN()`, `POOL_VAULT()` and
`ENTRYPOINT()` were called on chain and return exactly what is paired with them here;
the client re-checks `VAULT()` and `ENTRYPOINT()` before it will use one.

```solidity
depositExactShares((uint256[2],uint256[2][2],uint256[2],uint256[4]) proof,
                   (bytes32,bytes) noteData, bytes aspCiphertext,
                   uint256 maxUnderlyingIn) returns (uint256)        0xc63148e8
depositExactSharesNative(proof, noteData, aspCiphertext) payable returns (uint256)
                                                                     0x31c09bb4  (ETH router only)
withdrawToUnderlying((uint256[2],uint256[2][2],uint256[2],uint256[][]),
                     (address,bytes), (bytes32,bytes)[], uint256 minUnderlyingOut) payable
                                                                     0x23b370bb
quote(uint256 value) view returns (uint256 underlyingNeeded, uint256 total)   0xed1bd76c
quoteWithdraw(uint256 shares) view returns (uint256)                 0xec211840
ZAP() VAULT() POOL() A_TOKEN() UNDERLYING() POOL_VAULT() ENTRYPOINT() DUST_RECIPIENT() NATIVE_MODE()
```

The router quotes `total = value + vettingFee` (in **shares**), has the zap mint exactly
`total`, approves the Entrypoint and calls `Entrypoint.deposit(proof, noteData,
aspCiphertext)` with the three arguments untouched. That is what keeps the proof valid:
`context = keccak256(abi.encode(noteData))`, the router never touches `noteData`, so a
proof built against `tokenId = ppUSDC` and `value = shares` survives the indirection.

**The return value is the underlying actually spent, not the shares.** Simulating a whole
deposit against the live router returned `0x98e4a2` = 10,020,002 for a call whose quote
was 10,020,003 - underlying, to the unit, not the 1e19-scale share count.

### The slippage bound

`quote()` goes shares → underlying, which is the wrong direction for "I have 10 USDC".
The client uses the vault's ERC-4626 `previewDeposit(assets) → shares` to get there and
`quote()` to price it; the round trip is tight, `quote(previewDeposit(x)) = x + 2` across
the amounts checked.

The bound the SDK sets is **one part per million over the quote, minimum one unit**:

```
maxUnderlyingIn = underlyingNeeded + max(1, ceil(underlyingNeeded / 1e6))
```

Confirmed byte-exact against a real deposit: in
`0x49a5b063dbeb164a68ae6bea11b2640783b255e623c80168dc380aaf68732215`,
`quote(91710137931192912666)` one block before inclusion returned `91831035`, and
`91831035 + ceil(91831035/1e6) = 91831127` is the `maxUnderlyingIn` in the calldata.
It is small because the only thing moving between quote and mining is Aave's liquidity
index. `--max-fee-percent` widens it and the client prints the absolute bound in the
underlying's own units before doing anything.

### The routers' errors

Every selector below is a PUSH32 constant in the deployed bytecode. Two corrections to
what was assumed: **`PPRouter_SlippageExceeded` takes two arguments** - the zero-argument
spelling hashes to `0x7d1389bb`, which appears nowhere - and
**`PPRouter_SharesStranded()` is real** even though the app's own decoder does not list
it.

```
0x46314e2c  PPRouter_SlippageExceeded(uint256 underlyingIn, uint256 maxUnderlyingIn)
0xf58dc788  PPRouter_SharesStranded()
0x443b96b8  PPRouter_SharesNotReceived()      0x934a31a9  PPRouter_ZeroValue()
0x120637b6  PPRouter_BelowMinUnderlying(uint256,uint256)
0x09a64c28  PPRouter_FeeExceedsWithdrawal()   0x31bae423  PPRouter_FeeExceedsMax()
0x24b7e50c  PPRouter_NativeGasMismatch()      0x6d2aa205  PPRouter_ZeroRecipient()
0x5fa02c03  PPRouter_InvalidProcessor()       0x79aaee89  PPRouter_ZeroWithdrawal()
0x3d8c2936  PPRouter_AssetMismatch(address)
0x4344a77b  PPRouter_DirectEthTransfer()      0x093c7b6e  PPRouter_NotNativeMode()   (ETH router only)
0x11297127  ProofLib_TokenIdNotCanonical(uint256)
0x2c2f6301  PPYieldTokenZap_SlippageExceeded(uint256,uint256)
0xb95dfddb  PPYieldTokenZap_InsufficientWrap(uint256,uint256)
0x8abc2ca5  PPYieldTokenZap_ZeroAmount()
```

### The minimum is in shares, and the share price is above par

Worth its own line because it is the easy way to get an on-chain revert with a number in
the wrong unit. `ppUSDC.minAmount` is 1e19 - **10 ppUSDC**, not 10 USDC - and a share is
worth slightly more than a dollar, so `previewDeposit(10 USDC)` is about 9.984 ppUSDC and
falls under it. The client quotes the shares first and refuses in the underlying's units:

```
error: the minimum deposit is 10 ppUSDC, which costs about 10.020003 USDC --
       amounts for ppusdc are in USDC -- you asked for 10 USDC
```

The same holds for ppETH, where 0.004 ETH buys under the 0.004 ppETH minimum and the
real floor is about 0.0040009 ETH.

## Gaps: what is still unverified

Ordered by how much they would cost someone who trusted this client.

1. **Key derivation is implemented but never confirmed against a real account.** The
   constants, the ladder and the EIP-712 payload are the producer's own code
   ([Keys](#keys)), and the tests pin their shape, but nothing has checked that the keys
   this client derives are the keys the app would derive for the same wallet. If they
   are not, `register` writes a keystore leaf the app does not recognise and notes
   deposited against it are invisible there - recoverable by this client, since its note
   secrets come from the seed, but not by the app. **One small `register` transaction
   settles this**, and it should be the first thing anyone does.
2. **Nobody has watched the real ASP attest a blob this client produced.** The encoder
   round-trips against a key we hold and matches all the real blobs in length and shape,
   and the live Entrypoint accepts the whole transaction - but the chain never reads the
   opening, so only a funded deposit followed by the label appearing in the association
   set closes it. A deposit whose opening is wrong is accepted on chain and can then only
   be ragequit.
3. **No relayed withdrawal has been sent.** The routes and bodies are the SDK's own, and
   a committed quote from the production relayer passes every check this client makes,
   but `/v1/relay/.../withdrawal` has never been called with a real proof - that needs a
   funded, approved note. The open question is whether the relayer takes a change note's
   `noteData` with empty `data`, as this client sends it; the SDK's own `EMPTY_NOTE_DATA`
   is exactly that, which is encouraging.
4. **No `transact` has been executed or simulated with a real note.** The witness layout
   and the public-signal grouping are proven against the deployed verifiers
   (`transact_1x1/1x2/2x1`), and `transactParams.data` is confirmed against real
   calldata, but `withdraw` end to end needs a funded, ASP-approved note, which this
   client will not create. The `transact` context preimage is recovered from the bundle
   rather than re-derived from a successful on-chain call.
5. **Note decryption is implemented nowhere.** The format is recovered (RLP in the same
   sealed box; see [The Note ciphertext](#the-note-ciphertext-from-the-same-bundle)) but
   this client does not publish or read `Note` payloads: it finds its own notes from the
   seed instead. Consequences: a deposit made here is **not visible in the web app**, and
   a note *sent to you* by someone else is not visible here.
6. **The `--safe` path is built and simulated but never proposed.** `prepareSafeTx`
   simulates the batch as the Safe would run it and refuses one that reverts; a dry run
   against a Safe holding no USDC correctly refuses the batched approval + deposit. A
   funded Safe would settle the rest, and nothing here has ever been posted to the Safe
   Transaction Service.
7. **`depositExactSharesNative` has no observed mainnet calldata.** Its selector is on
   the ETH router and this client's call simulates green against it, but no third party
   has been seen using it, so the argument order rests on the shared `depositExactShares`
   layout rather than on a decoded example.
8. **The 182-vs-39 / 380-vs-52 leaf surplus** in the association set is unexplained.
9. **`RootSuperseded`'s third argument** - semantics not pinned down.
10. **The exact `aspRoot` acceptance rule.** The pool demonstrably reads
    `latestASPRoot()`, but whether it insists on equality or allows a window of older
    roots was not pinned down - proving it needs a spendable note.
11. Contracts are upgradeable proxies and closed-source; any of this can change.
12. Anonymity sets are small: production is a few dozen deposits spread over five assets.
13. No public audit report for V2 was located.

### What still rests on the retired staging deployment

With staging gone as a target, anything established only there needs saying out loud.
These are **not** re-confirmed against production:

- **`pool.verifiers(...)` for `transact_NxM`.** The router table was enumerated on
  staging; production's was not. The client resolves the verifier through the same
  on-chain `verifiers(keccak256(abi.encode(uint8 N, uint8 M)))` call at run time, so it
  will fail loudly rather than silently if production's differs.
- **The Note ciphertext length law** (66 of 66) was measured on staging's Note events.
- **"6 of 6 direct transacts used a published aspRoot"** was a staging observation.
- **Insertion order within one transact** (all commitments, then all nullifiers) was
  established on staging and re-checked against production's `LeavesInserted` logs when
  rebuilding the tree, which the pool confirms - so this one is effectively re-confirmed.
- The 39 `LabelRegistered` blobs behind the `330 + hexdigits(value)` length law are
  staging's. Production's blobs were not re-measured.

## Corrections to the earlier passes

### Fifth pass (2026-11-19)

- **The relayer body was another chain's.** See [The relayer](#the-relayer). The EVM
  path posts to `/v1/relay/evm/{chainId}/withdrawal`, and the SDK's schemas for it are
  in the bundle.
- **`/v1/quote` takes the recipient**, not `maxFeeAmount`, and signs a routing that
  names it: unlike V1's, a V2 relayer learns where a withdrawal goes.
- **`privacypools.com/artifacts` is gone.** The root is the V2 app now and answers 200
  with its HTML; V1's artifacts moved to `v1.privacypools.com/artifacts`, byte for byte.

### This pass (fourth)

- **"`Entrypoint.depositExactShares(...)`" was wrong about the contract.** The
  Entrypoint implementation has eleven selectors and that is not one of them. The call
  goes to a **PPRouter**, one per asset, and the ERC-20 approval goes to the router too -
  not the Entrypoint. Getting this backwards would approve the wrong spender and send
  the transaction to a contract with no such function.
- **`PPRouter_SlippageExceeded` is not zero-argument.** It carries
  `(uint256 underlyingIn, uint256 maxUnderlyingIn)`; the zero-argument spelling hashes to
  `0x7d1389bb`, which appears in neither router's bytecode. The right selector is
  `0x46314e2c`, and decoding it is what lets the client say how far over the cap the
  spend would have been.
- **`maxRelayFee` and `feeAmount` are absolute amounts, not basis points.** The third
  pass had already renamed the field; this pass established what the number *means*, by
  decoding a real transact's `transactParams.data`. V1's `--max-fee-percent` is a
  percentage, so the two need converting rather than passing through.
- **The EIP-712 derivation payload was recorded as unpublished.** It is
  `buildSecretDerivationPayload` in the same bundle that gave up everything else, and it
  is quoted verbatim in [Keys](#keys). The lesson of the third pass repeated itself: the
  gap was in where anyone had looked, not in what was available.
- **`depositExactShares` returns the underlying spent, not the shares.** Established by
  simulating a whole deposit against the live router.
- **ppUSDC's `asset()` is aEthUSDC, not USDC.** It is a real ERC-4626 vault, but over the
  Aave aToken, which is why the router carries both `A_TOKEN()` and `UNDERLYING()` and
  why the client cannot treat `previewDeposit` as taking USDC directly without saying so.
- **`--deployment` and staging are gone from the CLI.** Production is the only target.
  The staging fixtures stay in `test/v2-vectors.json` as historical regression data, and
  what still rests on them is listed under
  [Gaps](#what-still-rests-on-the-retired-staging-deployment).

### The big one: "no offline oracle, needs a funded deposit" was wrong

The second pass concluded that the ASP opening "cannot be finished by analysis"
because "without the ASP's private key a candidate ciphertext cannot be
checked". Both halves of that were mistaken, and for the same underlying reason:
**it only ever looked at the ciphertexts, never for the code that made them.**

- *The format was never secret.* The SDK is partner-gated as a package, but the
  app at `v2.privacypools.com` bundles its core into the JavaScript it serves to
  every visitor. `encodeASPCipherText`, `CryptoService`, the deposit service and
  the ASP's own parsing schema are all in `bootstrap-part-675e66a4….js`,
  minified and perfectly readable. "The SDK is gated" was treated as "the code
  is unavailable"; the second conclusion does not follow from the first.
- *The oracle was never missing.* A sealed box is encryption to a **published**
  public key. You do not need the ASP's private key to test an encoder — you
  need *a* keypair, and you can generate one. Encrypt to your own key, decrypt
  with your own private half, compare. That test was always available and the
  second pass never considered it, because it framed the problem as "decrypt
  theirs" rather than "reproduce the scheme".
- *The length law was already the answer, unread.* The pass measured
  `330 + hexdigits(value)` and computed that a four-field JSON object would be
  17 bytes shorter — then stopped at "an extra field, or different framing.
  Which one cannot be settled from outside". `,"metadata":"0x0"` is 17 bytes.
  The arithmetic had reached the answer and the conclusion overrode it.

The lesson generalises past this gap: two of the three remaining "unpublished
format" gaps (key derivation, Note encryption) fell out of the same bundle in
the same hour.

### Smaller ones

- The fourth field of `Entrypoint.assets()` was labelled `maximumDeposit`. The
  SDK's own ABI calls it **`maxRelayFee`**; the second field is `minAmount`.
- A deployment's `deployedBlock` must be the block its contracts got code, not
  the ASP's `fromBlock`. They differ by 9,057 blocks on production, and two
  keystore registrations fall in the gap.
- "A second, newer mainnet deployment already exists" was filed as a caveat. It
  is the **production** pool — the one the app actually deposits into — and it
  is now a first-class, verified deployment here, and the default.
- A provider that answers an `eth_getLogs` query with an empty set is not
  necessarily lying: an earlier bake-off blamed `rpc.mevblocker.io` for
  returning nothing, when the probe window had been computed one block range
  off. Recomputed, mevblocker answers archive log queries correctly and is what
  this pass used to rebuild the production trees. The known-answer probe is
  still the right instinct; the known answer has to be right too.
- Role labels were caveated as positional guesses; all four are **correct**, now
  proven two ways. The pool's real name is **PoolVault**.
- "300 returned; likely a page cap" — wrong on both counts. It is not a page cap,
  and it is not this pool's set: the request was missing the required
  `entrypoint` parameter, so the ASP answered for a different deployment.
- An intermediate conclusion in this pass — "no public source for this
  deployment's association set" — was **also wrong**, for the same reason. The
  set is public, complete and verifiable; see [ASP](#asp).
- The artifact manifest was untested; it is **good** for all six hashes checked.
- The ceremony API (`ceremony.privacypools.com/.../zkey`) is unnecessary — the
  IPFS manifest resolves fine through pinata.

## Reproducing

One package, one binary, two protocols. `v1` is assumed when the command is one V1 has,
so every invocation that worked before still works untouched.

```sh
pnpm install
pnpm typecheck && pnpm lint && pnpm test       # 68 tests

node src/cli.ts --help                         # both protocols
node src/cli.ts v2 --help

node src/cli.ts v2 setup                       # fetch + hash-check deposit, ragequit, transact_1x1
node src/cli.ts v2 status                      # roles, verifiers, roots, the ASP's key
node src/cli.ts v2 pools                       # assets, minimums, fees, and what you spend
node src/cli.ts v2 trees --rpc-url https://rpc.mevblocker.io   # needs an archive RPC

node src/cli.ts v2 init                        # a seed; --from-wallet derives the app's
node src/cli.ts v2 register --dry-run          # the Keystore leaf, simulated
```

Deposits, simulated against the live contracts and never sent:

```sh
export MONEYSURFER_MNEMONIC="$(cat words)"
ME=0xYourAddress
node src/cli.ts v2 deposit eth   0.004  --from $ME --dry-run --rpc-url https://rpc.mevblocker.io
node src/cli.ts v2 deposit ppeth 0.0041 --from $ME --dry-run --rpc-url https://rpc.mevblocker.io
node src/cli.ts v2 deposit usdc  10.02  --from $ME --dry-run --rpc-url https://rpc.mevblocker.io
```

`--dry-run` prints the approval and the transaction, then simulates. The ETH routes come
back `simulated: the chain accepts it`. The USDC route reports `transfer amount exceeds
allowance`, which is correct - the approval it printed has not been made yet. To simulate
the state *after* that approval, `eth_call` the printed transaction with the USDC
allowance and balance overridden (FiatTokenV2_2 keeps `balances` at slot 9 and `allowed`
at slot 10); the live router then returns the underlying it would have spent.

`--safe SAFE` builds the approval and the deposit as one batched SafeTx and, with
`--dry-run`, simulates it as the Safe would execute it and prints the `safeTxHash`
without proposing anything.

**Nothing in this client was ever signed, broadcast, or proposed to a Safe.** Every
result above is `eth_call`.

`trees`, `sync`, `balance` and `pools` need an archive `eth_getLogs`.
`ethereum-rpc.publicnode.com` (the default) is fine for `eth_call` but refuses archive
log queries without a token; `rpc.mevblocker.io` serves the whole range. Flashbots
returns empty log sets for these contracts - probe any new provider with a known-answer
query, and make sure the known answer is right too.

## The pool pays the processooor, not `routing.recipient` (2026-09-28, observed)

`transactParams.data` decodes as `(recipient, feeRecipient, feeAmount, nativeGas)` --
the four words a real transact carried, which is what test/v2-zap pins -- but the
PoolVault does not read `recipient` at all. It hands `amountOut` to `msg.sender`,
and it requires `msg.sender` to be the processooor the proof names.

Both halves were measured, not inferred:

- Withdrawing 0.004 ETH to a third party with `--self` paid the submitter.
  `debug_traceTransaction` on
  `0x7ef8c18d5dcf5148f0725e588aa96f4658959432cee33826f3205e5309690b60`:
  `0x0eb42804..97ed -> 0x205d2686..62cf value=0xe35fa931a0000`, while the calldata's
  routing named `0x7d3f0ca4..2aa9` in both address words. The recipient received nothing.
- `eth_call` of that same mined calldata at the block before it, `from` the
  processooor, succeeds; `from` `0x..dEaD` reverts. So the equality is enforced.

`routing` is therefore read by the distributor contract a relayer submits through.
`0x01a8fa4dbb60187ad8d3c3d08e7fb8c14198a461` is one: relayer
`0x9e2f1b234953f46c6091636290e9035618ea3c07` sends to *it*, it calls the pool, and
the `Transacted` event names it as processooor. That contract is what splits the
payout and takes the fee -- which is also why `feeAmount` is absolute rather than
basis points.

Consequence for this client: a spend can only land where it is submitted from, so
`withdraw --self` refuses a `<to>` that is not the submitter, and `--safe` a `<to>` that
is not the Safe. Paying anyone else is what the relayed withdrawal - the default since
the fifth pass - is for.
