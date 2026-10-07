<div align="center">

<img src=".github/assets/logo.png" alt="Dark" width="112" />

# Dark SDK

**Confidential balances, zero-knowledge proofs and verifiable selective disclosure for Robinhood Chain.**

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-f5a0c4?style=flat-square)](#license)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?style=flat-square&logo=typescript&logoColor=white)](tsconfig.json)
[![ESM only](https://img.shields.io/badge/module-ESM-informational?style=flat-square)](package.json)
[![Node](https://img.shields.io/badge/node-%E2%89%A522-339933?style=flat-square&logo=node.js&logoColor=white)](.github/workflows/ci.yml)
[![CI](https://img.shields.io/github/actions/workflow/status/DarkWalletRH/dark-sdk/ci.yml?branch=main&style=flat-square&label=CI)](.github/workflows/ci.yml)
[![Status: pre-audit](https://img.shields.io/badge/status-pre--audit-orange?style=flat-square)](#status)

[Website](https://darkwallet.cash) · [Whitepaper](https://darkwallet.cash/whitepaper) · [Docs](https://darkwallet.cash/docs) · [Contracts](https://github.com/DarkWalletRH/dark-contracts) · [Exit tool](https://github.com/DarkWalletRH/dark-exit) · [Starter template](https://github.com/DarkWalletRH/Darkwallet)

</div>

---

## Overview

`@darkwalletrh/dark-sdk` is the TypeScript client library behind the Dark wallet. It implements the
cryptography and the client-side protocol logic for **encrypted USDG balances** on Robinhood Chain:

- **Key derivation.** It derives an account's privacy keys deterministically from its secp256k1 key.
- **Twisted ElGamal encryption** over the Grumpkin curve, with bounded discrete-log decryption.
- **Zero-knowledge proofs.** It builds witnesses and public inputs for the Noir circuits
  (register, transfer, withdraw, range disclosure), and proves in the browser or on Node.
- **A live client** that reads and writes the vault through [viem]. It walks every action through
  explicit states, re-derives public inputs before trusting a proof, and simulates before sending.
- **Selective disclosure.** It creates, seals and verifies signed statements about a private
  balance, which anyone can check independently against the chain.

> [!NOTE]
> Dark encrypts balances and the amounts of transfers between Dark accounts. Deposits and
> withdrawals are public token transfers, and addresses are always visible. Dark is not a mixer and
> provides no anonymity set.

## Installation

The package is consumed from source. Installing from the repository builds `dist/` automatically.
Pin a release tag:

```bash
npm install github:DarkWalletRH/dark-sdk#v0.4.3 viem
```

### Peer dependencies

Optional peer dependencies, needed only for the features that use them:

| Peer | Needed for |
|---|---|
| `viem` ^2 | `LiveDarkClient` (on-chain reads and writes) and the `/disclosure` entry point (hashing, ABI encoding, EIP-712) |
| `@aztec/bb.js`, `@noir-lang/noir_js` | `WebDarkProver` (in-browser proving) |
| `react` ≥ 18 | the `useDark` hook from `@darkwalletrh/dark-sdk/react` |

The only runtime dependencies are [`@noble/curves`, `@noble/hashes` and `@noble/ciphers`][noble],
all audited and MIT-licensed. The dependency tree contains no GPL code.

## Quick start

### Verify a disclosure link

A disclosure link carries its decryption key in the URL fragment. Verification runs entirely on the
caller's side and does not trust the server that stored the blob.

```ts
import {
  parseDisclosureLink,
  openDisclosure,
  verifyDisclosure,
} from "@darkwalletrh/dark-sdk/disclosure";

const { id, key } = parseDisclosureLink(url);
const doc = openDisclosure(blob, key, id); // blob: the encrypted document, fetched by id
if (!doc) throw new Error("Link does not decrypt");

const { verdict, reason } = await verifyDisclosure({
  doc,
  onChain,     // the account's (c, d) ciphertext, read from the vault at the document's block
  registryKey, // registry.keyOf(account), read from the pinned key registry
});
// verdict: "verified" | "public_balance" | "invalid" | "expired" | "unsupported_version"
```

`verifyDisclosure` never throws on attacker-controlled input. Every malformed document resolves to
an explicit `invalid` verdict. Range disclosures carry an UltraHonk proof, which the SDK does not
verify itself: pass a `verifyRangeProof(proof, publicInputs)` callback built on bb.js. Without one, a
range disclosure resolves to `invalid`.

### Read and move a private balance

```ts
import { LiveDarkClient } from "@darkwalletrh/dark-sdk";

const client = await LiveDarkClient.create({
  chainId: 4663,  // Robinhood Chain mainnet (since 0.4.0); 46630 for testnet
  account,        // 0x… address
  privateKey,     // the account's secp256k1 key; privacy keys are derived from it
  prover,         // a DarkProver, see "Proving" below
});

await client.sync();
const balances = await client.getBalances();

await client.transfer(recipient, 25_000000n); // 25 USDG (6 decimals), amount encrypted on-chain
```

`LiveDarkClient.create` checks that `privateKey` derives `account` and throws `NOT_DEPLOYED` for a
chain without a Dark deployment.

## Modules

| Module | Exports |
|---|---|
| `grumpkin` | Curve parameters, generators `G` and `H`, point arithmetic, encoding with full point validation |
| `keys` | `deriveDarkKeys(sk, chainId)`, `checkRegistryKey` |
| `elgamal` | `encrypt`, `decryptAmount`, bounded `discreteLog`, ciphertext arithmetic, hedged randomness |
| `hint` | Authenticated encrypted balance and transfer hints (XChaCha20-Poly1305) |
| `publicInputs` | Circuit public-input order and `buildPublicInputs` / `assertPublicInputsEqual` |
| `witness` | Witness builders for register, transfer, withdraw and range disclosure |
| `prover` | `DarkProver` interface, `NodeDarkProver`, `FixtureDarkProver` |
| `prover/web` | `WebDarkProver` (bb.js + noir_js, lazily imported) |
| `deployments` | Contract addresses per chain, `isDeployed`, vault and registry ABIs |
| `client` | `LiveDarkClient` (viem) and the fixture `DarkClient` |
| `errors` | `DarkError` with a typed `DarkErrorCode`, `isDarkError` |
| `@darkwalletrh/dark-sdk/disclosure` | DLEQ proofs, RFC 8785 canonical JSON, EIP-712 typed data, `sealDisclosure`, `openDisclosure`, `verifyDisclosure` |
| `@darkwalletrh/dark-sdk/react` | `useDark(options)`, in fixture or live mode |

The disclosure module is a separate entry point, so a verifier-only bundle (such as a disclosure
viewer) never pulls in the prover or the client.

## Proving

| Prover | Environment | Notes |
|---|---|---|
| `WebDarkProver` | Browser / WebView | Runs bb.js in WebAssembly. Requires the compiled circuits and a pinned SRS. Multithreaded when the page is cross-origin isolated. |
| `NodeDarkProver` | Node.js | Shells out to `nargo` and `bb`. Locates the Noir workspace from `DARK_CIRCUITS_DIR` or the nearest `circuits/` directory. `DARK_NARGO` and `DARK_BB` override the binaries. |
| `FixtureDarkProver` | Tests | Deterministic, no toolchain required. |

Compiled circuits are not part of this repository; the Noir sources, their pinned toolchain and the
generated verifiers live in [dark-contracts]. Every proof result is checked against the SDK's own
`buildPublicInputs` before it is used.

## Networks

| Network | Chain ID | Status |
|---|---|---|
| Robinhood Chain mainnet | `4663` | Deployed, since SDK 0.4.0 ([explorer](https://robinhoodchain.blockscout.com)) |
| Robinhood Chain testnet | `46630` | Deployed ([explorer](https://explorer.testnet.chain.robinhood.com)) |

Contract addresses live in [`src/deployments.ts`](src/deployments.ts), the single source of
addresses for every Dark client. `isDeployed(chainId)` gates every live flow.

## Versions

| Version | Changes |
|---|---|
| **0.4.3** (latest) | Robustness and hardening: one incoming transfer that will not open no longer blocks the balance, history or dark-exit (the pending total is recovered by bounded search and that transfer shows no amount); the solved witness lives only in an owner-only temp directory while proving; AEAD nonces are hedged so a broken random generator cannot repeat one; `balancePublic` also accounts for pending; a stale proof revert is classified as stale state. No API changes. |
| 0.4.2 | Security: `transfer()` cross-checks the recipient key against a second RPC source before encrypting to it (new error `RPC_DISAGREEMENT`; options `keyCheckRpcUrl` / `keyCheckClient`). `newDisclosureId` never produces a mainnet id that looks like a testnet one. |
| 0.4.1 | Documentation and test hygiene. Tests that cross-check the Noir workspace skip when it is absent, so the suite runs standalone. No API or protocol changes. |
| 0.4.0 | Adds the Robinhood Chain mainnet deployment (chain `4663`) to `deployments`. No API changes. |
| 0.3.2 | First release in this repository. Testnet deployment only; on 0.3.2, `isDeployed(4663)` is `false`. |

Each version is tagged `vX.Y.Z` in this repository.

## Development

```bash
git clone https://github.com/DarkWalletRH/dark-sdk.git
cd dark-sdk
npm ci            # also builds dist/
npm test          # node:test via tsx
npm run build     # tsc → dist/
```

CI runs the same three commands on Node.js 22 for every push to `main` and every pull request.

The test suite includes **cross-implementation vectors** in `test/vectors/`, covering key
derivation, disclosure documents and range disclosures. Every field reproduces from the secret key
alone. A change that alters a vector changes the protocol. Tests that need `nargo` and `bb`, or the
Noir workspace from [dark-contracts], skip automatically when those are not available. In 0.3.2 and
0.4.0, the eight Noir-workspace cross-checks fail instead of skipping in a standalone checkout; every
other test passes. From 0.4.1 they skip.

## Specification references

Comments of the form `§n` cite sections of the DARK-CB-1 protocol specification, which is published
with the audit report; the code is complete without it.

## Status

The SDK and the contracts it targets are **pre-audit**. Do not rely on them to secure funds you
cannot afford to lose. Dark enforces deposit, transfer and total-value caps on-chain during the
beta.

## Security

Please report vulnerabilities privately to **team@darkwallet.cash**. Do not open a public issue.
Include the SDK version, the affected function and, where possible, a reproduction.
See [darkwallet.cash/.well-known/security.txt](https://darkwallet.cash/.well-known/security.txt).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this work shall be dual-licensed as above, without any additional terms or conditions.

[viem]: https://viem.sh
[dark-contracts]: https://github.com/DarkWalletRH/dark-contracts
[noble]: https://paulmillr.com/noble/
