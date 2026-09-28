# VaultCore

**Offline Bitcoin wallet primitives in Rust.**

BIP-39 mnemonics, BIP-32 key derivation, BIP-44/BIP-84 accounts, and explicit
transaction construction and signing. Small crates with clear trust boundaries;
cryptographic operations and consensus serialization are delegated to established
Rust libraries.

[Architecture](docs/bitcoin.md) · [Crypto core](docs/crypto-core.md) ·
[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

## What works today

| Component | Scope |
| --- | --- |
| `vaultcore-crypto` | BIP-39 mnemonic generation/validation, seeds, BIP-32 private/public derivation |
| `vaultcore-bitcoin` | BIP-44/P2PKH and BIP-84/native P2WPKH accounts and addresses |
| Transactions | Deterministic coin selection, measured fee estimation, change and dust handling |
| Signing | Legacy and BIP-143 ECDSA with SIGHASH_ALL and script ownership checks |
| Parsing | Bounded consensus decoding with malformed-input regression tests |

The project is pre-1.0 and has not received an independent security audit.
It is an offline library, not a complete wallet: there is no chain sync,
broadcasting, custody service, UI or RPC backend. Supported transaction inputs
are compressed-key P2PKH and native P2WPKH.

## Quick start

Requires Rust **1.75+**, Cargo and a native C compiler for the secp256k1 dependency.
The lockfile is committed; keep `--locked` for reproducible dependency resolution.

From a checkout or the extracted source directory:

```sh
cargo build --workspace --locked
cargo test --workspace --release --locked
cargo run --locked -p vaultcore-bitcoin --example offline_transaction
```

The [example](crates/vaultcore-bitcoin/examples/offline_transaction.rs) creates and
signs a deterministic **regtest fixture** using an invented UTXO. It prints only
public transaction metadata and never broadcasts. Its seed is public test data.

## Transaction flow

```rust,ignore
use vaultcore_bitcoin::transaction::{build_transaction, sign_transaction};

// account, utxos, recipients and fee_rate are supplied by the application.
let built = build_transaction(
    &utxos,
    &recipients,
    account.address(true, change_index)?.script_pubkey(),
    fee_rate,
)?;

// Authenticate prevouts and approve recipients + built.fee before signing.
let signed = sign_transaction(&built.transaction, &built.selected_utxos, &account)?;
```

This snippet shows the API boundary; the linked example is fully runnable.
`BuiltTransaction` exposes selected inputs, the actual input-minus-output fee,
and the optional change index for inspection before signing. Account signing
returns a new transaction and leaves the original untouched on failure.

## Design decisions

- **Measured fees.** Templates use worst-case signature sizes and rust-bitcoin's
  actual serialization weight, including mixed witness inputs and CompactSize.
- **Explicit change.** A remainder below the default dust threshold becomes
  fee; the actual fee is returned for application review.
- **Check ownership before signing.** The derived public key must match the
  supplied previous-output script. Creating a locally valid signature alone
  is not enough.
- **Keep secrets out of diagnostics.** Private-key debug output is redacted;
  errors do not include secret material. Memory-erasure limits are documented.
- **Boundaries stay visible.** Decoding does not prove consensus validity;
  signing does not authenticate chain state or enforce an application's fee cap.

## Verification

There are **68 tests** across the workspace, including official BIP-32, BIP-39,
BIP-84 and native P2WPKH BIP-143 vectors. Transaction regression coverage includes
signature tampering, dust boundaries, invalid UTXO metadata, malformed encodings
and fee sizing at the 253-input CompactSize boundary.

[CI](.github/workflows/ci.yml) is configured for Linux, Windows and macOS,
formatting, Clippy with warnings denied, documentation and Rust 1.75 compatibility.
Local checks are recorded in [GitHub preparation review](docs/github-readiness.md).
A workflow configuration is not a claim that hosted CI has already passed.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

## Scope and next steps

The completed scope is the cryptographic core and offline Bitcoin transaction
pipeline. Future candidates include fuzzing the parser, node-backed regtest
integration, PSBT and wallet-state persistence. These are not implemented or
promised release dates. See the [phase review](PHASE_2_REVIEW.md) for current
constraints and [security policy](SECURITY.md) before integration.

Maintained by [DushaneW](https://github.com/DushaneW). Licensed under [MIT](LICENSE).
