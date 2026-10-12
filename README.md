<div align="center">

# VaultCore

**Offline Bitcoin Wallet Primitives, Key Derivation & Deterministic Transaction Signing in Rust**

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](#installation--platform-setup)
[![License: MIT](https://img.shields.io/badge/License-MIT-white.svg)](LICENSE)
[![BIP Standards](https://img.shields.io/badge/BIP-32_%7C_39_%7C_44_%7C_84_%7C_143-blue.svg)](#supported-standards--architecture)
[![Platform](https://img.shields.io/badge/platform-Linux_%7C_macOS_%7C_Windows-lightgrey.svg)](#installation--platform-setup)
[![Tests](https://img.shields.io/badge/tests-68_passing-success.svg)](#verification--test-vectors)

[Architecture](docs/bitcoin.md) · [Crypto Core](docs/crypto-core.md) · [Installation](#installation--platform-setup) · [Usage & API](#transaction-lifecycle--api) · [Security](SECURITY.md) · [Changelog](CHANGELOG.md)

</div>

---

**VaultCore** is a modular, air-gapped-ready Rust workspace providing core cryptographic and transaction primitives for Bitcoin wallets. Designed around strict trust boundaries and minimal dependencies, VaultCore implements **BIP-39** mnemonics, **BIP-32** hierarchical deterministic (HD) key derivation, **BIP-44 / BIP-84** account structures, and deterministic transaction construction and signing—delegating underlying elliptic-curve operations and consensus serialization to battle-tested Rust cryptography crates.

---

## Supported Standards & Architecture

VaultCore separates key management from protocol-specific transaction logic across dedicated workspace crates:

| Crate / Module | Standards & Responsibilities |
| :--- | :--- |
| **`vaultcore-crypto`** | **BIP-39** mnemonic generation, entropy validation, and seed derivation; **BIP-32** hierarchical private and public key derivation (`secp256k1`). |
| **`vaultcore-bitcoin`** | **BIP-44** (`P2PKH` legacy) and **BIP-84** (`P2WPKH` native SegWit `bech32`) account hierarchies, script generation, and address encoding. |
| **Transaction Builder** | Deterministic UTXO coin selection, exact weight-based fee calculation (including mixed witness inputs and `CompactSize` varints), change allocation, and dust threshold enforcement. |
| **Signing Engine** | Legacy sighash and **BIP-143** SegWit ECDSA signing (`SIGHASH_ALL`) with mandatory pre-sign script ownership verification. |
| **Consensus Parser** | Bounded consensus deserialization hardened against malformed payloads and resource-exhaustion vectors. |

```text
+-------------------------------------------------------------------------+
|                           vaultcore-crypto                              |
|   [ Entropy / BIP-39 Mnemonic ] ---> [ 512-bit Seed ] ---> [ BIP-32 ]   |
+------------------------------------+------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                           vaultcore-bitcoin                             |
|   [ BIP-44 / BIP-84 Accounts ]  ---> [ ScriptPubKey / Address Gen ]     |
|                                                                         |
|   [ Unspent Outputs (UTXOs) ]   ---> [ Deterministic Coin Selection ]   |
|                                               |                         |
|                                               v                         |
|   [ Signed Raw Transaction ]    <--- [ BIP-143 / Legacy ECDSA Signer ]  |
+-------------------------------------------------------------------------+
```

---

## Core Engineering Principles

- **Measured Weight & Fee Precision:** Transaction templates calculate fees using worst-case signature sizes and exact `rust-bitcoin` serialization weights, accurately accounting for witness discount boundaries and `CompactSize` varint shifts (e.g., at the 253-input boundary).
- **Explicit Dust & Change Handling:** Change outputs falling below the protocol dust threshold are automatically folded into the miner fee. The exact input-minus-output fee delta is exposed on `BuiltTransaction` for explicit caller approval prior to signing.
- **Strict Script Ownership Verification:** Before producing an ECDSA signature, the signing engine verifies that the derived public key matches the supplied previous-output script (`script_pubkey`).
- **Zero Secret Leakage in Diagnostics:** Private keys and seed material implement redacted `Debug` and `Display` traits. Error types are guaranteed never to carry secret payloads, and memory-zeroization boundaries are strictly enforced.
- **Immutable Fault Recovery:** Signing operations return a new transaction instance, leaving the unsigned transaction structure untouched if an error occurs mid-flight.

---

## Installation & Platform Setup

VaultCore requires **Rust 1.75+**, **Cargo**, and a native **C11 compiler** to compile the underlying `libsecp256k1` cryptography bindings.

### 1. Install Toolchain & Native C Compiler

#### Linux (Debian / Ubuntu / Fedora / Arch)
```sh
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh

# Debian / Ubuntu
sudo apt update && sudo apt install -y build-essential clang

# Fedora
sudo dnf install -y gcc clang make

# Arch Linux
sudo pacman -S --needed base-devel clang
```

#### macOS (Apple Silicon & Intel)
```sh
# Install Xcode Command Line Tools (includes clang) & Rust
xcode-select --install
curl --proto '=https' --tlsv1.2 -sSf [https://sh.rustup.rs](https://sh.rustup.rs) | sh
```

#### Windows (10 / 11)
1. Install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (select the **Desktop development with C++** workload).
2. Install Rust via `winget` or [rustup.rs](https://rustup.rs/):
   ```powershell
   winget install Rustlang.Rustup
   ```

### 2. Add to Your Cargo Project

To embed VaultCore in your own Rust application, add the workspace crates to your `Cargo.toml`:

```toml
[dependencies]
vaultcore-crypto = { git = "[https://github.com/DushaneW/vaultcore.git](https://github.com/DushaneW/vaultcore.git)" }
vaultcore-bitcoin = { git = "[https://github.com/DushaneW/vaultcore.git](https://github.com/DushaneW/vaultcore.git)" }
```

### 3. Build from Source & Run the Offline Example

Clone the repository and build with `--locked` for deterministic dependency resolution:

```sh
git clone [https://github.com/DushaneW/vaultcore.git](https://github.com/DushaneW/vaultcore.git)
cd vaultcore

# Build workspace in release mode
cargo build --workspace --release --locked

# Run the standalone offline regtest transaction example
cargo run --locked -p vaultcore-bitcoin --example offline_transaction
```

> The [`offline_transaction.rs`](crates/vaultcore-bitcoin/examples/offline_transaction.rs) example derives a deterministic account, constructs a transaction from a synthetic regtest UTXO, verifies the fee calculation, signs all inputs offline, and outputs the public transaction metadata.

---

## Transaction Lifecycle & API

VaultCore enforces a strict two-phase **Build $\rightarrow$ Inspect $\rightarrow$ Sign** workflow so applications can audit selected inputs, change outputs, and exact fees before exposing private keys:

```rust
use vaultcore_bitcoin::transaction::{build_transaction, sign_transaction};

// 1. Construct an unsigned transaction with deterministic coin selection
let change_script = account.address(true, change_index)?.script_pubkey();

let built = build_transaction(
    &utxos,
    &recipients,
    change_script,
    fee_rate,
)?;

// 2. Inspect built.selected_utxos, built.fee, and built.change_index
//    to enforce application-level policy and fee caps before signing.

// 3. Verify script ownership and sign all inputs offline (Legacy P2PKH / BIP-143 P2WPKH)
let signed_tx = sign_transaction(
    &built.transaction,
    &built.selected_utxos,
    &account,
)?;
```

---

## Verification & Test Vectors

VaultCore is validated by **68 unit, vector, and regression tests** across the workspace, covering:

- **Official Standard Vectors:** Full compliance with reference test vectors for **BIP-32**, **BIP-39**, **BIP-84**, and native SegWit **BIP-143** sighash digests.
- **Adversarial & Boundary Regression Suite:** Signature tampering detection, dust threshold boundary conditions, mismatched UTXO script metadata, malformed consensus payloads, and exact fee sizing across the 253-input `CompactSize` varint boundary.

Run the complete verification, formatting, and static-analysis suite locally:

```sh
# Execute all unit and vector tests
cargo test --workspace --release --locked

# Verify formatting and strict Clippy lints
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings

# Build API documentation
cargo doc --workspace --no-deps --locked
```

Continuous Integration ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs automatically across **Linux**, **macOS**, and **Windows** targets.

---

## Documentation & Resources

- [**Bitcoin Architecture & Transaction Design**](docs/bitcoin.md) — Account derivation paths, coin selection rules, fee calculation, and signing internals.
- [**Cryptographic Core**](docs/crypto-core.md) — Entropy handling, BIP-39 seed generation, BIP-32 key trees, and memory safety.
- [**Security Policy & Threat Model**](SECURITY.md) — Trust boundaries, secret redaction guarantees, and vulnerability disclosure guidelines.
- [**Contributing Guide**](CONTRIBUTING.md) · [**Changelog**](CHANGELOG.md)

---

## License

Maintained by [**DushaneW**](https://github.com/DushaneW). Licensed under the [**MIT License**](LICENSE).
