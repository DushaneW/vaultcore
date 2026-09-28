//! Chain-agnostic cryptographic primitives for VaultCore.
//!
//! This crate provides two things, and deliberately nothing else:
//!
//! 1. **BIP-39 mnemonics** ([`Mnemonic`]): generating fresh mnemonic
//!    phrases, validating phrases a user typed in, and deriving the 64-byte
//!    seed from a mnemonic.
//! 2. **BIP-32 hierarchical deterministic derivation** ([`DerivationPath`],
//!    [`ExtendedPrivateKey`]): parsing derivation paths and walking them from a seed to
//!    produce extended private/public keys.
//!
//! It does not know about Bitcoin, Ethereum, addresses, transactions, or
//! signing schemes beyond raw secp256k1 key material -- those are the
//! concerns of chain-specific crates (`vaultcore-bitcoin`, `vaultcore-evm`)
//! that will depend on this one. Keeping this boundary sharp is intentional:
//! BIP-32/BIP-39 are shared by every chain this project will eventually
//! support, and a chain-specific assumption leaking in here would force
//! every downstream crate to route around it.
//!
//! # No cryptographic primitives are implemented in this crate
//!
//! Every operation here is delegated to an established dependency:
//! wordlist handling and PBKDF2-HMAC-SHA512 seed derivation to
//! [`bip39`](https://docs.rs/bip39), and HMAC-SHA512 child-key tweaking plus
//! secp256k1 point arithmetic to [`bip32`](https://docs.rs/bip32) (via
//! RustCrypto's `k256`). This crate's own code is limited to input
//! validation, error-type translation, and zeroization of the values it
//! returns -- see `docs/crypto-core.md` for the full rationale and the
//! specific test vectors each dependency is checked against.

mod derivation;
mod error;
mod keys;
mod mnemonic;

pub use derivation::{ChildNumber, DerivationPath};
pub use error::CryptoError;
pub use keys::{ExtendedPrivateKey, ExtendedPublicKey};
pub use mnemonic::{Mnemonic, WordCount};
