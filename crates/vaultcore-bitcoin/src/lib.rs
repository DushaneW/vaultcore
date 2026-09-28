//! Offline Bitcoin wallet primitives: accounts, coin selection and transactions.
//!
//! Build with [`transaction::build_transaction`], review the recipients and fee,
//! then sign with [`transaction::sign_transaction`]. Previous-output values and
//! scripts must come from a trusted source. This crate does not broadcast or
//! validate chain state. See `docs/bitcoin.md` in the repository for the contract.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod account;
mod error;
mod fee;
mod keys;
mod paths;

pub use account::Account;
pub use error::BitcoinError;
pub use fee::{build_template_transaction, estimate_fee, PlannedInput};
pub use keys::{derive_address, to_bitcoin_private_key, to_compressed_public_key, AddressKind};
pub use paths::{account_path, address_path};

pub mod transaction;
mod utxo;
pub use utxo::{select_utxos, Utxo};
