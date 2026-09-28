//! BIP-44 and BIP-84 derivation path construction.
//!
//! `vaultcore_crypto::DerivationPath` already parses arbitrary
//! `m/44'/0'/0'/0/0`-style strings correctly; this module's only job is
//! building the *string* for Bitcoin's specific account structure so
//! callers don't hand-format path literals themselves. It intentionally
//! does not build a `bip32::DerivationPath` some other way (e.g. appending
//! `ChildNumber`s one at a time) — a single `DerivationPath::parse` call on
//! a formatted string goes through the exact same, already-tested parser
//! every other path in this codebase does.
use vaultcore_crypto::{CryptoError, DerivationPath};

use crate::keys::AddressKind;
use bitcoin::Network;

/// SLIP-44 coin type: 0 for Bitcoin mainnet, 1 for every Bitcoin testnet
/// (regtest and signet included — they share coin type 1 by convention,
/// since none of them are the production chain).
fn coin_type(network: Network) -> u32 {
    match network {
        Network::Bitcoin => 0,
        _ => 1,
    }
}

/// The BIP-44/BIP-84 purpose field: `44` for legacy P2PKH, `84` for native
/// SegWit P2WPKH. (BIP-49's `49`, for P2SH-wrapped SegWit, is not
/// implemented — see `docs/bitcoin.md` for why.)
fn purpose(kind: AddressKind) -> u32 {
    match kind {
        AddressKind::P2pkh => 44,
        AddressKind::P2wpkh => 84,
    }
}

/// Builds the account-level path `m/purpose'/coin_type'/account'`.
///
/// This is the path an extended key is typically shared at (e.g. exporting
/// an `xpub`/`zpub` for a watch-only wallet) — everything below it
/// (`change`/`index`) is non-hardened, so an account-level public key can
/// derive every receive and change address for that account without ever
/// touching a private key.
pub fn account_path(
    kind: AddressKind,
    network: Network,
    account: u32,
) -> Result<DerivationPath, CryptoError> {
    DerivationPath::parse(&format!(
        "m/{}'/{}'/{}'",
        purpose(kind),
        coin_type(network),
        account
    ))
}

/// Builds the full address path `m/purpose'/coin_type'/account'/change/index`.
///
/// `change` is `false` for a receiving address, `true` for a change
/// address, matching BIP-44's `0`/`1` convention at that level.
pub fn address_path(
    kind: AddressKind,
    network: Network,
    account: u32,
    change: bool,
    index: u32,
) -> Result<DerivationPath, CryptoError> {
    DerivationPath::parse(&format!(
        "m/{}'/{}'/{}'/{}/{}",
        purpose(kind),
        coin_type(network),
        account,
        u32::from(change),
        index
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p2wpkh_mainnet_account_path() {
        let path = account_path(AddressKind::P2wpkh, Network::Bitcoin, 0).unwrap();
        assert_eq!(path.to_string(), "m/84'/0'/0'");
    }

    #[test]
    fn p2pkh_testnet_account_path() {
        let path = account_path(AddressKind::P2pkh, Network::Testnet, 2).unwrap();
        assert_eq!(path.to_string(), "m/44'/1'/2'");
    }

    #[test]
    fn address_path_receiving_and_change() {
        let receiving = address_path(AddressKind::P2wpkh, Network::Bitcoin, 0, false, 5).unwrap();
        assert_eq!(receiving.to_string(), "m/84'/0'/0'/0/5");

        let change = address_path(AddressKind::P2wpkh, Network::Bitcoin, 0, true, 5).unwrap();
        assert_eq!(change.to_string(), "m/84'/0'/0'/1/5");
    }

    #[test]
    fn regtest_and_signet_share_testnet_coin_type() {
        for network in [Network::Testnet, Network::Regtest, Network::Signet] {
            let path = account_path(AddressKind::P2pkh, network, 0).unwrap();
            assert_eq!(path.to_string(), "m/44'/1'/0'");
        }
    }
}
