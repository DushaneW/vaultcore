//! Conversions between `vaultcore-crypto`'s chain-agnostic key types and the
//! `bitcoin` crate's Bitcoin-specific ones, plus address derivation.
//!
//! This is deliberately the only place in the crate that reaches into
//! `vaultcore_crypto::{ExtendedPrivateKey, ExtendedPublicKey}` directly for
//! their raw bytes — everywhere else operates on `bitcoin::PrivateKey` /
//! `bitcoin::CompressedPublicKey` once the conversion has happened once,
//! at the boundary.
use bitcoin::{Address, CompressedPublicKey, KnownHrp, Network, NetworkKind, PrivateKey};
use vaultcore_crypto::{ExtendedPrivateKey, ExtendedPublicKey};

use crate::error::BitcoinError;

/// Which Bitcoin output script type an address (and the keys that spend it)
/// use. Determines both the BIP-44/49/84 derivation path purpose field
/// (handled in [`crate::account_path`]) and how a transaction input for it must be
/// signed (handled in [`crate::transaction::signer`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AddressKind {
    /// Legacy pay-to-pubkey-hash (BIP-44, `m/44'/...`). Spent with a
    /// `scriptSig` containing a DER signature and the public key.
    P2pkh,
    /// Native SegWit v0 pay-to-witness-pubkey-hash (BIP-84, `m/84'/...`).
    /// Spent with an empty `scriptSig` and the signature/pubkey in the
    /// witness stack instead.
    P2wpkh,
}

/// Converts a chain-agnostic public key into the compressed SEC1 form
/// `bitcoin::CompressedPublicKey` requires (used by P2WPKH, and by this
/// crate's P2PKH addresses too — see [`derive_address`]).
///
/// Every key `vaultcore-crypto` produces is already SEC1-compressed (see
/// `vaultcore_crypto::ExtendedPublicKey::to_bytes`), so this should never
/// fail in practice; it returns `Result` rather than panicking because the
/// conversion crosses a library boundary and nothing here can prove the
/// invariant holds without re-checking it.
pub fn to_compressed_public_key(
    pubkey: &ExtendedPublicKey,
) -> Result<CompressedPublicKey, BitcoinError> {
    CompressedPublicKey::from_slice(&pubkey.to_bytes()).map_err(|_| BitcoinError::InvalidPublicKey)
}

/// Converts a chain-agnostic private key into `bitcoin::PrivateKey`, tagged
/// for the given network (mainnet/testnet — this only affects WIF encoding,
/// never the key material itself).
pub fn to_bitcoin_private_key(
    privkey: &ExtendedPrivateKey,
    network: Network,
) -> Result<PrivateKey, BitcoinError> {
    let secret = bitcoin::secp256k1::SecretKey::from_slice(privkey.to_bytes().as_slice())
        .map_err(|_| BitcoinError::InvalidPrivateKey)?;
    Ok(PrivateKey::new(secret, network))
}

/// Derives the address for `pubkey` under the given [`AddressKind`] and
/// network.
///
/// Both address types VaultCore supports use a compressed public key —
/// P2WPKH by protocol rule (BIP-141/143 forbid uncompressed keys in
/// witness programs) and P2PKH by this crate's own choice, for consistency
/// with the compressed keys everywhere else. This crate never derives an
/// uncompressed-key P2PKH address.
pub fn derive_address(
    pubkey: &ExtendedPublicKey,
    kind: AddressKind,
    network: Network,
) -> Result<Address, BitcoinError> {
    let compressed = to_compressed_public_key(pubkey)?;
    match kind {
        AddressKind::P2pkh => Ok(Address::p2pkh(compressed, NetworkKind::from(network))),
        AddressKind::P2wpkh => Ok(Address::p2wpkh(&compressed, KnownHrp::from(network))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vaultcore_crypto::{DerivationPath, ExtendedPrivateKey};

    #[test]
    fn same_key_gives_different_addresses_per_kind() {
        let master = ExtendedPrivateKey::from_seed(&[0x77; 64]).unwrap();
        let pubkey = master.public_key();

        let p2pkh = derive_address(&pubkey, AddressKind::P2pkh, Network::Bitcoin).unwrap();
        let p2wpkh = derive_address(&pubkey, AddressKind::P2wpkh, Network::Bitcoin).unwrap();

        assert_ne!(p2pkh.to_string(), p2wpkh.to_string());
        assert!(p2pkh.to_string().starts_with('1'));
        assert!(p2wpkh.to_string().starts_with("bc1"));
    }

    #[test]
    fn testnet_addresses_have_testnet_prefixes() {
        let master = ExtendedPrivateKey::from_seed(&[0x88; 64]).unwrap();
        let pubkey = master.public_key();

        let p2pkh = derive_address(&pubkey, AddressKind::P2pkh, Network::Testnet).unwrap();
        let p2wpkh = derive_address(&pubkey, AddressKind::P2wpkh, Network::Testnet).unwrap();

        assert!(p2pkh.to_string().starts_with('m') || p2pkh.to_string().starts_with('n'));
        assert!(p2wpkh.to_string().starts_with("tb1"));
    }

    #[test]
    fn private_key_round_trips_through_wif() {
        let master = ExtendedPrivateKey::from_seed(&[0x99; 64]).unwrap();
        let child = master
            .derive_path(&DerivationPath::parse("m/84'/0'/0'/0/0").unwrap())
            .unwrap();

        let bitcoin_key = to_bitcoin_private_key(&child, Network::Bitcoin).unwrap();
        let wif = bitcoin_key.to_wif();
        let parsed_back = PrivateKey::from_wif(&wif).unwrap();

        assert_eq!(
            bitcoin_key.inner.secret_bytes(),
            parsed_back.inner.secret_bytes()
        );
    }
}
