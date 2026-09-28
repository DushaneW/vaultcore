//! A BIP-44/BIP-84 account: the key at `m/purpose'/coin_type'/account'`,
//! plus receiving/change address derivation below it.
use bitcoin::{Address, Network};
use vaultcore_crypto::{ChildNumber, CryptoError, ExtendedPrivateKey};

use crate::error::BitcoinError;
use crate::keys::{derive_address, to_bitcoin_private_key, AddressKind};
use crate::paths;

/// One BIP-44 (P2PKH) or BIP-84 (P2WPKH) account, derived once from a
/// wallet's master key and then used to derive as many receiving and
/// change addresses as needed.
///
/// Holds the account-level *private* key (`m/purpose'/coin_type'/account'`)
/// rather than the wallet's master key, so that a compromised `Account`
/// value exposes only that one account's derivation subtree — not every
/// account, and not the mnemonic.
pub struct Account {
    kind: AddressKind,
    network: Network,
    account_number: u32,
    account_key: ExtendedPrivateKey,
}

impl Account {
    /// Derives account number `account` of the given `kind` from a wallet's
    /// master key.
    pub fn derive(
        master: &ExtendedPrivateKey,
        kind: AddressKind,
        network: Network,
        account: u32,
    ) -> Result<Self, BitcoinError> {
        let path = paths::account_path(kind, network, account)?;
        let account_key = master.derive_path(&path)?;
        Ok(Self {
            kind,
            network,
            account_number: account,
            account_key,
        })
    }

    /// This account's [`AddressKind`] (fixed at derivation time — an
    /// account is either P2PKH or P2WPKH for its whole lifetime, matching
    /// how real wallets treat the BIP-44/84 purpose field as immutable).
    pub fn kind(&self) -> AddressKind {
        self.kind
    }

    /// Derives the private key for one address in this account.
    /// `change = false` is the receiving chain, `change = true` is the
    /// change chain, and `index` is the address index within that chain.
    pub fn address_private_key(
        &self,
        change: bool,
        index: u32,
    ) -> Result<ExtendedPrivateKey, CryptoError> {
        let change_step = ChildNumber::normal(u32::from(change))?;
        let index_step = ChildNumber::normal(index)?;
        self.account_key
            .derive_child(change_step)?
            .derive_child(index_step)
    }

    /// Derives the address for one address slot in this account. Equivalent
    /// to deriving the private key with [`Self::address_private_key`] and
    /// computing its address, but does not require a caller who only wants
    /// the address (e.g. for display) to touch a private key at all.
    pub fn address(&self, change: bool, index: u32) -> Result<Address, BitcoinError> {
        let key = self.address_private_key(change, index)?;
        derive_address(&key.public_key(), self.kind, self.network)
    }

    /// Returns the full `m/purpose'/coin_type'/account'/change/index`
    /// derivation path for one address slot, in the human-readable form a
    /// PSBT's `BIP32_DERIVATION` field or a hardware wallet's confirmation
    /// screen would display it in. Does not touch a private key.
    pub fn derivation_path(
        &self,
        change: bool,
        index: u32,
    ) -> Result<vaultcore_crypto::DerivationPath, CryptoError> {
        paths::address_path(self.kind, self.network, self.account_number, change, index)
    }

    /// Returns the `bitcoin::PrivateKey` for one address slot, ready to
    /// hand to the transaction signer. A thin convenience over
    /// [`Self::address_private_key`] plus the `vaultcore-crypto` ->
    /// `bitcoin` key type conversion.
    pub fn signing_key(
        &self,
        change: bool,
        index: u32,
    ) -> Result<bitcoin::PrivateKey, BitcoinError> {
        let key = self.address_private_key(change, index)?;
        to_bitcoin_private_key(&key, self.network)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiving_and_change_addresses_differ() {
        let master = ExtendedPrivateKey::from_seed(&[0x11; 64]).unwrap();
        let account = Account::derive(&master, AddressKind::P2wpkh, Network::Bitcoin, 0).unwrap();

        let receiving = account.address(false, 0).unwrap();
        let change = account.address(true, 0).unwrap();
        assert_ne!(receiving.to_string(), change.to_string());
    }

    #[test]
    fn sequential_indices_give_distinct_addresses() {
        let master = ExtendedPrivateKey::from_seed(&[0x22; 64]).unwrap();
        let account = Account::derive(&master, AddressKind::P2wpkh, Network::Bitcoin, 0).unwrap();

        let addr_0 = account.address(false, 0).unwrap();
        let addr_1 = account.address(false, 1).unwrap();
        assert_ne!(addr_0.to_string(), addr_1.to_string());
    }

    #[test]
    fn different_accounts_give_different_addresses() {
        let master = ExtendedPrivateKey::from_seed(&[0x33; 64]).unwrap();
        let account_0 = Account::derive(&master, AddressKind::P2wpkh, Network::Bitcoin, 0).unwrap();
        let account_1 = Account::derive(&master, AddressKind::P2wpkh, Network::Bitcoin, 1).unwrap();

        assert_ne!(
            account_0.address(false, 0).unwrap().to_string(),
            account_1.address(false, 0).unwrap().to_string()
        );
    }

    #[test]
    fn signing_key_matches_address() {
        let master = ExtendedPrivateKey::from_seed(&[0x44; 64]).unwrap();
        let account = Account::derive(&master, AddressKind::P2wpkh, Network::Bitcoin, 0).unwrap();

        // The bitcoin::PrivateKey handed to a signer and the address handed
        // to the person receiving funds must agree on the same public key.
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let signing_key = account.signing_key(false, 3).unwrap();
        let pubkey_from_signing_key = signing_key.public_key(&secp).to_bytes();

        let pubkey_from_address_path = account
            .address_private_key(false, 3)
            .unwrap()
            .public_key()
            .to_bytes();

        assert_eq!(pubkey_from_signing_key, pubkey_from_address_path);
    }

    #[test]
    fn derivation_path_matches_key_actually_derived() {
        // The path string this crate reports for an address must derive the
        // *same* key as the direct ChildNumber steps address_private_key
        // actually takes -- these are two independent code paths (one
        // string-formats and re-parses, the other steps ChildNumbers
        // directly) and nothing else guarantees they agree.
        let master = ExtendedPrivateKey::from_seed(&[0x66; 64]).unwrap();
        let account = Account::derive(&master, AddressKind::P2wpkh, Network::Testnet, 7).unwrap();

        let path = account.derivation_path(true, 42).unwrap();
        assert_eq!(path.to_string(), "m/84'/1'/7'/1/42");

        let via_path = master.derive_path(&path).unwrap();
        let via_account = account.address_private_key(true, 42).unwrap();
        assert_eq!(
            via_path.to_bytes().as_slice(),
            via_account.to_bytes().as_slice()
        );
    }

    #[test]
    fn rejects_index_at_hardened_boundary() {
        let master = ExtendedPrivateKey::from_seed(&[0x55; 64]).unwrap();
        let account = Account::derive(&master, AddressKind::P2wpkh, Network::Bitcoin, 0).unwrap();
        assert!(account
            .address_private_key(false, ChildNumber::HARDENED_FLAG)
            .is_err());
    }
}
