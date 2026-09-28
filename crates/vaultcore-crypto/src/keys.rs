//! BIP-32 extended private and public keys.
//!
//! Wraps `bip32::XPrv` / `bip32::XPub` (the `bip32` crate's secp256k1 type
//! aliases, backed by the pure-Rust `k256` implementation). This module does
//! not implement HMAC-SHA512 tweak derivation, elliptic-curve point
//! addition, or any other primitive itself — that is exactly the kind of
//! code this project deliberately delegates to an audited dependency.
//!
//! # Private key lifetime
//!
//! `k256::ecdsa::SigningKey` (the type `bip32::XPrv` derives keys as)
//! implements `ZeroizeOnDrop` upstream, so the secret scalar inside an
//! [`ExtendedPrivateKey`] is overwritten with zeros when the value is
//! dropped, regardless of this crate's own zeroize-feature limitation
//! documented in [`crate::mnemonic`]. The chain code and other
//! [`bip32::ExtendedKeyAttrs`] fields are plain `[u8; 32]`/`[u8; 4]` values
//! and are *not* zeroized on drop — a chain code alone cannot reconstruct a
//! private key, but it is not public information either (see
//! "Zeroization" in `docs/crypto-core.md`, and the BIP-32 spec's own
//! "Implications" section on why chain codes need care).
//!
//! [`ExtendedPrivateKey`] deliberately does not implement `Clone`. Every
//! derivation method takes `&self` and returns a new, independently owned
//! key, so a caller can derive as many children as needed from one master
//! key without ever needing to duplicate the parent's private key material
//! by hand.
use zeroize::Zeroizing;

use crate::derivation::{ChildNumber, DerivationPath};
use crate::error::CryptoError;

/// An extended private key: a private key plus the chain code and metadata
/// (depth, parent fingerprint, child number) needed to derive further keys
/// from it, per BIP-32.
pub struct ExtendedPrivateKey {
    inner: bip32::XPrv,
}

impl core::fmt::Debug for ExtendedPrivateKey {
    /// Redacts both the private scalar and the chain code. The chain code
    /// is not secret on its own, but combined with the corresponding public
    /// key (easy to obtain — see [`Self::public_key`]) and *any* one
    /// non-hardened child's private key, it reconstructs this entire key —
    /// see the "Implications" section of BIP-32. It is excluded here so
    /// that a stray `{:?}` in a log statement cannot become that leak.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExtendedPrivateKey")
            .field("depth", &self.depth())
            .field("parent_fingerprint", &self.parent_fingerprint())
            .field("child_number", &self.child_number())
            .field("private_key", &"<redacted>")
            .field("chain_code", &"<redacted>")
            .finish()
    }
}

impl ExtendedPrivateKey {
    /// Derives the master extended private key from a seed (typically the
    /// 64-byte output of [`crate::mnemonic::Mnemonic::to_seed`], though
    /// BIP-32 also accepts 16- or 32-byte seeds from non-BIP-39 sources).
    pub fn from_seed(seed: &[u8]) -> Result<Self, CryptoError> {
        if ![16, 32, 64].contains(&seed.len()) {
            return Err(CryptoError::InvalidSeedLength { got: seed.len() });
        }
        let inner = bip32::XPrv::new(seed)?;
        Ok(Self { inner })
    }

    /// Derives the master key from `seed` and then walks `path` from it in
    /// one call. Equivalent to [`Self::from_seed`] followed by
    /// [`Self::derive_path`], provided as a convenience for the common case.
    pub fn derive(seed: &[u8], path: &DerivationPath) -> Result<Self, CryptoError> {
        Self::from_seed(seed)?.derive_path(path)
    }

    /// Derives a single child key at the given [`ChildNumber`].
    ///
    /// Deriving a hardened child requires `self` to hold a private key,
    /// which it always does — hardened derivation is only exposed here, not
    /// on [`ExtendedPublicKey`], because BIP-32 makes it cryptographically
    /// impossible to derive a hardened child from a public key alone.
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, CryptoError> {
        let inner = self.inner.derive_child(child.as_bip32())?;
        Ok(Self { inner })
    }

    /// Walks every [`ChildNumber`] in `path`, in order, starting from this
    /// key. `path` may mix hardened and non-hardened indices freely.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, CryptoError> {
        let mut current = self.inner.clone();
        for child in path.as_bip32().iter() {
            current = current.derive_child(child)?;
        }
        Ok(Self { inner: current })
    }

    /// Returns the corresponding extended *public* key.
    pub fn public_key(&self) -> ExtendedPublicKey {
        ExtendedPublicKey {
            inner: self.inner.public_key(),
        }
    }

    /// Serializes the raw 32-byte private scalar.
    ///
    /// Wrapped in [`Zeroizing`]: the returned array is overwritten with
    /// zeros when the caller drops it.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.inner.to_bytes())
    }

    /// Depth in the derivation hierarchy (0 for the master key).
    pub fn depth(&self) -> u8 {
        self.inner.attrs().depth
    }

    /// The [`ChildNumber`] used to derive this key from its parent. For the
    /// master key this is the default (index 0, non-hardened) — it is not
    /// meaningful at depth 0 and should not be interpreted as a real
    /// derivation step.
    pub fn child_number(&self) -> ChildNumber {
        ChildNumber::from_bip32(self.inner.attrs().child_number)
    }

    /// The first 4 bytes of `RIPEMD160(SHA256(parent_public_key))`, used to
    /// identify (not authenticate) the parent key. Zero for the master key.
    pub fn parent_fingerprint(&self) -> [u8; 4] {
        self.inner.attrs().parent_fingerprint
    }

    /// The 32-byte chain code used as HMAC key material for child
    /// derivation.
    pub fn chain_code(&self) -> [u8; 32] {
        self.inner.attrs().chain_code
    }
}

/// An extended public key: a public key plus the chain code and metadata
/// needed to derive non-hardened child *public* keys from it, per BIP-32.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedPublicKey {
    inner: bip32::XPub,
}

impl ExtendedPublicKey {
    /// Derives a single non-hardened child public key.
    ///
    /// Returns [`CryptoError::InvalidChildNumber`] if `child` is hardened:
    /// hardened children cannot be derived from a public key alone, which is
    /// the entire point of using hardened indices at security boundaries.
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, CryptoError> {
        if child.is_hardened() {
            return Err(CryptoError::InvalidChildNumber {
                index: child.index(),
            });
        }
        let inner = self.inner.derive_child(child.as_bip32())?;
        Ok(Self { inner })
    }

    /// Serializes the raw 33-byte SEC1-compressed public key.
    pub fn to_bytes(&self) -> [u8; 33] {
        self.inner.to_bytes()
    }

    /// Computes this key's 4-byte fingerprint
    /// (`RIPEMD160(SHA256(public_key))[..4]`), used as the parent
    /// fingerprint of any key derived from it.
    pub fn fingerprint(&self) -> [u8; 4] {
        self.inner.fingerprint()
    }

    /// Depth in the derivation hierarchy (0 for a master public key).
    pub fn depth(&self) -> u8 {
        self.inner.attrs().depth
    }

    /// The 32-byte chain code used as HMAC key material for child
    /// derivation.
    pub fn chain_code(&self) -> [u8; 32] {
        self.inner.attrs().chain_code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed 64-byte seed used across unit tests. Not a real wallet seed —
    /// just 64 arbitrary bytes for exercising the derivation API.
    /// Cross-checked vectors against the official BIP-32 test suite live in
    /// `tests/bip32_vectors.rs`.
    const TEST_SEED: [u8; 64] = [0x42; 64];

    #[test]
    fn master_key_has_depth_zero() {
        let master = ExtendedPrivateKey::from_seed(&TEST_SEED).unwrap();
        assert_eq!(master.depth(), 0);
        assert_eq!(master.parent_fingerprint(), [0u8; 4]);
    }

    #[test]
    fn rejects_invalid_seed_length() {
        let bad_seed = [0u8; 17];
        assert!(matches!(
            ExtendedPrivateKey::from_seed(&bad_seed),
            Err(CryptoError::InvalidSeedLength { got: 17 })
        ));
    }

    #[test]
    fn accepts_all_three_valid_seed_lengths() {
        for len in [16, 32, 64] {
            let seed = vec![0x11u8; len];
            assert!(ExtendedPrivateKey::from_seed(&seed).is_ok());
        }
    }

    #[test]
    fn derive_path_matches_manual_child_derivation() {
        let master = ExtendedPrivateKey::from_seed(&TEST_SEED).unwrap();
        let via_path = master
            .derive_path(&DerivationPath::parse("m/44'/0'").unwrap())
            .unwrap();

        let via_manual = master
            .derive_child(ChildNumber::hardened(44).unwrap())
            .unwrap()
            .derive_child(ChildNumber::hardened(0).unwrap())
            .unwrap();

        assert_eq!(
            via_path.to_bytes().as_slice(),
            via_manual.to_bytes().as_slice()
        );
        assert_eq!(via_path.chain_code(), via_manual.chain_code());
        assert_eq!(via_path.depth(), 2);
    }

    #[test]
    fn public_key_derivation_matches_private_key_derivation() {
        let master = ExtendedPrivateKey::from_seed(&TEST_SEED).unwrap();
        let child_priv = master
            .derive_child(ChildNumber::normal(5).unwrap())
            .unwrap();

        let child_pub_via_parent_pub = master
            .public_key()
            .derive_child(ChildNumber::normal(5).unwrap())
            .unwrap();

        assert_eq!(
            child_priv.public_key().to_bytes(),
            child_pub_via_parent_pub.to_bytes()
        );
    }

    #[test]
    fn public_key_cannot_derive_hardened_child() {
        let master = ExtendedPrivateKey::from_seed(&TEST_SEED).unwrap();
        let result = master
            .public_key()
            .derive_child(ChildNumber::hardened(0).unwrap());
        assert!(matches!(
            result,
            Err(CryptoError::InvalidChildNumber { index: 0 })
        ));
    }

    #[test]
    fn different_seeds_produce_different_master_keys() {
        let a = ExtendedPrivateKey::from_seed(&[0x01; 64]).unwrap();
        let b = ExtendedPrivateKey::from_seed(&[0x02; 64]).unwrap();
        assert_ne!(a.to_bytes().as_slice(), b.to_bytes().as_slice());
    }

    #[test]
    fn debug_output_redacts_private_key_and_chain_code() {
        let master = ExtendedPrivateKey::from_seed(&TEST_SEED).unwrap();
        let debug_output = format!("{master:?}");
        assert!(debug_output.contains("<redacted>"));
        assert!(!debug_output.contains(&hex::encode(*master.to_bytes())));
        assert!(!debug_output.contains(&hex::encode(master.chain_code())));
    }

    #[test]
    fn fingerprint_becomes_next_parent_fingerprint() {
        let master = ExtendedPrivateKey::from_seed(&TEST_SEED).unwrap();
        let child = master
            .derive_child(ChildNumber::normal(0).unwrap())
            .unwrap();
        assert_eq!(
            child.parent_fingerprint(),
            master.public_key().fingerprint()
        );
    }
}
