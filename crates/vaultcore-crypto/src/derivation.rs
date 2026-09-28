//! BIP-32 derivation paths and child indices.
//!
//! This module wraps `bip32::DerivationPath` and `bip32::ChildNumber` rather
//! than reimplementing path parsing: the upstream types already parse
//! `m/44'/60'/0'/0/0`-style notation correctly (including the `'`/`h`
//! hardened suffixes) and are exercised by that crate's own test suite. The
//! wrapper exists for two concrete reasons, not as a reimplementation:
//!
//! 1. **Error-type consistency.** Every fallible operation in this crate
//!    returns [`CryptoError`]. Without a wrapper, parsing a path would
//!    return `bip32::Error` at the public API boundary, which is a leak of
//!    an internal dependency's error type and inconsistent with
//!    [`crate::mnemonic`] and [`crate::keys`].
//! 2. **A stable extension point.** Chain-specific crates (`vaultcore-bitcoin`,
//!    `vaultcore-evm`, in later phases) will want constructors such as
//!    `DerivationPath::bip44(coin_type, account, change, index)`. Adding
//!    those to this newtype does not require touching the upstream crate or
//!    duplicating its parsing logic.
use core::fmt;
use core::str::FromStr;

use crate::error::CryptoError;

/// A parsed BIP-32 derivation path, e.g. `m/44'/60'/0'/0/0`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DerivationPath {
    inner: bip32::DerivationPath,
}

impl DerivationPath {
    /// Parses a derivation path string.
    ///
    /// Accepts the standard `m/44'/60'/0'/0/0` notation. Both `'` and `h`
    /// are accepted as the hardened-index marker (both appear in the wild;
    /// BIP-32 itself does not mandate one over the other). The bare string
    /// `"m"` is a valid, empty path denoting the master key.
    pub fn parse(path: &str) -> Result<Self, CryptoError> {
        bip32::DerivationPath::from_str(path)
            .map(|inner| Self { inner })
            .map_err(|_| CryptoError::InvalidDerivationPath {
                path: path.to_string(),
            })
    }

    /// Returns `true` if this is the root path (`m`, with no child indices).
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of derivation steps (the depth this path would
    /// produce when applied to a master key).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Iterates over the [`ChildNumber`] values in this path, in order from
    /// the master key outward.
    pub fn iter(&self) -> impl Iterator<Item = ChildNumber> + '_ {
        self.inner.iter().map(ChildNumber)
    }

    pub(crate) fn as_bip32(&self) -> &bip32::DerivationPath {
        &self.inner
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl FromStr for DerivationPath {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// A single index in a derivation path, tagged as hardened or normal.
///
/// Hardened indices (conventionally written with a trailing `'`, e.g.
/// `44'`) occupy the upper half of the `u32` index space (`2^31` and
/// above) and can only be derived from a private key — this is what makes
/// them useful as a security boundary in paths like BIP-44, where the
/// purpose/coin/account levels are hardened so that leaking a non-hardened
/// extended *public* key at the account level cannot be used to derive
/// sibling accounts' private keys.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ChildNumber(bip32::ChildNumber);

impl ChildNumber {
    /// Indices `>= this` value are reserved for hardened derivation and
    /// cannot be used as a plain index.
    pub const HARDENED_FLAG: u32 = bip32::ChildNumber::HARDENED_FLAG;

    /// Constructs a hardened child index (e.g. the `44'` in `m/44'`).
    ///
    /// `index` must be less than [`Self::HARDENED_FLAG`] (`2^31`); the flag
    /// bit is set internally, not supplied by the caller.
    pub fn hardened(index: u32) -> Result<Self, CryptoError> {
        bip32::ChildNumber::new(index, true)
            .map(Self)
            .map_err(|_| CryptoError::InvalidChildNumber { index })
    }

    /// Constructs a normal (non-hardened) child index (e.g. the `0` in
    /// `m/0`).
    ///
    /// `index` must be less than [`Self::HARDENED_FLAG`] (`2^31`).
    pub fn normal(index: u32) -> Result<Self, CryptoError> {
        bip32::ChildNumber::new(index, false)
            .map(Self)
            .map_err(|_| CryptoError::InvalidChildNumber { index })
    }

    /// Returns the index with the hardened flag bit cleared.
    pub fn index(&self) -> u32 {
        self.0.index()
    }

    /// Returns `true` if this is a hardened index.
    pub fn is_hardened(&self) -> bool {
        self.0.is_hardened()
    }

    pub(crate) fn as_bip32(self) -> bip32::ChildNumber {
        self.0
    }

    pub(crate) fn from_bip32(inner: bip32::ChildNumber) -> Self {
        Self(inner)
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_root_path() {
        let path = DerivationPath::parse("m").unwrap();
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
    }

    #[test]
    fn parses_bip44_ethereum_path() {
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let indices: Vec<ChildNumber> = path.iter().collect();
        assert_eq!(indices.len(), 5);
        assert_eq!(indices[0].index(), 44);
        assert!(indices[0].is_hardened());
        assert_eq!(indices[1].index(), 60);
        assert!(indices[1].is_hardened());
        assert_eq!(indices[2].index(), 0);
        assert!(indices[2].is_hardened());
        assert_eq!(indices[3].index(), 0);
        assert!(!indices[3].is_hardened());
        assert_eq!(indices[4].index(), 0);
        assert!(!indices[4].is_hardened());
    }

    #[test]
    fn accepts_h_suffix_as_hardened() {
        let apostrophe = DerivationPath::parse("m/44'/0'").unwrap();
        let h_suffix = DerivationPath::parse("m/44h/0h").unwrap();
        assert_eq!(apostrophe, h_suffix);
    }

    #[test]
    fn round_trips_through_display() {
        let path = DerivationPath::parse("m/84'/0'/0'/0/12").unwrap();
        assert_eq!(path.to_string(), "m/84'/0'/0'/0/12");
    }

    #[test]
    fn rejects_missing_m_prefix() {
        assert!(DerivationPath::parse("44'/60'/0'/0/0").is_err());
    }

    #[test]
    fn rejects_garbage_segment() {
        assert!(DerivationPath::parse("m/44'/not-a-number").is_err());
    }

    #[test]
    fn rejects_empty_string() {
        assert!(DerivationPath::parse("").is_err());
    }

    #[test]
    fn child_number_rejects_out_of_range_index() {
        let too_large = ChildNumber::HARDENED_FLAG;
        assert!(ChildNumber::normal(too_large).is_err());
        assert!(ChildNumber::hardened(too_large).is_err());
    }

    #[test]
    fn child_number_accepts_max_valid_index() {
        let max_valid = ChildNumber::HARDENED_FLAG - 1;
        assert!(ChildNumber::normal(max_valid).is_ok());
        assert!(ChildNumber::hardened(max_valid).is_ok());
    }

    #[test]
    fn hardened_and_normal_with_same_index_are_distinct() {
        let hardened = ChildNumber::hardened(0).unwrap();
        let normal = ChildNumber::normal(0).unwrap();
        assert_ne!(hardened, normal);
        assert_eq!(hardened.index(), normal.index());
    }
}
