use core::fmt;

/// Errors produced by `vaultcore-crypto`.
///
/// Every variant is intended to be actionable: it names the specific input
/// that was rejected rather than collapsing into a generic failure. Variants
/// never carry secret material (mnemonics, seeds, or private keys) — only
/// enough context to explain *what* was invalid — so this type is safe to
/// log, print in a CLI, or return across an SDK boundary.
///
/// Numeric context (an offending length or index) is only ever included
/// when this crate itself observed that value before rejecting it. Where an
/// upstream library error carries no such context, the underlying error's
/// own message is preserved instead of inventing a placeholder value.
#[derive(Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// A mnemonic phrase failed BIP-39 validation: an invalid word count, a
    /// word not in the wordlist, or a checksum mismatch. Never includes the
    /// offending phrase.
    InvalidMnemonic {
        /// Human-readable reason, e.g. "invalid checksum".
        reason: String,
    },

    /// Entropy supplied for mnemonic generation was not a valid BIP-39
    /// length (16, 20, 24, 28, or 32 bytes).
    InvalidEntropyLength {
        /// The length that was rejected, in bytes.
        got: usize,
    },

    /// A derivation path string did not parse as `m/44'/60'/0'/0/0`-style
    /// BIP-32 notation.
    InvalidDerivationPath {
        /// The rejected path string, echoed back for diagnostics. Paths
        /// contain no secret material, so this is safe to include.
        path: String,
    },

    /// A child index was outside the valid range for its hardened/normal
    /// half of the `u32` index space (i.e. `>= 2^31`).
    InvalidChildNumber {
        /// The rejected index.
        index: u32,
    },

    /// Derivation would exceed the maximum BIP-32 depth (255 levels).
    DerivationDepthExceeded,

    /// A seed buffer was not one of the lengths BIP-32 accepts (16, 32, or
    /// 64 bytes).
    InvalidSeedLength {
        /// The length that was rejected, in bytes.
        got: usize,
    },

    /// An underlying elliptic-curve or HMAC operation failed while deriving
    /// a key. Per BIP-32 this occurs only on a probability-negligible edge
    /// case (a derived tweak of zero or out of curve-order range); it does
    /// not indicate malformed input in ordinary use.
    KeyDerivationFailed,

    /// A lower-level BIP-32 library error that does not map to a more
    /// specific variant above. The message is the library's own.
    Bip32(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMnemonic { reason } => write!(f, "invalid mnemonic: {reason}"),
            Self::InvalidEntropyLength { got } => write!(
                f,
                "invalid entropy length: got {got} bytes, expected one of 16, 20, 24, 28, 32"
            ),
            Self::InvalidDerivationPath { path } => {
                write!(f, "invalid derivation path: {path:?}")
            }
            Self::InvalidChildNumber { index } => write!(
                f,
                "invalid child number: {index} (must be less than 2^31 before applying hardening)"
            ),
            Self::DerivationDepthExceeded => {
                write!(f, "derivation depth exceeded maximum of 255")
            }
            Self::InvalidSeedLength { got } => write!(
                f,
                "invalid seed length: got {got} bytes, expected 16, 32, or 64"
            ),
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
            Self::Bip32(msg) => write!(f, "bip32 error: {msg}"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Converts errors from the `bip39` crate into the corresponding
/// [`CryptoError`] variant, preserving which failure mode occurred without
/// leaking the mnemonic that triggered it.
impl From<bip39::Error> for CryptoError {
    fn from(err: bip39::Error) -> Self {
        match err {
            bip39::Error::BadEntropyBitCount(bits) => Self::InvalidEntropyLength { got: bits / 8 },
            other => Self::InvalidMnemonic {
                reason: other.to_string(),
            },
        }
    }
}

/// Converts errors from the `bip32` crate (HD key derivation) into the
/// corresponding [`CryptoError`] variant. This is a defensive fallback path:
/// call sites that already validate a length or index themselves construct
/// the richer variant directly, with the value they observed, rather than
/// relying on this conversion.
impl From<bip32::Error> for CryptoError {
    fn from(err: bip32::Error) -> Self {
        match err {
            bip32::Error::Depth => Self::DerivationDepthExceeded,
            bip32::Error::Crypto => Self::KeyDerivationFailed,
            other => Self::Bip32(other.to_string()),
        }
    }
}
