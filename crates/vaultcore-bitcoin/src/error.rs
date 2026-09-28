use core::fmt;

/// Errors produced by `vaultcore-bitcoin`.
///
/// As in `vaultcore-crypto`, no variant carries secret material, and no
/// variant fabricates a numeric value this crate did not itself observe.
#[derive(Debug)]
#[non_exhaustive]
pub enum BitcoinError {
    /// Invalid transaction, UTXO metadata, or monetary range.
    InvalidTransaction(&'static str),
    /// Checked arithmetic or fee calculation overflowed.
    ArithmeticOverflow,
    /// A key from `vaultcore-crypto` could not be interpreted as a valid
    /// secp256k1 public key by the `bitcoin` crate. In practice this
    /// should be unreachable — both crates use the same curve — but the
    /// conversion is fallible in the type system, so it is handled rather
    /// than unwrapped.
    InvalidPublicKey,

    /// A private scalar from `vaultcore-crypto` could not be interpreted as
    /// a valid secp256k1 secret key. As with [`Self::InvalidPublicKey`],
    /// this should be unreachable in practice: `vaultcore-crypto`'s BIP-32
    /// derivation already guarantees a valid nonzero scalar under curve
    /// order. Handled rather than unwrapped regardless.
    InvalidPrivateKey,

    /// A raw byte string failed to decode as a Bitcoin transaction.
    /// `reason` is the underlying `bitcoin` crate's own message.
    MalformedTransaction { reason: String },

    /// Coin selection could not cover the requested output value plus the
    /// estimated fee with the UTXOs provided.
    InsufficientFunds {
        /// Total value of the UTXOs that were available to select from.
        available: u64,
        /// Value that was needed: outputs plus the estimated fee.
        needed: u64,
    },

    /// A transaction input referenced a UTXO whose script type this crate
    /// does not know how to sign (only P2PKH and P2WPKH are supported).
    UnsupportedScriptType,

    /// Signing produced a signature that the corresponding public key does
    /// not verify against. This should be unreachable given correct inputs
    /// — it indicates the wrong private key was matched to a UTXO, not a
    /// transient failure.
    SignatureVerificationFailed,

    /// A sighash computation failed because the transaction's input count
    /// did not include the index being signed, or similar structural
    /// mismatch between the transaction and the inputs being signed.
    SighashComputationFailed { reason: String },

    /// A derivation index or path was rejected by `vaultcore-crypto` (e.g.
    /// an address index `>= 2^31`, which would collide with the hardened
    /// index range). Wraps that crate's own error message rather than the
    /// value, since it already names what was invalid.
    InvalidDerivation(String),
}

impl From<vaultcore_crypto::CryptoError> for BitcoinError {
    fn from(err: vaultcore_crypto::CryptoError) -> Self {
        Self::InvalidDerivation(err.to_string())
    }
}

impl fmt::Display for BitcoinError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransaction(reason) => write!(f, "invalid transaction: {reason}"),
            Self::ArithmeticOverflow => write!(f, "amount or fee arithmetic overflow"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidPrivateKey => write!(f, "invalid private key"),
            Self::MalformedTransaction { reason } => {
                write!(f, "malformed transaction: {reason}")
            }
            Self::InsufficientFunds { available, needed } => write!(
                f,
                "insufficient funds: available {available} sats, needed {needed} sats"
            ),
            Self::UnsupportedScriptType => {
                write!(
                    f,
                    "unsupported script type: only P2PKH and P2WPKH can be signed"
                )
            }
            Self::SignatureVerificationFailed => {
                write!(
                    f,
                    "signature does not verify against the expected public key"
                )
            }
            Self::SighashComputationFailed { reason } => {
                write!(f, "sighash computation failed: {reason}")
            }
            Self::InvalidDerivation(reason) => write!(f, "invalid derivation: {reason}"),
        }
    }
}

impl std::error::Error for BitcoinError {}
