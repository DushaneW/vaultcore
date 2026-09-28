//! BIP-39 mnemonic generation, validation, and seed derivation.
//!
//! This module is a thin wrapper around the [`bip39`] crate (rust-bitcoin's
//! implementation). We do not reimplement wordlist handling, entropy
//! encoding, or the PBKDF2-HMAC-SHA512 seed derivation — those are exactly
//! the kind of security-critical primitives this project deliberately
//! avoids rewriting. What this module adds:
//!
//! - a [`CryptoError`]-based API consistent with the rest of this crate,
//!   instead of exposing `bip39::Error` directly at the public boundary;
//! - [`Zeroizing`] wrappers around every method that returns secret bytes
//!   (the seed) or secret text (the phrase), so callers get a scrub-on-drop
//!   buffer by default instead of having to remember to add one.
//!
//! ## Supported languages
//!
//! Only English is enabled in this build. BIP-39 defines wordlists for ten
//! languages; the `bip39` crate gates each one behind a Cargo feature so
//! that unused wordlists are not compiled in. Phase 1 only needs English —
//! additional languages can be turned on later by enabling the
//! corresponding feature on the `bip39` dependency, with no changes to this
//! module's API.
use bip39::Language;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Number of words in a BIP-39 mnemonic phrase.
///
/// Re-exported from the `bip39` crate: this is already a minimal, correctly
/// named type, so we expose it directly rather than introduce a duplicate
/// enum with no behavioral difference.
pub use bip39::WordCount;

/// A validated BIP-39 mnemonic phrase.
///
/// Construct one either by generating fresh entropy ([`Mnemonic::generate`])
/// or by validating a phrase a user typed in during wallet recovery
/// ([`Mnemonic::from_phrase`]). Both paths go through the same BIP-39
/// checksum validation, so a `Mnemonic` value is always well-formed.
///
/// # What this type does not do
///
/// It does not zeroize its own memory on drop. The underlying
/// `bip39::Mnemonic` stores word indices in a fixed-size array behind a
/// private field, and zeroizing it requires the upstream crate's `zeroize`
/// Cargo feature. That feature is not enabled in this build because its
/// `zeroize_derive` dependency requires Rust 1.85 (edition 2024), newer
/// than the Rust 1.75 toolchain available in this development environment.
/// This is a toolchain constraint, not a design decision — see
/// `docs/crypto-core.md` for detail and the plan to remove the limitation
/// once CI pins a newer stable Rust. Every byte *this crate* produces from
/// a `Mnemonic` (seeds, phrases) is returned wrapped in [`Zeroizing`].
///
/// It deliberately does not implement `Debug`: there is no partial view of
/// a mnemonic that is safe to print, so `{:?}` on a `Mnemonic` is a compile
/// error rather than a runtime footgun.
pub struct Mnemonic {
    inner: bip39::Mnemonic,
}

impl Mnemonic {
    /// Generates a new mnemonic phrase with fresh entropy from the
    /// operating system's CSPRNG (via the `rand` crate's `OsRng`).
    ///
    /// `word_count` determines the entropy size: 12 words = 128 bits of
    /// entropy through 24 words = 256 bits, in the fixed steps BIP-39
    /// defines (12/15/18/21/24).
    pub fn generate(word_count: WordCount) -> Result<Self, CryptoError> {
        let inner = bip39::Mnemonic::generate_in(Language::English, word_count)?;
        Ok(Self { inner })
    }

    /// Validates a mnemonic phrase a user supplied (e.g. during wallet
    /// recovery), checking word-count, wordlist membership of every word,
    /// and the BIP-39 checksum bits.
    ///
    /// The phrase is normalized (Unicode NFKD, matching the BIP-39 spec)
    /// before validation, so minor differences in how the user's input
    /// method composed accented characters do not cause a spurious
    /// checksum failure.
    pub fn from_phrase(phrase: &str) -> Result<Self, CryptoError> {
        let inner = bip39::Mnemonic::parse_in(Language::English, phrase)?;
        Ok(Self { inner })
    }

    /// Returns the number of words in this mnemonic (12, 15, 18, 21, or 24).
    pub fn word_count(&self) -> usize {
        self.inner.word_count()
    }

    /// Reconstructs the mnemonic phrase as space-separated words.
    ///
    /// Wrapped in [`Zeroizing`] so the allocated `String` is overwritten
    /// with zeros when the caller drops it, rather than left on the heap
    /// for the allocator to reuse unscrubbed.
    pub fn phrase(&self) -> Zeroizing<String> {
        Zeroizing::new(self.inner.to_string())
    }

    /// Derives the 64-byte BIP-39 seed from this mnemonic using PBKDF2 with
    /// HMAC-SHA512 (2048 rounds, as specified by BIP-39).
    ///
    /// `passphrase` is the optional user-supplied "25th word" (an empty
    /// string is valid and common). A different passphrase deterministically
    /// produces a different, unrelated seed from the same mnemonic — this is
    /// a BIP-39 feature, not a bug, and there is no way to detect that the
    /// wrong passphrase was used other than the derived wallet being empty.
    pub fn to_seed(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.inner.to_seed(passphrase))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_requested_word_count() {
        for (word_count, expected) in [
            (WordCount::Words12, 12),
            (WordCount::Words15, 15),
            (WordCount::Words18, 18),
            (WordCount::Words21, 21),
            (WordCount::Words24, 24),
        ] {
            let mnemonic = Mnemonic::generate(word_count).expect("generation should succeed");
            assert_eq!(mnemonic.word_count(), expected);
        }
    }

    #[test]
    fn generated_mnemonics_are_not_deterministic() {
        let a = Mnemonic::generate(WordCount::Words12).unwrap();
        let b = Mnemonic::generate(WordCount::Words12).unwrap();
        assert_ne!(*a.phrase(), *b.phrase(), "entropy source must not repeat");
    }

    #[test]
    fn round_trips_through_phrase() {
        let generated = Mnemonic::generate(WordCount::Words24).unwrap();
        let phrase = generated.phrase();
        let parsed = Mnemonic::from_phrase(&phrase).expect("valid phrase must parse");
        assert_eq!(*parsed.phrase(), *phrase);
    }

    #[test]
    fn rejects_bad_checksum() {
        // The canonical all-zero-entropy test vector: valid word count,
        // every word in the wordlist, correct checksum.
        let valid = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";
        assert!(Mnemonic::from_phrase(valid).is_ok());

        // Swap the last word for another in-wordlist word. This keeps the
        // word count and wordlist membership valid but breaks the checksum
        // bits, which are a function of the full entropy.
        let bogus_checksum = "abandon abandon abandon abandon abandon abandon \
                               abandon abandon abandon abandon abandon zoo";
        assert!(matches!(
            Mnemonic::from_phrase(bogus_checksum),
            Err(CryptoError::InvalidMnemonic { .. })
        ));
    }

    #[test]
    fn rejects_unknown_word() {
        let bad = "notaword abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
        assert!(matches!(
            Mnemonic::from_phrase(bad),
            Err(CryptoError::InvalidMnemonic { .. })
        ));
    }

    #[test]
    fn rejects_wrong_word_count() {
        let bad = "abandon abandon abandon";
        assert!(matches!(
            Mnemonic::from_phrase(bad),
            Err(CryptoError::InvalidMnemonic { .. })
        ));
    }

    #[test]
    fn different_passphrases_yield_different_seeds() {
        let mnemonic = Mnemonic::from_phrase(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
        )
        .unwrap();
        let seed_a = mnemonic.to_seed("");
        let seed_b = mnemonic.to_seed("TREZOR");
        assert_ne!(*seed_a, *seed_b);
    }
}
