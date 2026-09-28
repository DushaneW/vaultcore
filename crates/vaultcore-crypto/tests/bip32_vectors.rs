//! Official BIP-32 test vectors 1, 2, and 3, verified against this crate's
//! public API.
//!
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>
//! (Test Vectors 1-3; Test Vector 4 is a duplicate leading-zero regression
//! of the same kind as Test Vector 3, and Test Vector 5 exercises malformed
//! *serialized* keys, which this crate does not parse — see
//! `docs/crypto-core.md`).
//!
//! The BIP publishes each expected key as a Base58Check-encoded `xprv`/`xpub`
//! string, not as raw bytes. This crate's public API deliberately does not
//! expose that Base58 serialization (see the module docs in
//! `src/keys.rs` — it is a Bitcoin-specific wire format, out of place in a
//! chain-agnostic crate). To compare against the official vectors without
//! reimplementing anything cryptographic, this test decodes the published
//! strings with the `bs58` crate (`check` feature, so the checksum is
//! verified as a side effect of decoding) and compares the raw fields
//! against what this crate derived.
//!
//! An `xprv`/`xpub` payload, per the BIP-32 spec, is 78 bytes:
//! `version(4) || depth(1) || parent_fingerprint(4) || child_number(4) ||
//! chain_code(32) || key_data(33)`. For a private key, `key_data` is
//! `0x00 || <32-byte scalar>`; for a public key it is the 33-byte
//! SEC1-compressed point.

use vaultcore_crypto::{ChildNumber, DerivationPath, ExtendedPrivateKey};

struct DecodedExtendedKey {
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    chain_code: [u8; 32],
    /// Either a 32-byte private scalar or a 33-byte compressed public key,
    /// depending on which string was decoded.
    key_data: Vec<u8>,
}

/// Decodes a Base58Check `xprv`/`xpub` string into its BIP-32 fields.
/// Panics on malformed input: this helper only ever runs against the fixed,
/// known-good vectors below, not untrusted data.
fn decode_extended_key(encoded: &str) -> DecodedExtendedKey {
    let payload = bs58::decode(encoded)
        .with_check(None)
        .into_vec()
        .expect("official test vector must decode as valid base58check");
    assert_eq!(payload.len(), 78, "xprv/xpub payload is always 78 bytes");

    DecodedExtendedKey {
        depth: payload[4],
        parent_fingerprint: payload[5..9].try_into().unwrap(),
        child_number: u32::from_be_bytes(payload[9..13].try_into().unwrap()),
        chain_code: payload[13..45].try_into().unwrap(),
        key_data: payload[45..78].to_vec(),
    }
}

/// Asserts that the key this crate derived at `path` from `seed` matches the
/// official vector's published `ext_prv` string in every field BIP-32
/// defines: private scalar, chain code, depth, parent fingerprint, and own
/// child number.
fn assert_matches_vector(seed_hex: &str, path: &str, expected_ext_prv: &str) {
    let seed = hex::decode(seed_hex).unwrap();
    let path = DerivationPath::parse(path).unwrap();
    let derived = ExtendedPrivateKey::derive(&seed, &path).unwrap();

    let expected = decode_extended_key(expected_ext_prv);
    assert_eq!(
        expected.key_data[0], 0x00,
        "private key data is 0x00-prefixed"
    );
    assert_eq!(
        derived.to_bytes().as_slice(),
        &expected.key_data[1..],
        "private scalar mismatch at {expected_ext_prv}"
    );
    assert_eq!(derived.chain_code(), expected.chain_code);
    assert_eq!(derived.depth(), expected.depth);
    assert_eq!(derived.parent_fingerprint(), expected.parent_fingerprint);
    assert_eq!(
        derived.child_number().index(),
        expected.child_number & !ChildNumber::HARDENED_FLAG
    );
    assert_eq!(
        derived.child_number().is_hardened(),
        expected.child_number & ChildNumber::HARDENED_FLAG != 0
    );
}

// --- Test vector 1 --------------------------------------------------------
// Seed (hex): 000102030405060708090a0b0c0d0e0f

const VECTOR_1_SEED: &str = "000102030405060708090a0b0c0d0e0f";

#[test]
fn vector_1_master() {
    assert_matches_vector(
        VECTOR_1_SEED,
        "m",
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
    );
}

#[test]
fn vector_1_m_0h() {
    assert_matches_vector(
        VECTOR_1_SEED,
        "m/0'",
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    );
}

#[test]
fn vector_1_m_0h_1() {
    assert_matches_vector(
        VECTOR_1_SEED,
        "m/0'/1",
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
    );
}

#[test]
fn vector_1_m_0h_1_2h() {
    assert_matches_vector(
        VECTOR_1_SEED,
        "m/0'/1/2'",
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
    );
}

#[test]
fn vector_1_m_0h_1_2h_2() {
    assert_matches_vector(
        VECTOR_1_SEED,
        "m/0'/1/2'/2",
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
    );
}

#[test]
fn vector_1_m_0h_1_2h_2_1000000000() {
    assert_matches_vector(
        VECTOR_1_SEED,
        "m/0'/1/2'/2/1000000000",
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
    );
}

// --- Test vector 2 ----------------------------------------------------------
// Exercises indices at the top of both the normal and hardened ranges
// (2147483647 = 2^31-1, the largest normal index; its hardened sibling
// 2147483646' sits one below the top of the hardened range).
// Seed (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542

const VECTOR_2_SEED: &str = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";

#[test]
fn vector_2_master() {
    assert_matches_vector(
        VECTOR_2_SEED,
        "m",
        "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
    );
}

#[test]
fn vector_2_m_0() {
    assert_matches_vector(
        VECTOR_2_SEED,
        "m/0",
        "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
    );
}

#[test]
fn vector_2_m_0_max_hardened() {
    assert_matches_vector(
        VECTOR_2_SEED,
        "m/0/2147483647'",
        "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
    );
}

#[test]
fn vector_2_m_0_max_hardened_1() {
    assert_matches_vector(
        VECTOR_2_SEED,
        "m/0/2147483647'/1",
        "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
    );
}

#[test]
fn vector_2_m_0_max_hardened_1_near_max_hardened() {
    assert_matches_vector(
        VECTOR_2_SEED,
        "m/0/2147483647'/1/2147483646'",
        "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
    );
}

#[test]
fn vector_2_m_0_max_hardened_1_near_max_hardened_2() {
    assert_matches_vector(
        VECTOR_2_SEED,
        "m/0/2147483647'/1/2147483646'/2",
        "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
    );
}

// --- Test vector 3 ----------------------------------------------------------
// Regression coverage for leading-zero private keys: an early bug in some
// implementations (bitcore-lib#47, iancoleman/bip39#58) dropped leading
// zero bytes when serializing a private key whose scalar happened to begin
// with 0x00, producing a 31-byte value instead of 32. This seed is chosen
// specifically to produce such a key at m/0'.
// Seed (hex): 4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be

const VECTOR_3_SEED: &str = "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";

#[test]
fn vector_3_master() {
    assert_matches_vector(
        VECTOR_3_SEED,
        "m",
        "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
    );
}

#[test]
fn vector_3_m_0h_leading_zero_regression() {
    assert_matches_vector(
        VECTOR_3_SEED,
        "m/0'",
        "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
    );
}

/// Cross-checks the extended *public* keys the BIP publishes alongside
/// Test Vector 1's private keys, verifying `ExtendedPrivateKey::public_key`
/// end to end (private-key derivation, then neutering).
#[test]
fn vector_1_public_keys_match() {
    let seed = hex::decode(VECTOR_1_SEED).unwrap();

    let cases = [
        (
            "m",
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8",
        ),
        (
            "m/0'",
            "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        ),
        (
            "m/0'/1",
            "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        ),
    ];

    for (path, expected_ext_pub) in cases {
        let path = DerivationPath::parse(path).unwrap();
        let derived = ExtendedPrivateKey::derive(&seed, &path)
            .unwrap()
            .public_key();
        let expected = decode_extended_key(expected_ext_pub);
        assert_eq!(
            derived.to_bytes().as_slice(),
            expected.key_data.as_slice(),
            "public key mismatch at {expected_ext_pub}"
        );
        assert_eq!(derived.chain_code(), expected.chain_code);
        assert_eq!(derived.depth(), expected.depth);
    }
}
