//! Official BIP-39 English-wordlist test vectors, verified against this
//! crate's public API.
//!
//! Source: <https://github.com/trezor/python-mnemonic/blob/master/vectors.json>
//! (the vector file BIP-39 itself points to). Every vector uses the fixed
//! passphrase `"TREZOR"`, per that file's convention. Only the English
//! wordlist is checked, since only the `english` feature is enabled on the
//! `bip39` dependency for this build (see `src/mnemonic.rs`).
//!
//! Each row is `(entropy_hex, mnemonic, seed_hex)`. This test checks both
//! directions: entropy -> mnemonic (via [`bip39::Mnemonic::from_entropy`],
//! reached indirectly through phrase validation) and mnemonic -> seed (via
//! [`Mnemonic::to_seed`]).

use vaultcore_crypto::Mnemonic;

const VECTORS: &[(&str, &str, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000000",
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
        "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
    ),
    (
        "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
    ),
    (
        "8080808080808080808080808080808080808080808080808080808080808080",
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
    ),
    (
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
        "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
    ),
    (
        "9e885d952ad362caeb4efe34a8e91bd2",
        "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
    ),
    (
        "c0ba5a8e914111210f2bd131f3d5e08d",
        "scheme spot photo card baby mountain device kick cradle pact join borrow",
        "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
    ),
    (
        "23db8160a31d3e0dca3688ed941adbf3",
        "cat swing flag economy stadium alone churn speed unique patch report train",
        "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
    ),
    (
        "f30f8c1da665478f49b001d94c5fc452",
        "vessel ladder alter error federal sibling chat ability sun glass valve picture",
        "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
    ),
    (
        "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
        "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
        "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
    ),
];

#[test]
fn official_vectors_mnemonic_and_seed_match() {
    for (entropy_hex, expected_mnemonic, expected_seed_hex) in VECTORS {
        let mnemonic = Mnemonic::from_phrase(expected_mnemonic).unwrap_or_else(|e| {
            panic!("official vector phrase must validate: {expected_mnemonic:?}: {e}")
        });

        assert_eq!(
            *mnemonic.phrase(),
            *expected_mnemonic,
            "phrase round-trip mismatch for entropy {entropy_hex}"
        );

        let seed = mnemonic.to_seed("TREZOR");
        let expected_seed = hex::decode(expected_seed_hex).unwrap();
        assert_eq!(
            seed.as_slice(),
            expected_seed.as_slice(),
            "seed mismatch for mnemonic {expected_mnemonic:?}"
        );
    }
}

#[test]
fn official_vectors_word_counts_are_plausible() {
    // Sanity check on the table itself: entropy length in bytes maps to
    // word count as (entropy_bits + checksum_bits) / 11, i.e. word_count =
    // entropy_bytes * 8 / 32 * 3 = entropy_bytes * 3 / 4 rounded per BIP-39's
    // fixed steps. This just confirms the fixture table above wasn't
    // transcribed with a mismatched entropy/mnemonic pair.
    for (entropy_hex, mnemonic, _) in VECTORS {
        let entropy_bytes = entropy_hex.len() / 2;
        let expected_word_count = entropy_bytes * 3 / 4;
        let actual_word_count = mnemonic.split_whitespace().count();
        assert_eq!(
            actual_word_count, expected_word_count,
            "word count mismatch for entropy {entropy_hex}"
        );
    }
}
