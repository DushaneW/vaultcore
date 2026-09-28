//! Official BIP-84 test vectors, verified end to end: mnemonic -> seed ->
//! account -> address, plus the WIF-encoded private key at each address.
//!
//! Source: <https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki>
//! ("Test vectors" section).

use bitcoin::{Network, PrivateKey};
use vaultcore_bitcoin::{Account, AddressKind};
use vaultcore_crypto::{ExtendedPrivateKey, Mnemonic};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// (change, index, expected WIF private key, expected bech32 address)
const VECTORS: &[(bool, u32, &str, &str)] = &[
    (
        false,
        0,
        "KyZpNDKnfs94vbrwhJneDi77V6jF64PWPF8x5cdJb8ifgg2DUc9d",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    ),
    (
        false,
        1,
        "Kxpf5b8p3qX56DKEe5NqWbNUP9MnqoRFzZwHRtsFqhzuvUJsYZCy",
        "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g",
    ),
    (
        true,
        0,
        "KxuoxufJL5csa1Wieb2kp29VNdn92Us8CoaUG3aGtPtcF3AzeXvF",
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
    ),
];

#[test]
fn official_account_0_vectors_match() {
    let mnemonic = Mnemonic::from_phrase(MNEMONIC).unwrap();
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::from_seed(&*seed).unwrap();
    let account = Account::derive(&master, AddressKind::P2wpkh, Network::Bitcoin, 0).unwrap();

    for (change, index, expected_wif, expected_address) in VECTORS {
        let signing_key = account.signing_key(*change, *index).unwrap();
        assert_eq!(
            signing_key.to_wif(),
            *expected_wif,
            "private key mismatch at change={change} index={index}"
        );

        let expected_key = PrivateKey::from_wif(expected_wif).unwrap();
        assert_eq!(
            signing_key.inner.secret_bytes(),
            expected_key.inner.secret_bytes()
        );

        let address = account.address(*change, *index).unwrap();
        assert_eq!(
            address.to_string(),
            *expected_address,
            "address mismatch at change={change} index={index}"
        );
    }
}
