// Source: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
// Native P2WPKH, SIGHASH_ALL. First input is P2PK (outside our signer scope).
use bitcoin::{
    consensus::serialize, hashes::Hash, secp256k1::SecretKey, sighash::SighashCache, Amount,
    EcdsaSighashType, Network, PrivateKey, ScriptBuf,
};
use vaultcore_bitcoin::{
    transaction::{parse_transaction, sign_input},
    Utxo,
};
#[test]
fn official_native_p2wpkh_digest_signature_and_serialization() {
    let mut tx = parse_transaction(&hex::decode("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000").unwrap()).unwrap();
    let expected = parse_transaction(&hex::decode("01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000").unwrap()).unwrap();
    let u = Utxo {
        outpoint: tx.input[1].previous_output,
        value: Amount::from_sat(600_000_000),
        script_pubkey: ScriptBuf::from_bytes(
            hex::decode("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap(),
        ),
        change: false,
        index: 0,
    };
    let digest = SighashCache::new(&tx)
        .p2wpkh_signature_hash(1, &u.script_pubkey, u.value, EcdsaSighashType::All)
        .unwrap();
    assert_eq!(
        hex::encode(digest.to_byte_array()),
        "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
    );
    let key = PrivateKey::new(
        SecretKey::from_slice(
            &hex::decode("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9")
                .unwrap(),
        )
        .unwrap(),
        Network::Bitcoin,
    );
    sign_input(&mut tx, 1, &u, &key).unwrap();
    assert_eq!(tx.input[1].witness, expected.input[1].witness);
    assert!(tx.input[0].script_sig.is_empty());
    // Carry the source vector's already-signed P2PK input unchanged.
    tx.input[0].script_sig = expected.input[0].script_sig.clone();
    assert_eq!(serialize(&tx), serialize(&expected));
}
