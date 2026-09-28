use bitcoin::{
    consensus::serialize,
    hashes::Hash,
    secp256k1::{Message, Secp256k1},
    sighash::SighashCache,
    Amount, EcdsaSighashType, FeeRate, Network, OutPoint, ScriptBuf, TxOut, Txid,
};
use vaultcore_bitcoin::{
    estimate_fee, select_utxos, transaction::*, Account, AddressKind, BitcoinError, PlannedInput,
    Utxo,
};
use vaultcore_crypto::ExtendedPrivateKey;
fn account(kind: AddressKind) -> Account {
    Account::derive(
        &ExtendedPrivateKey::from_seed(&[42; 64]).unwrap(),
        kind,
        Network::Regtest,
        0,
    )
    .unwrap()
}
fn coin(a: &Account, index: u32, value: u64) -> Utxo {
    Utxo {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: index,
        },
        value: Amount::from_sat(value),
        script_pubkey: a.address(false, index).unwrap().script_pubkey(),
        change: false,
        index,
    }
}
fn output(a: &Account) -> TxOut {
    TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: a.address(false, 99).unwrap().script_pubkey(),
    }
}
fn rate() -> FeeRate {
    FeeRate::from_sat_per_vb(5).unwrap()
}

#[test]
fn signed_roundtrip_and_fee_for_both_kinds() {
    for kind in [AddressKind::P2pkh, AddressKind::P2wpkh] {
        let a = account(kind);
        let built = build_transaction(
            &[coin(&a, 0, 20_000)],
            &[output(&a)],
            a.address(true, 0).unwrap().script_pubkey(),
            rate(),
        )
        .unwrap();
        assert_eq!(built.change_index, Some(1));
        let signed = sign_transaction(&built.transaction, &built.selected_utxos, &a).unwrap();
        assert!(built.fee >= rate().fee_wu(signed.weight()).unwrap());
        assert_eq!(
            signed.output.iter().map(|o| o.value.to_sat()).sum::<u64>() + built.fee.to_sat(),
            20_000
        );
        assert_eq!(parse_transaction(&serialize(&signed)).unwrap(), signed);
        let u = &built.selected_utxos[0];
        let bytes = if kind == AddressKind::P2pkh {
            let instructions: Vec<_> = signed.input[0].script_sig.instructions().collect();
            assert_eq!(instructions.len(), 2);
            assert!(signed.input[0].witness.is_empty());
            instructions[0]
                .as_ref()
                .unwrap()
                .push_bytes()
                .unwrap()
                .as_bytes()
                .to_vec()
        } else {
            assert!(signed.input[0].script_sig.is_empty());
            assert_eq!(signed.input[0].witness.len(), 2);
            signed.input[0].witness.iter().next().unwrap().to_vec()
        };
        let sig = bitcoin::ecdsa::Signature::from_slice(&bytes).unwrap();
        let digest = if kind == AddressKind::P2pkh {
            SighashCache::new(&signed)
                .legacy_signature_hash(0, &u.script_pubkey, 1)
                .unwrap()
                .to_byte_array()
        } else {
            SighashCache::new(&signed)
                .p2wpkh_signature_hash(0, &u.script_pubkey, u.value, EcdsaSighashType::All)
                .unwrap()
                .to_byte_array()
        };
        let secp = Secp256k1::new();
        let public = a.signing_key(false, 0).unwrap().public_key(&secp);
        secp.verify_ecdsa(&Message::from_digest(digest), &sig.signature, &public.inner)
            .unwrap();
        let mut altered = signed.clone();
        altered.output[0].value += Amount::ONE_SAT;
        let altered_digest = if kind == AddressKind::P2pkh {
            SighashCache::new(&altered)
                .legacy_signature_hash(0, &u.script_pubkey, 1)
                .unwrap()
                .to_byte_array()
        } else {
            SighashCache::new(&altered)
                .p2wpkh_signature_hash(0, &u.script_pubkey, u.value, EcdsaSighashType::All)
                .unwrap()
                .to_byte_array()
        };
        assert!(secp
            .verify_ecdsa(
                &Message::from_digest(altered_digest),
                &sig.signature,
                &public.inner
            )
            .is_err());
    }
}
#[test]
fn dust_boundary_and_exact_funding() {
    for kind in [AddressKind::P2pkh, AddressKind::P2wpkh] {
        let a = account(kind);
        let out = output(&a);
        let change = a.address(true, 0).unwrap().script_pubkey();
        let planned = [PlannedInput { kind }];
        let no_change_fee = estimate_fee(&planned, std::slice::from_ref(&out), rate())
            .unwrap()
            .to_sat();
        let with_change_fee = estimate_fee(
            &planned,
            &[
                out.clone(),
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: change.clone(),
                },
            ],
            rate(),
        )
        .unwrap()
        .to_sat();
        let dust = change.minimal_non_dust().to_sat();
        for (value, expected) in [
            (10_000 + no_change_fee, None),
            (10_000 + with_change_fee + dust - 1, None),
            (10_000 + with_change_fee + dust, Some(1)),
        ] {
            let b = build_transaction(
                &[coin(&a, 0, value)],
                std::slice::from_ref(&out),
                change.clone(),
                rate(),
            )
            .unwrap();
            assert_eq!(b.change_index, expected);
            if expected.is_some() {
                assert_eq!(b.transaction.output[1].value.to_sat(), dust);
            }
            assert_eq!(
                b.fee.to_sat()
                    + b.transaction
                        .output
                        .iter()
                        .map(|o| o.value.to_sat())
                        .sum::<u64>(),
                value
            );
        }
    }
}
#[test]
fn selection_is_deterministic_and_fee_requires_another_input() {
    let a = account(AddressKind::P2wpkh);
    let coins = [coin(&a, 1, 10_000), coin(&a, 0, 10_000)];
    assert_eq!(
        select_utxos(&coins, Amount::from_sat(1)).unwrap()[0].index,
        0
    );
    let b = build_transaction(
        &coins,
        &[output(&a)],
        a.address(true, 0).unwrap().script_pubkey(),
        rate(),
    )
    .unwrap();
    assert_eq!(b.selected_utxos.len(), 2);
    assert!(select_utxos(&coins, Amount::from_sat(20_001)).is_err());
    assert!(select_utxos(&coins, Amount::ZERO).unwrap().is_empty());
}
#[test]
fn invalid_inputs_and_arithmetic_are_rejected() {
    let a = account(AddressKind::P2wpkh);
    let u = coin(&a, 0, 20_000);
    let out = output(&a);
    let change = a.address(true, 0).unwrap().script_pubkey();
    assert!(build_transaction(
        &[u.clone(), u.clone()],
        std::slice::from_ref(&out),
        change.clone(),
        rate()
    )
    .is_err());
    assert!(build_transaction(&[], std::slice::from_ref(&out), change.clone(), rate()).is_err());
    assert!(build_transaction(std::slice::from_ref(&u), &[], change.clone(), rate()).is_err());
    let mut bad = u.clone();
    bad.value = Amount::from_sat(u64::MAX);
    assert!(select_utxos(&[bad], Amount::ONE_SAT).is_err());
    let mut bad = u.clone();
    bad.outpoint = OutPoint::null();
    assert!(select_utxos(&[bad], Amount::ONE_SAT).is_err());
    let mut bad = u.clone();
    bad.script_pubkey = ScriptBuf::new();
    assert!(select_utxos(&[bad], Amount::ONE_SAT).is_err());
    let mut bad = u.clone();
    bad.index = 1 << 31;
    assert!(select_utxos(&[bad], Amount::ONE_SAT).is_err());
    assert!(matches!(
        build_transaction(&[u], &[out], change, FeeRate::from_sat_per_kwu(u64::MAX)),
        Err(BitcoinError::ArithmeticOverflow)
    ));
}
#[test]
fn signer_rejects_wrong_key_metadata_and_preserves_original() {
    let a = account(AddressKind::P2wpkh);
    let u = coin(&a, 0, 20_000);
    let b = build_transaction(
        std::slice::from_ref(&u),
        &[output(&a)],
        a.address(true, 0).unwrap().script_pubkey(),
        rate(),
    )
    .unwrap();
    let mut tx = b.transaction.clone();
    assert!(sign_input(&mut tx, 0, &u, &a.signing_key(false, 1).unwrap()).is_err());
    assert_eq!(tx, b.transaction);
    assert!(sign_input(&mut tx, 1, &u, &a.signing_key(false, 0).unwrap()).is_err());
    assert!(sign_transaction(&tx, &[], &a).is_err());
    let mut bad = u.clone();
    bad.outpoint.vout += 1;
    assert!(sign_transaction(&tx, &[bad], &a).is_err());
    let mut bad = u;
    bad.value = Amount::ONE_SAT;
    assert!(sign_transaction(&tx, &[bad], &a).is_err());
}
#[test]
fn malformed_parser_corpus() {
    let a = account(AddressKind::P2wpkh);
    let b = build_transaction(
        &[coin(&a, 0, 20_000)],
        &[output(&a)],
        a.address(true, 0).unwrap().script_pubkey(),
        rate(),
    )
    .unwrap();
    let signed = sign_transaction(&b.transaction, &b.selected_utxos, &a).unwrap();
    let raw = serialize(&signed);
    for end in 0..raw.len() {
        assert!(parse_transaction(&raw[..end]).is_err(), "prefix {end}");
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(parse_transaction(&trailing).is_err());
    let mut flag = raw;
    flag[5] = 0x80;
    assert!(parse_transaction(&flag).is_err());
    assert!(parse_transaction(&[0xff; 64]).is_err());
    assert!(parse_transaction(&vec![0; 4_000_001]).is_err());
    // CompactSize input count declares an unbounded allocation.
    assert!(parse_transaction(&[1, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255]).is_err());
}

#[test]
fn mixed_inputs_and_compactsize_boundary_stay_within_fee_estimate() {
    let legacy = account(AddressKind::P2pkh);
    let witness = account(AddressKind::P2wpkh);
    // Cross CompactSize's 252-input boundary, including empty legacy witnesses.
    let coins: Vec<_> = (0..253)
        .map(|i| coin(if i % 2 == 0 { &legacy } else { &witness }, i, 1_000))
        .collect();
    let recipient = TxOut {
        value: Amount::from_sat(252_000),
        script_pubkey: witness.address(false, 999).unwrap().script_pubkey(),
    };
    let low_rate = FeeRate::from_sat_per_kwu(1);
    let b = build_transaction(
        &coins,
        &[recipient],
        witness.address(true, 0).unwrap().script_pubkey(),
        low_rate,
    )
    .unwrap();
    assert_eq!(b.selected_utxos.len(), 253);
    let mut signed = b.transaction.clone();
    for (i, u) in b.selected_utxos.iter().enumerate() {
        let a = if u.index % 2 == 0 { &legacy } else { &witness };
        sign_input(&mut signed, i, u, &a.signing_key(false, u.index).unwrap()).unwrap();
    }
    let inputs: Vec<_> = b
        .selected_utxos
        .iter()
        .map(|u| PlannedInput {
            kind: u.kind().unwrap(),
        })
        .collect();
    assert!(
        vaultcore_bitcoin::build_template_transaction(&inputs, &signed.output).weight()
            >= signed.weight()
    );
    assert!(b.fee >= low_rate.fee_wu(signed.weight()).unwrap());
    assert_eq!(parse_transaction(&serialize(&signed)).unwrap(), signed);
}
