use crate::{
    utxo::{sum_amounts, validate_utxos},
    Account, AddressKind, BitcoinError, Utxo,
};
use bitcoin::{
    ecdsa,
    hashes::Hash,
    script::Builder,
    secp256k1::{Message, Secp256k1},
    sighash::SighashCache,
    EcdsaSighashType, PrivateKey, ScriptBuf, Transaction, Witness,
};

/// Sign one input using SIGHASH_ALL, after verifying outpoint and script ownership.
/// Previous-output metadata must come from a trusted chain source. No mutation
/// occurs on error. Compressed keys only, matching the fee estimator.
pub fn sign_input(
    tx: &mut Transaction,
    input_index: usize,
    utxo: &Utxo,
    key: &PrivateKey,
) -> Result<(), BitcoinError> {
    let input = tx
        .input
        .get(input_index)
        .ok_or(BitcoinError::InvalidTransaction("input index out of range"))?;
    if input.previous_output != utxo.outpoint {
        return Err(BitcoinError::InvalidTransaction("outpoint mismatch"));
    }
    if !key.compressed {
        return Err(BitcoinError::InvalidPublicKey);
    }
    if tx.output.is_empty() {
        return Err(BitcoinError::InvalidTransaction("no outputs"));
    }
    validate_utxos(std::slice::from_ref(utxo))?;
    sum_amounts(tx.output.iter().map(|o| o.value))?;
    let secp = Secp256k1::new();
    let public = key.public_key(&secp);
    let kind = utxo.kind()?;
    let expected = match kind {
        AddressKind::P2pkh => ScriptBuf::new_p2pkh(&public.pubkey_hash()),
        AddressKind::P2wpkh => ScriptBuf::new_p2wpkh(
            &public
                .wpubkey_hash()
                .map_err(|_| BitcoinError::InvalidPublicKey)?,
        ),
    };
    if expected != utxo.script_pubkey {
        return Err(BitcoinError::InvalidTransaction(
            "key does not own previous output",
        ));
    }
    let mut cache = SighashCache::new(&*tx);
    let digest = match kind {
        AddressKind::P2pkh => cache
            .legacy_signature_hash(
                input_index,
                &utxo.script_pubkey,
                EcdsaSighashType::All.to_u32(),
            )
            .map_err(|e| BitcoinError::SighashComputationFailed {
                reason: e.to_string(),
            })?
            .to_byte_array(),
        AddressKind::P2wpkh => cache
            .p2wpkh_signature_hash(
                input_index,
                &utxo.script_pubkey,
                utxo.value,
                EcdsaSighashType::All,
            )
            .map_err(|e| BitcoinError::SighashComputationFailed {
                reason: e.to_string(),
            })?
            .to_byte_array(),
    };
    let message = Message::from_digest(digest);
    let signature = secp.sign_ecdsa(&message, &key.inner);
    secp.verify_ecdsa(&message, &signature, &public.inner)
        .map_err(|_| BitcoinError::SignatureVerificationFailed)?;
    let signature = ecdsa::Signature::sighash_all(signature);
    let (script_sig, witness) = match kind {
        AddressKind::P2pkh => (
            Builder::new()
                .push_slice(signature.serialize())
                .push_key(&public)
                .into_script(),
            Witness::new(),
        ),
        AddressKind::P2wpkh => (
            ScriptBuf::new(),
            Witness::from_slice(&[signature.to_vec(), public.to_bytes()]),
        ),
    };
    tx.input[input_index].script_sig = script_sig;
    tx.input[input_index].witness = witness;
    Ok(())
}
/// Sign all inputs from one account atomically. UTXOs must be in input order.
/// Recipient and fee approval remains the caller's responsibility.
pub fn sign_transaction(
    tx: &Transaction,
    utxos: &[Utxo],
    account: &Account,
) -> Result<Transaction, BitcoinError> {
    if tx.input.is_empty() || tx.input.len() != utxos.len() {
        return Err(BitcoinError::InvalidTransaction(
            "input/UTXO count mismatch",
        ));
    }
    validate_utxos(utxos)?;
    let total_in = sum_amounts(utxos.iter().map(|u| u.value))?;
    let total_out = sum_amounts(tx.output.iter().map(|o| o.value))?;
    if total_out > total_in {
        return Err(BitcoinError::InsufficientFunds {
            available: total_in,
            needed: total_out,
        });
    }
    let mut signed = tx.clone();
    for (index, utxo) in utxos.iter().enumerate() {
        let key = account.signing_key(utxo.change, utxo.index)?;
        sign_input(&mut signed, index, utxo, &key)?;
    }
    Ok(signed)
}
