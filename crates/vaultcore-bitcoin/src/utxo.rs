//! Deterministic largest-first coin selection; no chain-state lookup.
use crate::{AddressKind, BitcoinError};
use bitcoin::{Amount, OutPoint, ScriptBuf};
use std::collections::HashSet;

/// Trusted previous-output data plus a slot in the signing account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    /// Transaction ID and output position in the funding transaction.
    pub outpoint: OutPoint,
    /// Authenticated value of the previous output.
    pub value: Amount,
    /// Authenticated locking script of the previous output.
    pub script_pubkey: ScriptBuf,
    /// Whether the key belongs to the internal (change) chain.
    pub change: bool,
    /// Non-hardened address index within the chain.
    pub index: u32,
}
impl Utxo {
    /// Identify a supported previous-output script.
    pub fn kind(&self) -> Result<AddressKind, BitcoinError> {
        if self.script_pubkey.is_p2pkh() {
            Ok(AddressKind::P2pkh)
        } else if self.script_pubkey.is_p2wpkh() {
            Ok(AddressKind::P2wpkh)
        } else {
            Err(BitcoinError::UnsupportedScriptType)
        }
    }
}
pub(crate) fn sum_amounts(mut values: impl Iterator<Item = Amount>) -> Result<u64, BitcoinError> {
    values.try_fold(0u64, |sum, value| {
        let total = sum
            .checked_add(value.to_sat())
            .ok_or(BitcoinError::ArithmeticOverflow)?;
        if total > Amount::MAX_MONEY.to_sat() {
            return Err(BitcoinError::InvalidTransaction("amount exceeds MAX_MONEY"));
        }
        Ok(total)
    })
}
pub(crate) fn validate_utxos(utxos: &[Utxo]) -> Result<(), BitcoinError> {
    let mut seen = HashSet::new();
    for u in utxos {
        if u.outpoint.is_null() || !seen.insert(u.outpoint) {
            return Err(BitcoinError::InvalidTransaction(
                "null or duplicate outpoint",
            ));
        }
        if u.index >= (1 << 31) {
            return Err(BitcoinError::InvalidTransaction("hardened address index"));
        }
        u.kind()?;
    }
    sum_amounts(utxos.iter().map(|u| u.value))?;
    Ok(())
}

pub(crate) fn ordered(utxos: &[Utxo]) -> Result<Vec<Utxo>, BitcoinError> {
    validate_utxos(utxos)?;
    let mut sorted = utxos.to_vec();
    sorted.sort_by(|a, b| b.value.cmp(&a.value).then(a.outpoint.cmp(&b.outpoint)));
    Ok(sorted)
}
/// Select a deterministic largest-first prefix. `target` must include fees.
pub fn select_utxos(utxos: &[Utxo], target: Amount) -> Result<Vec<Utxo>, BitcoinError> {
    sum_amounts(std::iter::once(target))?;
    let sorted = ordered(utxos)?;
    let mut total = 0;
    let mut selected = Vec::new();
    for u in sorted {
        if total >= target.to_sat() {
            break;
        }
        total += u.value.to_sat();
        selected.push(u);
    }
    if total < target.to_sat() {
        return Err(BitcoinError::InsufficientFunds {
            available: total,
            needed: target.to_sat(),
        });
    }
    Ok(selected)
}
