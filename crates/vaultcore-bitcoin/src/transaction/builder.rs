use crate::{
    estimate_fee,
    utxo::{ordered, sum_amounts},
    BitcoinError, PlannedInput, Utxo,
};
use bitcoin::{
    absolute, transaction, Amount, FeeRate, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// Fee is the actual input-output difference, including discarded dust.
#[derive(Debug)]
pub struct BuiltTransaction {
    /// Unsigned transaction with recipients followed by optional change.
    pub transaction: Transaction,
    /// Previous outputs in the exact order of transaction inputs.
    pub selected_utxos: Vec<Utxo>,
    /// Input value minus output value, including discarded dust.
    pub fee: Amount,
    /// Position of the change output, if one was economical to create.
    pub change_index: Option<usize>,
}
/// Select inputs while remeasuring both no-change and change templates.
/// Change supports P2PKH/P2WPKH and uses rust-bitcoin's default dust policy.
pub fn build_transaction(
    utxos: &[Utxo],
    outputs: &[TxOut],
    change_script: ScriptBuf,
    rate: FeeRate,
) -> Result<BuiltTransaction, BitcoinError> {
    if outputs.is_empty() {
        return Err(BitcoinError::InvalidTransaction("no recipients"));
    }
    if !change_script.is_p2pkh() && !change_script.is_p2wpkh() {
        return Err(BitcoinError::UnsupportedScriptType);
    }
    for output in outputs {
        if output.value < output.script_pubkey.minimal_non_dust() {
            return Err(BitcoinError::InvalidTransaction("dust recipient"));
        }
    }
    let send = sum_amounts(outputs.iter().map(|o| o.value))?;
    let sorted = ordered(utxos)?;
    let available = sum_amounts(sorted.iter().map(|u| u.value))?;
    let mut selected = Vec::new();
    let mut planned = Vec::new();
    let mut total = 0u64;
    let mut needed = send;
    for u in sorted {
        total += u.value.to_sat();
        planned.push(PlannedInput { kind: u.kind()? });
        selected.push(u);
        let base_fee = estimate_fee(&planned, outputs, rate)
            .ok_or(BitcoinError::ArithmeticOverflow)?
            .to_sat();
        needed = send
            .checked_add(base_fee)
            .ok_or(BitcoinError::ArithmeticOverflow)?;
        if total < needed {
            continue;
        }
        let mut final_outputs = outputs.to_vec();
        final_outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: change_script.clone(),
        });
        let change_fee = estimate_fee(&planned, &final_outputs, rate)
            .ok_or(BitcoinError::ArithmeticOverflow)?
            .to_sat();
        let change = total
            .checked_sub(send)
            .and_then(|v| v.checked_sub(change_fee));
        let change_index = match change {
            Some(value) if value > 0 && value >= change_script.minimal_non_dust().to_sat() => {
                final_outputs[outputs.len()].value = Amount::from_sat(value);
                Some(outputs.len())
            }
            _ => {
                final_outputs.pop();
                None
            }
        };
        let fee = total - sum_amounts(final_outputs.iter().map(|o| o.value))?;
        let transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: selected
                .iter()
                .map(|u| TxIn {
                    previous_output: u.outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: final_outputs,
        };
        return Ok(BuiltTransaction {
            transaction,
            selected_utxos: selected,
            fee: Amount::from_sat(fee),
            change_index,
        });
    }
    Err(BitcoinError::InsufficientFunds { available, needed })
}
