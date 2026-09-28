//! Fee estimation via template-transaction sizing.
//!
//! Before a transaction is signed, its inputs' `scriptSig`/witness fields
//! are empty, so measuring the unsigned transaction's size underestimates
//! the real, signed size — sometimes badly, since a signature is the
//! largest part of a typical input. This module instead builds a *template*
//! transaction with placeholder signatures and public keys sized to the
//! worst case for each input type, and measures `weight()`/`fee_wu()` on
//! that using the `bitcoin` crate's own (real, delegated) serialization —
//! it does not invent or hardcode a vbyte-per-input constant.
//!
//! The placeholder signature is a full 73-byte DER-encoded ECDSA signature
//! (72-byte signature + 1-byte sighash type), the maximum size such a
//! signature can reach. Real signatures are very often 1-2 bytes shorter
//! (whenever the `r` or `s` scalar doesn't need a leading zero padding
//! byte in DER's minimal-length integer encoding), so this is a
//! conservative estimate: it can overestimate the fee by a few sats per
//! input, never underestimate it. Overestimating a fee wastes a small
//! amount of the sender's own money; underestimating it risks a
//! transaction that doesn't relay or confirms slowly. Given that choice,
//! this crate always rounds toward overestimating.
use bitcoin::blockdata::script::Builder;
use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};

use crate::keys::AddressKind;

/// The maximum length of a DER-encoded ECDSA signature plus its trailing
/// sighash-type byte: a 6-byte DER header/length prefix, two 33-byte
/// integers (32 bytes plus a possible leading zero pad byte each) for `r`
/// and `s`, and 1 byte for the sighash type.
const MAX_ECDSA_SIGNATURE_LEN: usize = 6 + 33 + 33 + 1;

const COMPRESSED_PUBKEY_LEN: usize = 33;

fn dummy_p2pkh_script_sig() -> ScriptBuf {
    Builder::new()
        .push_slice([0u8; MAX_ECDSA_SIGNATURE_LEN])
        .push_slice([0u8; COMPRESSED_PUBKEY_LEN])
        .into_script()
}

fn dummy_p2wpkh_witness() -> Witness {
    let mut witness = Witness::new();
    witness.push(vec![0u8; MAX_ECDSA_SIGNATURE_LEN]);
    witness.push(vec![0u8; COMPRESSED_PUBKEY_LEN]);
    witness
}

/// One planned input's kind, for sizing purposes only — no real outpoint or
/// key material is needed to estimate a fee.
#[derive(Copy, Clone, Debug)]
pub struct PlannedInput {
    pub kind: AddressKind,
}

/// Estimates the fee for a transaction with `inputs` (each contributing a
/// worst-case-sized signature of its kind) and `outputs` (real
/// `scriptPubkey`s, since output sizes are exactly known before signing —
/// only inputs' witness data is unknown at this stage).
///
/// Returns `None` only if `fee_rate` overflows the fee calculation (an
/// unrealistically large rate or transaction), matching
/// `bitcoin::FeeRate::fee_wu`'s own overflow behavior — this crate does not
/// paper over that with a fabricated fallback value.
pub fn estimate_fee(
    inputs: &[PlannedInput],
    outputs: &[TxOut],
    fee_rate: FeeRate,
) -> Option<Amount> {
    let template = build_template_transaction(inputs, outputs);
    fee_rate.fee_wu(template.weight())
}

/// Builds the same template transaction `estimate_fee` sizes, for callers
/// that want the weight/vsize directly rather than a fee in sats (e.g. to
/// compare against a policy's minimum relay size).
pub fn build_template_transaction(inputs: &[PlannedInput], outputs: &[TxOut]) -> Transaction {
    let tx_in = inputs
        .iter()
        .map(|input| match input.kind {
            AddressKind::P2pkh => TxIn {
                previous_output: OutPoint::null(),
                script_sig: dummy_p2pkh_script_sig(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            AddressKind::P2wpkh => TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: dummy_p2wpkh_witness(),
            },
        })
        .collect();

    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: tx_in,
        output: outputs.to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;

    fn dummy_output() -> TxOut {
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new(),
        }
    }

    #[test]
    fn p2wpkh_input_costs_less_than_p2pkh_input() {
        let rate = FeeRate::from_sat_per_vb(1).unwrap();

        let p2pkh_fee = estimate_fee(
            &[PlannedInput {
                kind: AddressKind::P2pkh,
            }],
            &[dummy_output()],
            rate,
        )
        .unwrap();
        let p2wpkh_fee = estimate_fee(
            &[PlannedInput {
                kind: AddressKind::P2wpkh,
            }],
            &[dummy_output()],
            rate,
        )
        .unwrap();

        assert!(
            p2wpkh_fee < p2pkh_fee,
            "segwit discount should make a P2WPKH input cheaper: p2wpkh={p2wpkh_fee} p2pkh={p2pkh_fee}"
        );
    }

    #[test]
    fn more_inputs_cost_more() {
        let rate = FeeRate::from_sat_per_vb(1).unwrap();
        let one_input = estimate_fee(
            &[PlannedInput {
                kind: AddressKind::P2wpkh,
            }],
            &[dummy_output()],
            rate,
        )
        .unwrap();
        let two_inputs = estimate_fee(
            &[
                PlannedInput {
                    kind: AddressKind::P2wpkh,
                },
                PlannedInput {
                    kind: AddressKind::P2wpkh,
                },
            ],
            &[dummy_output()],
            rate,
        )
        .unwrap();
        assert!(two_inputs > one_input);
    }

    #[test]
    fn higher_fee_rate_costs_more() {
        let low = FeeRate::from_sat_per_vb(1).unwrap();
        let high = FeeRate::from_sat_per_vb(50).unwrap();
        let inputs = [PlannedInput {
            kind: AddressKind::P2wpkh,
        }];
        let outputs = [dummy_output()];

        let low_fee = estimate_fee(&inputs, &outputs, low).unwrap();
        let high_fee = estimate_fee(&inputs, &outputs, high).unwrap();
        assert!(high_fee > low_fee);
    }
}
