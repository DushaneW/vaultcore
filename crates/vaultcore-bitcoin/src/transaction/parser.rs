use crate::BitcoinError;
use bitcoin::{consensus::encode::deserialize, Transaction};
/// Decode exactly one transaction (including rejection of trailing bytes).
/// This is structural decoding, not script/consensus or chain-state validation.
/// Bound allocation/work by rejecting byte strings above a block's weight limit.
pub fn parse_transaction(bytes: &[u8]) -> Result<Transaction, BitcoinError> {
    if bytes.len() > 4_000_000 {
        return Err(BitcoinError::InvalidTransaction(
            "raw transaction exceeds 4 MB",
        ));
    }
    deserialize(bytes).map_err(|e| BitcoinError::MalformedTransaction {
        reason: e.to_string(),
    })
}
