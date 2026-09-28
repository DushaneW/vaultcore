//! Deterministic regtest demo. Public fixture seed and invented UTXO: no funds.
use bitcoin::{hashes::Hash, Amount, FeeRate, Network, OutPoint, TxOut, Txid};
use vaultcore_bitcoin::{
    transaction::{build_transaction, sign_transaction},
    Account, AddressKind, Utxo,
};
use vaultcore_crypto::ExtendedPrivateKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let master = ExtendedPrivateKey::from_seed(&[0x42; 64])?;
    let account = Account::derive(&master, AddressKind::P2wpkh, Network::Regtest, 0)?;
    let previous_output = Utxo {
        outpoint: OutPoint {
            txid: Txid::from_byte_array([0x11; 32]),
            vout: 0,
        },
        value: Amount::from_sat(100_000),
        script_pubkey: account.address(false, 0)?.script_pubkey(),
        change: false,
        index: 0,
    };
    let recipient = TxOut {
        value: Amount::from_sat(25_000),
        script_pubkey: account.address(false, 1)?.script_pubkey(),
    };
    let fee_rate = FeeRate::from_sat_per_vb(2).ok_or("fee rate out of range")?;
    let built = build_transaction(
        &[previous_output],
        &[recipient],
        account.address(true, 0)?.script_pubkey(),
        fee_rate,
    )?;

    // A real application authenticates prevouts and approves recipients and fee
    // before this point. This fixture is public and never broadcast.
    let signed = sign_transaction(&built.transaction, &built.selected_utxos, &account)?;
    println!("Offline regtest fixture (no broadcast)");
    println!(
        "Inputs: {} | Outputs: {}",
        signed.input.len(),
        signed.output.len()
    );
    println!(
        "Fee: {} sat | Signed size: {} vB",
        built.fee.to_sat(),
        signed.vsize()
    );
    println!("Transaction ID: {}", signed.compute_txid());
    Ok(())
}
