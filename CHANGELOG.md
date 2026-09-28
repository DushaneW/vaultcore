# Changelog

Notable changes are recorded here. No published release is implied by this file.

## Unreleased

### Added

- BIP-39 mnemonics and BIP-32 key derivation with official reference vectors.
- BIP-44/P2PKH and BIP-84/native P2WPKH accounts and address derivation.
- Deterministic UTXO selection and transaction-template fee estimation.
- Unsigned transactions with change and dust handling.
- Legacy and BIP-143 SIGHASH_ALL signing with script ownership checks.
- Bounded transaction decoding and malformed-input regression coverage.
- Official native P2WPKH BIP-143 signing regression.
- Offline regtest example, GitHub CI, contribution and security policies.

### Changed

- Signing validation no longer clones and sorts UTXOs just to validate them.
- Production Bitcoin code forbids unsafe code and enforces panic-related lints.
