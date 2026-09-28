# Bitcoin architecture — Phase 2

`vaultcore-bitcoin` layers Bitcoin transaction handling over the unchanged
`vaultcore-crypto` key core. It uses the workspace's locked rust-bitcoin 0.32
release; no custom serialization, elliptic-curve implementation or sighash
algorithm is introduced.

## API and data flow

1. Derive `Account` for BIP-44/P2PKH or BIP-84/native P2WPKH.
2. Obtain authenticated previous-output data from a trusted chain source.
   Construct `Utxo { outpoint, value, script_pubkey, change, index }`.
   `change` and `index` identify a slot under the account, not arbitrary paths.
3. Pass UTXOs, recipient `TxOut`s, an account-derived change script and a
   `FeeRate` to `transaction::build_transaction`.
4. Inspect returned recipients, `fee`, `change_index` and `selected_utxos`.
   Approve these at the application boundary before signing.
5. Call `transaction::sign_transaction(&built.transaction,
   &built.selected_utxos, &account)`; serialize the returned transaction with
   `bitcoin::consensus::serialize`.
6. `transaction::parse_transaction` decodes one complete raw transaction.

`BuiltTransaction` includes the unsigned transaction, selected UTXOs in exact
input order, actual input-minus-output fee, and optional change output index.
There is no broadcast, RPC, persistence, address reservation or UTXO locking.
Applications must reserve change slots and prevent concurrent double spends.

## Selection and fees

`select_utxos` is a deterministic largest-first prefix selector, with outpoint
ordering as a tie-breaker. Its target is a caller-supplied amount including any
fee. The builder independently repeats fee measurement as its prefix grows.
Selection is simple, not optimal or privacy-aware. Invalid candidates are
rejected rather than silently skipped; zero target returns an empty selection.

The builder measures real transaction templates with maximal DER signature
lengths and compressed public keys. Mixed inputs include witness marker/flag,
empty legacy witnesses, and CompactSize lengths via rust-bitcoin serialization.
All outputs retain caller order; change is appended. Version is 2, locktime 0,
sequence enables RBF without relative locktime. A rate of zero is accepted;
relay policy and fee-rate selection belong to the caller.

Once the selected prefix can fund recipients plus the no-change fee, the
builder measures the additional change output. It includes change only when
the remainder after that fee is positive and at least
`Script::minimal_non_dust()` (rust-bitcoin default policy: currently 546 sats
for P2PKH, 294 sats for P2WPKH). Otherwise the entire remainder becomes fee.
It does not add another input solely to avoid dust. Recipient dust is rejected;
recipient scripts otherwise remain caller-controlled. The change script must
be P2PKH or P2WPKH and should be derived by the caller from its own account.

The estimator is conservative, not exact after signing. Fees are not reduced
by rebuilding and resigning. The returned fee, not just the requested rate,
must be shown to the user, especially when no change is created.

## Signing and trust boundaries

Both supported types use deterministic ECDSA with SIGHASH_ALL. Legacy sighash
is delegated to `legacy_signature_hash`; native SegWit uses
`p2wpkh_signature_hash` (BIP-143), including the supplied previous-output amount.
The signer checks the derived compressed public key against the actual previous
script, checks outpoint/index alignment, verifies its generated signature,
and installs `[signature, public key]` in scriptSig or witness respectively.

`sign_transaction` signs one account's inputs on a clone: any failure leaves
the original untouched. It rejects duplicates, null outpoints, monetary-range
violations, mismatched input counts and outputs exceeding inputs.
`sign_input` is a lower-level primitive for an individual input and explicit
private key, including mixed-account transactions. It preserves other inputs
and is atomic on error, but does not validate the other inputs or total fee.
The caller must validate the complete transaction before using that primitive.

Neither function proves an outpoint exists, is unspent, or has the asserted
value/script. In particular legacy signatures do not commit to input amounts;
trusted previous transactions are essential. Network correctness of recipient
addresses must be checked before converting them to scripts. Scripts themselves
carry no network. No maximum fee policy is imposed by this library.

Only compressed P2PKH and native P2WPKH are supported. P2PK, P2SH-wrapped
SegWit, multisig, Taproot, PSBT and hardware signing are outside this phase.
Private-key conversions inherit rust-bitcoin/secp256k1 memory handling; this
phase does not claim guaranteed erasure of every temporary signing-key copy.

## Parsing and errors

The parser rejects inputs over 4,000,000 bytes before decoding, and delegates to
`consensus::encode::deserialize`, including rejection of trailing bytes.
Successful decoding means structurally valid encoding only: it is not chain,
script, full consensus, standardness or maximum transaction-weight validation.
Malformed-byte regression tests exercise truncations, invalid flags, enormous
CompactSize counts, trailing bytes and the outer size cap. These tests are not
a mathematical proof of panic freedom or a replacement for fuzzing dependencies.

Amounts and sums are bounded by MAX_MONEY, arithmetic and fee multiplication
are checked, and production Bitcoin code has no explicit unwrap/expect/panic
paths. Template signature bytes in `fee.rs` are deliberate sizing data, never
signatures returned for broadcast. Error messages contain no private material.

## Verification

`tests/bip143_vectors.rs` uses the official BIP-143 native P2WPKH SIGHASH_ALL
example: digest and witness are checked exactly. Full serialization is compared
with the published signed transaction after copying its pre-signed P2PK input
(which this crate does not sign). This is one applicable vector, not all BIP-143
script types/sighash modes.

`tests/transactions.rs` covers both signing types, signature verification and
output tampering, fee coverage, exact funding, dust thresholds, deterministic
selection, additional-input fees, invalid metadata, overflow, atomic failure,
parser corruption, and mixed 253-input serialization sizing.

Sources:
- https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
- https://docs.rs/bitcoin/0.32.102/bitcoin/
