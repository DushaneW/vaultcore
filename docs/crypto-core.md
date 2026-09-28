# `vaultcore-crypto`: architecture and design decisions

This document explains what `vaultcore-crypto` does, why it is scoped the
way it is, and the specific decisions made while building it — including
the ones driven by constraints of the development environment rather than
by design preference. It is written for a reader auditing the crate, not as
a tutorial.

## Scope

`vaultcore-crypto` implements two things:

1. **BIP-39**: mnemonic generation, validation, and seed derivation.
2. **BIP-32**: hierarchical deterministic key derivation — derivation path
   parsing and walking a seed through a path to produce extended
   private/public keys.

It does not know about Bitcoin, Ethereum, addresses, or transactions. That
boundary is deliberate. BIP-32 and BIP-39 are shared by every chain this
project intends to support eventually (Bitcoin, EVM chains, and — per the
architecture — anything else with a `secp256k1` or compatible key
hierarchy). Letting a Bitcoin- or EVM-specific assumption leak into this
layer would force every downstream chain crate to route around it. Concretely,
this is why the crate does *not* expose BIP-32's Base58Check `xprv`/`xpub`
serialization: that wire format encodes Bitcoin-specific version bytes
(`0x0488ADE4` for mainnet `xprv`, etc.) as part of its four-byte version
prefix, and a chain-agnostic layer should not be in the business of picking
one chain's serialization convention as the default. `vaultcore-bitcoin`
(Phase 2) is where that belongs, if it turns out to be needed.

## No cryptographic primitives implemented here

Every cryptographic operation is delegated:

| Operation | Delegated to |
|---|---|
| Wordlist encoding/decoding, BIP-39 checksum | [`bip39`](https://docs.rs/bip39) v3.0 (the rust-bitcoin org's maintained crate) |
| PBKDF2-HMAC-SHA512 seed derivation | `bip39` (internally) |
| HMAC-SHA512 child-key tweaking, secp256k1 point arithmetic | [`bip32`](https://docs.rs/bip32) v0.5 (RustCrypto), backed by the pure-Rust `k256` implementation |
| CSPRNG for mnemonic entropy | `rand`'s `OsRng`, via `bip39`'s `rand` feature |
| Zeroizing returned buffers | [`zeroize`](https://docs.rs/zeroize) v1.7 |

This crate's own code is limited to: input validation (seed lengths,
derivation path syntax, child-index ranges), translating dependency error
types into this crate's own [`CryptoError`], and wrapping returned secret
material in `Zeroizing`. No HMAC, no SHA-2, no elliptic-curve arithmetic,
no Base58/checksum logic is implemented in this crate.

## Why `bip32` (RustCrypto) instead of the `bitcoin` crate

The obvious alternative for BIP-32 support is `bitcoin` (rust-bitcoin's
main crate), which bundles its own `bip32` module. It was deliberately not
used here, for the same chain-agnosticism reason given above: pulling in
`bitcoin` to get "just BIP-32" would mean this supposedly generic crate
transitively depends on Bitcoin script, transaction, and network-message
types it has no use for, and would set a precedent of reaching for
Bitcoin-flavored tooling by default in a layer meant to serve every chain
equally. The standalone `bip32` crate (RustCrypto) implements the same
algorithm, generically over any curve backend, with no Bitcoin-specific
code at all — which is exactly the shape this layer needs.

## Why wrap `bip32::DerivationPath` / `bip32::ChildNumber` instead of
## reimplementing path parsing

`bip32::DerivationPath`'s `FromStr` implementation already parses
`m/44'/60'/0'/0/0`-style notation correctly, including both `'` and `h` as
the hardened-index marker, and is exercised by that crate's own test suite.
Reimplementing that parser here would be duplicated logic with no
correctness benefit and a real chance of introducing a bug the upstream
crate doesn't have. `vaultcore_crypto::DerivationPath` and `ChildNumber`
are newtypes around the upstream types, for two concrete, non-cosmetic
reasons:

1. **Error-type consistency.** Every fallible operation in this crate
   returns `CryptoError`. Without a wrapper, path parsing would leak
   `bip32::Error` at the public boundary — a dependency's internal error
   type becoming part of this crate's API, and inconsistent with how
   `mnemonic.rs` and `keys.rs` already behave.
2. **A stable extension point.** Chain crates in later phases will want
   path constructors like `DerivationPath::bip44(coin_type, account,
   change, index)`. Adding those to a newtype this crate owns doesn't
   require patching or forking the upstream crate.

## Why `bip39` (rust-bitcoin) with explicit `OsRng`-backed generation

`bip39::Mnemonic::generate_in` is used directly (via the crate's `rand`
feature) rather than hand-rolling entropy generation and calling
`from_entropy`. The crate's generation path already draws from
`rand::rngs::OsRng` — the operating system's CSPRNG — which is the correct
source; adding a manual entropy-generation step around it would be
extra code with no security benefit, and more code to review is not a
neutral cost in a project whose stated goal is a small, auditable core.

## Zeroization: what is guaranteed and what isn't

**Guaranteed**, independent of any feature flag: the private scalar inside
an `ExtendedPrivateKey` is zeroized on drop. This comes from
`k256::ecdsa::SigningKey` (the concrete type `bip32::XPrv` derives keys as)
implementing `ZeroizeOnDrop` unconditionally, upstream, in the `ecdsa`
crate. This crate's code does not need to do anything for this to hold.

**Provided by this crate**: every method that returns secret bytes or text
this crate itself produces — `Mnemonic::phrase()`, `Mnemonic::to_seed()`,
`ExtendedPrivateKey::to_bytes()` — wraps the result in `zeroize::Zeroizing`,
so the value is scrubbed when the caller's copy goes out of scope.

**Not guaranteed, and documented as a limitation**: the word-index array
inside `bip39::Mnemonic` is not zeroized on drop in this build. The `bip39`
crate has a `zeroize` Cargo feature that would derive `Zeroize` /
`ZeroizeOnDrop` on `Mnemonic` automatically. It is not enabled here because
of a concrete toolchain constraint, not a design choice:

- The `zeroize` feature pulls in `zeroize_derive` at whatever version
  satisfies `zeroize`'s own dependency range (`^1.3`).
- The latest published `zeroize_derive` (1.5.0) declares `edition = "2024"`
  in its manifest, which requires Rust 1.85. Cargo's dependency resolver
  fails outright trying to even *read* that manifest on an older
  toolchain — it does not gracefully fall back to an older, compatible
  `zeroize_derive` version.
- The Rust toolchain available in this development environment is 1.75.0
  (Ubuntu 24.04's packaged `rustc`/`cargo`, installed via `apt`; `rustup`
  was not usable because its download domain is outside this sandbox's
  network allowlist).

The alternative — forcing a precise transitive pin of `zeroize_derive` to
an older version via `cargo update -p zeroize_derive --precise <ver>` —
was considered and rejected for this phase: it works, but it is a pin on a
dependency this crate does not use directly, motivated entirely by a local
toolchain limitation, and it would need to be re-verified as compatible
every time `bip39` or `zeroize` bump their version ranges. It's the kind of
fragile, easy-to-forget workaround that tends to silently break in CI.
**When CI is set up in a later phase pinning current stable Rust
(≥ 1.85), enabling `bip39`'s `zeroize` feature should be revisited** — at
that point it costs nothing and removes this limitation outright.

The practical exposure from this gap is narrow: the mnemonic's word-index
array (12–24 `u16` values, not the phrase text itself) can persist in
process memory after a `Mnemonic` is dropped, until that memory is reused.
It does not affect the private key, the chain code, or anything derived
downstream, all of which zeroize correctly as described above.

## Error design

`CryptoError` (in `src/error.rs`) is a single `#[non_exhaustive]` enum
covering both BIP-39 and BIP-32 failure modes, rather than one error type
per module. Every variant that carries a value (an offending length, index,
or path string) only does so when *this crate* observed that value before
constructing the error — never a placeholder. The one exception is
`CryptoError::Bip32(String)`, a deliberate catch-all for `bip32::Error`
variants that don't map to a more specific case; it's a defensive fallback
that should be rare in practice, since call sites validate what they can
before delegating to the dependency (e.g. `ExtendedPrivateKey::from_seed`
checks the seed length itself, so a `bip32::Error::SeedLength` should never
actually reach the `From` impl in `error.rs`).

No variant carries a mnemonic, seed, or private key — errors from this
crate are safe to log or print in full.

## Testing

- **Unit tests** (`src/*.rs`, `#[cfg(test)]`): behavioral coverage per
  module — valid/invalid inputs, round-trips, and the specific security
  properties called out in the module docs (e.g. that `ExtendedPublicKey`
  refuses hardened derivation, that `Debug` on `ExtendedPrivateKey`
  redacts secret fields).
- **Official test vectors** (`tests/`):
  - `bip39_vectors.rs` checks the English-wordlist rows of the standard
    BIP-39 test suite (trezor/python-mnemonic's `vectors.json`, which
    BIP-39 itself links to), covering entropy → mnemonic → seed with the
    fixed `"TREZOR"` passphrase.
  - `bip32_vectors.rs` checks official BIP-32 Test Vectors 1–3 (the
    `bitcoin/bips` reference vectors), including Test Vector 3's specific
    regression case for private keys with a leading zero byte — a bug
    class that has bitten multiple real implementations historically.
    Because the BIP publishes expected keys as Base58Check `xprv`/`xpub`
    strings and this crate deliberately doesn't expose that serialization
    (see above), the test decodes the official strings itself (via `bs58`,
    a dev-only dependency) and compares raw fields — it does not
    reimplement or bypass the checksum: `bs58`'s `check` feature verifies
    it as part of decoding.

All tests run on both `cargo test` and `cargo test --release`.
