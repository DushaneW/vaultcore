# Contributing

Keep pull requests focused on one behavior or defect. Discuss API changes in an
issue before broad refactoring. The public API is pre-1.0 and may change.

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --release --locked
cargo run --locked -p vaultcore-bitcoin --example offline_transaction
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
```

The last command uses POSIX-shell environment syntax. In PowerShell set
`$env:RUSTDOCFLAGS = "-D warnings"` before running `cargo doc`.

## Engineering expectations

- Use upstream cryptographic and consensus implementations. Do not introduce
  custom cryptographic primitives.
- Validate at API boundaries and return meaningful errors. Never log secrets.
- Preserve atomic signing: a failed operation must not leave partial mutations.
- Keep monetary arithmetic checked and test behavior at relevant boundaries.
- Add public reference vectors or regression fixtures for behavior changes.
  Use synthetic values; never use live wallet credentials.
- Keep `Cargo.lock` committed. Review dependency and lockfile changes together.
  `zeroize` is deliberately pinned; read docs/crypto-core.md before changing it.
- Update docs and CHANGELOG.md when the public contract changes.
- Bitcoin production code forbids unsafe code and denies explicit unwrap,
  expect and panic through Clippy. Tests may use assertions and unwrap.

Describe why the change is needed, its resulting behavior and the checks
actually run. Test success does not substitute for review of signing logic.
