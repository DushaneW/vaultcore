# GitHub preparation review

Prepared for `DushaneW/vaultcore` on 2026-09-28. Publication and repository
settings remain under the owner's control; no remote was created or pushed.

## Changes beyond Phase 2

- English README with supported scope, architecture links and runnable example.
- MIT license matching existing Cargo metadata; repository URL set to DushaneW.
- GitHub Actions: formatting, Clippy, rustdoc, release tests, offline example,
  Linux/Windows/macOS matrix and Rust 1.75 compatibility job.
- Read-only workflow permissions, cancellation of superseded runs, timeouts,
  and checkout action pinned to the verified v4.2.2 commit.
- Dependabot updates, CODEOWNERS, issue/PR templates, contribution policy,
  security-reporting guidance, changelog and publishing instructions.
- EditorConfig, Git attributes and local credential exclusions.
- UTXO validation separated from ordering: signers avoid unnecessary cloning
  and sorting while preserving existing validation and atomic behavior.
- Bitcoin crate forbids unsafe code and denies explicit unwrap/expect/panic
  through Clippy outside tests.
- Public rustdoc links repaired in both crates. Crypto implementation is
  unchanged; its lib.rs documentation links changed. Cargo.lock is unchanged.

## Local verification

| Check | Result |
| --- | --- |
| Rust 1.75.0 workspace check, locked | Passed |
| Rust 1.75.0 release tests, locked | 68 passed |
| Rust 1.98.1 release tests, locked | 68 passed |
| rustfmt | Passed |
| Clippy, all workspace targets, warnings denied | Passed |
| rustdoc, warnings denied | Passed |
| Offline regtest example | Passed; no broadcasting |
| GitHub YAML parsing | Passed |
| Relative documentation links | Passed |

Checks ran locally on Linux. Windows, macOS and GitHub-hosted CI execution
remain unverified until the first hosted runs. No coverage percentage,
third-party audit, release or branch-protection enforcement is claimed.

The older phase review is a historical checkpoint. This review supersedes its
notes about an untested Rust 1.75 and byte-identical crypto source: Rust 1.75 is
now tested, and crypto changes are documentation-link fixes only.
