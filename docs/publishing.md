# Publish as DushaneW/vaultcore

The package contains repository files, including the hidden `.github` directory.
No remote repository has been created by preparing this archive.

## First push using Git

1. Sign in to https://github.com/new and choose owner `DushaneW`, repository
   name `vaultcore`, and the visibility you want. Leave initialization with a
   README, .gitignore and license unchecked: these files are already included.
2. Open a terminal in the extracted `vaultcore` directory (where Cargo.toml is).
3. Run:

```sh
git init -b main
git add .
git diff --cached --stat
git commit -m "feat: add offline Bitcoin wallet core and transaction pipeline"
git remote add origin https://github.com/DushaneW/vaultcore.git
git push -u origin main
```

Configure your own Git author name and email if Git prompts for them. Authenticate
through your local Git credential manager or GitHub CLI; never put tokens in
source files or share them in a chat. The commands above assume a new repository.
If `vaultcore` already exists, clone it and review the imported changes instead;
do not force-push over existing history.

With an authenticated GitHub CLI, step 1 and the remote/push steps can instead
be performed after the local commit with:

```sh
gh repo create DushaneW/vaultcore --private --source=. --remote=origin --push
```

This alternative creates a private repository. Change visibility only when you
intend to publish the code publicly.

## Repository presentation

Suggested description:

> Offline Bitcoin wallet primitives in Rust: BIP-32/39/44/84, measured fees, UTXO selection and P2PKH/P2WPKH signing.

Suggested topics:
`rust`, `bitcoin`, `wallet`, `bip32`, `bip39`, `bip84`, `segwit`, `cryptography`.

## After the first push

- Inspect Actions and allow the first CI run to finish. Windows/macOS and hosted
  runners have not been exercised merely by local package preparation.
- Create a main-branch ruleset requiring pull requests and passing CI if your
  repository plan supports it. CODEOWNERS routes reviews; it does not enforce
  approvals by itself. A solo-maintained repository may need zero mandatory
  external approvals until another reviewer is available.
- Enable private vulnerability reporting in Security settings before inviting
  confidential reports. Enable Dependabot alerts where available.
- Set repository Actions permissions to read-only by default (also set in CI).
- Do not create a production-ready release claim based only on passing tests.

The archive includes source and configuration, not compiled binaries, Git
history, account credentials or automatic repository-settings changes.
