# Security policy

VaultCore is experimental, pre-1.0 wallet infrastructure. It has not received an
independent security audit. Only the current development branch is maintained;
there are no supported release branches yet.

## Reporting

Use GitHub's **Security → Report a vulnerability** when private vulnerability
reporting is enabled for this repository. Never put exploit details, private
keys, recovery phrases or wallet data into a public issue.

If that option is unavailable, open an issue requesting a private contact
channel without disclosing the vulnerability. Response times are not guaranteed.

## Boundaries

The library derives keys and signs transactions offline. It does not establish
that UTXOs exist, authenticate RPC responses, validate full Bitcoin consensus,
reserve addresses, prevent concurrent spending or broadcast transactions.
Applications must authenticate prevouts and approve recipients and actual fees.

The parser accepts structural encodings; it is not a transaction-validity oracle.
Tests include official BIP vectors and malformed fixtures, not a complete fuzz
campaign. Secret erasure is best-effort within the documented dependency limits.
See docs/crypto-core.md and docs/bitcoin.md for implementation details.
