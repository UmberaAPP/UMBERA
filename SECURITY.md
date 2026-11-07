# Security Policy

Umbera exists to protect people's conversations. If you find a weakness in this code, we want to hear
about it before anyone else does.

## Reporting a vulnerability

E-mail **info@umbera.app** with the subject line `SECURITY`. Please include:

- the affected file and function,
- a description of the issue and its impact,
- steps or a proof of concept to reproduce it.

Please do **not** open a public issue for security problems.

## What to expect

| | |
|---|---|
| Acknowledgement | within 72 hours |
| Initial assessment | within 7 days |
| Fix for confirmed critical issues | as fast as possible, usually within 30 days |
| Credit | in the release notes, if you wish |

## Scope

In scope: everything in this repository — the Rust core, the Kotlin protocol layer and the protocol
specification in [docs/PROTOCOL.md](docs/PROTOCOL.md).

Out of scope: denial of service, social engineering, issues that require a compromised device
operating system, and third-party services.

## Review the cryptography

We invite cryptographers and security researchers to review the protocol in
[docs/PROTOCOL.md](docs/PROTOCOL.md) and the code in this repository. The protocol has not yet had an
independent third-party audit, so every careful read helps. Interesting places to start: the hybrid
X25519 + ML-KEM-1024 key agreement, sealed sender, rendezvous address rotation and message franking.

There is **no paid bug bounty yet.** Every confirmed finding is credited below (with your name or
handle, or anonymously if you prefer) and in the release notes.

## Hall of Fame

_No reports yet — your name could be the first._

## Safe harbour

We will not pursue legal action against researchers who act in good faith, avoid privacy violations
and service disruption, and give us reasonable time to fix an issue before disclosure.
