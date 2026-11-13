<a id="top"></a>

<p align="center">
  <img src="https://umbera.app/brand/github-core-banner.png" alt="umbera/core — the cryptographic core of the Umbera messenger" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-8b6cff?style=flat-square"></a>
  <img alt="Rust" src="https://img.shields.io/badge/rust-1.91%2B-1f1d29?style=flat-square&logo=rust">
  <img alt="Kotlin Multiplatform" src="https://img.shields.io/badge/kotlin-multiplatform-1f1d29?style=flat-square&logo=kotlin">
  <img alt="Post-quantum" src="https://img.shields.io/badge/post--quantum-ML--KEM%20%C2%B7%20ML--DSA-6aa0ff?style=flat-square">
  <img alt="Tests: 114 passing" src="https://img.shields.io/badge/tests-114%20passing-5fd3a1?style=flat-square">
</p>

<p align="center">
  <a href="https://umbera.app"><img alt="Website" src="https://img.shields.io/badge/Website-8b6cff?style=for-the-badge"></a>
  <a href="https://apps.apple.com/app/id6805525799"><img alt="App Store" src="https://img.shields.io/badge/App%20Store-1f1d29?style=for-the-badge&logo=apple&logoColor=white"></a>
  <a href="https://play.google.com/store/apps/details?id=cc.umbera.app"><img alt="Google Play" src="https://img.shields.io/badge/Google%20Play-1f1d29?style=for-the-badge&logo=googleplay&logoColor=white"></a>
  <a href="https://x.com/umberaapp"><img alt="X" src="https://img.shields.io/badge/X-1f1d29?style=for-the-badge&logo=x&logoColor=white"></a>
</p>

<p align="center">
  <a href="docs/PROOF.md"><img alt="Proof" src="https://img.shields.io/badge/Proof-5fd3a1?style=for-the-badge"></a>
  <a href="docs/PROOF.md#1-messages"><img alt="Messages" src="https://img.shields.io/badge/Messages-2c6b55?style=for-the-badge"></a>
  <a href="docs/PROOF.md#2-group-chats"><img alt="Groups" src="https://img.shields.io/badge/Groups-2c6b55?style=for-the-badge"></a>
  <a href="docs/PROOF.md#3-calls"><img alt="Calls" src="https://img.shields.io/badge/Calls-2c6b55?style=for-the-badge"></a>
  <a href="docs/PROOF.md#run-it-yourself"><img alt="Run the tests" src="https://img.shields.io/badge/Run%20the%20tests-2c6b55?style=for-the-badge"></a>
</p>

<p align="center">
  <a href="docs/PROTOCOL.md"><img alt="Protocol" src="https://img.shields.io/badge/Protocol-6aa0ff?style=for-the-badge"></a>
  <a href="core"><img alt="Rust core" src="https://img.shields.io/badge/Rust%20core-1f1d29?style=for-the-badge&logo=rust&logoColor=white"></a>
  <a href="kotlin"><img alt="Kotlin layer" src="https://img.shields.io/badge/Kotlin%20layer-1f1d29?style=for-the-badge&logo=kotlin&logoColor=white"></a>
  <a href="SECURITY.md"><img alt="Security" src="https://img.shields.io/badge/Security-1f1d29?style=for-the-badge"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/License-1f1d29?style=for-the-badge"></a>
</p>

---

**Umbera** is a private messenger built on one rule: *the server should never know who talks to whom.*
This repository contains the code that enforces that rule — the cryptographic core that runs on every
Umbera device. It is open source under the Apache License 2.0, so that anyone can read it, run its tests, check our
claims and reuse it.

> No phone number. No email. Post-quantum end-to-end encryption. Sealed sender.
> A relay that moves padded ciphertext between rotating mailbox addresses and learns nothing else.

## Contents

| This page | Proof | Protocol specification |
|---|---|---|
| [Why this repository exists](#why-this-repository-exists) · [Post-quantum status](#post-quantum-status-210--desktop-100) | [The claims](docs/PROOF.md#the-claims) | [What the relay sees](docs/PROTOCOL.md#2-what-the-relay-sees) |
| [Architecture](#architecture) | [Assumptions](docs/PROOF.md#assumptions) | [Hybrid key agreement](docs/PROTOCOL.md#4-hybrid-key-agreement) |
| [How a message travels](#how-a-message-travels) | [Messages](docs/PROOF.md#1-messages) · [Groups](docs/PROOF.md#2-group-chats) | [Double Ratchet](docs/PROTOCOL.md#5-one-to-one-sessions-double-ratchet) |
| [Cryptographic primitives](#cryptographic-primitives) | [Calls](docs/PROOF.md#3-calls) | [Sealed sender](docs/PROTOCOL.md#6-sealed-sender) |
| [Repository layout](#repository-layout) | [Run the tests](docs/PROOF.md#run-it-yourself) | [Rendezvous addressing](docs/PROTOCOL.md#7-rendezvous-addressing) |
| [Build and test](#build-and-test) | [Verify a call with Wireshark](docs/PROOF.md#verify-it-with-a-packet-capture) | [Groups: MLS](docs/PROTOCOL.md#12-groups-mls) |
| [Security](#security) | [Report a flaw](docs/PROOF.md#found-a-flaw) | [Key transparency](docs/PROTOCOL.md#14-key-transparency) |
| [Help us review it](#help-us-review-it) | | [All sections](docs/PROTOCOL.md#contents) |
| [Contact](#contact) | | |
| [License](#license) | | |

## Why this repository exists

A messenger that promises privacy should not ask to be trusted blindly. Everything that decides what
the server can or cannot learn lives on the device, and that code is here:

| | |
|---|---|
| **Key agreement** | Hybrid X25519 + ML-KEM-1024 (CRYSTALS-Kyber). An attacker must break both to read a message. |
| **Signatures** | Hybrid classical + ML-DSA-65 (CRYSTALS-Dilithium) identity keys. |
| **1:1 sessions** | Double Ratchet: forward secrecy and break-in recovery for every conversation. |
| **Sealed sender** | The sender's identity is encrypted inside the message, never visible to the relay. |
| **Rendezvous** | Mailbox addresses derived by both peers from a shared secret, rotated weekly. |
| **Groups** | MLS (RFC 9420) with the X-Wing cipher suite (X25519 + ML-KEM-768), ML-DSA-65 signed commits and a cryptographically enforced member cap. |
| **Calls** | A second layer on every call frame with keys from an X25519 + ML-KEM-1024 exchange per call, in addition to WebRTC's DTLS-SRTP. |
| **Linked devices** | A computer is linked to the phone by QR code with X25519 + ML-KEM-1024 session keys and a certificate signed with secp256k1 and ML-DSA-65. |
| **Abuse reports** | Asymmetric message franking: a recipient can prove to a moderator who sent an abusive message, while the relay never reads traffic. |
| **Attachments** | A fresh key per file, a derived key per 256 KiB chunk, encrypted metadata. |
| **Key transparency** | Merkle inclusion proofs that let clients detect a server substituting someone's keys. |

The server, billing and application UI are not part of this repository. None of them can change the
guarantees above, because the relay only ever handles data that this code has already encrypted.

<p align="right"><a href="#top">↑ Back to top</a></p>

## Post-quantum status (2.1.0 / Desktop 1.0.0)

Umbera 2.1.0 (Android, iOS) and Umbera Desktop 1.0.0 (Windows, macOS, Linux) combine a classical algorithm
with a NIST post-quantum algorithm in every end-to-end layer: 1:1 envelopes and file keys
(X25519 + ML-KEM-1024), group key schedule (MLS with X-Wing, X25519 + ML-KEM-768), group commits
(ML-DSA-65), a second encryption layer on call frames (X25519 + ML-KEM-1024 per call), linking a computer
by QR code, messages between linked devices, and Communities. Each mechanism, its code (file and line)
and the test that checks it are listed in [**docs/PQ_STATUS.md**](docs/PQ_STATUS.md); the changes of this
release are in [CHANGELOG.md](CHANGELOG.md).

Check it yourself:

```bash
cd core
cargo test --release                                  # whole Rust suite
cargo test --release --lib xwing_                     # X-Wing groups
cargo test --release --test compat_v06                # new core against the previous core (OpenMLS 0.6)
cargo test --release --lib callkey::                  # call frame keys
cargo test --release --lib devlink::                  # QR linking, device certificates
cargo test --release --lib sealv3::                   # envelope v3 vectors shared with Kotlin

cd ../communities/pqc
go test -v ./...                                      # Communities vectors (Go reference)
```

<p align="right"><a href="#top">↑ Back to top</a></p>

## Architecture

<p align="center">
  <img src="docs/assets/architecture.svg" alt="Architecture: apps, protocol layer, Rust core, blind relay" width="100%">
</p>

The Rust crate in [`core/`](core) is compiled once and shared by Android, iOS and the desktop app
through [UniFFI](https://github.com/mozilla/uniffi-rs). The protocol layer in [`kotlin/`](kotlin) is Kotlin
Multiplatform code built on top of it.

<p align="right"><a href="#top">↑ Back to top</a></p>

## How a message travels

<p align="center">
  <img src="docs/assets/sealed-sender.svg" alt="Sealed sender flow" width="100%">
</p>

1. The message is encrypted with the conversation's **Double Ratchet** session.
2. It is wrapped together with the sender's identity into an **inner package**.
3. The inner package is **sealed** to the recipient with a fresh ephemeral X25519 key and an ML-KEM-1024
   encapsulation; both secrets feed one HKDF, so the seal holds if either primitive survives.
4. The result is **padded** to a fixed size bucket so length reveals little.
5. It is delivered to a **rendezvous address** that only the two peers can compute:

<p align="center">
  <img src="docs/assets/rendezvous.svg" alt="Rendezvous addressing" width="100%">
</p>

The full specification, including every wire format and domain-separation label, is in
[**docs/PROTOCOL.md**](docs/PROTOCOL.md).

> **Don't trust, verify.** [docs/PROOF.md](docs/PROOF.md) shows, with code references, runnable tests
> and a packet-capture procedure, that nobody but the recipient can read a message, nobody but the
> members can read a group chat and nobody but the participants can listen to a call.

<p align="right"><a href="#top">↑ Back to top</a></p>

## Cryptographic primitives

<p align="center">
  <img src="docs/assets/primitives.svg" alt="Cryptographic primitives" width="100%">
</p>

ML-KEM and ML-DSA are the NIST-standardised versions of CRYSTALS-Kyber (FIPS 203) and CRYSTALS-Dilithium
(FIPS 204). All primitives come from established open-source Rust implementations
([RustCrypto](https://github.com/RustCrypto), [dalek-cryptography](https://github.com/dalek-cryptography),
[OpenMLS](https://github.com/openmls/openmls)). Umbera does not implement its own ciphers.

<p align="right"><a href="#top">↑ Back to top</a></p>

## Repository layout

```
umbera-core/
├── core/                      Rust crate: primitives, MLS engine, device linking, call keys, franking
│   ├── src/
│   │   ├── primitives.rs      ML-KEM, ML-DSA, X25519, Ed25519, secp256k1, AES-GCM, KDFs
│   │   ├── lib.rs             MLS group engine exposed over UniFFI (X-Wing and the previous suite)
│   │   ├── provider.rs        OpenMLS crypto provider with the X-Wing KEM
│   │   ├── callkey.rs         X25519 + ML-KEM-1024 call frame keys
│   │   ├── sealv3.rs          envelope v3 known-answer vectors (test only)
│   │   ├── devlink/           linking a computer by QR code, device certificates, transfer package
│   │   ├── amf.rs             asymmetric message franking
│   │   └── pdf.rs             metadata removal for outgoing PDF files
│   ├── tests/                 proofs, compatibility with the previous core, vectors
│   └── fuzz/                  cargo-fuzz targets
├── kotlin/                    protocol layer (Kotlin Multiplatform)
│   └── src/
│       ├── commonMain/kotlin/app/umbera/core/
│       │   ├── crypto/        envelopes, ratchet, files, rendezvous, groups, safety number
│       │   ├── devices/       envelopes and addresses between linked devices
│       │   ├── meet/          meetings by link
│       │   ├── webrtc/        call frame encryption
│       │   └── util/          small helpers used by the protocol code
│       ├── desktopMain/       desktop call frame encryptor
│       └── commonTest/, desktopTest/   tests, published for review
├── communities/               Communities cryptography
│   ├── src/                   Kotlin client code
│   └── pqc/                   Go reference with known-answer vectors
└── docs/
    ├── PROTOCOL.md            protocol specification
    ├── PROOF.md               claims and how to check them
    ├── PQ_STATUS.md           post-quantum status, code and tests
    └── assets/                diagrams
```

<p align="right"><a href="#top">↑ Back to top</a></p>

## Build and test

The Rust core builds and tests on any platform with a stable toolchain (Rust 1.91 or newer):

```bash
cd core
cargo test --release
```

```
test result: ok. 63 passed; 0 failed     (unit tests: primitives, MLS, X-Wing, call keys, device linking, envelope v3)
test result: ok. 21 passed; 0 failed     (tests/compat_v06.rs: new core against the previous core)
test result: ok. 1 passed; 0 failed      (tests/golden_primitives.rs)
test result: ok. 9 passed; 0 failed      (tests/pcs_rekey.rs)
test result: ok. 4 passed; 0 failed      (tests/pq_small_stack.rs)
test result: ok. 7 passed; 0 failed      (tests/proof.rs)
test result: ok. 6 passed; 0 failed      (tests/proof_groups.rs)
test result: ok. 3 passed; 0 failed      (tests/xwing_short_key.rs)
```

The tests include known-answer vectors for every primitive and end-to-end checks of ML-KEM-1024 and
ML-DSA-65 key generation, encapsulation, signing and verification. The Communities vectors are checked
by the Go reference (Go 1.27):

```bash
cd communities/pqc
go test ./...
```

To fuzz the parsers (franking, MLS Welcome and incoming messages, device linking, call keys, PDF):

```bash
cargo install cargo-fuzz
cd core/fuzz && cargo +nightly fuzz run amf_parse      # or mls_welcome, mls_incoming, devlink, callkey, pdf_strip
```

The Kotlin sources in [`kotlin/`](kotlin) are the protocol layer exactly as it ships in the apps and are
published for review. See [kotlin/README.md](kotlin/README.md).

<p align="right"><a href="#top">↑ Back to top</a></p>

## Security

Found a vulnerability? Please report it privately — see [SECURITY.md](SECURITY.md). We answer every report.

## Help us review it

**What is verified and what is not.** Every primitive has known-answer tests and the end-to-end tests above
pass on every change. The protocol has **not yet had an independent third-party audit.** Until it has, treat
it as reviewed by its authors and by whoever reads this code — and we would very much like that to be you.

- **Cryptographers:** read [docs/PROTOCOL.md](docs/PROTOCOL.md) and try to break it. Private reports go to
  [SECURITY.md](SECURITY.md); everyone who finds a real issue is credited there.
- **Questions and ideas:** use [Discussions](https://github.com/UmberaAPP/UMBERA/discussions).
- **Small, well-defined tasks:** see issues labelled
  [good first issue](https://github.com/UmberaAPP/UMBERA/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22).
  Pull requests are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

<p align="right"><a href="#top">↑ Back to top</a></p>

## Contact

| | |
|---|---|
| Questions, partnerships, licensing | [info@umbera.app](mailto:info@umbera.app) |
| Abuse reports | [abuse@umbera.app](mailto:abuse@umbera.app) |
| Security issues | see [SECURITY.md](SECURITY.md) |

<p align="right"><a href="#top">↑ Back to top</a></p>

## License

**Open source.** The cryptographic core in this repository is licensed under the
[Apache License 2.0](LICENSE): you may use, modify and redistribute it, including in commercial products,
as long as you keep the copyright and license notices. The Umbera apps, server and billing are separate
and are not part of this repository.

"Umbera" and the eclipse logo are trademarks of Umbera and are not covered by the license.
See [NOTICE.md](NOTICE.md).

<p align="right"><a href="#top">↑ Back to top</a></p>

<p align="center"><sub>© 2026 Umbera · <a href="https://umbera.app">umbera.app</a></sub></p>
