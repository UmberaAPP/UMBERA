# umbera-core

The cryptographic core of the [Umbera](https://umbera.app) messenger, shared by the Android and iOS apps
through [UniFFI](https://github.com/mozilla/uniffi-rs).

- **Primitives:** ML-KEM-1024, ML-DSA-65, X25519, Ed25519, AES-256-GCM, HKDF-SHA256, Argon2id
  (from RustCrypto and dalek-cryptography; no custom ciphers)
- **Group messaging:** MLS (RFC 9420) on [OpenMLS](https://github.com/openmls/openmls), with a member cap
  enforced by every member on incoming Commits
- **Abuse reports:** asymmetric message franking
- **PDF metadata removal** for outgoing files

The 1:1 protocol (hybrid X25519 + ML-KEM-1024 sealing, sealed sender, Double Ratchet, rendezvous
addressing) and the full specification live in the repository:
<https://github.com/UmberaAPP/UMBERA> — see `docs/PROTOCOL.md` and `docs/PROOF.md`.

```bash
cargo test                       # all tests
cargo test --test proof          # 1:1 sealing proofs
cargo test --test proof_groups   # MLS group proofs
```

No independent audit yet; reviews are welcome (see `SECURITY.md` in the repository).

Licensed under the Apache License, Version 2.0.
