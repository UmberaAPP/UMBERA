# umbera-core

The cryptographic core of the [Umbera](https://umbera.app) messenger, shared by the Android, iOS and desktop apps
through [UniFFI](https://github.com/mozilla/uniffi-rs).

- **Primitives:** ML-KEM-1024, ML-DSA-65, X25519, Ed25519, AES-256-GCM, HKDF-SHA256, Argon2id
  (from RustCrypto and dalek-cryptography; no custom ciphers)
- **Group messaging:** MLS (RFC 9420) on [OpenMLS](https://github.com/openmls/openmls) 0.9.2. New groups use
  the X-Wing cipher suite `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (X25519 + ML-KEM-768); groups with
  members on the previous core stay on `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. The member cap is
  enforced by every member on incoming Commits
- **Call frame keys:** X25519 + ML-KEM-1024 exchange per call, separate key per direction (`callkey`)
- **Device linking:** linking a computer to the phone by QR code (X25519 + ML-KEM-1024 session keys,
  key confirmation, 6-digit comparison code), device certificates signed with secp256k1 and ML-DSA-65,
  transfer package, the computer's own MLS leaf (`devlink`)
- **Abuse reports:** asymmetric message franking
- **PDF metadata removal** for outgoing files

The 1:1 protocol (hybrid X25519 + ML-KEM-1024 sealing, sealed sender, Double Ratchet, rendezvous
addressing) and the full specification live in the repository:
<https://github.com/UmberaAPP/UMBERA> — see `docs/PROTOCOL.md` and `docs/PROOF.md`.

```bash
cargo test --release                       # all tests
cargo test --release --test proof          # 1:1 sealing proofs
cargo test --release --test proof_groups   # MLS group proofs
cargo test --release --test compat_v06     # new core against the previous core (OpenMLS 0.6)
```

Every post-quantum mechanism, with code references and tests: `docs/PQ_STATUS.md` in the repository.

No independent audit yet; reviews are welcome (see `SECURITY.md` in the repository).

Licensed under the Apache License, Version 2.0.
