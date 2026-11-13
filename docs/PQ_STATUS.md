# Post-quantum status

Applies to **Umbera 2.1.0** (Android and iOS) and **Umbera Desktop 1.0.0** (Windows, macOS, Linux), released 13 November 2026.

This page lists every place where the apps use post-quantum cryptography today, which algorithm is used,
where the code is, and which test checks it. Every row describes shipped code. When a row depends on the
other side running the new version, the "Older apps" column says what happens instead.

**What "post-quantum" means on this page.** The end-to-end layers listed below combine a classical algorithm
with a NIST post-quantum algorithm (ML-KEM, FIPS 203; ML-DSA, FIPS 204). Both secrets go into one key
derivation, so an attacker has to break *both* to read or forge anything. The table covers the end-to-end
encryption between devices. It does not describe the transport connection to the server.

Paths are relative to this repository. Line numbers refer to the files as published in this commit.
`kotlin/...` stands for `kotlin/src/commonMain/kotlin/app/umbera/core`, `communities/...` for
`communities/src/commonMain/kotlin/app/umbera/communities`.

## Algorithms

| Name | Standard | Used for |
|---|---|---|
| ML-KEM-1024 | FIPS 203 | 1:1 envelopes, file keys, ratchet, call frame keys, device linking, device envelopes, Communities |
| X-Wing (X25519 + ML-KEM-768) | MLS cipher suite `MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519` (0x004D) | Group key schedule (MLS, RFC 9420) |
| ML-DSA-65 | FIPS 204 | Account and device identity, group commits, device certificates, Communities |
| X25519, Ed25519, secp256k1 | classical half of each hybrid | — |
| AES-256-GCM, ChaCha20-Poly1305, HKDF-SHA256, SHA-256 | symmetric | bulk encryption and key derivation |
| AES-128-GCM, PBKDF2-HMAC-SHA256 | symmetric, WebRTC frame-encryptor format | call frames (row 8); the key is derived from the 256-bit hybrid exchange output |

Implementations: RustCrypto `ml-kem` 0.3 and `ml-dsa` 0.1 for ML-KEM-1024 / ML-DSA-65; X-Wing KEM from
`openmls_libcrux_crypto` 0.4 inside OpenMLS 0.9.2 (all other MLS primitives stay on RustCrypto, byte-identical
to the previous suite). The same Rust core is compiled for Android, iOS, Windows, macOS and Linux.

## Mechanisms

| # | What is protected | Algorithm | Code | Tests | Older apps (2.0.x) |
|---|---|---|---|---|---|
| 1 | **1:1 messages: sealed envelope** (hides the sender, carries the ratchet message) | Full envelope v3: ephemeral X25519 + ML-KEM-1024, HKDF salted with the transcript hash (both public keys and the KEM ciphertext), AES-256-GCM. Short envelope v3s (up to 49 per full one, max 24 h): fresh ephemeral X25519 + a one-way chain from the last confirmed full envelope's hybrid pair secret | `kotlin/.../crypto/SealV3.kt:97-144`, `kotlin/.../crypto/HybridKeyExchange.kt:290` | Kotlin `SealV3Test` (18), `SealV3Replay1211Test` (3); Rust `core/src/sealv3.rs::kat_matches_kotlin` (Rust and Kotlin produce identical bytes) | Envelope v2: X25519 + ML-KEM-1024 in every message, unchanged |
| 2 | **1:1 messages: Double Ratchet** | X25519 ratchet; an ML-KEM-1024 shared secret is mixed into the root key on session start and again every 20 new chains or every 24 h (`root+mlkem1024`) | `kotlin/.../crypto/DoubleRatchet.kt:461`, `:495`, `:576` | Kotlin `PqRatchetTest` (8), including `x25519_secrets_alone_do_not_open_a_pq_session` | Same (2.0.x already speaks this ratchet version) |
| 3 | **Files and photos in 1:1** | File key wrapped with X25519 + ML-KEM-1024, transcript-bound (file wrap v2); content AES-256-GCM | `kotlin/.../crypto/SealV3.kt:129-135` | Kotlin `SealV3Test.fileWrapV2`, `katMatchesRust` | File wrap v1: X25519 + ML-KEM-1024 without transcript binding |
| 4 | **Mailbox addresses for 1:1** (where the relay stores a chat's envelopes) | Address derived from a direction secret of the hybrid v3 exchange; changes every week, at the same moment for everyone | `kotlin/.../crypto/RendezvousV2.kt:35-39`, `kotlin/.../crypto/SealV3.kt:113` | Kotlin `SealV3Test.rendezvousV2Handshake`, `rendezvousEpoch*` | Previous address scheme, unchanged |
| 5 | **Group chats: key schedule** | MLS with X-Wing (X25519 + ML-KEM-768). New groups are created on X-Wing. An existing group moves to X-Wing by itself once every member supports it, keeping the same group, members and history | `core/src/provider.rs:27-29`, `:122-185`; `core/src/lib.rs:126-163`, `:497`, `:530` | Rust `xwing_group_full_life`, `suites_do_not_mix`, `regroup_to_xwing_keeps_leaf_signature_keys`, `xwing_hundred_leaves_and_sizes`, `core/tests/xwing_short_key.rs` (3), `core/tests/pcs_rekey.rs` `*_xwing` (4); Kotlin `MlsXwingRegroupTest` (5) | A group that includes a 2.0.x member uses the previous suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. Every group packet still travels to each member inside that member's hybrid envelope (rows 1-2). Rust `old_core_rejects_xwing_key_package_and_takes_legacy_one`, `mixed_group_*` |
| 6 | **Group chats: who changed the group** | ML-DSA-65 signature over every Commit, Proposal and Welcome, on top of the MLS Ed25519 signature. Application messages: per-sender hash chain (32 bytes each) plus one ML-DSA-65 checkpoint every 20 messages or after 30 s of silence | `kotlin/.../crypto/GroupPqSig.kt:57-60`, `:131` | Kotlin `GroupPqSigTest` (29), including `forkIsViolated`, `substitutedMiddleFrameIsViolated`, `commitSignature` | 2.0.x members do not sign; their commits are accepted as before. Once a member's new-version signature is seen, unsigned commits from that member are refused |
| 7 | **Group chats: regular key refresh** | Each device updates its own MLS leaf every 7 days (±12 h), after 100 own packets, or after a long idle period | `kotlin/.../crypto/mls/GroupRekeyPolicy.kt` | Rust `core/tests/pcs_rekey.rs` (9), `compat_v06::periodic_self_updates_with_old_members`; Kotlin `MlsRekeyTest` (5) | Old members apply these commits normally |
| 8 | **1:1 calls: audio, video, screen sharing** | Second encryption layer on every media frame. Keys come from a fresh X25519 + ML-KEM-1024 exchange per call, carried inside the end-to-end encrypted call signal (`a=x-umbera-pq` in the SDP). Frames: AES-128-GCM in the WebRTC frame-encryptor format, key = PBKDF2-HMAC-SHA256 (100 000 rounds) of the 256-bit exchange output, separate key per direction. Runs in addition to WebRTC's own DTLS-SRTP | `core/src/callkey.rs:97`, `:114`, `:136`; `kotlin/.../webrtc/CallFrameE2ee.kt:23-87`; desktop frame transform `kotlin/src/desktopMain/.../webrtc/PcFrameCryptor.kt` | Rust `callkey::both_sides_get_the_same_directional_keys`, `tampering_changes_keys_or_fails`; Kotlin `DesktopCallPqLoopbackTest` (5) on a real WebRTC loopback: frames pass through the layer, a wrong key drops every frame, an old peer still connects | A 2.0.x peer does not send the attribute; the call runs without the second layer (DTLS-SRTP only) |
| 9 | **Call signalling** (offer, answer, ICE, hang-up) | Inside the 1:1 hybrid envelope (row 1). New format `callsig-v2`: one signed, compressed body in one v3 envelope | `kotlin/.../crypto/CallSigV2.kt:22` | Kotlin `CallSigV2Test` (9) | Previous signalling format, still inside the hybrid envelope |
| 10 | **Group conferences** (calls started from a group) | Each pair of participants runs its own X25519 + ML-KEM-1024 exchange (row 8) | `kotlin/.../webrtc/CallFrameE2ee.kt:52` | Kotlin `DesktopCallPqLoopbackTest.conferenceLegUsesItsOwnExchange` | Pairs with a 2.0.x participant run without the second layer |
| 11 | **Meetings by link** | A 256-bit room key lives only in the link fragment (after `#`) and never reaches the server; room description and signals: AES-256-GCM under HKDF-derived keys. Media: per-pair X25519 + ML-KEM-1024 frame keys (row 8) | `kotlin/.../meet/MeetCrypto.kt:28-73`, `kotlin/.../meet/MeetLink.kt` | Kotlin `MeetLinkCryptoTest` (7), `DesktopCallPqLoopbackTest.conferenceLegUsesItsOwnExchange` | Meeting links need 2.1.0 or Desktop 1.0.0 |
| 12 | **Linking a computer to the phone (QR)** | QR carries the computer's X25519 key and a hash of its ML-KEM-1024 key. Session keys: HKDF over X25519 ‖ ML-KEM-1024 with the full transcript as salt; key confirmation in both directions; 6-digit code compared on both screens; transfer blobs under AES-256-GCM. QR valid 60 s, confirmation 180 s | `core/src/devlink/session.rs:196-215`, `:425-500`; `core/src/devlink/package.rs` | Rust `devlink::tests` (26), including `mitm_with_substituted_desktop_keys_shows_different_codes`, `substituted_offer_is_rejected_by_phone`, `tampered_blob_kills_session`, `vectors_match_file`; Kotlin `DeviceLinkDesktopTest` (5) | Linking needs 2.1.0 on the phone |
| 13 | **Device identity and certificate** | The computer has its own keys (Ed25519 + ML-DSA-65, X25519 + ML-KEM-1024) from its own seed. The phone certifies them with the account's secp256k1 **and** ML-DSA-65 keys; apps reject a device without both signatures. Account keys never leave the phone | `core/src/devlink/cert.rs:397-460` | Rust `devlink::tests::certificate_checks`, `device_request_bound_to_its_link`, `server_keys_digest_vector` | — |
| 14 | **Messages to and between linked devices** (messages, copies of your sent messages, call control) | Per-device envelope: ephemeral X25519 + ML-KEM-1024 to the receiving device, AES-256-GCM, transcript-bound; body signed with both halves of the sender device's hybrid key; inside, a per-device-pair ratchet (row 2) | `kotlin/.../devices/DeviceEnvelope.kt:169-235`, `kotlin/.../devices/DeviceRidEpochs.kt` | Kotlin `DeviceMeshTest` (8), `DeviceRidEpochTest` (10) | — |
| 15 | **Moving a call between your devices** | The hand-over request travels in the device envelope (row 14); the call on the new device runs its own fresh exchange (row 8) | row 14 + row 8 | rows 8 and 14 | Not offered when the other person runs 2.0.x |
| 16 | **Group membership of a linked computer** | The computer joins each group as its own MLS leaf (never a copy of the phone's state); the phone/computer pairing inside a group is signed by both leaves | `core/src/devlink/mlsjoin.rs` | Rust `desktop_joins_mls_group_as_its_own_leaf`, `devlink_pc_joins_group_with_old_phones` | Works with 2.0.x members (group capped at 20 leaves while they are present) |
| 17 | **Communities** | Signatures: Ed25519 **and** ML-DSA-65 on every request and on every post in private channels. Encryption to a key: X25519 + ML-KEM-1024. Membership vault keys: derived from the account's X25519 secret and ML-KEM seed | `communities/.../crypto/CommCrypto.kt:113-140`; vault roots `core/src/devlink/comm.rs` | Go `communities/pqc` `TestVectorsFile`, `TestHybridNegatives` (fixed vectors `communities/pqc/testdata/pq-vectors.json`); Rust `devlink::tests::comm_vault_root_matches_communities_vectors` | Same format since Communities launched |
| 18 | **Safety number** | Safety number v2 covers secp256k1, X25519, ML-DSA-65 and ML-KEM-1024 keys | `kotlin/.../crypto/SafetyNumber.kt:51` | Kotlin `SafetyNumberV2Test` (6), `SafetyNumberNegotiationTest` (10) | With 2.0.x contacts the previous safety number is shown |
| 19 | **Recovery phrase** | The 12-word phrase deterministically derives every account key, including the ML-KEM-1024 and ML-DSA-65 keys (HKDF-SHA256, a separate context per key) | `kotlin/.../crypto/RecoverySeed.kt:89-107` | No dedicated test in this repository | Same derivation as 2.0.x |

### Downgrade protection

A new format (hybrid envelope v3, ratchet, frame layer, X-Wing, group signatures, safety number v2) is sent to
a contact only after that contact has announced support inside an end-to-end encrypted message. Once
announced, the capability is pinned. If a later message from the same contact lacks it, the app shows "key changed"
instead of quietly falling back. Kotlin `PeerCryptoCapsPinTest` (15), including `call_layer_and_xwing_pins`.

### Size cost (measured by the tests)

| Item | Bytes |
|---|---|
| 1:1 envelope v2 (previous, 40-character text, JSON) | 21 682 |
| 1:1 full envelope v3 | 5 038 |
| 1:1 short envelope v3s | 3 078 |
| Average over 50 envelopes (1 full + 49 short) | 3 117 |
| Group: ML-DSA-65 on a Commit / Proposal | +4 429 |
| Group: application message (hash chain + checkpoint every 20) | about +275 on average |
| X-Wing KeyPackage | 2 650 |
| X-Wing Welcome for 100 leaves | 268 368 |
| X-Wing Commit with update path, 100 leaves | 126 054 |
| Call: X25519 + ML-KEM-1024 per call, each direction | 1 601 (+ base64 in the SDP) |
| Call frame layer on desktop, encrypt + decrypt | about 0.46 ms per frame (loopback test) |

## How to verify

Rust core (all platforms share it):

```bash
git clone https://github.com/UmberaAPP/UMBERA
cd UMBERA/core
cargo test --release                      # whole suite, 114 tests

cargo test --release --lib xwing_         # X-Wing groups
cargo test --release --lib suites_do_not_mix
cargo test --release --lib regroup_to_xwing_keeps_leaf_signature_keys
cargo test --release --lib xwing_hundred_leaves_and_sizes -- --nocapture   # prints the X-Wing sizes
cargo test --release --test xwing_short_key
cargo test --release --test pcs_rekey
cargo test --release --test compat_v06    # new core against the previous core (OpenMLS 0.6)

cargo test --release --lib callkey::      # call frame keys
cargo test --release --lib devlink::      # QR linking, certificates, transfer package, MLS leaf
cargo test --release --lib sealv3::       # envelope v3 known-answer vectors, shared with Kotlin
cargo test --release --lib pq_tests       # ML-KEM-1024 and ML-DSA-65 known answers
```

Expected: `test result: ok` for every binary, 114 passed in total (101 for the mechanisms above, plus
13 in `tests/proof.rs` and `tests/proof_groups.rs`).

Communities vectors (Go reference implementation of the same formats):

```bash
cd UMBERA/communities/pqc
go test -v ./...
```

The Kotlin tests named in the table are part of the app build (they need the platform bindings to the Rust
core). Their sources are in `kotlin/src/commonTest` and `kotlin/src/desktopTest` for review.

Results of our own run for this release (13 November 2026):

| Suite | Result |
|---|---|
| Rust core, `cargo test --release` | 114 passed, 0 failed |
| Kotlin, the 15 test classes named above | 143 passed, 0 failed |
| Go Communities vectors, `go test ./...` | 2 passed, 0 failed |

## Report a problem

If you find a case where the code does less than this page says, please open an issue or write to the
address in [SECURITY.md](../SECURITY.md).
