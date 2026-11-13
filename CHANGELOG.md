# Changelog

## Umbera 2.1.0 (Android, iOS) and Umbera Desktop 1.0.0 (Windows, macOS, Linux) — 13 November 2026

### Desktop app
- New app for Windows 10 and 11 (x64), macOS 12 and newer (Apple Silicon and Intel) and Linux with glibc 2.35
  and newer. Packages: `.msi`, `.dmg`, `.deb`, AppImage and an apt repository. Download: https://umbera.app/download
- The computer is linked to your phone; it does not create a separate account.
- The computer generates its own device keys from its own seed: Ed25519 + ML-DSA-65 for signing,
  X25519 + ML-KEM-1024 for encryption. The account keys never leave the phone.

### Linking a computer by QR code
- The QR code carries the computer's X25519 public key and a SHA-256 hash of its ML-KEM-1024 public key.
  The full ML-KEM key is sent separately and checked against that hash.
- Session keys: HKDF-SHA256 over the X25519 and ML-KEM-1024 shared secrets, salted with a hash of the whole
  transcript (QR, both public keys, KEM ciphertext). Both sides confirm the key with an HMAC before anything
  else is exchanged.
- Both screens show a 6-digit code derived from the same key. A substituted key gives different codes
  (test `mitm_with_substituted_desktop_keys_shows_different_codes`).
- The QR code is valid for 60 seconds; the code must be confirmed within 180 seconds.
- The phone certifies the computer's keys with the account's secp256k1 key and its ML-DSA-65 key. The apps
  accept a linked device only if both signatures verify.
- Contacts, chats and photos move to the computer in an AES-256-GCM stream under the session key, with
  part numbers, a total hash and an acknowledgement. Records are stored only after the whole package arrives.
- In groups, the computer joins as its own MLS member, linked to the phone by signatures of both leaves.
  It never copies the phone's group state.
- Code: `core/src/devlink/`. Tests: 26 Rust tests in `devlink::tests`, plus `compat_v06` cases with phones on
  the previous version.

### Sync between your own devices
- Messages to and from a linked computer, copies of what you send, and call control travel in a
  per-device envelope: ephemeral X25519 + ML-KEM-1024 to the receiving device, AES-256-GCM, signed with both
  halves of the sending device's hybrid key, with a Double Ratchet per device pair inside.
- The mailbox address for each pair of devices changes every week.

### Meetings by link
- Create a meeting and share a link. A 256-bit room key lives only in the part of the link after `#`, which
  is never sent to the server.
- Room details and in-room signals are encrypted with AES-256-GCM under keys derived from the room key.
- Audio, video and screen sharing between every pair of participants carry a second encryption layer with
  keys from a fresh X25519 + ML-KEM-1024 exchange for that pair.
- Meetings need Umbera 2.1.0 or Desktop 1.0.0.

### Calls
- Every call frame (audio, video, screen sharing) is encrypted a second time, in addition to WebRTC's
  DTLS-SRTP, with keys from a fresh X25519 + ML-KEM-1024 exchange per call. This applies to 1:1 calls, group
  conferences (one exchange per pair), meetings by link and moved calls. Now on Android, iOS and desktop.
- Move a call between your phone and computer without hanging up. The request travels in the device
  envelope; the call on the new device runs its own new exchange.
- Call signals use a new compact format (`callsig-v2`) inside the 1:1 hybrid envelope.

### Messages and groups
- 1:1 envelope v3: ephemeral X25519 + ML-KEM-1024, with the key bound to the transcript of the exchange.
  Short envelopes in between reuse a hybrid pair secret through a one-way chain. Average envelope size for
  a short text: 3 117 bytes, previously 21 682.
- File keys in 1:1 are wrapped the same way (file wrap v2).
- New groups use the MLS cipher suite X-Wing (X25519 + ML-KEM-768). Existing groups switch over by
  themselves once every member runs the new version, keeping members and history.
- Every group Commit, Proposal and Welcome carries an ML-DSA-65 signature on top of the MLS Ed25519
  signature. Messages carry a per-sender hash chain, with an ML-DSA-65 checkpoint every 20 messages.
- Each device refreshes its own group keys every 7 days, after 100 packets or after a long idle period.
- Safety number v2 covers the ML-DSA-65 and ML-KEM-1024 keys as well.

### Compatibility with 2.0.x
- New formats are used only with contacts who announced support inside an end-to-end encrypted message.
  With 2.0.x contacts, envelopes, calls and safety numbers stay exactly as before.
- A group that includes a 2.0.x member stays on the previous MLS cipher suite, and its packets still travel
  inside each member's hybrid envelope.
- Moving a call and meetings by link are not offered to 2.0.x.

### Verification
- Rust core: 114 tests pass (`cd core && cargo test --release`), including the new X-Wing, call key,
  device-linking and compatibility tests.
- Communities Go reference: `cd communities/pqc && go test ./...` passes against the fixed vectors.
- App-layer Kotlin tests for these features (15 classes, sources in `kotlin/src/commonTest` and
  `kotlin/src/desktopTest`): 143 pass in our build.
- Details and commands: [docs/PQ_STATUS.md](docs/PQ_STATUS.md).
