# Protocol layer (Kotlin Multiplatform)

This directory contains the protocol layer of the Umbera apps, exactly as it ships on Android, iOS and desktop.
It is built on top of the Rust core in [`../core`](../core) through
[`RustCore`](src/commonMain/kotlin/app/umbera/core/crypto/RustCore.kt) and
[`MlsEngine`](src/commonMain/kotlin/app/umbera/core/crypto/MlsEngine.kt).

| File | What it does |
|---|---|
| [`MessageEncryption.kt`](src/commonMain/kotlin/app/umbera/core/crypto/MessageEncryption.kt) | message pipeline: ratchet, sealed sender, rendezvous IDs |
| [`DoubleRatchet.kt`](src/commonMain/kotlin/app/umbera/core/crypto/DoubleRatchet.kt) | Double Ratchet sessions |
| [`HybridKeyExchange.kt`](src/commonMain/kotlin/app/umbera/core/crypto/HybridKeyExchange.kt) | X25519 + ML-KEM-1024 key agreement |
| [`HybridSignature.kt`](src/commonMain/kotlin/app/umbera/core/crypto/HybridSignature.kt) | classical + ML-DSA-65 signatures |
| [`FileEncryption.kt`](src/commonMain/kotlin/app/umbera/core/crypto/FileEncryption.kt) | attachment encryption |
| [`HybridFileKeyWrap.kt`](src/commonMain/kotlin/app/umbera/core/crypto/HybridFileKeyWrap.kt) | hybrid wrapping of file keys |
| [`InboxReadCapability.kt`](src/commonMain/kotlin/app/umbera/core/crypto/InboxReadCapability.kt) | anonymous mailbox read proofs |
| [`RendezvousPadding.kt`](src/commonMain/kotlin/app/umbera/core/crypto/RendezvousPadding.kt) | size padding |
| [`RendezvousPow.kt`](src/commonMain/kotlin/app/umbera/core/crypto/RendezvousPow.kt) | anti-spam proof of work |
| [`KeyTransparencyVerifier.kt`](src/commonMain/kotlin/app/umbera/core/crypto/KeyTransparencyVerifier.kt) | Merkle inclusion proofs for keys |
| [`call/CallSignaling.kt`](src/commonMain/kotlin/app/umbera/core/call/CallSignaling.kt) | end-to-end encryption and signing of call setup |
| [`Labels.kt`](src/commonMain/kotlin/app/umbera/core/crypto/Labels.kt) | protocol domain-separation labels |
| [`LocalKeyStore.kt`](src/commonMain/kotlin/app/umbera/core/crypto/LocalKeyStore.kt) | interface to the device keystore |
| [`crypto/SealV3.kt`](src/commonMain/kotlin/app/umbera/core/crypto/SealV3.kt) | 1:1 envelope v3 / v3s, file wrap v2, direction secrets |
| [`crypto/RendezvousV2.kt`](src/commonMain/kotlin/app/umbera/core/crypto/RendezvousV2.kt) | mailbox addresses from the hybrid v3 direction secret, weekly epochs |
| [`crypto/GroupPqSig.kt`](src/commonMain/kotlin/app/umbera/core/crypto/GroupPqSig.kt) | ML-DSA-65 signatures on group Commits, Proposals and Welcomes; per-sender hash chain |
| [`crypto/mls/MlsManager.kt`](src/commonMain/kotlin/app/umbera/core/crypto/mls/MlsManager.kt) | MLS groups: X-Wing selection, moving a group to X-Wing |
| [`crypto/mls/GroupRekeyPolicy.kt`](src/commonMain/kotlin/app/umbera/core/crypto/mls/GroupRekeyPolicy.kt) | regular refresh of each device's own group leaf |
| [`crypto/SafetyNumber.kt`](src/commonMain/kotlin/app/umbera/core/crypto/SafetyNumber.kt) | safety number v2 over secp256k1, X25519, ML-DSA-65 and ML-KEM-1024 keys |
| [`crypto/CallSigV2.kt`](src/commonMain/kotlin/app/umbera/core/crypto/CallSigV2.kt) | compact call signalling format `callsig-v2` |
| [`crypto/DeviceLink.kt`](src/commonMain/kotlin/app/umbera/core/crypto/DeviceLink.kt) | facade over the Rust device-linking code (QR, certificate, transfer package) |
| [`crypto/RecoverySeed.kt`](src/commonMain/kotlin/app/umbera/core/crypto/RecoverySeed.kt) | derivation of every account key from the recovery phrase |
| [`webrtc/CallFrameE2ee.kt`](src/commonMain/kotlin/app/umbera/core/webrtc/CallFrameE2ee.kt) | second encryption layer for call frames: negotiation and keys |
| [`devices/DeviceEnvelope.kt`](src/commonMain/kotlin/app/umbera/core/devices/DeviceEnvelope.kt) | per-device envelope between linked devices |
| [`devices/DeviceRidEpochs.kt`](src/commonMain/kotlin/app/umbera/core/devices/DeviceRidEpochs.kt) | weekly mailbox addresses for each pair of devices |
| [`meet/MeetCrypto.kt`](src/commonMain/kotlin/app/umbera/core/meet/MeetCrypto.kt) | meetings by link: room key, encryption of room details and signals |
| [`meet/MeetLink.kt`](src/commonMain/kotlin/app/umbera/core/meet/MeetLink.kt) | meeting link format (room key in the fragment) |
| [`webrtc/PcFrameCryptor.kt`](src/desktopMain/kotlin/app/umbera/core/webrtc/PcFrameCryptor.kt) | desktop call frame encryptor (AES-128-GCM, WebRTC frame-encryptor format) |

Tests for these files are in [`src/commonTest`](src/commonTest) and [`src/desktopTest`](src/desktopTest).
They run in the app build, which provides the platform bindings to the Rust core; they are published
here for review.

The platform-specific parts (keystore, networking, storage, settings and UI) live in the apps and are not
needed to review the protocol. Some files refer to such app types (for example the key store, the
server data types or app settings); those types are not part of this repository.

The full specification is in [`../docs/PROTOCOL.md`](../docs/PROTOCOL.md).
