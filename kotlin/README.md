# Protocol layer (Kotlin Multiplatform)

This directory contains the protocol layer of the Umbera apps, exactly as it ships on Android and iOS.
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

The platform-specific parts (keystore, networking, storage and UI) live in the apps and are not
needed to review the protocol. The full specification is in [`../docs/PROTOCOL.md`](../docs/PROTOCOL.md).
