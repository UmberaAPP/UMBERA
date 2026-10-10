<p align="center">
  <img src="assets/banner.png" alt="umbera/core" width="100%">
</p>

# Umbera Protocol

**Version 1** · applies to Umbera for Android and iOS

This document describes how Umbera clients encrypt, address and deliver messages, and exactly what
the relay server can and cannot observe. Every statement here can be checked against the code in
[`core/`](../core) and [`kotlin/`](../kotlin).

## Contents

1. [Design goals](#1-design-goals)
2. [What the relay sees](#2-what-the-relay-sees)
3. [Identity and keys](#3-identity-and-keys)
4. [Hybrid key agreement](#4-hybrid-key-agreement)
5. [One-to-one sessions: Double Ratchet](#5-one-to-one-sessions-double-ratchet)
6. [Sealed sender](#6-sealed-sender)
7. [Rendezvous addressing](#7-rendezvous-addressing)
8. [Reading a mailbox](#8-reading-a-mailbox)
9. [Padding](#9-padding)
10. [Proof of work](#10-proof-of-work)
11. [Attachments](#11-attachments)
12. [Groups: MLS](#12-groups-mls)
13. [Abuse reports: message franking](#13-abuse-reports-message-franking)
14. [Key transparency](#14-key-transparency)
15. [Domain-separation labels](#15-domain-separation-labels)

---

## 1. Design goals

| Goal | How it is achieved |
|---|---|
| Confidentiality against today's and future adversaries | Hybrid X25519 + ML-KEM-1024 for every key agreement |
| Forward secrecy and break-in recovery | Double Ratchet for 1:1, MLS epochs for groups |
| The relay does not learn the sender | Sealed sender: the sender's identity is inside the ciphertext |
| The relay does not learn who talks to whom | Rendezvous addresses known only to the two peers, rotated weekly |
| No identifiers outside the app | Accounts are a username; no phone number or e-mail is collected |
| Abuse handling without surveillance | Asymmetric message franking: reports are verifiable, traffic stays opaque |
| Detection of key substitution | Key transparency log with Merkle inclusion proofs |

## 2. What the relay sees

<p align="center"><img src="assets/architecture.svg" alt="What the relay sees" width="100%"></p>

The relay stores and forwards opaque blobs keyed by **rendezvous IDs** (Section 7). For each blob it
observes the rendezvous ID, the padded size and the time of delivery. It never receives plaintext,
the sender's identity, the recipient's identity, or the relationship between rendezvous IDs that
belong to the same person or group.

## 3. Identity and keys

Each account generates on the device:

| Key | Algorithm | Purpose |
|---|---|---|
| Exchange key | X25519 | classical half of every key agreement, rendezvous derivation |
| KEM key | ML-KEM-1024 (CRYSTALS-Kyber, FIPS 203) | post-quantum half of every key agreement |
| Signature key | secp256k1 ECDSA | classical half of identity signatures |
| PQ signature key | ML-DSA-65 (CRYSTALS-Dilithium, FIPS 204) | post-quantum half of identity signatures |
| MLS credential | Ed25519 | group membership (Section 12) |
| Franking key | Ristretto255 | abuse reports (Section 13) |

Private keys never leave the device. They are stored in the platform keystore
(Android Keystore, iOS Keychain); the interface the protocol uses is
[`LocalKeyStore`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/LocalKeyStore.kt).

## 4. Hybrid key agreement

Every key agreement combines a classical and a post-quantum secret. The derived key is secure as long
as **either** X25519 **or** ML-KEM-1024 remains unbroken.

```
ss_classical = X25519(ephemeral_private, recipient_x25519_public)
(ct, ss_pq)  = ML-KEM-1024.Encapsulate(recipient_kyber_public)

okm = HKDF-SHA256(ikm  = ss_classical || ss_pq,
                  salt = HYBRID_LABEL,
                  info = "key-derivation",
                  L    = 64)
key = okm[0..32]
```

Source: [`HybridKeyExchange.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/HybridKeyExchange.kt),
[`primitives.rs`](../core/src/primitives.rs).

## 5. One-to-one sessions: Double Ratchet

Conversations use the Double Ratchet algorithm over X25519:

```
(root_key, chain_key) = HKDF-SHA256(ikm = DH_output, salt = root_key, info = "root",  L = 64)
(chain_key, msg_key)  = HKDF-SHA256(ikm = chain_key, salt = ∅,        info = "chain", L = 64)
ciphertext            = AES-256-GCM(msg_key, nonce, plaintext, aad = header)
```

| Parameter | Value |
|---|---|
| Max skipped messages per chain | 1000 |
| Max stored skipped keys | 2000 |

Every DH ratchet step mixes fresh randomness into the root key, so a compromised device state stops
being useful after the next round-trip (break-in recovery). Old message keys are deleted after use
(forward secrecy).

Source: [`DoubleRatchet.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/DoubleRatchet.kt).

## 6. Sealed sender

<p align="center"><img src="assets/sealed-sender.svg" alt="Sealed sender" width="100%"></p>

The ratchet ciphertext is wrapped together with the sender's identity into an **inner package**:

```json
{
  "senderId": "...",
  "senderPublicKey": "...",
  "senderX25519PublicKey": "...",
  "senderKyberPublicKey": "...",
  "senderDilithiumPublicKey": "...",
  "ratchetMessage": { ... },
  "timestamp": 0,
  "sealedVersion": "v2"
}
```

The inner package is encrypted to the recipient with the hybrid scheme of Section 4 using a fresh
ephemeral X25519 key for every message:

```
box = AES-256-GCM(key, iv = random(12), plaintext = inner_package)

sealed = {
  "version":            "v2",
  "ephemeralPublicKey": hex(ephemeral_x25519_public),
  "kyberCiphertext":    hex(ct),
  "iv":                 hex(iv),
  "encryptedInner":     hex(box.ciphertext),
  "authTag":            hex(box.tag)
}
```

Only the recipient can open the outer layer and learn who sent the message. The relay sees a random
ephemeral key and ciphertext.

Source: [`MessageEncryption.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/MessageEncryption.kt).

## 7. Rendezvous addressing

<p align="center"><img src="assets/rendezvous.svg" alt="Rendezvous addressing" width="100%"></p>

Messages are not addressed to an account. They are dropped into a mailbox whose address both peers
compute independently:

```
shared = X25519(my_private, peer_public)
epoch  = floor(unix_time / 604800)                     // one week

rendezvous_id = hex(HKDF-SHA256(ikm  = shared,
                                salt = RENDEZVOUS_LABEL,
                                info = "rdv|e{epoch}|{from}|{to}"))
```

- Each direction has its own address (`from`/`to` are swapped for the reverse direction).
- Addresses rotate every week; receivers poll the current and the previous epoch.
- The relay cannot link two rendezvous IDs to the same person, nor tell which two people share one.

## 8. Reading a mailbox

To read a mailbox the client proves it owns the X25519 key behind it, without revealing an account
identifier. A signing seed is derived from the X25519 private key and used as an Ed25519 key:

```
seed  = HKDF-SHA256(ikm = x25519_private, salt = INBOX_READ_LABEL, info = "inbox-seed")
proof = Ed25519.Sign(seed, INBOX_READ_LABEL || "|{rid}|{since}|{now}")
```

The relay checks the signature against a verification key registered for the mailbox. It learns that
the reader is authorised, not who the reader is.

Source: [`InboxReadCapability.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/InboxReadCapability.kt).

## 9. Padding

Payloads are padded to size buckets before delivery so that message length leaks as little as possible:

| Payload size | Padded to |
|---|---|
| ≤ 1 KiB | 1 KiB |
| ≤ 2 KiB | 2 KiB |
| ≤ 4 KiB | 4 KiB |
| ≤ 8 KiB | 8 KiB |
| ≤ 16 KiB | 16 KiB |
| larger | next multiple of 4 KiB |

Source: [`RendezvousPadding.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/RendezvousPadding.kt).

## 10. Proof of work

Because mailboxes are anonymous, the relay cannot rate-limit by account. Writing to a rendezvous
address therefore requires a small proof of work:

```
challenge = rid || ":" || hex(SHA-256(payload))
find stamp such that SHA-256(challenge || ":" || stamp) has ≥ 15 leading zero bits   // default difficulty
```

This costs a phone a fraction of a second per message and makes bulk spam expensive.

Source: [`RendezvousPow.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/RendezvousPow.kt).

## 11. Attachments

- Every file uses a fresh ephemeral X25519 key. The file key is derived from the Diffie-Hellman
  secret with the recipient and a per-conversation file counter, so no two files share a key.
- In hybrid mode the file key is additionally wrapped with X25519 + ML-KEM-1024
  (salt `FILE_WRAP_LABEL`, info `"file-key-wrap"`).
- The file is split into **256 KiB chunks**. Every chunk has its own derived key and random nonce,
  is encrypted with AES-256-GCM and padded.
- File name, type and size are encrypted separately as metadata.
- The relay stores only encrypted, padded chunks.
- Outgoing PDF documents are stripped of author, producer and other identifying metadata
  ([`pdf.rs`](../core/src/pdf.rs)).

Source: [`FileEncryption.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/FileEncryption.kt),
[`HybridFileKeyWrap.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/HybridFileKeyWrap.kt).

## 12. Groups: MLS

Groups use the Messaging Layer Security protocol (RFC 9420) through OpenMLS.

| Parameter | Value |
|---|---|
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| Max members | 20 |

The relay has no concept of a group: group messages are fanned out to the members' pairwise rendezvous
addresses. The member cap is therefore enforced **cryptographically by every client** — an honest
client refuses to merge a commit that would exceed it, so a malicious admin cannot force extra members
onto other devices. Call media keys are derived from the group with MLS `export_secret`.

Source: [`lib.rs`](../core/src/lib.rs), [`MlsEngine.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/MlsEngine.kt).

## 13. Abuse reports: message franking

Umbera uses asymmetric message franking (AMF) over Ristretto255. Each message carries a franking
signature bound to the sender, the recipient and a moderator ("judge") public key.

| Function | Who | Purpose |
|---|---|---|
| `amf_frank` | sender | produces the franking signature |
| `amf_verify` | recipient | checks it before displaying the message |
| `amf_judge` | moderator | confirms who sent a reported message |
| `amf_forge` | recipient | produces a valid-looking signature for any message (deniability) |

Because a recipient can forge signatures that only the moderator can tell apart, a franked message is
not a transferable proof to third parties. The relay never sees franking data.

Source: [`amf.rs`](../core/src/amf.rs).

## 14. Key transparency

When the relay serves a contact's public keys, a malicious relay could try to substitute its own. To
detect that, keys are published in an append-only Merkle log:

```
leaf = SHA-256(0x00 || canonical_entry)
node = SHA-256(0x01 || left || right)
```

Clients verify an inclusion proof against a signed tree head (Ed25519) before trusting new keys and
warn the user if a contact's keys change unexpectedly.

Source: [`KeyTransparencyVerifier.kt`](../kotlin/src/commonMain/kotlin/app/umbera/core/crypto/KeyTransparencyVerifier.kt).

## 15. Domain-separation labels

Labels are fixed byte strings that bind each derivation to its purpose. They are part of the wire
format of protocol version 1 and never change within a version. Their exact values are defined in the
source files listed below.

| Label | Used in | Defined in |
|---|---|---|
| `HYBRID_LABEL` | hybrid key agreement (Section 4) | `Labels.kt` |
| `RENDEZVOUS_LABEL` | rendezvous IDs (Section 7) | `Labels.kt` |
| `INBOX_READ_LABEL` | mailbox read proofs (Section 8) | `Labels.kt` |
| `FILE_WRAP_LABEL` | attachment key wrapping (Section 11) | `Labels.kt` |
| `GROUP_INBOX_LABEL` | group inbox identifiers | `Labels.kt` |
| `AES_KDF_LABEL` | generic AES key derivation | `Labels.kt` |
| `AMF_LABELS` | message franking (Section 13) | `amf.rs` |
| `root`, `chain`, `message` | Double Ratchet KDF chains (Section 5) | `DoubleRatchet.kt` |


---

<p align="center"><sub>© 2026 Umbera · <a href="https://umbera.app">umbera.app</a> · <a href="../LICENSE.md">PolyForm Strict 1.0.0</a></sub></p>
