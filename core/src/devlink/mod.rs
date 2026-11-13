// umbera_core::devlink — linked devices (desktop ↔ phone), core cryptography.
//
// Overview (see the protocol description for formats and design decisions):
//  * session  — QR linking: one-time desktop keys (X25519 + ML-KEM-1024), hybrid
//               key agreement, HKDF bound to the transcript, verification code (6 digits),
//               key confirmation in both directions, replay-free AEAD blobs {kind, seq, data};
//  * cert     — long-term device identity (Ed25519 + ML-DSA-65 for signing,
//               X25519 + ML-KEM-1024 for encryption), a "this device belongs to my
//               account" certificate signed with the account key (secp256k1 + ML-DSA-65), and revocation;
//  * package  — transfer bundle in chunks (AEAD per chunk, final checksum, strict limits:
//               videos and large files are not transferred);
//  * comm     — Communities membership vault root (no account private keys);
//  * mlsjoin  — every device is a separate leaf of an MLS group (requests, offers,
//               mutual signature of "sibling" leaves).
//
// Only vetted crates the core already uses (x25519-dalek, ml-kem, ml-dsa,
// ed25519-dalek, k256, aes-gcm, hkdf, hmac, sha2). No custom cryptography here — only
// composition of standard primitives and format parsing.

pub mod cert;
pub mod comm;
pub mod mlsjoin;
pub mod package;
pub mod session;

mod codec;

#[cfg(test)]
mod tests;

/// Linking errors. Each variant has exactly one string field (iOS binding contract:
/// variant ordinal + string). Variant order is part of the ABI, do not change it.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LinkError {
    /// Malformed input: wrong QR, truncated blob, trailing bytes, lengths.
    #[error("malformed: {0}")]
    Malformed(String),
    /// Expired: QR older than 60 s, verification code not confirmed in time.
    #[error("expired: {0}")]
    Expired(String),
    /// Mismatch: key confirmation, ML-KEM commitment, signature, AEAD, final
    /// checksum. Indicates tampering — the session is destroyed afterwards.
    #[error("mismatch: {0}")]
    Mismatch(String),
    /// Replay of an already accepted blob (seq lower than expected). The session is unchanged.
    #[error("replay: {0}")]
    Replay(String),
    /// Call in the wrong session state (or the session is already destroyed).
    #[error("state: {0}")]
    State(String),
    /// Primitive error (wrong key length, etc.).
    #[error("crypto: {0}")]
    Crypto(String),
}

pub type LR<T> = Result<T, LinkError>;

impl From<crate::primitives::PrimitiveError> for LinkError {
    fn from(e: crate::primitives::PrimitiveError) -> Self {
        LinkError::Crypto(e.to_string())
    }
}

/// Prefix of all protocol domain labels (HKDF info, signatures, AAD).
pub(crate) const DOMAIN: &[u8] = b"umbera-link-v1";

/// Constant-time comparison (for MACs, commitments and checksums).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    // black_box keeps the compiler from turning the loop into an early exit.
    std::hint::black_box(d) == 0
}

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SHA-256 over parts, each prefixed with a 4-byte length: unambiguous concatenation.
pub(crate) fn sha256_framed(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u32).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}
