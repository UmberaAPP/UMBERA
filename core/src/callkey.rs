// Second, post-quantum layer for calls.
//
// DTLS-SRTP in WebRTC agrees on a key via ECDHE, which is not post-quantum: a conversation recorded today
// can be decrypted by a quantum computer tomorrow. Therefore frames (audio, camera, screen sharing)
// are additionally encrypted with a key the parties agreed on via a hybrid X25519 + ML-KEM-1024 exchange
// over the already protected messaging channel (call offer/answer travel inside the 1:1 E2E envelope). A frame opens
// only if BOTH DTLS AND this exchange are broken — i.e. both X25519 and ML-KEM.
//
// Flow (per PeerConnection pair: 1:1 and every pair in a conference):
//   initiator (sends the offer):      call_pq_keypair()          → public in the offer, secret kept locally;
//   responder (if supported):         call_pq_respond(id, public) → answer back, keys ready;
//   initiator:                         call_pq_finish(id, secret, public, answer) → the same keys.
// An old peer neither sends nor reads these fields — the call proceeds as before, without the second layer.
//
//   public  = version(1) ‖ X25519 (32) ‖ ML-KEM-1024 key (1568)
//   answer  = version(1) ‖ X25519 (32) ‖ ML-KEM-1024 ciphertext (1568)
//   TH      = SHA-256( ∀ part: u32be len ‖ part ) over ["umbera-call-v1/transcript", call_id, public, answer]
//   PRK     = HKDF-SHA256-Extract(salt = TH, IKM = X25519(eph., eph.) ‖ ss ML-KEM)
//   key i→r, key r→i = HKDF-Expand(PRK, "umbera-call-v1/frames/initiator->responder" | "…/responder->initiator", 32)
//   code    = 4 bytes HKDF-Expand(PRK, "umbera-call-v1/check", 4) — for comparison in the verification log, not in the UI.
// Keys are fresh for every call (ephemeral X25519 and ML-KEM) — forward secrecy: a later leak of long-term
// keys does not open a recorded conversation. An all-zero X25519 result (small-order point) is rejected.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::primitives as p;
use crate::primitives::PrimitiveError;

const VERSION: u8 = 1;
const X_LEN: usize = 32;
const EK_LEN: usize = 1568;
const CT_LEN: usize = 1568;
/// Length of `public` and `answer`.
pub const CALL_PQ_BLOB_LEN: usize = 1 + X_LEN + EK_LEN;

#[derive(uniffi::Record)]
pub struct CallPqKeypair {
    /// Goes into the call offer (base64 in the signal).
    pub public: Vec<u8>,
    /// Keep locally until the answer; X25519 (32) ‖ ML-KEM seed (64). Erase after call_pq_finish.
    pub secret: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct CallFrameKeys {
    /// Key for frames this side SENDS.
    pub send: Vec<u8>,
    /// Key for frames this side RECEIVES.
    pub recv: Vec<u8>,
    /// 4 check bytes: identical on both sides.
    pub check: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct CallPqResponse {
    pub answer: Vec<u8>,
    pub keys: CallFrameKeys,
}

fn bad(m: &str) -> PrimitiveError {
    PrimitiveError::Key(format!("call pq: {m}"))
}

fn transcript(call_id: &str, public: &[u8], answer: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    for part in [b"umbera-call-v1/transcript".as_slice(), call_id.as_bytes(), public, answer] {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.finalize().to_vec()
}

fn derive(call_id: &str, public: &[u8], answer: &[u8], ss_x: &[u8], ss_k: &[u8], initiator: bool) -> Result<CallFrameKeys, PrimitiveError> {
    if ss_x.iter().all(|b| *b == 0) {
        return Err(bad("x25519 low-order point"));
    }
    let th = transcript(call_id, public, answer);
    let ikm = Zeroizing::new([ss_x, ss_k].concat());
    let prk = Zeroizing::new(hkdf::Hkdf::<Sha256>::extract(Some(&th), &ikm).0.to_vec());
    let exp = |info: &str, n: u32| p::hkdf_sha256_expand(prk.to_vec(), info.as_bytes().to_vec(), n);
    let i2r = exp("umbera-call-v1/frames/initiator->responder", 32)?;
    let r2i = exp("umbera-call-v1/frames/responder->initiator", 32)?;
    let check = exp("umbera-call-v1/check", 4)?;
    Ok(if initiator { CallFrameKeys { send: i2r, recv: r2i, check } } else { CallFrameKeys { send: r2i, recv: i2r, check } })
}

fn check_id(call_id: &str) -> Result<(), PrimitiveError> {
    if call_id.is_empty() || call_id.len() > 128 {
        return Err(bad("call id length"));
    }
    Ok(())
}

/// Initiator: an ephemeral X25519 + ML-KEM-1024 pair for one call.
#[uniffi::export]
pub fn call_pq_keypair() -> CallPqKeypair {
    let xs: Zeroizing<[u8; 32]> = Zeroizing::new(p::os_random());
    let kem = p::mlkem1024_generate_keypair();
    let xp = p::x25519_public_key(xs.to_vec()).expect("32-byte x25519 scalar");
    let mut public = Vec::with_capacity(CALL_PQ_BLOB_LEN);
    public.push(VERSION);
    public.extend_from_slice(&xp);
    public.extend_from_slice(&kem.public_key);
    let mut secret = Vec::with_capacity(32 + 64);
    secret.extend_from_slice(xs.as_ref());
    secret.extend_from_slice(&kem.private_key);
    let _wipe = Zeroizing::new(kem.private_key);
    CallPqKeypair { public, secret }
}

/// Responder: verify the initiator's `public`, answer and immediately derive the frame keys.
#[uniffi::export]
pub fn call_pq_respond(call_id: String, initiator_public: Vec<u8>) -> Result<CallPqResponse, PrimitiveError> {
    check_id(&call_id)?;
    if initiator_public.len() != CALL_PQ_BLOB_LEN || initiator_public[0] != VERSION {
        return Err(bad("initiator public: length/version"));
    }
    let peer_x = initiator_public[1..1 + X_LEN].to_vec();
    let ek = initiator_public[1 + X_LEN..].to_vec();
    let enc = p::mlkem1024_encapsulate(ek)?;
    let xs: Zeroizing<[u8; 32]> = Zeroizing::new(p::os_random());
    let xp = p::x25519_public_key(xs.to_vec())?;
    let ss_x = Zeroizing::new(p::x25519_shared_secret(xs.to_vec(), peer_x)?);
    let ss_k = Zeroizing::new(enc.shared_secret);
    let mut answer = Vec::with_capacity(CALL_PQ_BLOB_LEN);
    answer.push(VERSION);
    answer.extend_from_slice(&xp);
    answer.extend_from_slice(&enc.ciphertext);
    let keys = derive(&call_id, &initiator_public, &answer, &ss_x, &ss_k, false)?;
    Ok(CallPqResponse { answer, keys })
}

/// Initiator: from the responder's answer — the same frame keys.
#[uniffi::export]
pub fn call_pq_finish(call_id: String, secret: Vec<u8>, initiator_public: Vec<u8>, answer: Vec<u8>) -> Result<CallFrameKeys, PrimitiveError> {
    check_id(&call_id)?;
    let secret = Zeroizing::new(secret);
    if secret.len() != 32 + 64 {
        return Err(bad("secret length"));
    }
    if initiator_public.len() != CALL_PQ_BLOB_LEN || answer.len() != CALL_PQ_BLOB_LEN || answer[0] != VERSION {
        return Err(bad("answer: length/version"));
    }
    // public must be ours: otherwise the keys would come from someone else's transcript.
    let own_x = p::x25519_public_key(secret[..32].to_vec())?;
    let own_ek = p::mlkem1024_public_key(secret[32..].to_vec())?;
    if initiator_public[1..1 + X_LEN] != own_x[..] || initiator_public[1 + X_LEN..] != own_ek[..] {
        return Err(bad("public does not belong to secret"));
    }
    let peer_x = answer[1..1 + X_LEN].to_vec();
    let ct = answer[1 + X_LEN..1 + X_LEN + CT_LEN].to_vec();
    let ss_x = Zeroizing::new(p::x25519_shared_secret(secret[..32].to_vec(), peer_x)?);
    let ss_k = Zeroizing::new(p::mlkem1024_decapsulate(ct, secret[32..].to_vec())?);
    derive(&call_id, &initiator_public, &answer, &ss_x, &ss_k, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_get_the_same_directional_keys() {
        let kp = call_pq_keypair();
        assert_eq!(kp.public.len(), CALL_PQ_BLOB_LEN);
        let r = call_pq_respond("call-1".into(), kp.public.clone()).unwrap();
        let i = call_pq_finish("call-1".into(), kp.secret.clone(), kp.public.clone(), r.answer.clone()).unwrap();
        assert_eq!(i.send, r.keys.recv);
        assert_eq!(i.recv, r.keys.send);
        assert_ne!(i.send, i.recv);
        assert_eq!(i.check, r.keys.check);
        // A different call — different keys, even with the same exchange bytes.
        let other = call_pq_finish("call-2".into(), kp.secret.clone(), kp.public.clone(), r.answer.clone()).unwrap();
        assert_ne!(other.send, i.send);
    }

    #[test]
    fn tampering_changes_keys_or_fails() {
        let kp = call_pq_keypair();
        let r = call_pq_respond("c".into(), kp.public.clone()).unwrap();
        // Substituted ML-KEM ciphertext: FIPS 203 implicit rejection → different keys (the check fails, frames do not open).
        let mut a = r.answer.clone();
        a[100] ^= 1;
        let k = call_pq_finish("c".into(), kp.secret.clone(), kp.public.clone(), a).unwrap();
        assert_ne!(k.recv, r.keys.send);
        // Substituted responder X25519.
        let mut a = r.answer.clone();
        a[5] ^= 1;
        let k = call_pq_finish("c".into(), kp.secret.clone(), kp.public.clone(), a).unwrap();
        assert_ne!(k.recv, r.keys.send);
        // Someone else's public with our secret — rejected.
        let other = call_pq_keypair();
        assert!(call_pq_finish("c".into(), kp.secret.clone(), other.public, r.answer.clone()).is_err());
        // Invalid lengths/version.
        assert!(call_pq_respond("c".into(), kp.public[..100].to_vec()).is_err());
        let mut v = kp.public.clone();
        v[0] = 2;
        assert!(call_pq_respond("c".into(), v).is_err());
        assert!(call_pq_respond(String::new(), kp.public.clone()).is_err());
        // Small-order point (all-zero X25519) — rejected.
        let mut z = kp.public.clone();
        z[1..33].fill(0);
        assert!(call_pq_respond("c".into(), z).is_err());
    }
}
