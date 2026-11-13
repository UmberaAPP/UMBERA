// umbera_core::primitives — 1:1 crypto primitives (KMP-prep phase 6).
//
// These move the personal (1:1) message/file/backup crypto OFF the JVM-only
// BouncyCastle provider and into this shared Rust core, so Android (uniffi→Kotlin)
// today and iOS (uniffi→Swift) later run the SAME battle-tested implementations.
//
// Only mature RustCrypto/dalek crates are used — no hand-rolled primitives, no
// weakened parameters. Where an algorithm is a fixed standard (Argon2id, AES-GCM,
// HKDF, X25519, secp256k1/RFC6979, Ed25519, SHA-256/PBKDF2), the output is
// byte-identical to the previous BouncyCastle output, which the golden vectors
// assert cross-implementation. PQ algorithms (ML-KEM / ML-DSA) are migrated to the
// FINAL FIPS standard and their new byte formats are re-captured + documented.

use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

/// Errors surfaced across the FFI. Mapped to a Kotlin/Swift exception by UniFFI.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum PrimitiveError {
    #[error("aead: {0}")]
    Aead(String),
    #[error("key: {0}")]
    Key(String),
}

fn to_arr32(v: &[u8], what: &str) -> Result<[u8; 32], PrimitiveError> {
    v.try_into()
        .map_err(|_| PrimitiveError::Key(format!("{what} must be 32 bytes, got {}", v.len())))
}

/// Argon2id key derivation. Fixed parameters, matching the previous BouncyCastle
/// call exactly so existing backups (and the golden vector) verify unchanged:
///   Algorithm = Argon2id, Version = 0x13 (19), m = 65536 KiB (64 MiB),
///   t = 3 iterations, p = 4 lanes, output = `key_length` bytes.
///
/// CONTRACT (iOS must reproduce): password is UTF-8 bytes, salt is raw bytes,
/// no associated data, no secret key.
#[uniffi::export]
pub fn argon2id_derive(password: String, salt: Vec<u8>, key_length: u32) -> Result<Vec<u8>, PrimitiveError> {
    let params = Params::new(65536, 3, 4, Some(key_length as usize))
        .map_err(|e| PrimitiveError::Key(format!("argon2 params: {e}")))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = vec![0u8; key_length as usize];
    a2.hash_password_into(password.as_bytes(), &salt, &mut out)
        .map_err(|e| PrimitiveError::Key(format!("argon2id: {e}")))?;
    Ok(out)
}

/// SHA-256 digest. Fixed standard → byte-identical to the previous
/// BouncyCastle SHA256Digest output.
#[uniffi::export]
pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(&data);
    h.finalize().to_vec()
}

/// PBKDF2-HMAC-SHA256. Matches the previous BouncyCastle
/// PKCS5S2ParametersGenerator(SHA256Digest) exactly: password is UTF-8 bytes,
/// `iterations` rounds, `key_length` output bytes. Used for the zero-knowledge
/// password hash the server verifies, so the output MUST stay byte-stable.
#[uniffi::export]
pub fn pbkdf2_hmac_sha256(password: String, salt: Vec<u8>, iterations: u32, key_length: u32) -> Result<Vec<u8>, PrimitiveError> {
    let mut out = vec![0u8; key_length as usize];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, iterations, &mut out)
        .map_err(|e| PrimitiveError::Key(format!("pbkdf2: {e}")))?;
    Ok(out)
}

/// HKDF-SHA256 (RFC 5869) extract-then-expand. Byte-identical to the previous
/// BouncyCastle HKDFBytesGenerator(SHA256Digest).
#[uniffi::export]
pub fn hkdf_sha256(ikm: Vec<u8>, salt: Vec<u8>, info: Vec<u8>, length: u32) -> Result<Vec<u8>, PrimitiveError> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut out = vec![0u8; length as usize];
    hk.expand(&info, &mut out)
        .map_err(|e| PrimitiveError::Key(format!("hkdf: {e}")))?;
    Ok(out)
}

/// HMAC-SHA256 (RFC 2104). Same output as javax.crypto.Mac("HmacSHA256") for
/// any key length. Used for the file/chunk key schedule in FileEncryption.
#[uniffi::export]
pub fn hmac_sha256(key: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    use hmac::Mac as _;
    let mut m = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key)
        .expect("HMAC-SHA256 accepts keys of any length");
    m.update(&data);
    m.finalize().into_bytes().to_vec()
}

/// HKDF-SHA256 EXPAND-ONLY (RFC 5869 §2.3): `prk` is used directly as the
/// pseudorandom key, no extract step. Byte-identical to BC's
/// `HKDFParameters.skipExtractParameters(prk, info)`.
#[uniffi::export]
pub fn hkdf_sha256_expand(prk: Vec<u8>, info: Vec<u8>, length: u32) -> Result<Vec<u8>, PrimitiveError> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|e| PrimitiveError::Key(format!("hkdf-expand prk: {e}")))?;
    let mut out = vec![0u8; length as usize];
    hk.expand(&info, &mut out)
        .map_err(|e| PrimitiveError::Key(format!("hkdf-expand: {e}")))?;
    Ok(out)
}

/// AES-256-GCM encrypt. Returns `ciphertext || tag(16)`, exactly the layout the
/// JCA `Cipher("AES/GCM/NoPadding").doFinal` produced, so the wire format is
/// unchanged. `aad` empty = no associated data (identical to a null AAD in JCA).
#[uniffi::export]
pub fn aes256_gcm_encrypt(key: Vec<u8>, iv: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| PrimitiveError::Aead(e.to_string()))?;
    // Typed error, not a panic: the wire format always uses 96-bit nonces, and
    // a hostile peer must not be able to panic the FFI with a bad IV length.
    if iv.len() != 12 {
        return Err(PrimitiveError::Aead(format!("iv must be 12 bytes, got {}", iv.len())));
    }
    let nonce = &Nonce::try_from(iv.as_slice()).map_err(|_| PrimitiveError::Aead("iv must be 12 bytes".into()))?;
    cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
        .map_err(|e| PrimitiveError::Aead(e.to_string()))
}

/// AES-256-GCM decrypt. Consumes `ciphertext || tag(16)` (the JCA layout) and
/// fails (like JCA's AEADBadTagException) on tag/AAD mismatch.
#[uniffi::export]
pub fn aes256_gcm_decrypt(key: Vec<u8>, iv: Vec<u8>, ciphertext_with_tag: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| PrimitiveError::Aead(e.to_string()))?;
    // Typed error, not a panic — the IV arrives from the wire (hostile input).
    if iv.len() != 12 {
        return Err(PrimitiveError::Aead(format!("iv must be 12 bytes, got {}", iv.len())));
    }
    let nonce = &Nonce::try_from(iv.as_slice()).map_err(|_| PrimitiveError::Aead("iv must be 12 bytes".into()))?;
    cipher
        .decrypt(nonce, Payload { msg: &ciphertext_with_tag, aad: &aad })
        .map_err(|e| PrimitiveError::Aead(e.to_string()))
}

/// X25519 public-key derivation (RFC 7748 scalar mult by the basepoint).
/// Raw 32-byte keys. The bare `x25519()` function clamps the scalar on use,
/// exactly like BouncyCastle's X25519PrivateKeyParameters.generatePublicKey(),
/// so the derived public key is byte-identical.
#[uniffi::export]
pub fn x25519_public_key(private_key: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let sk = to_arr32(&private_key, "x25519 private key")?;
    Ok(x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES).to_vec())
}

/// X25519 ECDH (RFC 7748). Raw scalar multiplication, byte-identical to
/// BouncyCastle's X25519Agreement. Low-order-point rejection and the all-zero
/// shared-secret check stay in the Kotlin caller (crypto/X25519.kt), which
/// validates BEFORE calling in — same defense-in-depth as before.
#[uniffi::export]
pub fn x25519_shared_secret(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let sk = to_arr32(&private_key, "x25519 private key")?;
    let pk = to_arr32(&public_key, "x25519 public key")?;
    Ok(x25519_dalek::x25519(sk, pk).to_vec())
}

/// secp256k1 public-key derivation. Input is the raw 32-byte scalar, output is
/// the SEC1 UNCOMPRESSED point (65 bytes, 0x04 || X || Y) — the exact encoding
/// BC's `q.getEncoded(false)` produced. Errors (instead of panicking) if the
/// scalar is zero or >= the group order, which is also how a caller-side
/// rejection-sampling keygen detects the ~2^-128 invalid draw.
#[uniffi::export]
pub fn secp256k1_public_key(private_key: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let sk = SigningKey::from_slice(&private_key)
        .map_err(|e| PrimitiveError::Key(format!("secp256k1 private key: {e}")))?;
    Ok(sk.verifying_key().to_sec1_point(false).as_bytes().to_vec())
}

/// secp256k1 ECDSA over a 32-byte prehash. RFC 6979 deterministic nonce
/// (HMAC-SHA-256) + low-S normalization (BIP-62) — identical to the previous
/// BC ECDSASigner(HMacDSAKCalculator(SHA256Digest)) + normalizeS path, so the
/// signature is byte-exact (proven by the golden vector). Returns r||s (64 bytes,
/// both fixed 32-byte big-endian).
#[uniffi::export]
pub fn secp256k1_sign_hash(hash: Vec<u8>, private_key: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    if hash.len() != 32 {
        return Err(PrimitiveError::Key(format!("hash must be 32 bytes, got {}", hash.len())));
    }
    let sk = SigningKey::from_slice(&private_key)
        .map_err(|e| PrimitiveError::Key(format!("secp256k1 private key: {e}")))?;
    let sig: EcdsaSignature = sk
        .sign_prehash(&hash)
        .map_err(|e| PrimitiveError::Key(format!("secp256k1 sign: {e}")))?;
    // k256 already emits low-S; normalize defensively so the invariant is explicit.
    let sig = sig.normalize_s();
    Ok(sig.to_bytes().to_vec())
}

/// secp256k1 ECDSA verify over a 32-byte prehash. `signature` is r||s (64 bytes),
/// `public_key` is any SEC1 point encoding (compressed or uncompressed — BC's
/// decodePoint accepted both). High-S signatures are normalized before verifying,
/// matching BC's verifier which imposed no low-S policy. Any parse failure
/// returns false, exactly like the previous Kotlin catch-all.
#[uniffi::export]
pub fn secp256k1_verify_hash(hash: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
    if hash.len() != 32 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&public_key) else { return false };
    let Ok(sig) = EcdsaSignature::from_slice(&signature) else { return false };
    let sig = sig.normalize_s();
    vk.verify_prehash(&hash, &sig).is_ok()
}

/// Ed25519 signature verification (RFC 8032). Used for the Key Transparency
/// STH and the signed federation server directory — the client only VERIFIES;
/// signing keys live server-side. Cofactorless verification with canonical-S
/// rejection, same as BC's Ed25519Signer. Any malformed key/signature returns
/// false, matching the previous Kotlin catch-all/length-check behavior.
#[uniffi::export]
pub fn ed25519_verify(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let Ok(pk_arr): Result<[u8; 32], _> = public_key.as_slice().try_into() else { return false };
    let Ok(sig_arr): Result<[u8; 64], _> = signature.as_slice().try_into() else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) else { return false };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    use ed25519_dalek::Verifier;
    vk.verify(&message, &sig).is_ok()
}

/// Ed25519 public key from a 32-byte seed (RFC 8032 §5.1.5).
///
/// AUDIT K-2 — the inbox READ capability. A self-inbox rendezvous id is derived
/// from data the anonymous directory publishes, so anyone can address it (that is
/// how a stranger sends you a contact request) and, until this key existed, anyone
/// could also READ it. The account publishes this public half; only the holder of
/// the seed can sign a fetch. The seed is derived on-device and never leaves it.
#[uniffi::export]
pub fn ed25519_public_from_seed(seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let seed_arr = to_arr32(&seed, "ed25519 seed")?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    Ok(sk.verifying_key().to_bytes().to_vec())
}

/// Ed25519 signature over [message] with the 32-byte seed (audit K-2).
#[uniffi::export]
pub fn ed25519_sign(message: Vec<u8>, seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let seed_arr = to_arr32(&seed, "ed25519 seed")?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    use ed25519_dalek::Signer;
    Ok(sk.sign(&message).to_bytes().to_vec())
}

// ---------------------------------------------------------------------------
// Post-quantum: FINAL FIPS 203 (ML-KEM-1024) + FIPS 204 (ML-DSA-65).
//
// This REPLACES the BouncyCastle round-3 Kyber/Dilithium implementations and
// their X.509/PKCS8-DER key encodings. New byte contract (documented for iOS
// below; wire-break accepted, goldens re-captured):
//   ML-KEM-1024: public key = raw ek (1568 B), private key = SEED d||z (64 B,
//     FIPS 203 §7.1 storage form), ciphertext = raw (1568 B), shared key 32 B.
//   ML-DSA-65:   public key = raw vk (1952 B), private key = SEED xi (32 B,
//     FIPS 204 approved private-key form), signature = raw (3309 B),
//     pure mode (no pre-hash), empty context string, deterministic variant.
// All randomness (key seeds, encapsulation m) comes from the OS via getrandom,
// exactly the values the FIPS KeyGen/Encaps algorithms draw internally.
// ---------------------------------------------------------------------------

use ml_kem::{Decapsulate as _, KeyExport as _};

/// A generated PQ key pair. `private_key` is the compact FIPS seed form
/// (64 B for ML-KEM-1024, 32 B for ML-DSA-65), NOT the expanded key.
#[derive(uniffi::Record)]
pub struct PqKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Result of ML-KEM encapsulation.
#[derive(uniffi::Record)]
pub struct KemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

pub(crate) fn os_random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).expect("OS RNG is always available on Android/iOS");
    out
}

pub(crate) fn mlkem_dk_from_seed(private_key_seed: &[u8]) -> Result<ml_kem::DecapsulationKey1024, PrimitiveError> {
    let seed: [u8; 64] = private_key_seed
        .try_into()
        .map_err(|_| PrimitiveError::Key(format!("ml-kem seed must be 64 bytes, got {}", private_key_seed.len())))?;
    Ok(ml_kem::DecapsulationKey1024::from_seed(seed.into()))
}

pub(crate) fn mlkem_ek_from_bytes(public_key: &[u8]) -> Result<ml_kem::EncapsulationKey1024, PrimitiveError> {
    let arr: [u8; 1568] = public_key
        .try_into()
        .map_err(|_| PrimitiveError::Key(format!("ml-kem public key must be 1568 bytes, got {}", public_key.len())))?;
    ml_kem::EncapsulationKey1024::new(&arr.into())
        .map_err(|_| PrimitiveError::Key("ml-kem public key failed FIPS 203 modulus validation".into()))
}

/// ML-KEM-1024 key generation (FIPS 203). Returns the raw 1568-byte
/// encapsulation key and the 64-byte d||z seed as the private key.
#[uniffi::export]
pub fn mlkem1024_generate_keypair() -> PqKeyPair {
    let seed: [u8; 64] = os_random();
    let dk = ml_kem::DecapsulationKey1024::from_seed(seed.into());
    PqKeyPair {
        public_key: dk.encapsulation_key().to_bytes().to_vec(),
        private_key: seed.to_vec(),
    }
}

/// Derive the ML-KEM-1024 public (encapsulation) key from a stored 64-byte seed.
#[uniffi::export]
pub fn mlkem1024_public_key(private_key_seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    Ok(mlkem_dk_from_seed(&private_key_seed)?.encapsulation_key().to_bytes().to_vec())
}

/// ML-KEM-1024 encapsulation (FIPS 203 Encaps). The 32-byte randomness m is
/// drawn from the OS RNG — identical to `encapsulate_with_rng`.
#[uniffi::export]
pub fn mlkem1024_encapsulate(public_key: Vec<u8>) -> Result<KemEncapsulation, PrimitiveError> {
    let ek = mlkem_ek_from_bytes(&public_key)?;
    let m: [u8; 32] = os_random();
    let (ct, k) = ek.encapsulate_deterministic(&m.into());
    Ok(KemEncapsulation { ciphertext: ct.to_vec(), shared_secret: k.to_vec() })
}

/// ML-KEM-1024 decapsulation (FIPS 203 Decaps). Implicit rejection per the
/// standard: a forged/corrupt ciphertext of the right length yields a
/// pseudorandom shared key, not an error.
#[uniffi::export]
pub fn mlkem1024_decapsulate(ciphertext: Vec<u8>, private_key_seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let dk = mlkem_dk_from_seed(&private_key_seed)?;
    let ct: [u8; 1568] = ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| PrimitiveError::Key(format!("ml-kem ciphertext must be 1568 bytes, got {}", ciphertext.len())))?;
    Ok(dk.decapsulate(&ct.into()).to_vec())
}

/// Check that bytes are a valid ML-KEM-1024 encapsulation key (length + the
/// FIPS 203 modulus check).
#[uniffi::export]
pub fn mlkem1024_validate_public_key(public_key: Vec<u8>) -> bool {
    mlkem_ek_from_bytes(&public_key).is_ok()
}

/// ML-DSA-65 (crate ml-dsa 0.1) keeps polynomial matrices and vectors on the STACK: signing in a release
/// build takes ~400–512 KiB, in debug ~768 KiB. The calling thread is not ours: a JVM thread (desktop, Android —
/// 1 MiB, part of which is already used by Kotlin/JNA frames), a GCD thread on iOS — 512 KiB. Not enough means
/// SIGSEGV in the core and an app crash (the desktop window crashed while signing in republishPublicKeys). So
/// all ML-DSA work runs on a dedicated short-lived thread with a guaranteed stack; a panic is propagated
/// back to the caller, the result is identical byte for byte.
pub(crate) const PQ_STACK_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn on_pq_stack<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    std::thread::scope(|s| {
        let h = std::thread::Builder::new()
            .name("typex-pq".into())
            .stack_size(PQ_STACK_BYTES)
            .spawn_scoped(s, f)
            .expect("spawn ML-DSA worker thread");
        match h.join() {
            Ok(v) => v,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

pub(crate) fn mldsa_sk_from_seed(private_key_seed: &[u8]) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa65>, PrimitiveError> {
    let seed: [u8; 32] = private_key_seed
        .try_into()
        .map_err(|_| PrimitiveError::Key(format!("ml-dsa seed must be 32 bytes, got {}", private_key_seed.len())))?;
    Ok(ml_dsa::SigningKey::from_seed(&seed.into()))
}

/// ML-DSA-65 key generation (FIPS 204). Returns the raw 1952-byte verifying
/// key and the 32-byte xi seed as the private key.
#[uniffi::export]
pub fn mldsa65_generate_keypair() -> PqKeyPair {
    on_pq_stack(|| {
        let seed: [u8; 32] = os_random();
        let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed.into());
        PqKeyPair {
            public_key: sk.expanded_key().verifying_key().encode().to_vec(),
            private_key: seed.to_vec(),
        }
    })
}

/// Derive the ML-DSA-65 public (verifying) key from a stored 32-byte seed.
#[uniffi::export]
pub fn mldsa65_public_key(private_key_seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    on_pq_stack(|| Ok(mldsa_sk_from_seed(&private_key_seed)?.expanded_key().verifying_key().encode().to_vec()))
}

/// ML-DSA-65 signature (FIPS 204, pure mode, empty context, DETERMINISTIC
/// variant §3.4 — like Ed25519, same message → same signature). 3309 bytes.
#[uniffi::export]
pub fn mldsa65_sign(message: Vec<u8>, private_key_seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    on_pq_stack(|| {
        let sk = mldsa_sk_from_seed(&private_key_seed)?;
        let sig = sk
            .expanded_key()
            .sign_deterministic(&message, b"")
            .map_err(|e| PrimitiveError::Key(format!("ml-dsa sign: {e}")))?;
        Ok(sig.encode().to_vec())
    })
}

/// ML-DSA-65 verification (FIPS 204, pure mode, empty context). Wrong-length
/// or malformed key/signature returns false, never panics.
#[uniffi::export]
pub fn mldsa65_verify(message: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
    let Ok(pk_arr): Result<[u8; 1952], _> = public_key.as_slice().try_into() else { return false };
    let Ok(sig_arr): Result<[u8; 3309], _> = signature.as_slice().try_into() else { return false };
    on_pq_stack(|| {
        let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk_arr.into());
        let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sig_arr.into()) else { return false };
        vk.verify_with_context(&message, b"", &sig)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 TEST 1 — the standard Ed25519 vector. Signing was added for the
    /// self-inbox read capability (audit K-2) and the Go server verifies these
    /// signatures, so a drift here would lock every user out of their own inbox.
    #[test]
    fn ed25519_sign_matches_rfc8032_test1() {
        let seed =
            hex_decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let want_pub = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let want_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

        let pk = ed25519_public_from_seed(seed.clone()).expect("derive");
        assert_eq!(hex_encode(&pk), want_pub);

        let sig = ed25519_sign(Vec::new(), seed).expect("sign");
        assert_eq!(hex_encode(&sig), want_sig);
        assert!(ed25519_verify(pk, Vec::new(), sig));
    }

    /// A wrong-sized seed must be a typed error, never a panic across the FFI.
    #[test]
    fn ed25519_rejects_malformed_seed() {
        assert!(ed25519_public_from_seed(vec![0u8; 31]).is_err());
        assert!(ed25519_sign(b"msg".to_vec(), vec![0u8; 33]).is_err());
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn seed32(label: &str) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(format!("nyxel-golden-{label}").as_bytes());
        h.finalize().to_vec()
    }

    #[test]
    fn sha256_and_pbkdf2_match_bouncycastle_golden() {
        // Golden values captured from BouncyCastle at step 0.
        assert_eq!(
            hex::encode(sha256(b"nyxel".to_vec())),
            "341d83ef0cb6f854e03c3e7a6b8d27371ec0d3b3c019d7c364a1bec86a5214fe"
        );
        // PBKDF2-100k (password "Str0ngPass!123", salt = sha256("nyxel-golden-kdf-salt"))
        let salt = seed32("kdf-salt");
        assert_eq!(
            hex::encode(pbkdf2_hmac_sha256("Str0ngPass!123".to_string(), salt, 100000, 32).unwrap()),
            "25b5a55043bc5eb90d860e95bd1d556eb1bc9a15c94bd8a5bc4e526157903dc1"
        );
    }

    #[test]
    fn aesgcm_and_hkdf_match_bouncycastle_golden() {
        // HKDF golden (shared = sha256("nyxel-golden-aes-shared"))
        let shared = seed32("aes-shared");
        // deriveKeyHKDF(shared, "typex-hybrid-v1", "key-derivation")
        assert_eq!(
            hex::encode(hkdf_sha256(shared.clone(), b"typex-hybrid-v1".to_vec(), b"key-derivation".to_vec(), 32).unwrap()),
            "0fa9fd4c01255dc0ebd201f3a5e62677cfd244896b44d9b0fa4f5c50fc5c1a38"
        );
        // deriveKey(shared): salt = sha256("Typex-AES-Key-Derivation-v1"), info = "aes-key"
        let salt = sha256(b"Typex-AES-Key-Derivation-v1".to_vec());
        assert_eq!(
            hex::encode(hkdf_sha256(shared, salt, b"aes-key".to_vec(), 32).unwrap()),
            "250f129c33aee2f657521ac51fd26cf61b3016cdb3f19dace1e370fc62438c7f"
        );

        // HMAC-SHA256: RFC 4231 test case 2 known-answer.
        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec())),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        // HKDF expand-only (BC skipExtractParameters equivalent): RFC 5869 A.1
        // PRK/OKM known-answer.
        let prk = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        assert_eq!(
            hex::encode(hkdf_sha256_expand(prk, info, 42).unwrap()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        // AES-256-GCM golden (fixed key/iv/plaintext) → ct || tag
        let key = hex::decode("84c8d785a6bde1ef6a3edd523d2012e10f22652aae2dcc977ecb7db1b0ed5d96").unwrap();
        let iv = hex::decode("fecf1704cb8d25bbbc33a4a2").unwrap();
        let pt = hex::decode("476f6c64656e204145532d47434d20d0b2d0b5d0bad182d0bed18020f09f9a80").unwrap();
        let ct_tag = aes256_gcm_encrypt(key.clone(), iv.clone(), pt.clone(), vec![]).unwrap();
        let ct = &ct_tag[..ct_tag.len() - 16];
        let tag = &ct_tag[ct_tag.len() - 16..];
        assert_eq!(hex::encode(ct), "796f5592e87ea9828c2172f9fe546b99c8d0b9e79452a7abfa54e3a457e755a7");
        assert_eq!(hex::encode(tag), "bd324b4be30ebd262d3d631387703043");
        // roundtrip
        assert_eq!(aes256_gcm_decrypt(key, iv, ct_tag, vec![]).unwrap(), pt);
    }

    #[test]
    fn x25519_matches_bouncycastle_golden() {
        // Golden from app/src/androidTest/assets/golden/primitives.json (x25519):
        // priv_a = sha256("nyxel-golden-x25519-a"), priv_b = sha256("nyxel-golden-x25519-b").
        let priv_a = seed32("x25519-a");
        let priv_b = seed32("x25519-b");
        assert_eq!(hex::encode(&priv_a), "baf85156061ca0a4bce59e3a4e7326f0d37eaa8245b612fb2166dc1d8141ae65");

        let pub_a = x25519_public_key(priv_a.clone()).unwrap();
        let pub_b = x25519_public_key(priv_b.clone()).unwrap();
        assert_eq!(hex::encode(&pub_a), "9243caff4580359ac499e2c4f5af355b11e2554ce82cbf3683f03f7529dd6346");
        assert_eq!(hex::encode(&pub_b), "b006817088e3e556316d434c5a1ef3fbd33a24be67d6f917066902d537f41f15");

        let shared_ab = x25519_shared_secret(priv_a, pub_b).unwrap();
        let shared_ba = x25519_shared_secret(priv_b, pub_a).unwrap();
        assert_eq!(shared_ab, shared_ba);
        assert_eq!(hex::encode(&shared_ab), "c754757d72fcc3284709b37244e2ab466a170e4813bb10cb2f8bc3bbf853b41a");

        // Wrong-length keys must error, not panic across the FFI.
        assert!(x25519_public_key(vec![0u8; 31]).is_err());
        assert!(x25519_shared_secret(vec![0u8; 32], vec![0u8; 33]).is_err());
    }

    #[test]
    fn secp256k1_matches_bouncycastle_golden() {
        // Golden from app/src/androidTest/assets/golden/primitives.json (secp256k1):
        // priv = sha256("nyxel-golden-secp256k1"), message "nyxel golden secp256k1 message".
        let priv_key = seed32("secp256k1");
        assert_eq!(hex::encode(&priv_key), "29bbc813047bffa96baaabfaed510d1dc5783ccc5e25d7b7ab0cc9e65e4fb596");

        let pub_key = secp256k1_public_key(priv_key.clone()).unwrap();
        assert_eq!(
            hex::encode(&pub_key),
            "04c63dc4414c49fe286fa82635bbe33509f7c68e3bcb6ac003dc3ae993c24cf546f5cb6b5309e4aa231ace61634557297997184f3c95e5b3b752f0cf448ab817b9"
        );

        // The Kotlin wrapper hashes the message with SHA-256 before signing.
        let hash = sha256(b"nyxel golden secp256k1 message".to_vec());
        let sig = secp256k1_sign_hash(hash.clone(), priv_key).unwrap();
        assert_eq!(
            hex::encode(&sig),
            "6cd34c12f6cbfc78b84d62066aaa8468824efc7631fbb41409c75ec2248d8590171209bfefe39c67cb9a6b76ed0f788b00f4286cdbbf0204d12b81a8cad0859c"
        );

        assert!(secp256k1_verify_hash(hash.clone(), sig.clone(), pub_key.clone()));
        // Tampered message must fail.
        assert!(!secp256k1_verify_hash(sha256(b"tampered".to_vec()), sig.clone(), pub_key.clone()));
        // BC's verifier accepted high-S signatures — ours must too (s' = n - s).
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
        let mut high_s = sig.clone();
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = n[i] as i16 - sig[32 + i] as i16 - borrow;
            borrow = if d < 0 { 1 } else { 0 };
            high_s[32 + i] = (d & 0xff) as u8;
        }
        assert!(secp256k1_verify_hash(hash.clone(), high_s, pub_key.clone()));
        // Garbage inputs return false, never panic.
        assert!(!secp256k1_verify_hash(hash, vec![0u8; 64], pub_key));
    }

    #[test]
    fn ed25519_matches_bouncycastle_golden() {
        // Golden from primitives.json (key_transparency): STH message signed by
        // the BC Ed25519Signer with priv = sha256("nyxel-golden-kt-ed25519").
        let pub_key = hex::decode("bb285d8fc24b89c1946dc20594665139980a4f1d5c954a0fc8cb8e9795846b42").unwrap();
        let msg = b"KT-STH-v1|2|57198f35d3dd5baff384d33c1ac3bb4e0b99979123071a141d091baf4bb8ba24|1750000000000".to_vec();
        let sig = hex::decode("c837c2522777d5054ed3896494f481e85ff545831165f96d150ecdd2c9f3c7c5d22975ec83544579f376bae0839da3863ae8fda4966db6c30ce2c96006042500").unwrap();

        assert!(ed25519_verify(pub_key.clone(), msg.clone(), sig.clone()));

        // Tampered message / signature / wrong key must fail.
        let mut tampered = msg.clone();
        tampered[0] ^= 1;
        assert!(!ed25519_verify(pub_key.clone(), tampered, sig.clone()));
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 1;
        assert!(!ed25519_verify(pub_key.clone(), msg.clone(), bad_sig));
        // Malformed inputs return false, never panic.
        assert!(!ed25519_verify(vec![0u8; 31], msg.clone(), sig.clone()));
        assert!(!ed25519_verify(pub_key, msg, vec![0u8; 63]));
    }

    #[test]
    fn argon2id_matches_bouncycastle_golden() {
        // Golden captured from the BouncyCastle Argon2id (step 0):
        // password "Str0ngPass!123", salt = sha256("nyxel-golden-kdf-salt").
        let salt = seed32("kdf-salt");
        assert_eq!(
            hex::encode(&salt),
            "15d08088d333b971dba0ee899f2494051a4bf59f1db2ae42869d4cc8f4dfac9a"
        );
        let out = argon2id_derive("Str0ngPass!123".to_string(), salt, 32).unwrap();
        assert_eq!(
            hex::encode(out),
            "5993fde73c0fc6dfa02bc96fb5ec405bb6a62f9f87ca647c875d517d97a509a2"
        );
    }
}

#[cfg(test)]
mod pq_tests {
    use super::*;

    fn seed32(label: &str) -> Vec<u8> {
        sha256(format!("nyxel-golden-{label}").as_bytes().to_vec())
    }

    // SELF-GOLDEN (iOS contract anchors): all PQ inputs are deterministic from
    // fixed seeds, so these byte-anchor the FINAL-FIPS formats. If a future
    // crate update changes any of these hashes, the wire format broke — stop.
    #[test]
    fn mlkem1024_fips203_self_golden_and_roundtrip() {
        let kem_seed = [seed32("mlkem-d"), seed32("mlkem-z")].concat(); // 64-byte d||z
        let pk = mlkem1024_public_key(kem_seed.clone()).unwrap();
        assert_eq!(pk.len(), 1568);
        assert_eq!(
            hex::encode(sha256(pk.clone())),
            "d0f9b0bb537d7f66d4e687edb450aed1875d1e5ba5b50489b12e0e6cce76a5c5"
        );

        // Deterministic Encaps with fixed m — anchors ciphertext + shared key bytes.
        let m: [u8; 32] = seed32("mlkem-m").try_into().unwrap();
        let ek = mlkem_ek_from_bytes(&pk).unwrap();
        let (ct, k) = ek.encapsulate_deterministic(&m.into());
        assert_eq!(ct.len(), 1568);
        assert_eq!(
            hex::encode(sha256(ct.to_vec())),
            "4b3616bed3b1d0e9a354d660710818bc7d8fe548a60a2859ce14047eb157b23a"
        );
        assert_eq!(
            hex::encode(&k),
            "1abd9c7d449b01c4e7c71a710d8b8ca96e24478114ff736b4baa2cb4b477f1c7"
        );
        assert_eq!(mlkem1024_decapsulate(ct.to_vec(), kem_seed.clone()).unwrap(), k.to_vec());

        // FIPS 203 implicit rejection: corrupt ct of the right length yields a
        // DIFFERENT pseudorandom key, not an error.
        let mut bad = ct.to_vec();
        bad[0] ^= 1;
        let k2 = mlkem1024_decapsulate(bad, kem_seed.clone()).unwrap();
        assert_eq!(k2.len(), 32);
        assert_ne!(k2, k.to_vec());

        // Random-keypair roundtrip through the exported API.
        let kp = mlkem1024_generate_keypair();
        assert_eq!(kp.public_key.len(), 1568);
        assert_eq!(kp.private_key.len(), 64);
        let enc = mlkem1024_encapsulate(kp.public_key.clone()).unwrap();
        assert_eq!(
            mlkem1024_decapsulate(enc.ciphertext, kp.private_key).unwrap(),
            enc.shared_secret
        );
        assert!(mlkem1024_validate_public_key(kp.public_key));
        // Coefficients >= q fail the FIPS 203 modulus check; wrong length fails too.
        assert!(!mlkem1024_validate_public_key(vec![0xffu8; 1568]));
        assert!(!mlkem1024_validate_public_key(vec![0u8; 1567]));
        assert!(mlkem1024_decapsulate(vec![0u8; 1568], vec![0u8; 63]).is_err());
        assert!(mlkem1024_decapsulate(vec![0u8; 1567], kem_seed).is_err());
    }

    #[test]
    fn mldsa65_fips204_self_golden_and_roundtrip() {
        let dsa_seed = seed32("mldsa-xi"); // 32-byte xi
        let pk = mldsa65_public_key(dsa_seed.clone()).unwrap();
        assert_eq!(pk.len(), 1952);
        assert_eq!(
            hex::encode(sha256(pk.clone())),
            "230b6006a6591511b6609862bd9e0cdc91679ba865a47a054d989159d4bd3eaa"
        );

        // Deterministic variant → byte-exact signature from a fixed seed+message.
        let msg = b"nyxel golden ml-dsa message".to_vec();
        let sig = mldsa65_sign(msg.clone(), dsa_seed.clone()).unwrap();
        assert_eq!(sig.len(), 3309);
        assert_eq!(
            hex::encode(sha256(sig.clone())),
            "89b659b70d4d1553d2d92f7b86d24120ab2e55de6d9098b82c049d3368c1404d"
        );

        assert!(mldsa65_verify(msg.clone(), sig.clone(), pk.clone()));
        // Tampered message / signature must fail.
        let mut tampered = msg.clone();
        tampered[0] ^= 1;
        assert!(!mldsa65_verify(tampered, sig.clone(), pk.clone()));
        let mut bad_sig = sig.clone();
        bad_sig[100] ^= 1;
        assert!(!mldsa65_verify(msg.clone(), bad_sig, pk.clone()));
        // Malformed lengths return false / error, never panic.
        assert!(!mldsa65_verify(msg.clone(), sig.clone(), vec![0u8; 1951]));
        assert!(!mldsa65_verify(msg.clone(), vec![0u8; 3308], pk.clone()));
        assert!(mldsa65_sign(msg.clone(), vec![0u8; 31]).is_err());

        // Random-keypair roundtrip through the exported API.
        let kp = mldsa65_generate_keypair();
        assert_eq!(kp.public_key.len(), 1952);
        assert_eq!(kp.private_key.len(), 32);
        let sig2 = mldsa65_sign(msg.clone(), kp.private_key.clone()).unwrap();
        assert!(mldsa65_verify(msg.clone(), sig2.clone(), kp.public_key.clone()));
        // Signature bound to its key: does not verify under the golden key.
        assert!(!mldsa65_verify(msg, sig2, pk));
    }
}
