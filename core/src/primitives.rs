//! Cryptographic primitives: ML-KEM-1024, ML-DSA-65, X25519, Ed25519, secp256k1,
//! AES-256-GCM, HKDF-SHA256, PBKDF2, Argon2id.

#[cfg(test)]
const HYBRID_LABEL: [u8; 15] = [0x74, 0x79, 0x70, 0x65, 0x78, 0x2d, 0x68, 0x79, 0x62, 0x72, 0x69, 0x64, 0x2d, 0x76, 0x31];
#[cfg(test)]
const AES_KDF_LABEL: [u8; 27] = [0x54, 0x79, 0x70, 0x65, 0x78, 0x2d, 0x41, 0x45, 0x53, 0x2d, 0x4b, 0x65, 0x79, 0x2d, 0x44, 0x65, 0x72, 0x69, 0x76, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d, 0x76, 0x31];
use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hmac::Hmac;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

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

#[uniffi::export]
pub fn sha256(data: Vec<u8>) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(&data);
    h.finalize().to_vec()
}

#[uniffi::export]
pub fn pbkdf2_hmac_sha256(password: String, salt: Vec<u8>, iterations: u32, key_length: u32) -> Result<Vec<u8>, PrimitiveError> {
    let mut out = vec![0u8; key_length as usize];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, iterations, &mut out)
        .map_err(|e| PrimitiveError::Key(format!("pbkdf2: {e}")))?;
    Ok(out)
}

#[uniffi::export]
pub fn hkdf_sha256(ikm: Vec<u8>, salt: Vec<u8>, info: Vec<u8>, length: u32) -> Result<Vec<u8>, PrimitiveError> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut out = vec![0u8; length as usize];
    hk.expand(&info, &mut out)
        .map_err(|e| PrimitiveError::Key(format!("hkdf: {e}")))?;
    Ok(out)
}

#[uniffi::export]
pub fn hmac_sha256(key: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    use hmac::Mac as _;
    let mut m = <Hmac<Sha256> as hmac::Mac>::new_from_slice(&key)
        .expect("HMAC-SHA256 accepts keys of any length");
    m.update(&data);
    m.finalize().into_bytes().to_vec()
}

#[uniffi::export]
pub fn hkdf_sha256_expand(prk: Vec<u8>, info: Vec<u8>, length: u32) -> Result<Vec<u8>, PrimitiveError> {
    let hk = hkdf::Hkdf::<Sha256>::from_prk(&prk)
        .map_err(|e| PrimitiveError::Key(format!("hkdf-expand prk: {e}")))?;
    let mut out = vec![0u8; length as usize];
    hk.expand(&info, &mut out)
        .map_err(|e| PrimitiveError::Key(format!("hkdf-expand: {e}")))?;
    Ok(out)
}

#[uniffi::export]
pub fn aes256_gcm_encrypt(key: Vec<u8>, iv: Vec<u8>, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| PrimitiveError::Aead(e.to_string()))?;

    if iv.len() != 12 {
        return Err(PrimitiveError::Aead(format!("iv must be 12 bytes, got {}", iv.len())));
    }
    let nonce = Nonce::from_slice(&iv);
    cipher
        .encrypt(nonce, Payload { msg: &plaintext, aad: &aad })
        .map_err(|e| PrimitiveError::Aead(e.to_string()))
}

#[uniffi::export]
pub fn aes256_gcm_decrypt(key: Vec<u8>, iv: Vec<u8>, ciphertext_with_tag: Vec<u8>, aad: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| PrimitiveError::Aead(e.to_string()))?;

    if iv.len() != 12 {
        return Err(PrimitiveError::Aead(format!("iv must be 12 bytes, got {}", iv.len())));
    }
    let nonce = Nonce::from_slice(&iv);
    cipher
        .decrypt(nonce, Payload { msg: &ciphertext_with_tag, aad: &aad })
        .map_err(|e| PrimitiveError::Aead(e.to_string()))
}

#[uniffi::export]
pub fn x25519_public_key(private_key: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let sk = to_arr32(&private_key, "x25519 private key")?;
    Ok(x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES).to_vec())
}

#[uniffi::export]
pub fn x25519_shared_secret(private_key: Vec<u8>, public_key: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let sk = to_arr32(&private_key, "x25519 private key")?;
    let pk = to_arr32(&public_key, "x25519 public key")?;
    Ok(x25519_dalek::x25519(sk, pk).to_vec())
}

#[uniffi::export]
pub fn secp256k1_public_key(private_key: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let sk = SigningKey::from_slice(&private_key)
        .map_err(|e| PrimitiveError::Key(format!("secp256k1 private key: {e}")))?;
    Ok(sk.verifying_key().to_encoded_point(false).as_bytes().to_vec())
}

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

    let sig = sig.normalize_s().unwrap_or(sig);
    Ok(sig.to_bytes().to_vec())
}

#[uniffi::export]
pub fn secp256k1_verify_hash(hash: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
    if hash.len() != 32 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_sec1_bytes(&public_key) else { return false };
    let Ok(sig) = EcdsaSignature::from_slice(&signature) else { return false };
    let sig = sig.normalize_s().unwrap_or(sig);
    vk.verify_prehash(&hash, &sig).is_ok()
}

#[uniffi::export]
pub fn ed25519_verify(public_key: Vec<u8>, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let Ok(pk_arr): Result<[u8; 32], _> = public_key.as_slice().try_into() else { return false };
    let Ok(sig_arr): Result<[u8; 64], _> = signature.as_slice().try_into() else { return false };
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr) else { return false };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    use ed25519_dalek::Verifier;
    vk.verify(&message, &sig).is_ok()
}

#[uniffi::export]
pub fn ed25519_public_from_seed(seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let seed_arr = to_arr32(&seed, "ed25519 seed")?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    Ok(sk.verifying_key().to_bytes().to_vec())
}

#[uniffi::export]
pub fn ed25519_sign(message: Vec<u8>, seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let seed_arr = to_arr32(&seed, "ed25519 seed")?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
    use ed25519_dalek::Signer;
    Ok(sk.sign(&message).to_bytes().to_vec())
}

use ml_kem::{Decapsulate as _, KeyExport as _};

#[derive(uniffi::Record)]
pub struct PqKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(uniffi::Record)]
pub struct KemEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

fn os_random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).expect("OS RNG is always available on Android/iOS");
    out
}

fn mlkem_dk_from_seed(private_key_seed: &[u8]) -> Result<ml_kem::DecapsulationKey1024, PrimitiveError> {
    let seed: [u8; 64] = private_key_seed
        .try_into()
        .map_err(|_| PrimitiveError::Key(format!("ml-kem seed must be 64 bytes, got {}", private_key_seed.len())))?;
    Ok(ml_kem::DecapsulationKey1024::from_seed(seed.into()))
}

fn mlkem_ek_from_bytes(public_key: &[u8]) -> Result<ml_kem::EncapsulationKey1024, PrimitiveError> {
    let arr: [u8; 1568] = public_key
        .try_into()
        .map_err(|_| PrimitiveError::Key(format!("ml-kem public key must be 1568 bytes, got {}", public_key.len())))?;
    ml_kem::EncapsulationKey1024::new(&arr.into())
        .map_err(|_| PrimitiveError::Key("ml-kem public key failed FIPS 203 modulus validation".into()))
}

#[uniffi::export]
pub fn mlkem1024_generate_keypair() -> PqKeyPair {
    let seed: [u8; 64] = os_random();
    let dk = ml_kem::DecapsulationKey1024::from_seed(seed.into());
    PqKeyPair {
        public_key: dk.encapsulation_key().to_bytes().to_vec(),
        private_key: seed.to_vec(),
    }
}

#[uniffi::export]
pub fn mlkem1024_public_key(private_key_seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    Ok(mlkem_dk_from_seed(&private_key_seed)?.encapsulation_key().to_bytes().to_vec())
}

#[uniffi::export]
pub fn mlkem1024_encapsulate(public_key: Vec<u8>) -> Result<KemEncapsulation, PrimitiveError> {
    let ek = mlkem_ek_from_bytes(&public_key)?;
    let m: [u8; 32] = os_random();
    let (ct, k) = ek.encapsulate_deterministic(&m.into());
    Ok(KemEncapsulation { ciphertext: ct.to_vec(), shared_secret: k.to_vec() })
}

#[uniffi::export]
pub fn mlkem1024_decapsulate(ciphertext: Vec<u8>, private_key_seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let dk = mlkem_dk_from_seed(&private_key_seed)?;
    let ct: [u8; 1568] = ciphertext
        .as_slice()
        .try_into()
        .map_err(|_| PrimitiveError::Key(format!("ml-kem ciphertext must be 1568 bytes, got {}", ciphertext.len())))?;
    Ok(dk.decapsulate(&ct.into()).to_vec())
}

#[uniffi::export]
pub fn mlkem1024_validate_public_key(public_key: Vec<u8>) -> bool {
    mlkem_ek_from_bytes(&public_key).is_ok()
}

fn mldsa_sk_from_seed(private_key_seed: &[u8]) -> Result<ml_dsa::SigningKey<ml_dsa::MlDsa65>, PrimitiveError> {
    let seed: [u8; 32] = private_key_seed
        .try_into()
        .map_err(|_| PrimitiveError::Key(format!("ml-dsa seed must be 32 bytes, got {}", private_key_seed.len())))?;
    Ok(ml_dsa::SigningKey::from_seed(&seed.into()))
}

#[uniffi::export]
pub fn mldsa65_generate_keypair() -> PqKeyPair {
    let seed: [u8; 32] = os_random();
    let sk = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_seed(&seed.into());
    PqKeyPair {
        public_key: sk.expanded_key().verifying_key().encode().to_vec(),
        private_key: seed.to_vec(),
    }
}

#[uniffi::export]
pub fn mldsa65_public_key(private_key_seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    Ok(mldsa_sk_from_seed(&private_key_seed)?.expanded_key().verifying_key().encode().to_vec())
}

#[uniffi::export]
pub fn mldsa65_sign(message: Vec<u8>, private_key_seed: Vec<u8>) -> Result<Vec<u8>, PrimitiveError> {
    let sk = mldsa_sk_from_seed(&private_key_seed)?;
    let sig = sk
        .expanded_key()
        .sign_deterministic(&message, b"")
        .map_err(|e| PrimitiveError::Key(format!("ml-dsa sign: {e}")))?;
    Ok(sig.encode().to_vec())
}

#[uniffi::export]
pub fn mldsa65_verify(message: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
    let Ok(pk_arr): Result<[u8; 1952], _> = public_key.as_slice().try_into() else { return false };
    let Ok(sig_arr): Result<[u8; 3309], _> = signature.as_slice().try_into() else { return false };
    let vk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk_arr.into());
    let Some(sig) = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sig_arr.into()) else { return false };
    vk.verify_with_context(&message, b"", &sig)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        h.update(format!("umbera-golden-{label}").as_bytes());
        h.finalize().to_vec()
    }

    #[test]
    fn sha256_and_pbkdf2_match_bouncycastle_golden() {
        assert_eq!(
            hex::encode(sha256(b"umbera".to_vec())),
            "6be97ca35300f193da159056e21aeda76d71b45d29a97c40fab320f01718d314"
        );

        let salt = seed32("kdf-salt");
        assert_eq!(
            hex::encode(pbkdf2_hmac_sha256("Str0ngPass!123".to_string(), salt, 100000, 32).unwrap()),
            "18383ccbdd79c4be94c64e6a0841a79a6ea17d69820a6c7d2ba5937b026ee685"
        );
    }

    #[test]
    fn aesgcm_and_hkdf_match_bouncycastle_golden() {
        let shared = seed32("aes-shared");

        assert_eq!(
            hex::encode(hkdf_sha256(shared.clone(), HYBRID_LABEL.to_vec(), b"key-derivation".to_vec(), 32).unwrap()),
            "eded6b879def64aa51556812a8b2c3e4a2a2a19807797f0c971a716806b9d72e"
        );

        let salt = sha256(AES_KDF_LABEL.to_vec());
        assert_eq!(
            hex::encode(hkdf_sha256(shared, salt, b"aes-key".to_vec(), 32).unwrap()),
            "d1935e58b6766bdd6319abb728997a338f2edc5a9ff6f7c6f5e12e4f1e11e480"
        );

        assert_eq!(
            hex::encode(hmac_sha256(b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec())),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );

        let prk = hex::decode("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        assert_eq!(
            hex::encode(hkdf_sha256_expand(prk, info, 42).unwrap()),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );

        let key = hex::decode("84c8d785a6bde1ef6a3edd523d2012e10f22652aae2dcc977ecb7db1b0ed5d96").unwrap();
        let iv = hex::decode("fecf1704cb8d25bbbc33a4a2").unwrap();
        let pt = hex::decode("476f6c64656e204145532d47434d20d0b2d0b5d0bad182d0bed18020f09f9a80").unwrap();
        let ct_tag = aes256_gcm_encrypt(key.clone(), iv.clone(), pt.clone(), vec![]).unwrap();
        let ct = &ct_tag[..ct_tag.len() - 16];
        let tag = &ct_tag[ct_tag.len() - 16..];
        assert_eq!(hex::encode(ct), "796f5592e87ea9828c2172f9fe546b99c8d0b9e79452a7abfa54e3a457e755a7");
        assert_eq!(hex::encode(tag), "bd324b4be30ebd262d3d631387703043");

        assert_eq!(aes256_gcm_decrypt(key, iv, ct_tag, vec![]).unwrap(), pt);
    }

    #[test]
    fn x25519_matches_bouncycastle_golden() {
        let priv_a = seed32("x25519-a");
        let priv_b = seed32("x25519-b");
        assert_eq!(hex::encode(&priv_a), "af572cf62c73cb1ee9d7c990ac233adabec4df9457dd23e195c2af5c13c4bfda");

        let pub_a = x25519_public_key(priv_a.clone()).unwrap();
        let pub_b = x25519_public_key(priv_b.clone()).unwrap();
        assert_eq!(hex::encode(&pub_a), "f795c99206b879d3c6f1313a40f35deab66a970d085783a23937254ec280ca48");
        assert_eq!(hex::encode(&pub_b), "a104a2fd2125cd530b9fe9153e7b02e7dbd60f2b22919e7a9076f5466861bd6a");

        let shared_ab = x25519_shared_secret(priv_a, pub_b).unwrap();
        let shared_ba = x25519_shared_secret(priv_b, pub_a).unwrap();
        assert_eq!(shared_ab, shared_ba);
        assert_eq!(hex::encode(&shared_ab), "c5e7e82161c4a967cbd43acfec1f41d04103ca6cfdae3e009ebd79ddc65d0b07");

        assert!(x25519_public_key(vec![0u8; 31]).is_err());
        assert!(x25519_shared_secret(vec![0u8; 32], vec![0u8; 33]).is_err());
    }

    #[test]
    fn secp256k1_matches_bouncycastle_golden() {
        let priv_key = seed32("secp256k1");
        assert_eq!(hex::encode(&priv_key), "7122dbc3d5da2a1e8253d7872cc121e242107108e5eed8eaccb40b16612b9e83");

        let pub_key = secp256k1_public_key(priv_key.clone()).unwrap();
        assert_eq!(
            hex::encode(&pub_key),
            "04a32baa880dc2dd1346a52f80c40b10e95299972dd538d3e87601949a23830cb0acf70e0e0d2426289716b0eebbe20831d2a6465c6d07bdda5ac62d98c8a1dab9"
        );

        let hash = sha256(b"umbera golden secp256k1 message".to_vec());
        let sig = secp256k1_sign_hash(hash.clone(), priv_key).unwrap();
        assert_eq!(
            hex::encode(&sig),
            "f72df61ee88df8126441f1a0ce337486c517369ac597f584351f14d2e16f44607636df45b66c115c48aaeae135c0bea3939ead8f75d534debf7999552a88b1b2"
        );

        assert!(secp256k1_verify_hash(hash.clone(), sig.clone(), pub_key.clone()));

        assert!(!secp256k1_verify_hash(sha256(b"tampered".to_vec()), sig.clone(), pub_key.clone()));

        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
        let mut high_s = sig.clone();
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = n[i] as i16 - sig[32 + i] as i16 - borrow;
            borrow = if d < 0 { 1 } else { 0 };
            high_s[32 + i] = (d & 0xff) as u8;
        }
        assert!(secp256k1_verify_hash(hash.clone(), high_s, pub_key.clone()));

        assert!(!secp256k1_verify_hash(hash, vec![0u8; 64], pub_key));
    }

    #[test]
    fn ed25519_matches_bouncycastle_golden() {
        let pub_key = hex::decode("bb285d8fc24b89c1946dc20594665139980a4f1d5c954a0fc8cb8e9795846b42").unwrap();
        let msg = b"KT-STH-v1|2|57198f35d3dd5baff384d33c1ac3bb4e0b99979123071a141d091baf4bb8ba24|1750000000000".to_vec();
        let sig = hex::decode("c837c2522777d5054ed3896494f481e85ff545831165f96d150ecdd2c9f3c7c5d22975ec83544579f376bae0839da3863ae8fda4966db6c30ce2c96006042500").unwrap();

        assert!(ed25519_verify(pub_key.clone(), msg.clone(), sig.clone()));

        let mut tampered = msg.clone();
        tampered[0] ^= 1;
        assert!(!ed25519_verify(pub_key.clone(), tampered, sig.clone()));
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 1;
        assert!(!ed25519_verify(pub_key.clone(), msg.clone(), bad_sig));

        assert!(!ed25519_verify(vec![0u8; 31], msg.clone(), sig.clone()));
        assert!(!ed25519_verify(pub_key, msg, vec![0u8; 63]));
    }

    #[test]
    fn argon2id_matches_bouncycastle_golden() {
        let salt = seed32("kdf-salt");
        assert_eq!(
            hex::encode(&salt),
            "8cf9f89c4e41387f332e528b9d05529db015291c3ac90edd20028b1fe69f6d64"
        );
        let out = argon2id_derive("Str0ngPass!123".to_string(), salt, 32).unwrap();
        assert_eq!(
            hex::encode(out),
            "1481c73b225be8026423a3ade1f8b68c482f4be7267a3d0c1cdd1ae56a7df887"
        );
    }
}

#[cfg(test)]
mod pq_tests {
    use super::*;

    fn seed32(label: &str) -> Vec<u8> {
        sha256(format!("umbera-golden-{label}").as_bytes().to_vec())
    }

    #[test]
    fn mlkem1024_fips203_self_golden_and_roundtrip() {
        let kem_seed = [seed32("mlkem-d"), seed32("mlkem-z")].concat();
        let pk = mlkem1024_public_key(kem_seed.clone()).unwrap();
        assert_eq!(pk.len(), 1568);
        assert_eq!(
            hex::encode(sha256(pk.clone())),
            "c3a1e351fd7d95157d6af9eae41e63c391471ad4f11f5e74fe549f6a1bfcab5e"
        );

        let m: [u8; 32] = seed32("mlkem-m").try_into().unwrap();
        let ek = mlkem_ek_from_bytes(&pk).unwrap();
        let (ct, k) = ek.encapsulate_deterministic(&m.into());
        assert_eq!(ct.len(), 1568);
        assert_eq!(
            hex::encode(sha256(ct.to_vec())),
            "9abacc3c7c775dec48d2fcc1413e8e46e283a90d78fe37ec23f2fdc44393426f"
        );
        assert_eq!(
            hex::encode(&k),
            "3c5838542d57419231bb0ea71525e2d4457d2bc46d03e4a95760a06c4856cedd"
        );
        assert_eq!(mlkem1024_decapsulate(ct.to_vec(), kem_seed.clone()).unwrap(), k.to_vec());

        let mut bad = ct.to_vec();
        bad[0] ^= 1;
        let k2 = mlkem1024_decapsulate(bad, kem_seed.clone()).unwrap();
        assert_eq!(k2.len(), 32);
        assert_ne!(k2, k.to_vec());

        let kp = mlkem1024_generate_keypair();
        assert_eq!(kp.public_key.len(), 1568);
        assert_eq!(kp.private_key.len(), 64);
        let enc = mlkem1024_encapsulate(kp.public_key.clone()).unwrap();
        assert_eq!(
            mlkem1024_decapsulate(enc.ciphertext, kp.private_key).unwrap(),
            enc.shared_secret
        );
        assert!(mlkem1024_validate_public_key(kp.public_key));

        assert!(!mlkem1024_validate_public_key(vec![0xffu8; 1568]));
        assert!(!mlkem1024_validate_public_key(vec![0u8; 1567]));
        assert!(mlkem1024_decapsulate(vec![0u8; 1568], vec![0u8; 63]).is_err());
        assert!(mlkem1024_decapsulate(vec![0u8; 1567], kem_seed).is_err());
    }

    #[test]
    fn mldsa65_fips204_self_golden_and_roundtrip() {
        let dsa_seed = seed32("mldsa-xi");
        let pk = mldsa65_public_key(dsa_seed.clone()).unwrap();
        assert_eq!(pk.len(), 1952);
        assert_eq!(
            hex::encode(sha256(pk.clone())),
            "6134bfb91668b5db307287832690fd006d26a054fb0ada2db1b3b26990a6e173"
        );

        let msg = b"umbera golden ml-dsa message".to_vec();
        let sig = mldsa65_sign(msg.clone(), dsa_seed.clone()).unwrap();
        assert_eq!(sig.len(), 3309);
        assert_eq!(
            hex::encode(sha256(sig.clone())),
            "165d89a70f91c3d2106658d9977fa7011d4fa87768149d64dcc8c7443612f422"
        );

        assert!(mldsa65_verify(msg.clone(), sig.clone(), pk.clone()));

        let mut tampered = msg.clone();
        tampered[0] ^= 1;
        assert!(!mldsa65_verify(tampered, sig.clone(), pk.clone()));
        let mut bad_sig = sig.clone();
        bad_sig[100] ^= 1;
        assert!(!mldsa65_verify(msg.clone(), bad_sig, pk.clone()));

        assert!(!mldsa65_verify(msg.clone(), sig.clone(), vec![0u8; 1951]));
        assert!(!mldsa65_verify(msg.clone(), vec![0u8; 3308], pk.clone()));
        assert!(mldsa65_sign(msg.clone(), vec![0u8; 31]).is_err());

        let kp = mldsa65_generate_keypair();
        assert_eq!(kp.public_key.len(), 1952);
        assert_eq!(kp.private_key.len(), 32);
        let sig2 = mldsa65_sign(msg.clone(), kp.private_key.clone()).unwrap();
        assert!(mldsa65_verify(msg.clone(), sig2.clone(), kp.public_key.clone()));

        assert!(!mldsa65_verify(msg, sig2, pk));
    }
}
