// Core golden vectors. Captured with the crate versions shipped in the store builds
// Android 2.0.3 (221) and iOS 2.0.1 (100): sha2 0.10, hmac 0.12, hkdf 0.12, pbkdf2 0.12, argon2 0.5,
// aes-gcm 0.10, x25519-dalek 2, ed25519-dalek 2, curve25519-dalek 4, k256 0.13, ml-kem 0.3, ml-dsa 0.1.
// After upgrading any of them this test must pass without regeneration: otherwise old messages,
// keys, archives and signatures will not open for existing users.
//
// Regenerate (ONLY on the old crates): GOLDEN_WRITE=1 cargo test --test golden_primitives
use std::collections::BTreeMap;

use umbera_core::amf;
use umbera_core::devlink::{cert, comm};
use umbera_core::primitives as p;

fn hx(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhx(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn seq(n: usize, start: u8) -> Vec<u8> {
    (0..n).map(|i| start.wrapping_add((i * 7) as u8)).collect()
}

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/primitives-golden.json");

/// Inputs are deterministic; the ML-KEM ciphertext was generated randomly once and is stored in the file's inputs.
fn compute(stored: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut v = BTreeMap::new();
    let mut put = |k: &str, b: Vec<u8>| {
        v.insert(k.to_string(), hx(&b));
    };
    put("sha256", p::sha256(b"umbera golden".to_vec()));
    put("argon2id", p::argon2id_derive("correct horse".into(), seq(16, 1), 32).unwrap());
    put("pbkdf2", p::pbkdf2_hmac_sha256("pass".into(), seq(16, 3), 1000, 32).unwrap());
    put("hkdf", p::hkdf_sha256(seq(32, 5), seq(16, 9), b"umbera-info".to_vec(), 42).unwrap());
    put("hkdf_expand", p::hkdf_sha256_expand(seq(32, 11), b"exp".to_vec(), 64).unwrap());
    put("hmac", p::hmac_sha256(seq(32, 13), b"data".to_vec()));
    put("aes_gcm", p::aes256_gcm_encrypt(seq(32, 17), seq(12, 19), b"plaintext golden".to_vec(), b"aad".to_vec()).unwrap());
    put("x25519_pub", p::x25519_public_key(seq(32, 23)).unwrap());
    let peer = p::x25519_public_key(seq(32, 29)).unwrap();
    put("x25519_shared", p::x25519_shared_secret(seq(32, 23), peer).unwrap());
    let mut sk = seq(32, 31);
    sk[0] = 0x11; // guaranteed to be below the curve order
    put("secp256k1_pub", p::secp256k1_public_key(sk.clone()).unwrap());
    put("secp256k1_sig", p::secp256k1_sign_hash(p::sha256(b"m".to_vec()), sk).unwrap());
    put("ed25519_pub", p::ed25519_public_from_seed(seq(32, 37)).unwrap());
    put("ed25519_sig", p::ed25519_sign(b"golden".to_vec(), seq(32, 37)).unwrap());
    put("mlkem_pub", p::mlkem1024_public_key(seq(64, 41)).unwrap());
    let ct = unhx(stored.get("in_mlkem_ct").expect("in_mlkem_ct"));
    put("in_mlkem_ct", ct.clone());
    put("mlkem_ss", p::mlkem1024_decapsulate(ct, seq(64, 41)).unwrap());
    put("mldsa_pub", p::mldsa65_public_key(seq(32, 43)).unwrap());
    put("mldsa_sig", p::mldsa65_sign(b"golden".to_vec(), seq(32, 43)).unwrap());
    let kp = amf::amf_keypair_from_seed(seq(64, 47));
    put("amf_seed_secret", kp.secret.clone());
    put("amf_seed_public", kp.public.clone());
    put("amf_public_of", amf::amf_public_of(kp.secret).unwrap());
    put("amf_commit", amf::amf_commit(seq(32, 53), b"msg".to_vec()).unwrap());
    let dk = cert::device_public_keys(seq(32, 59)).unwrap();
    put("device_ed25519", dk.ed25519.clone());
    put("device_mldsa", dk.mldsa65.clone());
    put("device_x25519", dk.x25519.clone());
    put("device_mlkem", dk.mlkem1024.clone());
    put("device_sig", cert::device_sign(seq(32, 59), "ctx".into(), b"m".to_vec()).unwrap());
    put("account_sync_key", cert::account_sync_key(seq(32, 61), seq(64, 67)).unwrap());
    let roots = comm::comm_vault_roots(seq(32, 61), seq(64, 67)).unwrap();
    put("comm_root_v3", roots.v3.clone());
    put("comm_root_v2", roots.v2.clone());
    let ek = comm::comm_vault_epoch_keys(roots.v3.clone(), 7).unwrap();
    put("comm_epoch7", [ek.id, ek.auth_seed, ek.enc_key].concat());
    put("quant", umbera_core::quant_address("02".to_string() + &hx(&seq(32, 71)), hx(&seq(40, 73))).unwrap().into_bytes());
    v
}

#[test]
fn primitives_match_store_core_byte_for_byte() {
    let stored: BTreeMap<String, String> = match std::fs::read(PATH) {
        Ok(b) => serde_json::from_slice(&b).unwrap(),
        Err(_) => BTreeMap::new(),
    };
    if std::env::var("GOLDEN_WRITE").is_ok() {
        let mut seed = stored.clone();
        if !seed.contains_key("in_mlkem_ct") {
            let ek = p::mlkem1024_public_key(seq(64, 41)).unwrap();
            seed.insert("in_mlkem_ct".into(), hx(&p::mlkem1024_encapsulate(ek).unwrap().ciphertext));
        }
        let out = compute(&seed);
        std::fs::write(PATH, serde_json::to_vec_pretty(&out).unwrap()).unwrap();
        return;
    }
    assert!(!stored.is_empty(), "missing golden file {PATH}");
    let now = compute(&stored);
    for (k, want) in &stored {
        assert_eq!(now.get(k), Some(want), "vector {k} changed");
    }
    assert_eq!(now.len(), stored.len(), "vector set changed");
}
