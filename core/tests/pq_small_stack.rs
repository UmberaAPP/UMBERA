//! ML-DSA/ML-KEM must work on a thread with a small stack (JVM thread on desktop/Android, GCD on iOS):
//! ML-DSA signing used to take up to ~768 KiB of stack and crashed the desktop window (SIGSEGV in the core in republishPublicKeys).
use umbera_core::devlink::cert::{device_public_keys, device_seed_generate, device_sign, device_verify};
use umbera_core::primitives::*;

const SMALL: usize = 160 * 1024;

fn on_small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new().stack_size(SMALL).spawn(f).unwrap().join().unwrap();
}

#[test]
fn mldsa_on_a_small_caller_stack() {
    on_small_stack(|| {
        let kp = mldsa65_generate_keypair();
        assert_eq!(mldsa65_public_key(kp.private_key.clone()).unwrap(), kp.public_key);
        let sig = mldsa65_sign(b"republish".to_vec(), kp.private_key.clone()).unwrap();
        assert_eq!(sig.len(), 3309);
        assert!(mldsa65_verify(b"republish".to_vec(), sig.clone(), kp.public_key.clone()));
        assert!(!mldsa65_verify(b"other".to_vec(), sig, kp.public_key));
        // Deterministic signature — the same on any thread.
        let a = mldsa65_sign(b"x".to_vec(), kp.private_key.clone()).unwrap();
        let b = std::thread::spawn(move || mldsa65_sign(b"x".to_vec(), kp.private_key).unwrap()).join().unwrap();
        assert_eq!(a, b);
    });
}

#[test]
fn device_keys_and_signatures_on_a_small_caller_stack() {
    on_small_stack(|| {
        let seed = device_seed_generate();
        let keys = device_public_keys(seed.clone()).unwrap();
        let sig = device_sign(seed, "ctx".into(), b"m".to_vec()).unwrap();
        assert!(device_verify(keys, "ctx".into(), b"m".to_vec(), sig));
    });
}

#[test]
fn mlkem_on_a_small_caller_stack() {
    on_small_stack(|| {
        let kp = mlkem1024_generate_keypair();
        let enc = mlkem1024_encapsulate(kp.public_key.clone()).unwrap();
        assert_eq!(mlkem1024_decapsulate(enc.ciphertext.clone(), kp.private_key).unwrap(), enc.shared_secret);
    });
}

#[test]
fn many_parallel_signatures() {
    let kp = mldsa65_generate_keypair();
    let hs: Vec<_> = (0..16).map(|i| {
        let (sk, pk) = (kp.private_key.clone(), kp.public_key.clone());
        std::thread::Builder::new().stack_size(SMALL).spawn(move || {
            let m = format!("m{i}").into_bytes();
            let s = mldsa65_sign(m.clone(), sk).unwrap();
            assert!(mldsa65_verify(m, s, pk));
        }).unwrap()
    }).collect();
    for h in hs { h.join().unwrap(); }
}
