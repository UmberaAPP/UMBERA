//! Proof tests: a sealed message opens only with the recipient's private keys.
//!
//! The sealing below is the same construction the apps use for every message
//! (see kotlin/.../MessageEncryption.kt, createSealedSenderHybridPQ):
//! ephemeral X25519 + ML-KEM-1024 encapsulation -> HKDF-SHA256 -> AES-256-GCM.
//! Run with: cargo test --test proof

use umbera_core::primitives::*;

const HYBRID_LABEL: [u8; 15] = [0x74, 0x79, 0x70, 0x65, 0x78, 0x2d, 0x68, 0x79, 0x62, 0x72, 0x69, 0x64, 0x2d, 0x76, 0x31];
const INFO: &[u8] = b"key-derivation";

fn random<const N: usize>() -> Vec<u8> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).unwrap();
    b.to_vec()
}

struct Recipient {
    x25519_private: Vec<u8>,
    x25519_public: Vec<u8>,
    kyber_private: Vec<u8>,
    kyber_public: Vec<u8>,
}

fn new_recipient() -> Recipient {
    let x25519_private = random::<32>();
    let x25519_public = x25519_public_key(x25519_private.clone()).unwrap();
    let kp = mlkem1024_generate_keypair();
    Recipient { x25519_private, x25519_public, kyber_private: kp.private_key, kyber_public: kp.public_key }
}

/// What travels over the network: only public values and ciphertext.
struct Sealed {
    ephemeral_public: Vec<u8>,
    kyber_ciphertext: Vec<u8>,
    iv: Vec<u8>,
    box_: Vec<u8>,
}

fn key(x25519_secret: Vec<u8>, kyber_secret: Vec<u8>) -> Vec<u8> {
    let okm = hkdf_sha256([x25519_secret, kyber_secret].concat(), HYBRID_LABEL.to_vec(), INFO.to_vec(), 64).unwrap();
    okm[..32].to_vec()
}

fn seal(to: &Recipient, plaintext: &[u8]) -> Sealed {
    let ephemeral_private = random::<32>();
    let ephemeral_public = x25519_public_key(ephemeral_private.clone()).unwrap();
    let ss1 = x25519_shared_secret(ephemeral_private, to.x25519_public.clone()).unwrap();
    let enc = mlkem1024_encapsulate(to.kyber_public.clone()).unwrap();
    let iv = random::<12>();
    let box_ = aes256_gcm_encrypt(key(ss1, enc.shared_secret), iv.clone(), plaintext.to_vec(), vec![]).unwrap();
    Sealed { ephemeral_public, kyber_ciphertext: enc.ciphertext, iv, box_ }
}

fn open(x25519_private: &[u8], kyber_private: &[u8], s: &Sealed) -> Option<Vec<u8>> {
    let ss1 = x25519_shared_secret(x25519_private.to_vec(), s.ephemeral_public.clone()).ok()?;
    let ss2 = mlkem1024_decapsulate(s.kyber_ciphertext.clone(), kyber_private.to_vec()).ok()?;
    aes256_gcm_decrypt(key(ss1, ss2), s.iv.clone(), s.box_.clone(), vec![]).ok()
}

const MESSAGE: &[u8] = b"meet at 7";

#[test]
fn the_recipient_can_read_the_message() {
    let bob = new_recipient();
    let sealed = seal(&bob, MESSAGE);
    assert_eq!(open(&bob.x25519_private, &bob.kyber_private, &sealed).as_deref(), Some(MESSAGE));
}

#[test]
fn the_ciphertext_does_not_contain_the_message() {
    let bob = new_recipient();
    let sealed = seal(&bob, MESSAGE);
    assert!(!sealed.box_.windows(MESSAGE.len()).any(|w| w == MESSAGE));
}

#[test]
fn anyone_with_other_keys_cannot_read_it() {
    let bob = new_recipient();
    let eve = new_recipient();
    let sealed = seal(&bob, MESSAGE);
    assert_eq!(open(&eve.x25519_private, &eve.kyber_private, &sealed), None);
}

#[test]
fn breaking_only_x25519_is_not_enough() {
    // An attacker who somehow learned Bob's X25519 key (for example with a future
    // quantum computer) still cannot open the message without his Kyber key.
    let bob = new_recipient();
    let eve = new_recipient();
    let sealed = seal(&bob, MESSAGE);
    assert_eq!(open(&bob.x25519_private, &eve.kyber_private, &sealed), None);
}

#[test]
fn breaking_only_kyber_is_not_enough() {
    let bob = new_recipient();
    let eve = new_recipient();
    let sealed = seal(&bob, MESSAGE);
    assert_eq!(open(&eve.x25519_private, &bob.kyber_private, &sealed), None);
}

#[test]
fn a_tampered_message_is_rejected() {
    let bob = new_recipient();
    let mut sealed = seal(&bob, MESSAGE);
    sealed.box_[0] ^= 1;
    assert_eq!(open(&bob.x25519_private, &bob.kyber_private, &sealed), None);
}

#[test]
fn every_message_is_sealed_with_fresh_keys() {
    // The same text sent twice produces unrelated ciphertexts.
    let bob = new_recipient();
    let a = seal(&bob, MESSAGE);
    let b = seal(&bob, MESSAGE);
    assert_ne!(a.ephemeral_public, b.ephemeral_public);
    assert_ne!(a.kyber_ciphertext, b.kyber_ciphertext);
    assert_ne!(a.box_, b.box_);
}
