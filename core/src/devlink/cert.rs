// Device identity and the "this device belongs to my account" certificate.
//
// A device stores ONE secret — 32 random bytes (device_seed). HKDF derives from it:
//   Ed25519 seed, ML-DSA-65 ξ  — device signature (hybrid: valid only if both verify);
//   X25519, ML-KEM-1024 d‖z    — encryption to the device (messages "to all devices").
// The account's private keys stay on the phone.
//
// The certificate uses the server's format, so the same signature
// works both for the server (desktop registration) and for any peer (directory /api/anon/devices):
//   keys        = [{ed25519}, {ml-dsa-65}, {x25519}, {ml-kem-1024}] — order matters;
//   keys_digest = SHA-256("umbera-device-keys-v1" ‖ ∀key: u8 len(alg) ‖ alg ‖ u32be len(key) ‖ key);
//   M           = "umbera-device-link-v1|<user_id>|<device_id>|<hex(keys_digest)>";
//   primary_sig = ECDSA secp256k1 (account key users.public_key) over SHA-256(M), r‖s;
//   pq_sig      = ML-DSA-65 (account dilithium key) over M — the server does not verify it, clients
//                 REQUIRE it (without it the certificate is rejected: the post-quantum chain is mandatory).
// A peer verifies both signatures with the account keys already bound to the quant address
// (FederationKeyVerify, layer 1) — the server takes no part in the chain of trust.

use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::codec::{label_from, Rd, W};
use super::{sha256, LinkError, DOMAIN, LR};
use crate::primitives as p;

pub const DEVICE_TYPE_PHONE: u8 = 1;
pub const DEVICE_TYPE_DESKTOP: u8 = 2;
pub const LABEL_MAX: usize = 64;

const ED_PUB: usize = 32;
const DSA_PUB: usize = 1952;
const DSA_SIG: usize = 3309;
const X_PUB: usize = 32;
const KEM_PUB: usize = 1568;
const SECP_PUB: usize = 65;
const SECP_SIG: usize = 64;
const CERT_MAGIC: &[u8; 3] = b"UDC";
const CERT_VERSION: u8 = 1;
const SEED_SALT: &[u8] = b"umbera-device-seed-v1";
const KEYS_DIGEST_DOMAIN: &[u8] = b"umbera-device-keys-v1";
const LINK_SIG_DOMAIN: &str = "umbera-device-link-v1|";
const LABEL_SEALED_MAX: usize = 512;

/// Device key algorithms in the order they are sent to the server.
pub const ALG_ED25519: &str = "ed25519";
pub const ALG_MLDSA65: &str = "ml-dsa-65";
pub const ALG_X25519: &str = "x25519";
pub const ALG_MLKEM1024: &str = "ml-kem-1024";

/// Device public keys.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DevicePublicKeys {
    pub ed25519: Vec<u8>,
    pub mldsa65: Vec<u8>,
    pub x25519: Vec<u8>,
    pub mlkem1024: Vec<u8>,
}

/// A key in the server's `{alg, key}` format.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DeviceKey {
    pub alg: String,
    pub key: Vec<u8>,
}

/// Verified device certificate. `wire_keys`, `primary_sig`, `pq_sig`, `label_sealed` are
/// exactly what the desktop sends to /api/devices/link/register.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DeviceCertInfo {
    pub user_id: String,
    pub device_id: String,
    pub keys: DevicePublicKeys,
    pub wire_keys: Vec<DeviceKey>,
    pub primary_sig: Vec<u8>,
    pub pq_sig: Vec<u8>,
    /// Account keys: secp256k1 (65 B, uncompressed) and ML-DSA-65 (1952 B).
    pub account_secp256k1: Vec<u8>,
    pub account_mldsa65: Vec<u8>,
    /// The account's quant address, computed from these keys.
    pub account_address: String,
    pub label_sealed: Vec<u8>,
    pub issued_at: u64,
}

/// Device encryption private keys (X25519 32 B, ML-KEM-1024 seed 64 B).
#[derive(uniffi::Record)]
pub struct DeviceEncryptionKeys {
    pub x25519_private: Vec<u8>,
    pub mlkem1024_seed: Vec<u8>,
}

/// Plaintext device name (inside label_sealed).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DeviceLabel {
    pub device_type: u8,
    pub label: String,
}

pub(crate) struct DeviceSecrets {
    pub ed_seed: Zeroizing<[u8; 32]>,
    pub dsa_seed: Zeroizing<[u8; 32]>,
    pub x_priv: Zeroizing<[u8; 32]>,
    pub kem_seed: Zeroizing<[u8; 64]>,
}

pub(crate) fn device_secrets(seed: &[u8]) -> LR<DeviceSecrets> {
    if seed.len() != 32 {
        return Err(LinkError::Crypto(format!("device seed must be 32 bytes, got {}", seed.len())));
    }
    let h = Hkdf::<Sha256>::new(Some(SEED_SALT), seed);
    let mut s = DeviceSecrets {
        ed_seed: Zeroizing::new([0; 32]),
        dsa_seed: Zeroizing::new([0; 32]),
        x_priv: Zeroizing::new([0; 32]),
        kem_seed: Zeroizing::new([0; 64]),
    };
    h.expand(b"ed25519", s.ed_seed.as_mut()).expect("hkdf len");
    h.expand(b"mldsa65", s.dsa_seed.as_mut()).expect("hkdf len");
    h.expand(b"x25519", s.x_priv.as_mut()).expect("hkdf len");
    h.expand(b"mlkem1024", s.kem_seed.as_mut()).expect("hkdf len");
    Ok(s)
}

fn public_of(s: &DeviceSecrets) -> LR<DevicePublicKeys> {
    Ok(DevicePublicKeys {
        ed25519: p::ed25519_public_from_seed(s.ed_seed.to_vec())?,
        mldsa65: p::mldsa65_public_key(s.dsa_seed.to_vec())?,
        x25519: p::x25519_public_key(s.x_priv.to_vec())?,
        mlkem1024: p::mlkem1024_public_key(s.kem_seed.to_vec())?,
    })
}

fn check_type(t: u8) -> LR<()> {
    if t != DEVICE_TYPE_PHONE && t != DEVICE_TYPE_DESKTOP {
        return Err(LinkError::Malformed(format!("unknown device type {t}")));
    }
    Ok(())
}

fn check_label(label: &str) -> LR<()> {
    if label.len() > LABEL_MAX {
        return Err(LinkError::Malformed(format!("device label longer than {LABEL_MAX} bytes")));
    }
    label_from(label.as_bytes(), "device label").map(|_| ())
}

/// Lowercase hyphenated UUID (the way the server formats user_id and device_id).
fn check_uuid(s: &str, what: &str) -> LR<()> {
    let b = s.as_bytes();
    let ok = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        });
    if !ok {
        return Err(LinkError::Malformed(format!("{what} must be a lowercase UUID")));
    }
    Ok(())
}

fn check_keys(k: &DevicePublicKeys) -> LR<()> {
    if k.ed25519.len() != ED_PUB || k.mldsa65.len() != DSA_PUB || k.x25519.len() != X_PUB || k.mlkem1024.len() != KEM_PUB {
        return Err(LinkError::Malformed("device public key lengths".into()));
    }
    if !p::mlkem1024_validate_public_key(k.mlkem1024.clone()) {
        return Err(LinkError::Malformed("device ML-KEM key failed FIPS 203 validation".into()));
    }
    Ok(())
}

fn write_keys(w: &mut W, k: &DevicePublicKeys) {
    w.raw(&k.ed25519).raw(&k.mldsa65).raw(&k.x25519).raw(&k.mlkem1024);
}

fn read_keys(r: &mut Rd) -> LR<DevicePublicKeys> {
    let k = DevicePublicKeys {
        ed25519: r.raw(ED_PUB)?.to_vec(),
        mldsa65: r.raw(DSA_PUB)?.to_vec(),
        x25519: r.raw(X_PUB)?.to_vec(),
        mlkem1024: r.raw(KEM_PUB)?.to_vec(),
    };
    check_keys(&k)?;
    Ok(k)
}

fn wire_of(k: &DevicePublicKeys) -> Vec<DeviceKey> {
    vec![
        DeviceKey { alg: ALG_ED25519.into(), key: k.ed25519.clone() },
        DeviceKey { alg: ALG_MLDSA65.into(), key: k.mldsa65.clone() },
        DeviceKey { alg: ALG_X25519.into(), key: k.x25519.clone() },
        DeviceKey { alg: ALG_MLKEM1024.into(), key: k.mlkem1024.clone() },
    ]
}

/// Strictly our set: exactly four keys in our order (otherwise it is not our device).
fn keys_from_wire(w: &[DeviceKey]) -> LR<DevicePublicKeys> {
    let algs: Vec<&str> = w.iter().map(|k| k.alg.as_str()).collect();
    if algs != [ALG_ED25519, ALG_MLDSA65, ALG_X25519, ALG_MLKEM1024] {
        return Err(LinkError::Malformed(format!("unexpected device key set {algs:?}")));
    }
    let k = DevicePublicKeys {
        ed25519: w[0].key.clone(),
        mldsa65: w[1].key.clone(),
        x25519: w[2].key.clone(),
        mlkem1024: w[3].key.clone(),
    };
    check_keys(&k)?;
    Ok(k)
}

fn keys_digest_of(w: &[DeviceKey]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(KEYS_DIGEST_DOMAIN);
    for k in w {
        h.update([k.alg.len() as u8]);
        h.update(k.alg.as_bytes());
        h.update((k.key.len() as u32).to_be_bytes());
        h.update(&k.key);
    }
    h.finalize().into()
}

fn link_message(user_id: &str, device_id: &str, w: &[DeviceKey]) -> String {
    let d = keys_digest_of(w);
    let hexd: String = d.iter().map(|x| format!("{x:02x}")).collect();
    format!("{LINK_SIG_DOMAIN}{user_id}|{device_id}|{hexd}")
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn address_of(secp_pub: &[u8], dsa_pub: &[u8]) -> LR<String> {
    crate::quant_address(hex_of(secp_pub), hex_of(dsa_pub)).map_err(|e| LinkError::Crypto(e.to_string()))
}

fn hybrid_device_verify(k: &DevicePublicKeys, msg: &[u8], ed_sig: &[u8], dsa_sig: &[u8]) -> bool {
    // Both signatures are always verified (no early exit on the first one).
    let a = p::ed25519_verify(k.ed25519.clone(), msg.to_vec(), ed_sig.to_vec());
    let b = p::mldsa65_verify(msg.to_vec(), dsa_sig.to_vec(), k.mldsa65.clone());
    a & b
}

/// Both account signatures over M. Returns the device public keys from the wire set.
fn verify_link_sigs(
    user_id: &str,
    device_id: &str,
    wire: &[DeviceKey],
    primary_sig: &[u8],
    pq_sig: &[u8],
    secp_pub: &[u8],
    dsa_pub: &[u8],
) -> LR<DevicePublicKeys> {
    check_uuid(user_id, "user id")?;
    check_uuid(device_id, "device id")?;
    let keys = keys_from_wire(wire)?;
    if primary_sig.len() != SECP_SIG || pq_sig.len() != DSA_SIG {
        return Err(LinkError::Mismatch("device certificate needs both account signatures".into()));
    }
    let m = link_message(user_id, device_id, wire);
    let a = p::secp256k1_verify_hash(p::sha256(m.as_bytes().to_vec()), primary_sig.to_vec(), secp_pub.to_vec());
    let b = p::mldsa65_verify(m.into_bytes(), pq_sig.to_vec(), dsa_pub.to_vec());
    if !(a & b) {
        return Err(LinkError::Mismatch("device certificate signature is invalid".into()));
    }
    Ok(keys)
}

// ---------- device request (inside the link) ----------

fn pop_message(th: &[u8; 32], body: &[u8]) -> Vec<u8> {
    [DOMAIN, b"/device-pop".as_slice(), th, body].concat()
}

pub(crate) fn device_request_encode(th: &[u8; 32], seed: &[u8], device_type: u8, label: &str) -> LR<Vec<u8>> {
    check_type(device_type)?;
    check_label(label)?;
    let s = device_secrets(seed)?;
    let keys = public_of(&s)?;
    let mut w = W::new();
    w.u8(CERT_VERSION).u8(device_type).b8(label.as_bytes());
    write_keys(&mut w, &keys);
    let mut body = w.done();
    let msg = pop_message(th, &body);
    body.extend(p::ed25519_sign(msg.clone(), s.ed_seed.to_vec())?);
    body.extend(p::mldsa65_sign(msg, s.dsa_seed.to_vec())?);
    Ok(body)
}

pub(crate) fn device_request_decode(th: &[u8; 32], pt: &[u8]) -> LR<super::session::DeviceRequest> {
    let mut r = Rd::new(pt, "device request");
    let v = r.u8()?;
    if v != CERT_VERSION {
        return Err(LinkError::Malformed(format!("device request version {v}")));
    }
    let device_type = r.u8()?;
    check_type(device_type)?;
    let label = label_from(r.b8(LABEL_MAX)?, "device label")?;
    let keys = read_keys(&mut r)?;
    let body_len = r.pos();
    let ed_sig = r.raw(64)?;
    let dsa_sig = r.raw(DSA_SIG)?;
    r.end()?;
    if !hybrid_device_verify(&keys, &pop_message(th, &pt[..body_len]), ed_sig, dsa_sig) {
        return Err(LinkError::Mismatch("device proof of possession failed".into()));
    }
    Ok(super::session::DeviceRequest { device_type, label, keys })
}

// ---------- certificate ----------
//
// DEVICE_CERT blob (phone → desktop, inside the link):
//   "UDC" ‖ version ‖ b8 user_id ‖ b8 device_id ‖ account secp256k1 (65) ‖ account ML-DSA (1952)
//   ‖ device keys (4 × fixed length, wire order) ‖ primary_sig (64) ‖ pq_sig (3309)
//   ‖ b16 label_sealed (≤512) ‖ issued_at u64
// Only what is signed in M (keys and ids) is signed; label_sealed is AEAD under the account key
// (account_sync_key), issued_at is for display.

fn cert_check(cert: &[u8]) -> LR<DeviceCertInfo> {
    let mut r = Rd::new(cert, "device cert");
    if r.raw(3)? != CERT_MAGIC {
        return Err(LinkError::Malformed("not a device certificate".into()));
    }
    let v = r.u8()?;
    if v != CERT_VERSION {
        return Err(LinkError::Malformed(format!("device cert version {v}")));
    }
    let user_id = label_from(r.b8(36)?, "user id")?;
    let device_id = label_from(r.b8(36)?, "device id")?;
    let account_secp256k1 = r.raw(SECP_PUB)?.to_vec();
    let account_mldsa65 = r.raw(DSA_PUB)?.to_vec();
    let keys = read_keys(&mut r)?;
    let primary_sig = r.raw(SECP_SIG)?.to_vec();
    let pq_sig = r.raw(DSA_SIG)?.to_vec();
    let label_sealed = r.b16(LABEL_SEALED_MAX)?.to_vec();
    let issued_at = r.u64()?;
    r.end()?;
    let wire_keys = wire_of(&keys);
    verify_link_sigs(&user_id, &device_id, &wire_keys, &primary_sig, &pq_sig, &account_secp256k1, &account_mldsa65)?;
    let account_address = address_of(&account_secp256k1, &account_mldsa65)?;
    Ok(DeviceCertInfo {
        user_id,
        device_id,
        keys,
        wire_keys,
        primary_sig,
        pq_sig,
        account_secp256k1,
        account_mldsa65,
        account_address,
        label_sealed,
        issued_at,
    })
}

/// Phone: issue a certificate to a device from a verified request. `user_id` — account id,
/// `device_id` — the desktop's id from the /link/claim response (UUID, lowercase). Signs with the
/// account key (secp256k1 32 B + ML-DSA-65 seed 32 B); the account public keys are derived from the
/// private ones, so the certificate cannot name someone else's account.
#[uniffi::export]
pub fn device_cert_issue(
    request: super::session::DeviceRequest,
    user_id: String,
    device_id: String,
    account_secp256k1_private: Vec<u8>,
    account_mldsa65_seed: Vec<u8>,
    label_sealed: Vec<u8>,
    issued_at: u64,
) -> LR<Vec<u8>> {
    check_type(request.device_type)?;
    check_label(&request.label)?;
    check_uuid(&user_id, "user id")?;
    check_uuid(&device_id, "device id")?;
    check_keys(&request.keys)?;
    if label_sealed.len() > LABEL_SEALED_MAX {
        return Err(LinkError::Malformed("label_sealed longer than 512 bytes".into()));
    }
    let secp_pub = p::secp256k1_public_key(account_secp256k1_private.clone())?;
    let dsa_pub = p::mldsa65_public_key(account_mldsa65_seed.clone())?;
    let wire = wire_of(&request.keys);
    let m = link_message(&user_id, &device_id, &wire);
    let primary_sig = p::secp256k1_sign_hash(p::sha256(m.as_bytes().to_vec()), account_secp256k1_private)?;
    let pq_sig = p::mldsa65_sign(m.into_bytes(), account_mldsa65_seed)?;
    let mut w = W::new();
    w.raw(CERT_MAGIC).u8(CERT_VERSION).b8(user_id.as_bytes()).b8(device_id.as_bytes());
    w.raw(&secp_pub).raw(&dsa_pub);
    write_keys(&mut w, &request.keys);
    w.raw(&primary_sig).raw(&pq_sig).b16(&label_sealed).u64(issued_at);
    Ok(w.done())
}

/// Verify a certificate blob against the account's quant address.
#[uniffi::export]
pub fn device_cert_verify(cert: Vec<u8>, expected_account_address: String) -> LR<DeviceCertInfo> {
    let info = cert_check(&cert)?;
    if info.account_address != expected_account_address.trim() {
        return Err(LinkError::Mismatch("device certificate belongs to another account".into()));
    }
    Ok(info)
}

/// Desktop: verify the received certificate — signatures are valid and the keys in it are ours.
/// This is how the desktop learns its account (account_address, user_id).
#[uniffi::export]
pub fn device_cert_verify_for_device(cert: Vec<u8>, device_seed: Vec<u8>) -> LR<DeviceCertInfo> {
    let info = cert_check(&cert)?;
    let own = public_of(&device_secrets(&device_seed)?)?;
    if info.keys != own {
        return Err(LinkError::Mismatch("certificate was issued for other device keys".into()));
    }
    Ok(info)
}

/// Peer: verify a device from the /api/anon/devices directory. `account_*` — account keys
/// from the anonymous directory, `expected_account_address` — the address under which the person
/// was added to contacts (the keys must hash to it). Returns the device keys that can be
/// encrypted to.
#[uniffi::export]
#[allow(clippy::too_many_arguments)]
pub fn device_listing_verify(
    user_id: String,
    device_id: String,
    wire_keys: Vec<DeviceKey>,
    primary_sig: Vec<u8>,
    pq_sig: Vec<u8>,
    account_secp256k1: Vec<u8>,
    account_mldsa65: Vec<u8>,
    expected_account_address: String,
) -> LR<DevicePublicKeys> {
    if address_of(&account_secp256k1, &account_mldsa65)? != expected_account_address.trim() {
        return Err(LinkError::Mismatch("account keys do not match the contact address".into()));
    }
    verify_link_sigs(&user_id, &device_id, &wire_keys, &primary_sig, &pq_sig, &account_secp256k1, &account_mldsa65)
}

/// Device keys in the server's format (in signing order).
#[uniffi::export]
pub fn device_wire_keys(keys: DevicePublicKeys) -> LR<Vec<DeviceKey>> {
    check_keys(&keys)?;
    Ok(wire_of(&keys))
}

/// The server's keys_digest (for checking against the directory field and the vectors).
#[uniffi::export]
pub fn device_keys_digest(wire_keys: Vec<DeviceKey>) -> Vec<u8> {
    keys_digest_of(&wire_keys).to_vec()
}

/// New device secret (32 random bytes from the OS). Keep it in secure storage.
#[uniffi::export]
pub fn device_seed_generate() -> Vec<u8> {
    p::os_random::<32>().to_vec()
}

/// Device public keys from its secret.
#[uniffi::export]
pub fn device_public_keys(device_seed: Vec<u8>) -> LR<DevicePublicKeys> {
    public_of(&device_secrets(&device_seed)?)
}

/// Device encryption private keys — for decrypting messages addressed to it
/// with the app's existing hybrid (HybridKeyExchange: X25519 + ML-KEM-1024).
#[uniffi::export]
pub fn device_encryption_keys(device_seed: Vec<u8>) -> LR<DeviceEncryptionKeys> {
    let s = device_secrets(&device_seed)?;
    Ok(DeviceEncryptionKeys { x25519_private: s.x_priv.to_vec(), mlkem1024_seed: s.kem_seed.to_vec() })
}

fn device_sig_message(context: &str, message: &[u8]) -> LR<Vec<u8>> {
    if context.is_empty() || context.len() > 64 {
        return Err(LinkError::Malformed("signature context must be 1..64 bytes".into()));
    }
    let mut w = W::new();
    w.raw(DOMAIN).raw(b"/device-sig").b8(context.as_bytes()).raw(message);
    Ok(w.done())
}

/// Hybrid device signature (Ed25519 64 B ‖ ML-DSA-65 3309 B) with domain `context`.
#[uniffi::export]
pub fn device_sign(device_seed: Vec<u8>, context: String, message: Vec<u8>) -> LR<Vec<u8>> {
    let s = device_secrets(&device_seed)?;
    let msg = device_sig_message(&context, &message)?;
    let mut out = p::ed25519_sign(msg.clone(), s.ed_seed.to_vec())?;
    out.extend(p::mldsa65_sign(msg, s.dsa_seed.to_vec())?);
    Ok(out)
}

/// Verify a device signature with its public keys (from a verified certificate).
#[uniffi::export]
pub fn device_verify(keys: DevicePublicKeys, context: String, message: Vec<u8>, signature: Vec<u8>) -> bool {
    let Ok(msg) = device_sig_message(&context, &message) else { return false };
    if signature.len() != 64 + DSA_SIG {
        return false;
    }
    hybrid_device_verify(&keys, &msg, &signature[..64], &signature[64..])
}

// ---------- device name (label_sealed) ----------
//
// The server stores the desktop name only encrypted. The key is account_sync_key: derived on
// the phone from the account's private keys and passed to devices in the bundle (SECTION_ACCOUNT_SYNC),
// so all of the account's devices can read the names, the server cannot.

/// Phone: shared key of the account's devices (32 B) from the account's X25519 private key and ML-KEM seed.
#[uniffi::export]
pub fn account_sync_key(account_x25519_private: Vec<u8>, account_mlkem_seed: Vec<u8>) -> LR<Vec<u8>> {
    if account_x25519_private.len() != 32 || account_mlkem_seed.len() != 64 {
        return Err(LinkError::Crypto("account keys must be 32 + 64 bytes".into()));
    }
    let ikm = Zeroizing::new([account_x25519_private, account_mlkem_seed].concat());
    let mut out = vec![0u8; 32];
    Hkdf::<Sha256>::new(Some(b"umbera-account-devices-v1"), &ikm)
        .expand(b"sync-key", &mut out)
        .expect("hkdf len");
    Ok(out)
}

fn label_key(sync_key: &[u8]) -> LR<Zeroizing<[u8; 32]>> {
    if sync_key.len() != 32 {
        return Err(LinkError::Crypto("sync key must be 32 bytes".into()));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, sync_key).expand(b"umbera-device-label-v1", k.as_mut()).expect("hkdf len");
    Ok(k)
}

/// Encrypt the device type and name (nonce 12 ‖ AES-256-GCM, AAD = device_id).
#[uniffi::export]
pub fn device_label_seal(sync_key: Vec<u8>, device_id: String, device_type: u8, label: String) -> LR<Vec<u8>> {
    check_type(device_type)?;
    check_label(&label)?;
    check_uuid(&device_id, "device id")?;
    let k = label_key(&sync_key)?;
    let mut pt = W::new();
    pt.u8(device_type).b8(label.as_bytes());
    let nonce: [u8; 12] = p::os_random();
    let aad = sha256(&[DOMAIN, b"/device-label", device_id.as_bytes()]);
    let ct = Aes256Gcm::new_from_slice(k.as_ref())
        .expect("32-byte key")
        .encrypt(&Nonce::try_from(&nonce[..]).expect("12-byte nonce"), Payload { msg: &pt.done(), aad: &aad })
        .map_err(|_| LinkError::Crypto("aes-gcm encrypt".into()))?;
    Ok([nonce.to_vec(), ct].concat())
}

#[uniffi::export]
pub fn device_label_open(sync_key: Vec<u8>, device_id: String, sealed: Vec<u8>) -> LR<DeviceLabel> {
    check_uuid(&device_id, "device id")?;
    if sealed.len() < 12 + 16 || sealed.len() > LABEL_SEALED_MAX {
        return Err(LinkError::Malformed("label_sealed length".into()));
    }
    let k = label_key(&sync_key)?;
    let aad = sha256(&[DOMAIN, b"/device-label", device_id.as_bytes()]);
    let pt = Aes256Gcm::new_from_slice(k.as_ref())
        .expect("32-byte key")
        .decrypt(&Nonce::try_from(&sealed[..12]).expect("12-byte nonce"), Payload { msg: &sealed[12..], aad: &aad })
        .map_err(|_| LinkError::Mismatch("device label authentication failed".into()))?;
    let mut r = Rd::new(&pt, "device label");
    let device_type = r.u8()?;
    check_type(device_type)?;
    let label = label_from(r.b8(LABEL_MAX)?, "device label")?;
    r.end()?;
    Ok(DeviceLabel { device_type, label })
}

#[cfg(test)]
pub(crate) fn link_message_for_tests(user_id: &str, device_id: &str, w: &[DeviceKey]) -> String {
    link_message(user_id, device_id, w)
}
