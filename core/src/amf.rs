//! Asymmetric message franking: verifiable abuse reports while the relay stays blind.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as B;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

const AMF_CHALLENGE: [u8; 22] = [0x54, 0x59, 0x50, 0x45, 0x58, 0x2d, 0x41, 0x4d, 0x46, 0x2d, 0x76, 0x31, 0x2f, 0x63, 0x68, 0x61, 0x6c, 0x6c, 0x65, 0x6e, 0x67, 0x65];
const AMF_SEED: [u8; 17] = [0x54, 0x59, 0x50, 0x45, 0x58, 0x2d, 0x41, 0x4d, 0x46, 0x2d, 0x76, 0x31, 0x2f, 0x73, 0x65, 0x65, 0x64];

type R<T> = Result<T, AmfError>;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum AmfError {
    #[error("amf crypto error: {0}")]
    Crypto(String),
}
fn err<T>(m: &str) -> R<T> {
    Err(AmfError::Crypto(m.to_string()))
}

#[derive(uniffi::Record)]
pub struct AmfKeyPair {
    pub secret: Vec<u8>,
    pub public: Vec<u8>,
}

fn rand_scalar() -> Scalar {
    let mut b = [0u8; 64];
    getrandom::getrandom(&mut b).expect("OS RNG");
    Scalar::from_bytes_mod_order_wide(&b)
}
fn pt_bytes(p: &RistrettoPoint) -> [u8; 32] {
    p.compress().to_bytes()
}
fn pt_from(b: &[u8]) -> R<RistrettoPoint> {
    if b.len() != 32 {
        return err("point must be 32 bytes");
    }
    CompressedRistretto::from_slice(b)
        .map_err(|_| AmfError::Crypto("bad compressed point".into()))?
        .decompress()
        .ok_or_else(|| AmfError::Crypto("point not on curve".into()))
}
fn sc_from(b: &[u8]) -> R<Scalar> {
    let arr: [u8; 32] = b.try_into().map_err(|_| AmfError::Crypto("scalar must be 32 bytes".into()))?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(arr))
        .ok_or_else(|| AmfError::Crypto("non-canonical scalar".into()))
}

fn challenge(msg: &[u8], pts: &[&RistrettoPoint]) -> Scalar {
    let mut h = Sha512::new();
    h.update(AMF_CHALLENGE);
    h.update((msg.len() as u64).to_le_bytes());
    h.update(msg);
    for p in pts {
        h.update(p.compress().as_bytes());
    }
    let d = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&d);
    Scalar::from_bytes_mod_order_wide(&wide)
}

struct Branch {
    a1: RistrettoPoint,
    a2: RistrettoPoint,
    a3: RistrettoPoint,
}
fn recompute_branch(
    p: &RistrettoPoint,
    t1: &RistrettoPoint,
    t2: &RistrettoPoint,
    pk_j: &RistrettoPoint,
    c: &Scalar,
    z1: &Scalar,
    z2: &Scalar,
) -> Branch {
    Branch {
        a1: z1 * B - c * p,
        a2: z2 * B - c * t1,
        a3: (z1 * B + z2 * pk_j) - c * t2,
    }
}

#[uniffi::export]
pub fn amf_commit(frank_key: Vec<u8>, msg: Vec<u8>) -> R<Vec<u8>> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(&frank_key)
        .map_err(|_| AmfError::Crypto("bad hmac key".into()))?;
    mac.update(&msg);
    Ok(mac.finalize().into_bytes().to_vec())
}

#[uniffi::export]
pub fn amf_keygen() -> AmfKeyPair {
    let x = rand_scalar();
    AmfKeyPair {
        secret: x.to_bytes().to_vec(),
        public: pt_bytes(&(x * B)).to_vec(),
    }
}

#[uniffi::export]
pub fn amf_public_of(secret: Vec<u8>) -> R<Vec<u8>> {
    let x = sc_from(&secret)?;
    Ok(pt_bytes(&(x * B)).to_vec())
}

#[uniffi::export]
pub fn amf_keypair_from_seed(seed: Vec<u8>) -> AmfKeyPair {
    let mut h = Sha512::new();
    h.update(AMF_SEED);
    h.update(&seed);
    let d = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&d);
    let x = Scalar::from_bytes_mod_order_wide(&wide);
    AmfKeyPair {
        secret: x.to_bytes().to_vec(),
        public: pt_bytes(&(x * B)).to_vec(),
    }
}

fn sign_internal(
    sk_real: &Scalar,
    pk_real: &RistrettoPoint,
    pk_sim: &RistrettoPoint,
    pk_j: &RistrettoPoint,
    label: &RistrettoPoint,
    msg: &[u8],
    sender_is_real: bool,
) -> Vec<u8> {
    let k = rand_scalar();
    let t1 = k * B;
    let t2 = k * pk_j + label;

    let rho1 = rand_scalar();
    let rho2 = rand_scalar();
    let a1 = rho1 * B;
    let a2 = rho2 * B;
    let a3 = rho1 * B + rho2 * pk_j;

    let c_sim = rand_scalar();
    let z_sim_1 = rand_scalar();
    let z_sim_2 = rand_scalar();
    let sim = recompute_branch(pk_sim, &t1, &t2, pk_j, &c_sim, &z_sim_1, &z_sim_2);

    let (sa1, sa2, sa3, ra1, ra2, ra3) = if sender_is_real {
        (&a1, &a2, &a3, &sim.a1, &sim.a2, &sim.a3)
    } else {
        (&sim.a1, &sim.a2, &sim.a3, &a1, &a2, &a3)
    };

    let (pk_s_t, pk_r_t) = if sender_is_real { (pk_real, pk_sim) } else { (pk_sim, pk_real) };

    let c = challenge(
        msg,
        &[pk_s_t, pk_r_t, pk_j, &t1, &t2, sa1, sa2, sa3, ra1, ra2, ra3],
    );
    let c_real = c - c_sim;
    let z_real_1 = rho1 + c_real * sk_real;
    let z_real_2 = rho2 + c_real * k;

    let (c_s, c_r, z_s1, z_s2, z_r1, z_r2) = if sender_is_real {
        (c_real, c_sim, z_real_1, z_real_2, z_sim_1, z_sim_2)
    } else {
        (c_sim, c_real, z_sim_1, z_sim_2, z_real_1, z_real_2)
    };
    let mut out = Vec::with_capacity(256);
    for b in [
        pt_bytes(&t1),
        pt_bytes(&t2),
        c_s.to_bytes(),
        c_r.to_bytes(),
        z_s1.to_bytes(),
        z_s2.to_bytes(),
        z_r1.to_bytes(),
        z_r2.to_bytes(),
    ] {
        out.extend_from_slice(&b);
    }
    out
}

#[uniffi::export]
pub fn amf_frank(sk_s: Vec<u8>, pk_r: Vec<u8>, pk_j: Vec<u8>, msg: Vec<u8>) -> R<Vec<u8>> {
    let a = sc_from(&sk_s)?;
    let pk_s = a * B;
    let pk_r = pt_from(&pk_r)?;
    let pk_j = pt_from(&pk_j)?;
    Ok(sign_internal(&a, &pk_s, &pk_r, &pk_j, &pk_s, &msg, true))
}

struct Sig {
    t1: RistrettoPoint,
    t2: RistrettoPoint,
    c_s: Scalar,
    c_r: Scalar,
    z_s1: Scalar,
    z_s2: Scalar,
    z_r1: Scalar,
    z_r2: Scalar,
}
fn parse_sig(sig: &[u8]) -> R<Sig> {
    if sig.len() != 256 {
        return err("signature must be 256 bytes");
    }
    Ok(Sig {
        t1: pt_from(&sig[0..32])?,
        t2: pt_from(&sig[32..64])?,
        c_s: sc_from(&sig[64..96])?,
        c_r: sc_from(&sig[96..128])?,
        z_s1: sc_from(&sig[128..160])?,
        z_s2: sc_from(&sig[160..192])?,
        z_r1: sc_from(&sig[192..224])?,
        z_r2: sc_from(&sig[224..256])?,
    })
}

fn check_or_proof(pk_s: &RistrettoPoint, pk_r: &RistrettoPoint, pk_j: &RistrettoPoint, msg: &[u8], s: &Sig) -> bool {
    let sb = recompute_branch(pk_s, &s.t1, &s.t2, pk_j, &s.c_s, &s.z_s1, &s.z_s2);
    let rb = recompute_branch(pk_r, &s.t1, &s.t2, pk_j, &s.c_r, &s.z_r1, &s.z_r2);
    let c = challenge(
        msg,
        &[pk_s, pk_r, pk_j, &s.t1, &s.t2, &sb.a1, &sb.a2, &sb.a3, &rb.a1, &rb.a2, &rb.a3],
    );
    (s.c_s + s.c_r) == c
}

#[uniffi::export]
pub fn amf_verify(pk_s: Vec<u8>, pk_r: Vec<u8>, pk_j: Vec<u8>, msg: Vec<u8>, sig: Vec<u8>) -> R<bool> {
    let pk_s = pt_from(&pk_s)?;
    let pk_r = pt_from(&pk_r)?;
    let pk_j = pt_from(&pk_j)?;
    let s = parse_sig(&sig)?;
    Ok(check_or_proof(&pk_s, &pk_r, &pk_j, &msg, &s))
}

#[uniffi::export]
pub fn amf_judge(pk_s: Vec<u8>, pk_r: Vec<u8>, sk_j: Vec<u8>, msg: Vec<u8>, sig: Vec<u8>) -> R<bool> {
    let pk_s = pt_from(&pk_s)?;
    let pk_r = pt_from(&pk_r)?;
    let j = sc_from(&sk_j)?;
    let pk_j = j * B;
    let s = parse_sig(&sig)?;
    if !check_or_proof(&pk_s, &pk_r, &pk_j, &msg, &s) {
        return Ok(false);
    }
    let label = s.t2 - j * s.t1;
    Ok(label == pk_s)
}

#[uniffi::export]
pub fn amf_forge(pk_s: Vec<u8>, sk_r: Vec<u8>, pk_j: Vec<u8>, msg: Vec<u8>) -> R<Vec<u8>> {
    let r = sc_from(&sk_r)?;
    let pk_r = r * B;
    let pk_s = pt_from(&pk_s)?;
    let pk_j = pt_from(&pk_j)?;
    Ok(sign_internal(&r, &pk_r, &pk_s, &pk_j, &pk_r, &msg, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frank_verify_judge_roundtrip() {
        let s = amf_keygen();
        let r = amf_keygen();
        let j = amf_keygen();
        let msg = b"hello group".to_vec();
        let sig = amf_frank(s.secret.clone(), r.public.clone(), j.public.clone(), msg.clone()).unwrap();

        assert!(amf_verify(s.public.clone(), r.public.clone(), j.public.clone(), msg.clone(), sig.clone()).unwrap());
        assert!(amf_judge(s.public.clone(), r.public.clone(), j.secret.clone(), msg.clone(), sig.clone()).unwrap());
    }

    #[test]
    fn tamper_fails() {
        let s = amf_keygen();
        let r = amf_keygen();
        let j = amf_keygen();
        let sig = amf_frank(s.secret.clone(), r.public.clone(), j.public.clone(), b"a".to_vec()).unwrap();

        assert!(!amf_verify(s.public.clone(), r.public.clone(), j.public.clone(), b"b".to_vec(), sig).unwrap());
    }

    #[test]
    fn deniability_and_sender_binding() {
        let s = amf_keygen();
        let r = amf_keygen();
        let j = amf_keygen();
        let msg = b"deniable".to_vec();
        let forged = amf_forge(s.public.clone(), r.secret.clone(), j.public.clone(), msg.clone()).unwrap();
        assert!(amf_verify(s.public.clone(), r.public.clone(), j.public.clone(), msg.clone(), forged.clone()).unwrap(),
                "forgery must verify (deniability)");
        assert!(!amf_judge(s.public.clone(), r.public.clone(), j.secret.clone(), msg.clone(), forged).unwrap(),
                "judge must REJECT the receiver forgery (sender binding)");
    }

    #[test]
    fn commit_binds() {
        let k = vec![7u8; 32];
        let c1 = amf_commit(k.clone(), b"x".to_vec()).unwrap();
        let c2 = amf_commit(k.clone(), b"y".to_vec()).unwrap();
        let c1b = amf_commit(k, b"x".to_vec()).unwrap();
        assert_eq!(c1, c1b);
        assert_ne!(c1, c2);
    }
}
