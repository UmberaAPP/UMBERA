// Desktop ↔ phone QR linking: hybrid key agreement, verification code, AEAD blobs.
//
// Flow (seq is a per-direction counter starting at zero):
//   desktop : QR = {version, link_id, issued_at, desktop X25519, SHA-256(desktop ML-KEM), relay, checksum}
//   dt→ph   : OFFER   seq 0  — desktop ML-KEM-1024 public key (1568 B), checked against the QR
//   ph→dt   : ACCEPT  seq 0  — phone X25519 (ephemeral), ML-KEM ciphertext, phone MAC
//   dt→ph   : CONFIRM seq 1  — desktop MAC
//   both    : verification code (6 digits) on screens → the user taps "Link" on both
//   then    : AEAD blobs (AES-256-GCM, per-direction key, nonce = seq,
//             AAD = domain ‖ link_id ‖ seq ‖ kind ‖ direction)
//
// Keys: PRK = HKDF-Extract(salt = TH, IKM = X25519 ‖ ML-KEM), TH = SHA-256 of the transcript
// (the whole QR, desktop ML-KEM key, phone X25519, ciphertext). PRK yields the direction keys,
// the confirmation keys and the verification code. Changing any transcript byte yields different keys,
// the confirmation fails and the verification code differs.

use std::sync::{Arc, Mutex};

use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit, Nonce};
use base64::Engine as _;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::{Decapsulate as _, KeyExport as _};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use super::codec::{label_from, Rd, W};
use super::package::{PackageProgress, PackageReader, PackageWriter};
use super::{cert, ct_eq, sha256, sha256_framed, LinkError, DOMAIN, LR};
use crate::primitives::{mlkem_dk_from_seed, mlkem_ek_from_bytes, os_random};

pub const LINK_VERSION: u8 = 1;
/// QR lifetime: one minute, then a new one.
pub const QR_TTL_SECS: u64 = 60;
/// Allowed clock skew between desktop and phone (QR check on the phone).
pub const MAX_CLOCK_SKEW_SECS: u64 = 300;
/// How long we wait for "Link" to be tapped after the keys are agreed.
pub const SAS_TTL_SECS: u64 = 180;
pub const QR_TEXT_PREFIX: &str = "umbera-link:";
const QR_MAGIC: &[u8; 2] = b"UL";
const LINK_ID_MIN: usize = 16;
const LINK_ID_MAX: usize = 32;
const RELAY_MAX: usize = 200;
const ABORT_MAX: usize = 256;

pub const MLKEM_EK_LEN: usize = 1568;
pub const MLKEM_CT_LEN: usize = 1568;

// Blob kinds. The values are part of the format (the server does not interpret them, only stores them).
pub const KIND_OFFER: u8 = 1;
pub const KIND_ACCEPT: u8 = 2;
pub const KIND_CONFIRM: u8 = 3;
pub const KIND_DEVICE_REQUEST: u8 = 16;
pub const KIND_DEVICE_CERT: u8 = 17;
pub const KIND_MLS_JOIN_REQUESTS: u8 = 18;
pub const KIND_MLS_JOIN_OFFERS: u8 = 19;
pub const KIND_PACKAGE_HEADER: u8 = 32;
pub const KIND_PACKAGE_PART: u8 = 33;
pub const KIND_PACKAGE_END: u8 = 34;
pub const KIND_PACKAGE_ACK: u8 = 35;
pub const KIND_ABORT: u8 = 48;

const DIR_PHONE_TO_PC: u8 = 1;
const DIR_PC_TO_PHONE: u8 = 2;

/// Blob that travels through the relay server. The server sees only these three fields.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct LinkBlob {
    pub kind: u8,
    pub seq: u64,
    pub data: Vec<u8>,
}

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkRole {
    /// New device (desktop): shows the QR.
    Desktop,
    /// Primary device (phone): scans the QR, signs the certificate, sends the package.
    Phone,
}

/// Session state (exposed to the UI).
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// Desktop: QR shown, waiting for ACCEPT.
    AwaitingAccept,
    /// Phone: QR read, waiting for OFFER.
    AwaitingOffer,
    /// Phone: ACCEPT sent, waiting for CONFIRM.
    AwaitingConfirm,
    /// Keys agreed and confirmed, verification code on screen, waiting for "Link".
    AwaitingSas,
    /// The user confirmed the code: data may be transferred.
    Established,
    /// Session finished or destroyed (expired, tampering, cancelled). No secrets left in memory.
    Closed,
}

/// Parsed content of the desktop's "sign my keys" request (the phone displays and signs it).
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct DeviceRequest {
    pub device_type: u8,
    pub label: String,
    pub keys: cert::DevicePublicKeys,
}

struct Keys {
    send: Zeroizing<[u8; 32]>,
    recv: Zeroizing<[u8; 32]>,
    th: [u8; 32],
    sas: String,
}

pub(crate) struct Inner {
    role: LinkRole,
    state: LinkState,
    link_id: Vec<u8>,
    relay: String,
    issued_at: u64,
    qr: Vec<u8>,
    pc_x25519: [u8; 32],
    ek_commit: [u8; 32],
    // Desktop: ephemeral secrets until ACCEPT.
    x_priv: Option<Zeroizing<[u8; 32]>>,
    kem_seed: Option<Zeroizing<[u8; 64]>>,
    ek: Vec<u8>,
    // Phone: expected desktop MAC until CONFIRM.
    expect_pc_tag: Option<Zeroizing<[u8; 32]>>,
    keys: Option<Keys>,
    send_seq: u64,
    recv_seq: u64,
    keyed_at: u64,
    pkg_out: Option<PackageWriter>,
    pkg_in: Option<PackageReader>,
}

/// Linking session, one side (desktop or phone). Secrets never leave the core and are wiped
/// on close, on any mismatch and when the object is dropped.
#[derive(uniffi::Object)]
pub struct LinkSession {
    inner: Mutex<Inner>,
}

/// No secrets: only the side and the state.
impl std::fmt::Debug for LinkSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.lock();
        write!(f, "LinkSession({:?}, {:?})", g.role, g.state)
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.wipe();
    }
}

fn kdf(prk: &Hkdf<Sha256>, label: &str) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    let info = [DOMAIN, label.as_bytes()].concat();
    prk.expand(&info, out.as_mut()).expect("32 bytes is a valid HKDF length");
    out
}

fn mac(key: &[u8; 32], th: &[u8; 32]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    m.update(th);
    m.finalize().into_bytes().into()
}

/// Verification code: 8 bytes of PRK as a big-endian number modulo 10^6 (bias ~5·10^-14).
fn sas_from(prk: &Hkdf<Sha256>) -> String {
    let mut b = [0u8; 8];
    let info = [DOMAIN, b"/sas".as_slice()].concat();
    prk.expand(&info, &mut b).expect("8 bytes is a valid HKDF length");
    format!("{:06}", u64::from_be_bytes(b) % 1_000_000)
}

pub(crate) fn ek_commitment(ek: &[u8]) -> [u8; 32] {
    sha256(&[DOMAIN, b"/mlkem-ek", ek])
}

fn transcript(qr: &[u8], ek: &[u8], phone_x: &[u8; 32], ct: &[u8]) -> [u8; 32] {
    let tag = [DOMAIN, b"/transcript".as_slice()].concat();
    sha256_framed(&[&tag, qr, ek, phone_x, ct])
}

struct Derived {
    p2d: Zeroizing<[u8; 32]>,
    d2p: Zeroizing<[u8; 32]>,
    phone_tag: [u8; 32],
    pc_tag: [u8; 32],
    sas: String,
}

fn derive(th: &[u8; 32], ss_x: &[u8; 32], ss_k: &[u8]) -> Derived {
    let mut ikm = Zeroizing::new(Vec::with_capacity(64));
    ikm.extend_from_slice(ss_x);
    ikm.extend_from_slice(ss_k);
    let prk = Hkdf::<Sha256>::new(Some(th), &ikm);
    let ck_phone = kdf(&prk, "/confirm/phone");
    let ck_pc = kdf(&prk, "/confirm/pc");
    Derived {
        p2d: kdf(&prk, "/key/phone->pc"),
        d2p: kdf(&prk, "/key/pc->phone"),
        phone_tag: mac(&ck_phone, th),
        pc_tag: mac(&ck_pc, th),
        sas: sas_from(&prk),
    }
}

fn x25519(priv_: &[u8; 32], pub_: &[u8; 32]) -> LR<Zeroizing<[u8; 32]>> {
    let ss = Zeroizing::new(x25519_dalek::x25519(*priv_, *pub_));
    // A small-order point yields an all-zero shared secret: key substitution.
    if ct_eq(ss.as_ref(), &[0u8; 32]) {
        return Err(LinkError::Mismatch("x25519: low-order public key".into()));
    }
    Ok(ss)
}

fn blob_aad(link_id: &[u8], seq: u64, kind: u8, dir: u8) -> Vec<u8> {
    let mut w = W::new();
    w.raw(DOMAIN).raw(b"/blob").b8(link_id).u64(seq).u8(kind).u8(dir);
    w.done()
}

fn nonce(seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Which encrypted kinds a side may send.
fn may_send(role: LinkRole, kind: u8) -> bool {
    match role {
        LinkRole::Desktop => matches!(
            kind,
            KIND_DEVICE_REQUEST | KIND_MLS_JOIN_OFFERS | KIND_PACKAGE_ACK | KIND_ABORT
        ),
        LinkRole::Phone => matches!(
            kind,
            KIND_DEVICE_CERT
                | KIND_MLS_JOIN_REQUESTS
                | KIND_PACKAGE_HEADER
                | KIND_PACKAGE_PART
                | KIND_PACKAGE_END
                | KIND_ABORT
        ),
    }
}

fn peer(role: LinkRole) -> LinkRole {
    match role {
        LinkRole::Desktop => LinkRole::Phone,
        LinkRole::Phone => LinkRole::Desktop,
    }
}

fn dir_of(sender: LinkRole) -> u8 {
    match sender {
        LinkRole::Phone => DIR_PHONE_TO_PC,
        LinkRole::Desktop => DIR_PC_TO_PHONE,
    }
}

/// Parsed QR (magic, version, lengths and checksum verified).
pub(crate) struct Qr {
    pub link_id: Vec<u8>,
    pub issued_at: u64,
    pub pc_x25519: [u8; 32],
    pub ek_commit: [u8; 32],
    pub relay: String,
}

pub(crate) fn qr_encode(link_id: &[u8], issued_at: u64, pc_x: &[u8; 32], commit: &[u8; 32], relay: &str) -> Vec<u8> {
    let mut w = W::new();
    w.raw(QR_MAGIC).u8(LINK_VERSION).b8(link_id).u64(issued_at).raw(pc_x).raw(commit).b8(relay.as_bytes());
    let mut body = w.done();
    let sum = sha256(&[DOMAIN, b"/qr-check", &body]);
    body.extend_from_slice(&sum[..4]);
    body
}

pub(crate) fn qr_decode(bytes: &[u8]) -> LR<Qr> {
    if bytes.len() < 4 {
        return Err(LinkError::Malformed("qr: too short".into()));
    }
    let (body, sum) = bytes.split_at(bytes.len() - 4);
    if !ct_eq(&sha256(&[DOMAIN, b"/qr-check", body])[..4], sum) {
        return Err(LinkError::Malformed("qr: checksum".into()));
    }
    let mut r = Rd::new(body, "qr");
    if r.raw(2)? != QR_MAGIC {
        return Err(LinkError::Malformed("qr: not an Umbera link code".into()));
    }
    let v = r.u8()?;
    if v != LINK_VERSION {
        return Err(LinkError::Malformed(format!("qr: unsupported version {v}")));
    }
    let link_id = r.b8(LINK_ID_MAX)?.to_vec();
    if link_id.len() < LINK_ID_MIN {
        return Err(LinkError::Malformed("qr: link id too short".into()));
    }
    let issued_at = r.u64()?;
    let pc_x25519 = r.arr::<32>()?;
    let ek_commit = r.arr::<32>()?;
    let relay = label_from(r.b8(RELAY_MAX)?, "qr relay")?;
    r.end()?;
    Ok(Qr { link_id, issued_at, pc_x25519, ek_commit, relay })
}

pub(crate) fn qr_text_of(qr: &[u8]) -> String {
    format!("{QR_TEXT_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(qr))
}

pub(crate) fn qr_bytes_of(text: &str) -> LR<Vec<u8>> {
    let t = text.trim();
    let b64 = t
        .strip_prefix(QR_TEXT_PREFIX)
        .ok_or_else(|| LinkError::Malformed("qr: not an Umbera link code".into()))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|_| LinkError::Malformed("qr: base64".into()))
}

impl Inner {
    fn wipe(&mut self) {
        self.x_priv = None;
        self.kem_seed = None;
        self.expect_pc_tag = None;
        if let Some(k) = self.keys.as_mut() {
            k.th.zeroize();
            k.sas.zeroize();
        }
        self.keys = None;
        self.pkg_out = None;
        self.pkg_in = None;
    }

    fn close(&mut self) {
        self.wipe();
        self.state = LinkState::Closed;
    }

    /// Destroy the session and return an error, for any mismatch.
    fn fail<T>(&mut self, e: LinkError) -> LR<T> {
        self.close();
        Err(e)
    }

    fn need(&self, role: LinkRole, st: LinkState, what: &str) -> LR<()> {
        if self.role != role {
            return Err(LinkError::State(format!("{what}: wrong side")));
        }
        if self.state != st {
            return Err(LinkError::State(format!("{what}: session is {:?}", self.state)));
        }
        Ok(())
    }

    fn desktop_with(link_id: Vec<u8>, relay: String, now: u64, x_priv: [u8; 32], kem_seed: [u8; 64]) -> LR<Inner> {
        if !(LINK_ID_MIN..=LINK_ID_MAX).contains(&link_id.len()) {
            return Err(LinkError::Malformed(format!("link id must be {LINK_ID_MIN}..{LINK_ID_MAX} bytes")));
        }
        if relay.len() > RELAY_MAX {
            return Err(LinkError::Malformed("relay hint too long".into()));
        }
        label_from(relay.as_bytes(), "relay hint")?;
        let x_priv = Zeroizing::new(x_priv);
        let kem_seed = Zeroizing::new(kem_seed);
        let pc_x25519 = x25519_dalek::x25519(*x_priv, x25519_dalek::X25519_BASEPOINT_BYTES);
        let dk = ml_kem::DecapsulationKey1024::from_seed((*kem_seed).into());
        let ek = dk.encapsulation_key().to_bytes().to_vec();
        let ek_commit = ek_commitment(&ek);
        let qr = qr_encode(&link_id, now, &pc_x25519, &ek_commit, &relay);
        Ok(Inner {
            role: LinkRole::Desktop,
            state: LinkState::AwaitingAccept,
            link_id,
            relay,
            issued_at: now,
            qr,
            pc_x25519,
            ek_commit,
            x_priv: Some(x_priv),
            kem_seed: Some(kem_seed),
            ek,
            expect_pc_tag: None,
            keys: None,
            // OFFER is desktop seq 0, CONFIRM is seq 1.
            send_seq: 1,
            recv_seq: 0,
            keyed_at: 0,
            pkg_out: None,
            pkg_in: None,
        })
    }

    fn phone_from(qr_text: &str, now: u64) -> LR<Inner> {
        let qr = qr_bytes_of(qr_text)?;
        let q = qr_decode(&qr)?;
        check_qr_age(q.issued_at, now)?;
        Ok(Inner {
            role: LinkRole::Phone,
            state: LinkState::AwaitingOffer,
            link_id: q.link_id,
            relay: q.relay,
            issued_at: q.issued_at,
            qr,
            pc_x25519: q.pc_x25519,
            ek_commit: q.ek_commit,
            x_priv: None,
            kem_seed: None,
            ek: Vec::new(),
            expect_pc_tag: None,
            keys: None,
            send_seq: 0,
            recv_seq: 0,
            keyed_at: 0,
            pkg_out: None,
            pkg_in: None,
        })
    }

    fn phone_accept_with(&mut self, offer: &LinkBlob, now: u64, eph: [u8; 32], m: [u8; 32]) -> LR<LinkBlob> {
        self.need(LinkRole::Phone, LinkState::AwaitingOffer, "accept")?;
        if offer.kind != KIND_OFFER || offer.seq != 0 {
            return self.fail(LinkError::Malformed(format!("expected OFFER seq 0, got kind {} seq {}", offer.kind, offer.seq)));
        }
        if let Err(e) = check_qr_age(self.issued_at, now) {
            return self.fail(e);
        }
        if offer.data.len() != MLKEM_EK_LEN || !ct_eq(&ek_commitment(&offer.data), &self.ek_commit) {
            return self.fail(LinkError::Mismatch("ML-KEM key does not match the QR code".into()));
        }
        let ek = match mlkem_ek_from_bytes(&offer.data) {
            Ok(k) => k,
            Err(_) => return self.fail(LinkError::Mismatch("ML-KEM key failed FIPS 203 validation".into())),
        };
        let eph = Zeroizing::new(eph);
        let phone_x = x25519_dalek::x25519(*eph, x25519_dalek::X25519_BASEPOINT_BYTES);
        let ss_x = match x25519(&eph, &self.pc_x25519) {
            Ok(s) => s,
            Err(e) => return self.fail(e),
        };
        let (ct, ss_k) = ek.encapsulate_deterministic(&m.into());
        let ss_k = Zeroizing::new(ss_k.to_vec());
        let th = transcript(&self.qr, &offer.data, &phone_x, &ct);
        let d = derive(&th, &ss_x, &ss_k);
        let mut w = W::new();
        w.u8(LINK_VERSION).raw(&phone_x).raw(&ct).raw(&d.phone_tag);
        self.ek = offer.data.clone();
        self.expect_pc_tag = Some(Zeroizing::new(d.pc_tag));
        self.keys = Some(Keys { send: d.p2d, recv: d.d2p, th, sas: d.sas });
        self.state = LinkState::AwaitingConfirm;
        self.recv_seq = 1;
        self.send_seq = 1;
        Ok(LinkBlob { kind: KIND_ACCEPT, seq: 0, data: w.done() })
    }

    fn desktop_accept(&mut self, accept: &LinkBlob, now: u64) -> LR<LinkBlob> {
        self.need(LinkRole::Desktop, LinkState::AwaitingAccept, "accept")?;
        if now.saturating_sub(self.issued_at) > QR_TTL_SECS {
            return self.fail(LinkError::Expired("QR code is older than 60 seconds".into()));
        }
        if accept.kind != KIND_ACCEPT || accept.seq != 0 {
            return self.fail(LinkError::Malformed(format!("expected ACCEPT seq 0, got kind {} seq {}", accept.kind, accept.seq)));
        }
        let parsed = (|| {
            let mut r = Rd::new(&accept.data, "accept");
            let v = r.u8()?;
            if v != LINK_VERSION {
                return Err(LinkError::Malformed(format!("accept: version {v}")));
            }
            let px = r.arr::<32>()?;
            let ct = r.arr::<MLKEM_CT_LEN>()?;
            let tag = r.arr::<32>()?;
            r.end()?;
            Ok((px, ct, tag))
        })();
        let (phone_x, ct, tag) = match parsed {
            Ok(p) => p,
            Err(e) => return self.fail(e),
        };
        // Take the ephemeral secrets out of the session: whatever happens next, they are gone.
        let x_priv = self.x_priv.take().expect("present in AwaitingAccept");
        let kem_seed = self.kem_seed.take().expect("present in AwaitingAccept");
        let ss_x = match x25519(&x_priv, &phone_x) {
            Ok(s) => s,
            Err(e) => return self.fail(e),
        };
        let dk = match mlkem_dk_from_seed(kem_seed.as_ref()) {
            Ok(k) => k,
            Err(e) => return self.fail(e.into()),
        };
        // ML-KEM implicit rejection: a corrupted ciphertext yields a random secret → the MAC will not match.
        let ss_k = Zeroizing::new(dk.decapsulate(&ct.into()).to_vec());
        let th = transcript(&self.qr, &self.ek, &phone_x, &ct);
        let d = derive(&th, &ss_x, &ss_k);
        if !ct_eq(&d.phone_tag, &tag) {
            return self.fail(LinkError::Mismatch("phone key confirmation failed".into()));
        }
        self.keys = Some(Keys { send: d.d2p, recv: d.p2d, th, sas: d.sas });
        self.state = LinkState::AwaitingSas;
        self.keyed_at = now;
        self.recv_seq = 1;
        let seq = self.send_seq;
        self.send_seq += 1;
        Ok(LinkBlob { kind: KIND_CONFIRM, seq, data: d.pc_tag.to_vec() })
    }

    fn phone_confirm(&mut self, confirm: &LinkBlob, now: u64) -> LR<()> {
        self.need(LinkRole::Phone, LinkState::AwaitingConfirm, "confirm")?;
        if confirm.kind != KIND_CONFIRM || confirm.seq != 1 {
            return self.fail(LinkError::Malformed(format!("expected CONFIRM seq 1, got kind {} seq {}", confirm.kind, confirm.seq)));
        }
        let want = self.expect_pc_tag.take().expect("present in AwaitingConfirm");
        if !ct_eq(want.as_ref(), &confirm.data) {
            return self.fail(LinkError::Mismatch("desktop key confirmation failed".into()));
        }
        self.state = LinkState::AwaitingSas;
        self.keyed_at = now;
        self.recv_seq = 2;
        Ok(())
    }

    fn confirm_sas(&mut self, now: u64) -> LR<()> {
        if self.state != LinkState::AwaitingSas {
            return Err(LinkError::State(format!("confirm_sas: session is {:?}", self.state)));
        }
        if now.saturating_sub(self.keyed_at) > SAS_TTL_SECS {
            return self.fail(LinkError::Expired("verification code was not confirmed in time".into()));
        }
        self.state = LinkState::Established;
        Ok(())
    }

    pub(crate) fn seal(&mut self, kind: u8, pt: &[u8]) -> LR<LinkBlob> {
        let ok_state = match self.state {
            LinkState::Established => true,
            LinkState::AwaitingSas => kind == KIND_ABORT,
            _ => false,
        };
        if !ok_state {
            return Err(LinkError::State(format!("seal: session is {:?}", self.state)));
        }
        if !may_send(self.role, kind) {
            return Err(LinkError::State(format!("seal: kind {kind} is not ours to send")));
        }
        if kind == KIND_ABORT && pt.len() > ABORT_MAX {
            return Err(LinkError::Malformed("abort reason too long".into()));
        }
        let keys = self.keys.as_ref().expect("keyed state");
        let seq = self.send_seq;
        let aad = blob_aad(&self.link_id, seq, kind, dir_of(self.role));
        let ct = Aes256Gcm::new_from_slice(keys.send.as_ref())
            .expect("32-byte key")
            .encrypt(&Nonce::try_from(&nonce(seq)[..]).expect("12-byte nonce"), Payload { msg: pt, aad: &aad })
            .map_err(|_| LinkError::Crypto("aes-gcm encrypt".into()))?;
        self.send_seq += 1;
        if kind == KIND_ABORT {
            self.close();
        }
        Ok(LinkBlob { kind, seq, data: ct })
    }

    /// Decrypt the peer's next blob. A replay yields Replay (session intact); anything else
    /// invalid (gap, wrong kind, corruption) destroys the session.
    pub(crate) fn open_any(&mut self, blob: &LinkBlob) -> LR<Zeroizing<Vec<u8>>> {
        let ok_state = match self.state {
            LinkState::Established => true,
            LinkState::AwaitingSas => blob.kind == KIND_ABORT,
            _ => false,
        };
        if !ok_state {
            return Err(LinkError::State(format!("open: session is {:?}", self.state)));
        }
        if blob.seq < self.recv_seq {
            return Err(LinkError::Replay(format!("seq {} already received (next {})", blob.seq, self.recv_seq)));
        }
        if blob.seq > self.recv_seq {
            return self.fail(LinkError::Mismatch(format!("seq gap: got {}, expected {}", blob.seq, self.recv_seq)));
        }
        let sender = peer(self.role);
        if !may_send(sender, blob.kind) {
            return self.fail(LinkError::Mismatch(format!("kind {} cannot come from the other side", blob.kind)));
        }
        let keys = self.keys.as_ref().expect("keyed state");
        let aad = blob_aad(&self.link_id, blob.seq, blob.kind, dir_of(sender));
        let pt = Aes256Gcm::new_from_slice(keys.recv.as_ref())
            .expect("32-byte key")
            .decrypt(&Nonce::try_from(&nonce(blob.seq)[..]).expect("12-byte nonce"), Payload { msg: &blob.data, aad: &aad });
        let pt = match pt {
            Ok(p) => Zeroizing::new(p),
            Err(_) => return self.fail(LinkError::Mismatch("blob authentication failed".into())),
        };
        self.recv_seq += 1;
        if blob.kind == KIND_ABORT {
            self.close();
        }
        Ok(pt)
    }

    fn th(&self) -> LR<[u8; 32]> {
        self.keys.as_ref().map(|k| k.th).ok_or_else(|| LinkError::State("no keys".into()))
    }
}

fn check_qr_age(issued_at: u64, now: u64) -> LR<()> {
    if issued_at > now.saturating_add(MAX_CLOCK_SKEW_SECS) {
        return Err(LinkError::Expired("QR code is from the future (check the clock)".into()));
    }
    if now.saturating_sub(issued_at) > QR_TTL_SECS + MAX_CLOCK_SKEW_SECS {
        return Err(LinkError::Expired("QR code has expired".into()));
    }
    Ok(())
}

impl LinkSession {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic inside the call must not leave the session open: a poisoned mutex
        // is recovered, but the state is already closed or untouched (parsing does not panic).
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn desktop_with(link_id: Vec<u8>, relay: String, now: u64, x_priv: [u8; 32], kem_seed: [u8; 64]) -> LR<Arc<Self>> {
        Ok(Arc::new(LinkSession { inner: Mutex::new(Inner::desktop_with(link_id, relay, now, x_priv, kem_seed)?) }))
    }

    pub(crate) fn phone_accept_with(&self, offer: &LinkBlob, now: u64, eph: [u8; 32], m: [u8; 32]) -> LR<LinkBlob> {
        self.lock().phone_accept_with(offer, now, eph, m)
    }

    #[cfg(test)]
    pub(crate) fn lock_for_tests(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.lock()
    }

    #[cfg(test)]
    pub(crate) fn package_digest_for_tests(&self) -> Option<Vec<u8>> {
        self.lock().pkg_out.as_ref().and_then(|w| w.digest())
    }

    #[cfg(test)]
    pub(crate) fn transcript_hash(&self) -> LR<[u8; 32]> {
        self.lock().th()
    }

    pub(crate) fn package_begin_with(&self, include_history: bool, package_id: [u8; 16]) -> LR<LinkBlob> {
        let mut g = self.lock();
        g.need(LinkRole::Phone, LinkState::Established, "package_begin")?;
        if g.pkg_out.is_some() {
            return Err(LinkError::State("package already started".into()));
        }
        let (w, header) = PackageWriter::begin(package_id, include_history);
        let blob = g.seal(KIND_PACKAGE_HEADER, &header)?;
        g.pkg_out = Some(w);
        Ok(blob)
    }

    pub(crate) fn device_request_with(&self, device_seed: &[u8], device_type: u8, label: &str) -> LR<LinkBlob> {
        let mut g = self.lock();
        g.need(LinkRole::Desktop, LinkState::Established, "device_request")?;
        let th = g.th()?;
        let pt = cert::device_request_encode(&th, device_seed, device_type, label)?;
        g.seal(KIND_DEVICE_REQUEST, &pt)
    }
}

#[uniffi::export]
impl LinkSession {
    /// Desktop: new session with ephemeral keys. `link_id` is 16..32 bytes (issued by the server or
    /// random), `relay_hint` is the relay address for the phone (part of the transcript),
    /// `now_secs` is the desktop's Unix time.
    #[uniffi::constructor]
    pub fn desktop(link_id: Vec<u8>, relay_hint: String, now_secs: u64) -> LR<Arc<Self>> {
        Self::desktop_with(link_id, relay_hint, now_secs, os_random(), os_random())
    }

    /// Phone: session from the QR text. Checks format, checksum and validity window (with clock tolerance).
    #[uniffi::constructor]
    pub fn phone(qr_text: String, now_secs: u64) -> LR<Arc<Self>> {
        Ok(Arc::new(LinkSession { inner: Mutex::new(Inner::phone_from(&qr_text, now_secs)?) }))
    }

    pub fn role(&self) -> LinkRole {
        self.lock().role
    }

    pub fn state(&self) -> LinkState {
        self.lock().state
    }

    pub fn link_id(&self) -> Vec<u8> {
        self.lock().link_id.clone()
    }

    pub fn relay_hint(&self) -> String {
        self.lock().relay.clone()
    }

    pub fn issued_at(&self) -> u64 {
        self.lock().issued_at
    }

    /// Desktop: text for the QR ("umbera-link:" + base64url).
    pub fn qr_text(&self) -> LR<String> {
        let g = self.lock();
        g.need(LinkRole::Desktop, LinkState::AwaitingAccept, "qr_text")?;
        Ok(qr_text_of(&g.qr))
    }

    /// Desktop: OFFER blob (ML-KEM key). May be resent; it is always the same.
    pub fn offer(&self) -> LR<LinkBlob> {
        let g = self.lock();
        g.need(LinkRole::Desktop, LinkState::AwaitingAccept, "offer")?;
        Ok(LinkBlob { kind: KIND_OFFER, seq: 0, data: g.ek.clone() })
    }

    /// Phone: check OFFER against the QR, encapsulate, return ACCEPT.
    pub fn phone_accept(&self, offer: LinkBlob, now_secs: u64) -> LR<LinkBlob> {
        self.phone_accept_with(&offer, now_secs, os_random(), os_random())
    }

    /// Desktop: accept ACCEPT (no later than 60 s after the QR was shown), verify the phone's confirmation,
    /// return CONFIRM. Any mismatch destroys the session.
    pub fn desktop_accept(&self, accept: LinkBlob, now_secs: u64) -> LR<LinkBlob> {
        self.lock().desktop_accept(&accept, now_secs)
    }

    /// Phone: verify the desktop's CONFIRM.
    pub fn phone_confirm(&self, confirm: LinkBlob, now_secs: u64) -> LR<()> {
        self.lock().phone_confirm(&confirm, now_secs)
    }

    /// Verification code (6 digits), after mutual key confirmation.
    pub fn sas(&self) -> LR<String> {
        let g = self.lock();
        match g.state {
            LinkState::AwaitingSas | LinkState::Established => Ok(g.keys.as_ref().expect("keyed").sas.clone()),
            s => Err(LinkError::State(format!("sas: session is {s:?}"))),
        }
    }

    /// The user saw matching codes and tapped "Link".
    pub fn confirm_sas(&self, now_secs: u64) -> LR<()> {
        self.lock().confirm_sas(now_secs)
    }

    /// Encrypt a blob of one's own kind (see KIND_*). The package goes only through package_*.
    pub fn seal(&self, kind: u8, plaintext: Vec<u8>) -> LR<LinkBlob> {
        if matches!(kind, KIND_PACKAGE_HEADER | KIND_PACKAGE_PART | KIND_PACKAGE_END | KIND_DEVICE_REQUEST) {
            return Err(LinkError::State(format!("seal: kind {kind} has its own method")));
        }
        self.lock().seal(kind, &plaintext)
    }

    /// Decrypt a peer blob (except package parts and the device request).
    pub fn open(&self, blob: LinkBlob) -> LR<Vec<u8>> {
        if matches!(blob.kind, KIND_PACKAGE_HEADER | KIND_PACKAGE_PART | KIND_PACKAGE_END | KIND_DEVICE_REQUEST) {
            return Err(LinkError::State(format!("open: kind {} has its own method", blob.kind)));
        }
        Ok(self.lock().open_any(&blob)?.to_vec())
    }

    /// Desktop: "sign my keys" request: device public keys from `device_seed` and
    /// proof of possession (Ed25519 + ML-DSA-65 signatures over the linking transcript).
    pub fn device_request(&self, device_seed: Vec<u8>, device_type: u8, label: String) -> LR<LinkBlob> {
        self.device_request_with(&device_seed, device_type, &label)
    }

    /// Phone: open the desktop's request and verify the proof of possession.
    pub fn open_device_request(&self, blob: LinkBlob) -> LR<DeviceRequest> {
        let mut g = self.lock();
        g.need(LinkRole::Phone, LinkState::Established, "open_device_request")?;
        if blob.kind != KIND_DEVICE_REQUEST {
            return Err(LinkError::State(format!("open_device_request: kind {}", blob.kind)));
        }
        let th = g.th()?;
        let pt = g.open_any(&blob)?;
        match cert::device_request_decode(&th, &pt) {
            Ok(r) => Ok(r),
            Err(e) => g.fail(e),
        }
    }

    /// Phone: start a transfer package. `include_history`: the user chose "with history".
    pub fn package_begin(&self, include_history: bool) -> LR<LinkBlob> {
        self.package_begin_with(include_history, os_random())
    }

    /// Phone: add a record. Returns parts ready to send (may be empty).
    pub fn package_add(&self, section: u8, id: Vec<u8>, body: Vec<u8>) -> LR<Vec<LinkBlob>> {
        let mut g = self.lock();
        g.need(LinkRole::Phone, LinkState::Established, "package_add")?;
        let w = g.pkg_out.as_mut().ok_or_else(|| LinkError::State("package not started".into()))?;
        let parts = w.add(section, &id, &body)?;
        parts.iter().map(|p| g.seal(KIND_PACKAGE_PART, p)).collect()
    }

    /// Phone: finish the package: the last parts and END with the final checksum.
    pub fn package_finish(&self) -> LR<Vec<LinkBlob>> {
        let mut g = self.lock();
        g.need(LinkRole::Phone, LinkState::Established, "package_finish")?;
        let w = g.pkg_out.as_mut().ok_or_else(|| LinkError::State("package not started".into()))?;
        let (parts, end) = w.finish()?;
        let mut out: Vec<LinkBlob> = parts.iter().map(|p| g.seal(KIND_PACKAGE_PART, p)).collect::<LR<_>>()?;
        out.push(g.seal(KIND_PACKAGE_END, &end)?);
        Ok(out)
    }

    /// Desktop: accept HEADER/PART/END. Records are returned as they arrive; commit them to the database
    /// only once `done` (the final checksum matched).
    pub fn package_receive(&self, blob: LinkBlob) -> LR<PackageProgress> {
        let mut g = self.lock();
        g.need(LinkRole::Desktop, LinkState::Established, "package_receive")?;
        if !matches!(blob.kind, KIND_PACKAGE_HEADER | KIND_PACKAGE_PART | KIND_PACKAGE_END) {
            return Err(LinkError::State(format!("package_receive: kind {}", blob.kind)));
        }
        // AEAD and ordering first (a replay is REPLAY, harmless to the session), then semantics.
        let pt = g.open_any(&blob)?;
        if blob.kind == KIND_PACKAGE_HEADER && g.pkg_in.is_some() {
            return g.fail(LinkError::Mismatch("second package header".into()));
        }
        if blob.kind != KIND_PACKAGE_HEADER && g.pkg_in.is_none() {
            return g.fail(LinkError::Mismatch("package part before header".into()));
        }
        let res = match blob.kind {
            KIND_PACKAGE_HEADER => PackageReader::begin(&pt).map(|(r, p)| {
                g.pkg_in = Some(r);
                p
            }),
            KIND_PACKAGE_PART => g.pkg_in.as_mut().expect("checked").part(&pt),
            _ => g.pkg_in.as_mut().expect("checked").end(&pt),
        };
        match res {
            Ok(p) => Ok(p),
            Err(e) => g.fail(e),
        }
    }

    /// Desktop: "package received in full" acknowledgement (package checksum inside), after done.
    pub fn package_ack(&self) -> LR<LinkBlob> {
        let mut g = self.lock();
        g.need(LinkRole::Desktop, LinkState::Established, "package_ack")?;
        let digest = g
            .pkg_in
            .as_ref()
            .and_then(|r| r.digest())
            .ok_or_else(|| LinkError::State("package is not complete".into()))?;
        g.seal(KIND_PACKAGE_ACK, &digest)
    }

    /// Phone: verify the desktop's acknowledgement: the package checksum must match the one sent.
    pub fn package_check_ack(&self, blob: LinkBlob) -> LR<()> {
        let mut g = self.lock();
        g.need(LinkRole::Phone, LinkState::Established, "package_check_ack")?;
        let want = g
            .pkg_out
            .as_ref()
            .and_then(|w| w.digest())
            .ok_or_else(|| LinkError::State("package is not finished".into()))?;
        if blob.kind != KIND_PACKAGE_ACK {
            return Err(LinkError::State(format!("package_check_ack: kind {}", blob.kind)));
        }
        let got = g.open_any(&blob)?;
        if !ct_eq(&got, &want) {
            return g.fail(LinkError::Mismatch("package digest acknowledged by the desktop differs".into()));
        }
        Ok(())
    }

    /// Cancel and wipe secrets (without notifying the peer; to notify, seal(KIND_ABORT)).
    /// Not named `close`: in the Kotlin bindings that name is taken by AutoCloseable.
    pub fn wipe(&self) {
        self.lock().close();
    }
}

