// Device-link tests: end-to-end flow, vectors (tests/vectors/link-vectors.json) and negative cases.
// Vectors are regenerated only explicitly: LINK_VECTORS_WRITE=1 cargo test devlink.

use std::sync::Arc;

use serde_json::{json, Value};

use super::cert::*;
use super::comm::*;
use super::mlsjoin::*;
use super::package::*;
use super::session::*;
use super::LinkError;
use crate::primitives as p;
use crate::MlsClient;

const NOW: u64 = 1_762_700_000;
const USER_ID: &str = "11111111-1111-1111-1111-111111111111";
const DEVICE_ID: &str = "22222222-2222-2222-2222-222222222222";

/// label_sealed with a fixed nonce (for vectors; in real use the nonce is random).
fn label_sealed_fixed(sync: &[u8]) -> Vec<u8> {
    use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit, Nonce};
    let mut k = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, sync).expand(b"umbera-device-label-v1", &mut k).unwrap();
    let nonce = &h32("label-nonce")[..12];
    let aad = super::sha256(&[super::DOMAIN, b"/device-label", DEVICE_ID.as_bytes()]);
    let pt = [vec![DEVICE_TYPE_DESKTOP, 5], b"Linux".to_vec()].concat();
    let ct = Aes256Gcm::new_from_slice(&k).unwrap().encrypt(&Nonce::try_from(&nonce[..]).unwrap(), Payload { msg: &pt, aad: &aad }).unwrap();
    [nonce.to_vec(), ct].concat()
}
const RELAY: &str = "https://umbera.app";

fn h32(label: &str) -> [u8; 32] {
    super::sha256(&[b"umbera-link-vector/", label.as_bytes()])
}
fn h64(a: &str, b: &str) -> [u8; 64] {
    let mut o = [0u8; 64];
    o[..32].copy_from_slice(&h32(a));
    o[32..].copy_from_slice(&h32(b));
    o
}
fn hx(b: &[u8]) -> String {
    hex::encode(b)
}
fn sha(b: &[u8]) -> String {
    hex::encode(super::sha256(&[b]))
}

fn link_id() -> Vec<u8> {
    h32("link-id")[..16].to_vec()
}

/// Deterministic pair of sessions up to the verification codes (without "Link").
struct Pair {
    pc: Arc<LinkSession>,
    ph: Arc<LinkSession>,
    offer: LinkBlob,
    accept: LinkBlob,
    confirm: LinkBlob,
}

fn keyed_pair(tag: &str) -> Pair {
    let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32(&format!("{tag}pc-x25519")), h64(&format!("{tag}pc-mlkem-d"), &format!("{tag}pc-mlkem-z"))).unwrap();
    let ph = LinkSession::phone(pc.qr_text().unwrap(), NOW + 3).unwrap();
    let offer = pc.offer().unwrap();
    let accept = ph.phone_accept_with(&offer, NOW + 4, h32(&format!("{tag}phone-x25519")), h32(&format!("{tag}mlkem-m"))).unwrap();
    let confirm = pc.desktop_accept(accept.clone(), NOW + 5).unwrap();
    ph.phone_confirm(confirm.clone(), NOW + 6).unwrap();
    Pair { pc, ph, offer, accept, confirm }
}

fn established(tag: &str) -> Pair {
    let p = keyed_pair(tag);
    p.pc.confirm_sas(NOW + 10).unwrap();
    p.ph.confirm_sas(NOW + 10).unwrap();
    p
}

fn account() -> (Vec<u8>, Vec<u8>) {
    (h32("account-secp256k1").to_vec(), h32("account-mldsa65").to_vec())
}

fn account_address() -> String {
    let (s, d) = account();
    let sp = p::secp256k1_public_key(s).unwrap();
    let dp = p::mldsa65_public_key(d).unwrap();
    crate::quant_address(hx(&sp), hx(&dp)).unwrap()
}

fn jpeg(n: usize) -> Vec<u8> {
    let mut b = vec![0xFF, 0xD8, 0xFF, 0xE0, 0, 16, b'J', b'F', b'I', b'F', 0, 1];
    b.extend((0..n).map(|i| (i * 31 % 251) as u8));
    b
}

fn is<T: std::fmt::Debug>(r: Result<T, LinkError>, want: &str) {
    match r {
        Err(e) => {
            let got = format!("{e:?}");
            assert!(got.starts_with(want), "want {want}, got {got}");
        }
        Ok(v) => panic!("want {want}, got Ok({v:?})"),
    }
}

// ---------------------------------------------------------------------------
// End-to-end flow + vectors
// ---------------------------------------------------------------------------

fn package_records() -> Vec<PackageRecord> {
    let roots = comm_vault_roots(h32("acct-x25519").to_vec(), h64("acct-kem-d", "acct-kem-z").to_vec()).unwrap();
    vec![
        PackageRecord { section: SECTION_PROFILE, id: vec![], body: br#"{"name":"Demo","about":"vector"}"#.to_vec() },
        PackageRecord { section: SECTION_CONTACT, id: b"c1".to_vec(), body: br#"{"address":"quantDemo1","name":"Alice"}"#.to_vec() },
        PackageRecord { section: SECTION_CHAT, id: b"chat1".to_vec(), body: br#"{"peer":"quantDemo1"}"#.to_vec() },
        PackageRecord { section: SECTION_MESSAGE_TEXT, id: b"m1".to_vec(), body: "Привет с телефона".as_bytes().to_vec() },
        PackageRecord { section: SECTION_MESSAGE_PHOTO, id: b"m2".to_vec(), body: jpeg(300 * 1024) },
        PackageRecord { section: SECTION_COMM_VAULT, id: vec![], body: comm_vault_record_body(roots).unwrap() },
        PackageRecord { section: SECTION_COMM_MEMBERSHIP, id: b"chan-1".to_vec(), body: br#"{"channel":"chan-1"}"#.to_vec() },
    ]
}

fn build_vectors() -> Value {
    let pr = established("");
    let th = pr.pc.transcript_hash().unwrap();
    assert_eq!(th, pr.ph.transcript_hash().unwrap());
    let sas = pr.pc.sas().unwrap();
    assert_eq!(sas, pr.ph.sas().unwrap(), "both screens show the same code");
    assert_eq!(sas.len(), 6);

    // Desktop device and certificate (server format).
    let dseed = h32("device-seed").to_vec();
    let keys = device_public_keys(dseed.clone()).unwrap();
    let req_blob = pr.pc.device_request_with(&dseed, DEVICE_TYPE_DESKTOP, "Linux").unwrap();
    let req = pr.ph.open_device_request(req_blob.clone()).unwrap();
    assert_eq!(req.keys, keys);
    let (acct_s, acct_d) = account();
    let sync = account_sync_key(h32("acct-x25519").to_vec(), h64("acct-kem-d", "acct-kem-z").to_vec()).unwrap();
    let label_sealed = label_sealed_fixed(&sync);
    let cert = device_cert_issue(req, USER_ID.into(), DEVICE_ID.into(), acct_s, acct_d, label_sealed.clone(), NOW + 20).unwrap();
    let cert_blob = pr.ph.seal(KIND_DEVICE_CERT, cert.clone()).unwrap();
    let got_cert = pr.pc.open(cert_blob.clone()).unwrap();
    let info = device_cert_verify_for_device(got_cert, dseed.clone()).unwrap();
    assert_eq!(info.account_address, account_address());
    let info2 = device_cert_verify(cert.clone(), account_address()).unwrap();
    assert_eq!(info, info2);
    assert_eq!(device_label_open(sync.clone(), DEVICE_ID.into(), info.label_sealed.clone()).unwrap().label, "Linux");

    // Package.
    let header = pr.ph.package_begin_with(true, h32("package-id")[..16].try_into().unwrap()).unwrap();
    let mut blobs = vec![header];
    for r in package_records() {
        blobs.extend(pr.ph.package_add(r.section, r.id, r.body).unwrap());
    }
    blobs.extend(pr.ph.package_finish().unwrap());
    let mut got = Vec::new();
    let mut done = false;
    for b in &blobs {
        let prog = pr.pc.package_receive(b.clone()).unwrap();
        got.extend(prog.records);
        done = prog.done;
    }
    assert!(done);
    assert_eq!(got, package_records());
    let ack = pr.pc.package_ack().unwrap();
    pr.ph.package_check_ack(ack.clone()).unwrap();

    let blob_json = |b: &LinkBlob| json!({"kind": b.kind, "seq": b.seq, "data_sha256": sha(&b.data)});
    let qr_text = pr.pc_qr_text_for_vectors();
    json!({
        "note": "Generated by core/src/devlink/tests.rs (LINK_VECTORS_WRITE=1 cargo test devlink). Inputs are SHA-256(\"umbera-link-vector/\" + label). Hex everywhere.",
        "inputs": {
            "now": NOW, "relay": RELAY, "link_id": hx(&link_id()),
            "pc_x25519_private": hx(&h32("pc-x25519")),
            "pc_mlkem_seed": hx(&h64("pc-mlkem-d", "pc-mlkem-z")),
            "phone_x25519_private": hx(&h32("phone-x25519")),
            "phone_mlkem_m": hx(&h32("mlkem-m")),
            "device_seed": hx(&dseed),
            "account_secp256k1_private": hx(&h32("account-secp256k1")),
            "account_mldsa65_seed": hx(&h32("account-mldsa65")),
            "package_id": hx(&h32("package-id")[..16]),
        },
        "handshake": {
            "qr_text": qr_text,
            "offer_sha256": sha(&pr.offer.data),
            "accept": hx(&pr.accept.data),
            "confirm": hx(&pr.confirm.data),
            "transcript_hash": hx(&th),
            "sas": sas,
        },
        "device": {
            "ed25519": hx(&keys.ed25519),
            "mldsa65_sha256": sha(&keys.mldsa65),
            "x25519": hx(&keys.x25519),
            "mlkem1024_sha256": sha(&keys.mlkem1024),
            "user_id": USER_ID,
            "device_id": DEVICE_ID,
            "keys_digest": hx(&device_keys_digest(info.wire_keys.clone())),
            "link_message": super::cert::link_message_for_tests(USER_ID, DEVICE_ID, &info.wire_keys),
            "primary_sig": hx(&info.primary_sig),
            "pq_sig_sha256": sha(&info.pq_sig),
            "request_blob": blob_json(&req_blob),
            "account_address": account_address(),
            "account_secp256k1": hx(&info.account_secp256k1),
            "account_mldsa65_sha256": sha(&info.account_mldsa65),
            "sync_key": hx(&sync),
            "label_sealed": hx(&label_sealed),
            "cert": hx(&cert),
            "cert_blob": blob_json(&cert_blob),
        },
        "package": {
            "blobs": blobs.iter().map(blob_json).collect::<Vec<_>>(),
            "digest": hx(&pr.ph.package_digest_for_tests().unwrap()),
            "ack_blob": blob_json(&ack),
        },
    })
}

impl Pair {
    fn pc_qr_text_for_vectors(&self) -> String {
        // The QR is no longer shown after negotiation — reconstruct it from the same code.
        let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
        pc.qr_text().unwrap()
    }
}

#[test]
fn vectors_match_file() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/link-vectors.json");
    let v = build_vectors();
    if std::env::var("LINK_VECTORS_WRITE").as_deref() == Ok("1") {
        std::fs::write(path, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
        return;
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("tests/vectors/link-vectors.json")).unwrap();
    assert_eq!(v, want, "wire format drifted from tests/vectors/link-vectors.json");
}

#[test]
fn vectors_verify_from_file_inputs() {
    // Verification "from the peer's side" from the file alone: the certificate is valid for the address, the server
    // directory (keys + signatures) is checked separately, any byte flip breaks the signature.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/link-vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let addr = v["device"]["account_address"].as_str().unwrap().to_string();
    let cert = hex::decode(v["device"]["cert"].as_str().unwrap()).unwrap();
    let info = device_cert_verify(cert.clone(), addr.clone()).unwrap();
    assert_eq!(info.device_id, DEVICE_ID);
    assert_eq!(info.user_id, USER_ID);
    let pk = device_listing_verify(
        info.user_id.clone(), info.device_id.clone(), info.wire_keys.clone(), info.primary_sig.clone(), info.pq_sig.clone(),
        info.account_secp256k1.clone(), info.account_mldsa65.clone(), addr.clone(),
    )
    .unwrap();
    assert_eq!(pk, info.keys);
    let mut bad = cert.clone();
    let n = bad.len();
    bad[n - 600] ^= 1; // inside pq_sig
    is(device_cert_verify(bad, addr.clone()), "Mismatch");
    // A different device_id with the same signatures — rejected (the signature is bound to the server id).
    is(
        device_listing_verify(
            info.user_id.clone(), "33333333-3333-3333-3333-333333333333".into(), info.wire_keys.clone(), info.primary_sig.clone(),
            info.pq_sig.clone(), info.account_secp256k1.clone(), info.account_mldsa65.clone(), addr.clone(),
        ),
        "Mismatch",
    );
    // Without the PQ signature — rejected, even if ECDSA is valid (the server would have accepted it).
    is(
        device_listing_verify(
            info.user_id.clone(), info.device_id.clone(), info.wire_keys.clone(), info.primary_sig.clone(), vec![],
            info.account_secp256k1.clone(), info.account_mldsa65.clone(), addr.clone(),
        ),
        "Mismatch",
    );
    // Account keys for the wrong address — rejected.
    is(
        device_listing_verify(
            info.user_id, info.device_id, info.wire_keys, info.primary_sig, info.pq_sig, info.account_secp256k1,
            info.account_mldsa65, "quantOther".into(),
        ),
        "Mismatch",
    );
}

/// Server test vector (the server's TestKeysDigestVector): the core computes
/// keys_digest and the signature string byte for byte like the Go implementation.
#[test]
fn server_keys_digest_vector() {
    let w = vec![
        DeviceKey { alg: "x25519".into(), key: vec![1; 32] },
        DeviceKey { alg: "ml-kem-1024".into(), key: vec![2; 4] },
    ];
    assert_eq!(hx(&device_keys_digest(w.clone())), "27ebe18be48a8c5b97f47d9c05e17020307921b9af324dae08d76fdba39f6848");
    let m = super::cert::link_message_for_tests(USER_ID, DEVICE_ID, &w);
    assert_eq!(sha(m.as_bytes()), "4cbecf9695023e3492688b59e23da356303ad047932d8061934d8c9b95deb57c");
}

#[test]
fn device_label_roundtrip() {
    let sync = account_sync_key(h32("x").to_vec(), h64("d", "z").to_vec()).unwrap();
    let sealed = device_label_seal(sync.clone(), DEVICE_ID.into(), DEVICE_TYPE_DESKTOP, "Рабочий".into()).unwrap();
    assert!(sealed.len() <= 512);
    let l = device_label_open(sync.clone(), DEVICE_ID.into(), sealed.clone()).unwrap();
    assert_eq!((l.device_type, l.label.as_str()), (DEVICE_TYPE_DESKTOP, "Рабочий"));
    // Someone else's device / someone else's key — rejected.
    is(device_label_open(sync.clone(), "33333333-3333-3333-3333-333333333333".into(), sealed.clone()), "Mismatch");
    is(device_label_open(vec![9; 32], DEVICE_ID.into(), sealed), "Mismatch");
    is(device_label_seal(sync, "NOT-A-UUID".into(), DEVICE_TYPE_DESKTOP, "x".into()), "Malformed");
}

// ---------------------------------------------------------------------------
// Negative: substitution, corruption, replay, timeouts
// ---------------------------------------------------------------------------

/// Desktop substitution: the attacker sees the real QR, impersonates the phone to the desktop and its own
/// "desktop" to the phone. Confirmations match on each half, but the codes on the desktop and
/// phone screens differ — the user sees the mismatch and does not press "Link".
#[test]
fn mitm_with_substituted_desktop_keys_shows_different_codes() {
    let real_pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    // Attacker → real desktop (posing as the phone).
    let evil_phone = LinkSession::phone(real_pc.qr_text().unwrap(), NOW).unwrap();
    let acc = evil_phone.phone_accept_with(&real_pc.offer().unwrap(), NOW, h32("evil-eph"), h32("evil-m")).unwrap();
    let conf = real_pc.desktop_accept(acc, NOW + 1).unwrap();
    evil_phone.phone_confirm(conf, NOW + 1).unwrap();
    // The attacker shows the phone its own QR with the SAME link_id and its own keys.
    let evil_pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("evil-x"), h64("evil-d", "evil-z")).unwrap();
    let phone = LinkSession::phone(evil_pc.qr_text().unwrap(), NOW).unwrap();
    let acc2 = phone.phone_accept_with(&evil_pc.offer().unwrap(), NOW, h32("phone-x25519"), h32("mlkem-m")).unwrap();
    let conf2 = evil_pc.desktop_accept(acc2, NOW + 1).unwrap();
    phone.phone_confirm(conf2, NOW + 1).unwrap();
    assert_ne!(real_pc.sas().unwrap(), phone.sas().unwrap(), "codes on the real desktop and the phone differ");
}

/// The phone read the real QR, but the relay substituted its own ML-KEM key.
#[test]
fn substituted_offer_is_rejected_by_phone() {
    let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    let evil = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("evil-x"), h64("evil-d", "evil-z")).unwrap();
    let ph = LinkSession::phone(pc.qr_text().unwrap(), NOW).unwrap();
    is(ph.phone_accept(evil.offer().unwrap(), NOW), "Mismatch");
    assert_eq!(ph.state(), LinkState::Closed);
}

/// A relay that knows link_id (but not the QR) cannot answer the desktop itself: without the desktop's X25519
/// the confirmation cannot be built. Substitute keys "out of thin air" — the desktop rejects.
#[test]
fn accept_from_someone_without_the_qr_is_rejected() {
    let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    // The attacker sees OFFER and link_id but takes a wrong desktop X25519 instead of the one from the QR.
    let other = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("guess-x"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    let fake = LinkSession::phone(other.qr_text().unwrap(), NOW).unwrap();
    let acc = fake.phone_accept(pc.offer().unwrap(), NOW).unwrap();
    is(pc.desktop_accept(acc, NOW + 1), "Mismatch");
    assert_eq!(pc.state(), LinkState::Closed);
}

#[test]
fn tampered_accept_and_confirm_are_rejected() {
    for byte in [1usize, 40, 1600] {
        let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
        let ph = LinkSession::phone(pc.qr_text().unwrap(), NOW).unwrap();
        let mut acc = ph.phone_accept(pc.offer().unwrap(), NOW).unwrap();
        acc.data[byte] ^= 0x80;
        is(pc.desktop_accept(acc, NOW + 1), "Mismatch");
        assert_eq!(pc.state(), LinkState::Closed);
        is(pc.sas(), "State");
    }
    let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    let ph = LinkSession::phone(pc.qr_text().unwrap(), NOW).unwrap();
    let acc = ph.phone_accept(pc.offer().unwrap(), NOW).unwrap();
    let mut conf = pc.desktop_accept(acc, NOW + 1).unwrap();
    conf.data[7] ^= 1;
    is(ph.phone_confirm(conf, NOW + 1), "Mismatch");
    assert_eq!(ph.state(), LinkState::Closed);
}

#[test]
fn second_accept_is_refused() {
    let pr = keyed_pair("");
    is(pr.pc.desktop_accept(pr.accept.clone(), NOW + 6), "State");
    // And the session is still alive.
    assert_eq!(pr.pc.state(), LinkState::AwaitingSas);
}

#[test]
fn tampered_blob_kills_session() {
    let pr = established("");
    let mut b = pr.ph.seal(KIND_MLS_JOIN_REQUESTS, b"groups".to_vec()).unwrap();
    b.data[0] ^= 1;
    is(pr.pc.open(b), "Mismatch");
    assert_eq!(pr.pc.state(), LinkState::Closed);
    // A changed kind with the same bytes — also rejected (kind is in the AAD).
    let pr = established("");
    let mut b = pr.ph.seal(KIND_MLS_JOIN_REQUESTS, b"groups".to_vec()).unwrap();
    b.kind = KIND_DEVICE_CERT;
    is(pr.pc.open(b), "Mismatch");
    // A foreign link_id (a blob from another link with the same keys is impossible, but we check the AAD):
    let pr = established("");
    let q = established("other-");
    let b = q.ph.seal(KIND_MLS_JOIN_REQUESTS, b"groups".to_vec()).unwrap();
    is(pr.pc.open(b), "Mismatch");
}

#[test]
fn replay_and_gap() {
    let pr = established("");
    let b1 = pr.ph.seal(KIND_MLS_JOIN_REQUESTS, b"one".to_vec()).unwrap();
    let b2 = pr.ph.seal(KIND_MLS_JOIN_REQUESTS, b"two".to_vec()).unwrap();
    let b3 = pr.ph.seal(KIND_MLS_JOIN_REQUESTS, b"three".to_vec()).unwrap();
    assert_eq!(pr.pc.open(b1.clone()).unwrap(), b"one");
    is(pr.pc.open(b1), "Replay");
    assert_eq!(pr.pc.state(), LinkState::Established, "replay does not kill the session");
    is(pr.pc.open(b3), "Mismatch"); // b2 skipped
    assert_eq!(pr.pc.state(), LinkState::Closed);
    is(pr.pc.open(b2), "State");
}

#[test]
fn wrong_direction_is_refused() {
    let pr = established("");
    // The phone cannot send a "device request", the desktop cannot send package parts.
    is(pr.ph.seal(KIND_PACKAGE_ACK, vec![]), "State");
    is(pr.pc.seal(KIND_DEVICE_CERT, vec![]), "State");
    // Reflection: one's own blob sent back — wrong direction.
    let b = pr.pc.seal(KIND_MLS_JOIN_OFFERS, b"x".to_vec()).unwrap();
    is(pr.pc.open(b), "Mismatch");
}

#[test]
fn nothing_before_codes_are_confirmed() {
    let pr = keyed_pair("");
    is(pr.ph.seal(KIND_DEVICE_CERT, vec![1]), "State");
    is(pr.ph.package_begin(false), "State");
    is(pr.pc.device_request(h32("device-seed").to_vec(), DEVICE_TYPE_DESKTOP, "Linux".into()), "State");
    // A rejection is delivered even before confirmation.
    let ab = pr.ph.seal(KIND_ABORT, vec![1]).unwrap();
    assert_eq!(pr.ph.state(), LinkState::Closed);
    assert_eq!(pr.pc.open(ab).unwrap(), vec![1]);
    assert_eq!(pr.pc.state(), LinkState::Closed);
}

#[test]
fn expiry() {
    // Desktop: ACCEPT at second 61.
    let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    let ph = LinkSession::phone(pc.qr_text().unwrap(), NOW).unwrap();
    let acc = ph.phone_accept(pc.offer().unwrap(), NOW + 59).unwrap();
    is(pc.desktop_accept(acc, NOW + QR_TTL_SECS + 1), "Expired");
    assert_eq!(pc.state(), LinkState::Closed);
    // Phone: a stale QR snapshot.
    let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    is(LinkSession::phone(pc.qr_text().unwrap(), NOW + QR_TTL_SECS + MAX_CLOCK_SKEW_SECS + 1), "Expired");
    is(LinkSession::phone(pc.qr_text().unwrap(), NOW - MAX_CLOCK_SKEW_SECS - 1), "Expired");
    // Verification code not confirmed in time.
    let pr = keyed_pair("");
    is(pr.pc.confirm_sas(NOW + 5 + SAS_TTL_SECS + 1), "Expired");
    assert_eq!(pr.pc.state(), LinkState::Closed);
}

#[test]
fn qr_format_errors() {
    let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    let text = pc.qr_text().unwrap();
    is(LinkSession::phone(text.replace("umbera-link:", "otherapp:"), NOW), "Malformed");
    let mut raw = qr_bytes_of(&text).unwrap();
    raw[20] ^= 1;
    is(LinkSession::phone(qr_text_of(&raw), NOW), "Malformed");
    is(LinkSession::desktop(vec![1; 8], RELAY.into(), NOW), "Malformed");
    is(LinkSession::desktop(vec![1; 16], "bad\nrelay".into(), NOW), "Malformed");
}

#[test]
fn low_order_phone_key_is_rejected() {
    let pc = LinkSession::desktop_with(link_id(), RELAY.into(), NOW, h32("pc-x25519"), h64("pc-mlkem-d", "pc-mlkem-z")).unwrap();
    let ph = LinkSession::phone(pc.qr_text().unwrap(), NOW).unwrap();
    let mut acc = ph.phone_accept(pc.offer().unwrap(), NOW).unwrap();
    acc.data[1..33].copy_from_slice(&[0u8; 32]); // zero point
    is(pc.desktop_accept(acc, NOW + 1), "Mismatch");
}

// ---------------------------------------------------------------------------
// Device and certificate
// ---------------------------------------------------------------------------

#[test]
fn device_request_bound_to_its_link() {
    let a = established("");
    let b = established("b-");
    let dseed = h32("device-seed").to_vec();
    // A request signed in link A opens in A, but its proof is not valid in B:
    // move the plaintext from A to B.
    let blob = a.pc.device_request(dseed.clone(), DEVICE_TYPE_DESKTOP, "Linux".into()).unwrap();
    assert!(a.ph.open_device_request(blob).is_ok());
    let th_a = a.pc.transcript_hash().unwrap();
    let pt = super::cert::device_request_encode(&th_a, &dseed, DEVICE_TYPE_DESKTOP, "Linux").unwrap();
    let moved = b.pc.lock_for_tests().seal(KIND_DEVICE_REQUEST, &pt).unwrap();
    is(b.ph.open_device_request(moved), "Mismatch");
}

#[test]
fn certificate_checks() {
    let (sk, d) = account();
    let dseed = h32("device-seed").to_vec();
    let req = DeviceRequest { device_type: DEVICE_TYPE_DESKTOP, label: "Linux".into(), keys: device_public_keys(dseed.clone()).unwrap() };
    let cert = device_cert_issue(req.clone(), USER_ID.into(), DEVICE_ID.into(), sk.clone(), d.clone(), vec![], NOW).unwrap();
    // Someone else's address.
    is(device_cert_verify(cert.clone(), "quantSomeoneElse".into()), "Mismatch");
    // A certificate for different keys — the desktop does not accept it.
    is(device_cert_verify_for_device(cert.clone(), h32("other-device").to_vec()), "Mismatch");
    // Substituted X25519 encryption key inside the certificate: the signature does not match.
    let mut bad = cert.clone();
    let x_off = 3 + 1 + 1 + 36 + 1 + 36 + 65 + 1952 + 32 + 1952;
    bad[x_off] ^= 1;
    is(device_cert_verify(bad, account_address()), "Mismatch");
    // Substituted device_id in the certificate (another string of the same length).
    let mut bad = cert.clone();
    bad[3 + 1 + 1 + 36 + 1] = b'3';
    is(device_cert_verify(bad, account_address()), "Mismatch");
    // Truncated and with trailing bytes.
    is(device_cert_verify(cert[..cert.len() - 1].to_vec(), account_address()), "Malformed");
    let mut long = cert.clone();
    long.push(0);
    is(device_cert_verify(long, account_address()), "Malformed");
    // Invalid request fields.
    let mut r2 = req.clone();
    r2.device_type = 9;
    is(device_cert_issue(r2, USER_ID.into(), DEVICE_ID.into(), sk.clone(), d.clone(), vec![], NOW), "Malformed");
    let mut r3 = req.clone();
    r3.label = "x".repeat(65);
    is(device_cert_issue(r3, USER_ID.into(), DEVICE_ID.into(), sk.clone(), d.clone(), vec![], NOW), "Malformed");
    is(device_cert_issue(req.clone(), "11111111-1111-1111-1111-11111111111A".into(), DEVICE_ID.into(), sk.clone(), d.clone(), vec![], NOW), "Malformed");
    is(device_cert_issue(req, USER_ID.into(), DEVICE_ID.into(), sk, d, vec![0; 513], NOW), "Malformed");
}

#[test]
fn device_signature_roundtrip() {
    let dseed = h32("device-seed").to_vec();
    let keys = device_public_keys(dseed.clone()).unwrap();
    let sig = device_sign(dseed, "sync".into(), b"hello".to_vec()).unwrap();
    assert!(device_verify(keys.clone(), "sync".into(), b"hello".to_vec(), sig.clone()));
    assert!(!device_verify(keys.clone(), "other".into(), b"hello".to_vec(), sig.clone()));
    let mut bad = sig;
    bad[10] ^= 1;
    assert!(!device_verify(keys, "sync".into(), b"hello".to_vec(), bad));
    let ek = device_encryption_keys(h32("device-seed").to_vec()).unwrap();
    assert_eq!(p::x25519_public_key(ek.x25519_private).unwrap(), device_public_keys(h32("device-seed").to_vec()).unwrap().x25519);
}

// ---------------------------------------------------------------------------
// Package
// ---------------------------------------------------------------------------

fn send_package(pr: &Pair, history: bool, recs: &[PackageRecord]) -> Vec<LinkBlob> {
    let mut out = vec![pr.ph.package_begin(history).unwrap()];
    for r in recs {
        out.extend(pr.ph.package_add(r.section, r.id.clone(), r.body.clone()).unwrap());
    }
    out.extend(pr.ph.package_finish().unwrap());
    out
}

#[test]
fn package_rejects_video_large_files_and_unrequested_history() {
    let pr = established("");
    pr.ph.package_begin(false).unwrap();
    is(pr.ph.package_add(SECTION_MESSAGE_TEXT, b"m".to_vec(), b"hi".to_vec()), "Malformed");
    let pr = established("");
    pr.ph.package_begin(true).unwrap();
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypmp42");
    mp4.extend(vec![0u8; 100]);
    is(pr.ph.package_add(SECTION_MESSAGE_PHOTO, b"v".to_vec(), mp4), "Malformed");
    let mut heics = vec![0, 0, 0, 0x20];
    heics.extend_from_slice(b"ftypmsf1");
    heics.extend(vec![0u8; 100]);
    is(pr.ph.package_add(SECTION_MESSAGE_PHOTO, b"v".to_vec(), heics), "Malformed");
    is(pr.ph.package_add(SECTION_MESSAGE_PHOTO, b"p".to_vec(), jpeg(PHOTO_MAX)), "Malformed");
    is(pr.ph.package_add(99, b"x".to_vec(), vec![]), "Malformed");
    pr.ph.package_add(SECTION_PROFILE, vec![], b"{}".to_vec()).unwrap();
    is(pr.ph.package_add(SECTION_PROFILE, vec![], b"{}".to_vec()), "Malformed");
}

#[test]
fn package_tamper_reorder_truncate() {
    let recs = package_records();
    // Corrupted part.
    let pr = established("");
    let mut blobs = send_package(&pr, true, &recs);
    blobs[2].data[5] ^= 1;
    let mut err = None;
    for b in blobs {
        if let Err(e) = pr.pc.package_receive(b) {
            err = Some(format!("{e:?}"));
            break;
        }
    }
    assert!(err.unwrap().starts_with("Mismatch"));
    assert_eq!(pr.pc.state(), LinkState::Closed);
    // Reordered parts.
    let pr = established("");
    let mut blobs = send_package(&pr, true, &recs);
    blobs.swap(1, 2);
    pr.pc.package_receive(blobs[0].clone()).unwrap();
    is(pr.pc.package_receive(blobs[1].clone()), "Mismatch");
    // Cut off: END never arrived — done is never true, no ACK is issued.
    let pr = established("");
    let blobs = send_package(&pr, true, &recs);
    let mut last = None;
    for b in &blobs[..blobs.len() - 1] {
        last = Some(pr.pc.package_receive(b.clone()).unwrap());
    }
    assert!(!last.unwrap().done);
    is(pr.pc.package_ack(), "State");
    // Replayed part — REPLAY, reception continues.
    let pr = established("");
    let blobs = send_package(&pr, true, &recs);
    pr.pc.package_receive(blobs[0].clone()).unwrap();
    pr.pc.package_receive(blobs[1].clone()).unwrap();
    is(pr.pc.package_receive(blobs[1].clone()), "Replay");
    is(pr.pc.package_receive(blobs[0].clone()), "Replay");
    let mut done = false;
    for b in &blobs[2..] {
        done = pr.pc.package_receive(b.clone()).unwrap().done;
    }
    assert!(done);
    // No header.
    let pr = established("");
    let blobs = send_package(&pr, false, &recs[..3]);
    is(pr.pc.package_receive(blobs[1].clone()), "Mismatch");
}

#[test]
fn package_budget_is_enforced() {
    let pr = established("");
    pr.ph.package_begin(true).unwrap();
    let photo = jpeg(PHOTO_MAX - 64);
    let mut n = 0;
    let err = loop {
        match pr.ph.package_add(SECTION_MESSAGE_PHOTO, vec![b'p', n], photo.clone()) {
            Ok(_) => n += 1,
            Err(e) => break e,
        }
    };
    assert_eq!(n, 3, "63 MiB budget holds three 16 MiB photos");
    assert!(format!("{err:?}").contains("budget"));
    // From here on — by blob reference.
    pr.ph.package_add(SECTION_PHOTO_BLOB_REF, b"p9".to_vec(), b"{\"blob\":\"id\",\"key\":\"k\"}".to_vec()).unwrap();
    assert!(link_is_still_image(jpeg(10)));
    assert!(!link_is_still_image(b"\0\0\0\x20ftypisom\0\0\0\0".to_vec()));
}

#[test]
fn package_reader_rejects_crafted_streams() {
    // The reader on its own (the writer would never let this through): video posing as a photo, history without
    // the flag, cut off mid-record, bogus checksum, huge declared length.
    let (mut rd, _) = PackageReader::begin(&{
        let (_, h) = PackageWriter::begin([7; 16], false);
        h
    })
    .unwrap();
    let mut rec = vec![SECTION_MESSAGE_TEXT, 0, 1, b'm', 0, 0, 0, 2, b'h', b'i'];
    let mut part = 0u32.to_be_bytes().to_vec();
    part.append(&mut rec);
    is(rd.part(&part), "Malformed");

    let (mut rd, _) = PackageReader::begin(&PackageWriter::begin([7; 16], true).1).unwrap();
    let mut part = 0u32.to_be_bytes().to_vec();
    part.extend([SECTION_MESSAGE_PHOTO, 0, 1, b'v', 0xFF, 0xFF, 0xFF, 0xFF]);
    is(rd.part(&part), "Malformed");

    let (mut rd, _) = PackageReader::begin(&PackageWriter::begin([7; 16], true).1).unwrap();
    let mut part = 0u32.to_be_bytes().to_vec();
    part.extend([SECTION_CONTACT, 0, 1, b'c', 0, 0, 0, 10, 1, 2]);
    assert!(rd.part(&part).unwrap().records.is_empty());
    let mut end = 1u32.to_be_bytes().to_vec();
    end.extend(0u64.to_be_bytes());
    end.extend(10u64.to_be_bytes());
    end.extend([0u8; 32]);
    is(rd.end(&end), "Mismatch");
}

#[test]
fn package_with_many_parts_and_big_photos() {
    let pr = established("");
    let mut recs = vec![PackageRecord { section: SECTION_PROFILE, id: vec![], body: b"{}".to_vec() }];
    for i in 0..5u8 {
        recs.push(PackageRecord { section: SECTION_MESSAGE_PHOTO, id: vec![b'p', i], body: jpeg(700 * 1024 + i as usize) });
        recs.push(PackageRecord { section: SECTION_MESSAGE_TEXT, id: vec![b't', i], body: vec![b'a'; 1000] });
    }
    let blobs = send_package(&pr, true, &recs);
    assert!(blobs.len() >= 6, "split into parts: {}", blobs.len());
    assert!(blobs.iter().all(|b| b.data.len() < 1024 * 1024), "every blob fits the relay limit");
    let mut got = Vec::new();
    let mut last = None;
    for b in blobs {
        let pg = pr.pc.package_receive(b).unwrap();
        got.extend(pg.records.clone());
        last = Some(pg);
    }
    let last = last.unwrap();
    assert!(last.done && last.include_history);
    assert_eq!(got, recs);
    let ack = pr.pc.package_ack().unwrap();
    pr.ph.package_check_ack(ack).unwrap();
}

// ---------------------------------------------------------------------------
// Communities
// ---------------------------------------------------------------------------

#[test]
fn comm_vault_root_matches_communities_vectors() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../communities/pqc/testdata/pq-vectors.json");
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vault = &v["vault"];
    let xp = hex::decode(vault["x25519_priv"].as_str().unwrap()).unwrap();
    let ks = hex::decode(vault["mlkem_seed"].as_str().unwrap()).unwrap();
    let roots = comm_vault_roots(xp.clone(), ks.clone()).unwrap();
    let legacy = comm_vault_legacy_keys(roots.v2.clone()).unwrap();
    assert_eq!(hx(&legacy.id), vault["id"].as_str().unwrap());
    assert_eq!(hx(&legacy.auth_seed), vault["auth_seed"].as_str().unwrap());
    assert_eq!(hx(&legacy.enc_key), vault["enc_key"].as_str().unwrap());
    // Epoch: same as CommCrypto.vaultKeysEpoch = HKDF(IKM, "umbera-comm-vault-v3", "vault-id/<e>").
    let ikm = [xp, ks].concat();
    for e in [0u32, 10, 33] {
        let k = comm_vault_epoch_keys(roots.v3.clone(), e).unwrap();
        let full = |info: &str| p::hkdf_sha256(ikm.clone(), b"umbera-comm-vault-v3".to_vec(), info.as_bytes().to_vec(), 32).unwrap();
        assert_eq!(k.id, full(&format!("vault-id/{e}")));
        assert_eq!(k.auth_seed, full(&format!("vault-auth/{e}")));
        assert_eq!(k.enc_key, full(&format!("vault-key/{e}")));
    }
    let body = comm_vault_record_body(roots.clone()).unwrap();
    assert_eq!(comm_vault_record_parse(body).unwrap(), roots);
    is(comm_vault_epoch_keys(vec![0; 31], 1), "Crypto");
}

// ---------------------------------------------------------------------------
// MLS: the desktop is a separate leaf
// ---------------------------------------------------------------------------

#[test]
fn desktop_joins_mls_group_as_its_own_leaf() {
    let gid = b"group-desktop-link-0001".to_vec();
    let phone_mid = h32("phone-member").to_vec();
    let bob_mid = h32("bob-member").to_vec();
    let pc_mid = h32("pc-member").to_vec();
    let phone = MlsClient::new(phone_mid.clone()).unwrap();
    let bob = MlsClient::new(bob_mid.clone()).unwrap();
    phone.create_group(gid.clone()).unwrap();
    let b = phone.add_members(gid.clone(), vec![bob.generate_key_package().unwrap()]).unwrap();
    bob.process_welcome(b.welcome).unwrap();

    // Over the link: phone → desktop join requests, desktop → phone join offers.
    let pr = established("");
    let reqs = vec![MlsJoinRequest { gid: gid.clone(), primary_member_id: phone_mid.clone() }];
    let blob = pr.ph.seal(KIND_MLS_JOIN_REQUESTS, mls_join_requests_encode(reqs).unwrap()).unwrap();
    let got_reqs = mls_join_requests_decode(pr.pc.open(blob).unwrap()).unwrap();
    let pc = MlsClient::new(pc_mid.clone()).unwrap();
    let offers: Vec<MlsJoinOffer> = got_reqs
        .iter()
        .map(|r| MlsJoinOffer {
            gid: r.gid.clone(),
            device_member_id: pc_mid.clone(),
            key_package: pc.generate_key_package().unwrap(),
            device_sibling_sig: pc.sibling_sign(r.gid.clone(), r.primary_member_id.clone(), pc_mid.clone()).unwrap(),
        })
        .collect();
    let blob = pr.pc.seal(KIND_MLS_JOIN_OFFERS, mls_join_offers_encode(offers).unwrap()).unwrap();
    let offers = mls_join_offers_decode(pr.ph.open(blob).unwrap()).unwrap();
    let offer = offers[0].clone();
    assert!(mls_sibling_verify_key_package(phone_mid.clone(), offer.clone()));
    // A signature for someone else's leaf or for another group does not verify.
    let mut wrong = offer.clone();
    wrong.gid = b"another-group".to_vec();
    assert!(!mls_sibling_verify_key_package(phone_mid.clone(), wrong));
    let mut wrong = offer.clone();
    wrong.device_member_id = bob_mid.clone();
    assert!(!mls_sibling_verify_key_package(phone_mid.clone(), wrong));

    let primary_sig = phone.sibling_sign(gid.clone(), phone_mid.clone(), pc_mid.clone()).unwrap();
    let add = phone.add_members(gid.clone(), vec![offer.key_package.clone()]).unwrap();
    // Welcome goes into the package (id = the desktop's memberId).
    let header = pr.ph.package_begin(false).unwrap();
    let mut blobs = vec![header];
    blobs.extend(pr.ph.package_add(SECTION_MLS_WELCOME, pc_mid.clone(), add.welcome.clone()).unwrap());
    blobs.extend(pr.ph.package_finish().unwrap());
    let mut recs = Vec::new();
    for b in blobs {
        recs.extend(pr.pc.package_receive(b).unwrap().records);
    }
    assert_eq!(recs[0].id, pc_mid);
    assert_eq!(pc.process_welcome(recs[0].body.clone()).unwrap(), gid);
    assert!(matches!(bob.process_incoming(gid.clone(), add.commit).unwrap(), crate::Incoming::CommitApplied));

    // Three distinct leaves, none a copy of another.
    let mem = bob.members(gid.clone()).unwrap();
    assert_eq!(mem.len(), 3);
    assert_ne!(phone.signature_public_key(), pc.signature_public_key());
    // Any member verifies the link against the leaf keys in the tree.
    assert!(bob.sibling_verify(gid.clone(), phone_mid.clone(), pc_mid.clone(), primary_sig.clone(), offer.device_sibling_sig.clone()).unwrap());
    assert!(pc.sibling_verify(gid.clone(), phone_mid.clone(), pc_mid.clone(), primary_sig.clone(), offer.device_sibling_sig.clone()).unwrap());
    // Bob cannot pose as the "phone's device": his leaf did not sign.
    let bob_sig = bob.sibling_sign(gid.clone(), phone_mid.clone(), bob_mid.clone()).unwrap();
    assert!(!bob.sibling_verify(gid.clone(), phone_mid.clone(), bob_mid.clone(), primary_sig.clone(), bob_sig).unwrap());
    // Swapped signatures — rejected.
    assert!(!bob.sibling_verify(gid.clone(), phone_mid.clone(), pc_mid.clone(), offer.device_sibling_sig.clone(), primary_sig.clone()).unwrap());
    // The desktop's message is decrypted by the phone and Bob; the sender is the desktop leaf.
    let ct = pc.encrypt(gid.clone(), b"from desktop".to_vec()).unwrap();
    match phone.process_incoming(gid.clone(), ct).unwrap() {
        crate::Incoming::Application { plaintext, sender_identity } => {
            assert_eq!(plaintext, b"from desktop");
            assert_eq!(sender_identity, pc_mid);
        }
        _ => panic!("expected application"),
    }
    // Only one of the two leaves can sign the link.
    assert!(bob.sibling_sign(gid, phone_mid, pc_mid).is_err());
}
