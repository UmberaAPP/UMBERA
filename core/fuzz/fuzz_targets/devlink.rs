#![no_main]
// Desktop ↔ phone QR linking: everything that arrives via the relay or from the QR is untrusted.
// Each iteration uses a fresh pair of sessions (any mismatch destroys the session, as intended).
// Modes: QR text; OFFER / ACCEPT / CONFIRM with mutations on top of real ones; encrypted blobs with mutations;
// and PLAINTEXT under real encryption (malicious linked phone/desktop): device request,
// certificate, history package: the parsers behind AEAD. Plus standalone devlink parsers without a session.
use libfuzzer_sys::fuzz_target;
use std::time::{SystemTime, UNIX_EPOCH};
use umbera_core::devlink::cert::{device_cert_verify, device_label_open, device_seed_generate, DEVICE_TYPE_DESKTOP};
use umbera_core::devlink::comm::comm_vault_record_parse;
use umbera_core::devlink::mlsjoin::{mls_join_offers_decode, mls_join_requests_decode};
use umbera_core::devlink::package::link_is_still_image;
use umbera_core::devlink::session::*;

fn mutate(src: &[u8], edits: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    for ch in edits.chunks_exact(3) {
        if v.is_empty() {
            break;
        }
        let i = u16::from_le_bytes([ch[0], ch[1]]) as usize % v.len();
        match ch[2] >> 6 {
            0 => v[i] ^= ch[2] | 1,
            1 => v.truncate(i.max(1)),
            2 => v.insert(i, ch[2]),
            _ => {
                v.remove(i);
            }
        }
    }
    v
}

fn mblob(b: &LinkBlob, edits: &[u8]) -> LinkBlob {
    let (kind, seq) = match edits.first() {
        Some(&x) if x & 0x80 != 0 => (x & 0x7f, b.seq ^ (x as u64 & 3)),
        _ => (b.kind, b.seq),
    };
    LinkBlob { kind, seq, data: mutate(&b.data, edits.get(1..).unwrap_or(&[])) }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let t = now();
    let m = mode % 12;
    if m == 0 {
        let _ = LinkSession::phone(String::from_utf8_lossy(rest).into_owned(), t);
        return;
    }
    if m == 1 {
        let _ = comm_vault_record_parse(rest.to_vec());
        let _ = mls_join_requests_decode(rest.to_vec());
        let _ = mls_join_offers_decode(rest.to_vec());
        let _ = device_cert_verify(rest.to_vec(), "fuzz".into());
        let _ = link_is_still_image(rest.to_vec());
        let _ = device_label_open(vec![7; 32], "22222222-2222-2222-2222-222222222222".into(), rest.to_vec());
        return;
    }
    let pc = LinkSession::desktop(vec![9; 16], "https://umbera.app".into(), t).unwrap();
    let qr = pc.qr_text().unwrap();
    if m == 2 {
        let _ = LinkSession::phone(String::from_utf8_lossy(&mutate(qr.as_bytes(), rest)).into_owned(), t);
        return;
    }
    let ph = LinkSession::phone(qr, t).unwrap();
    let offer = pc.offer().unwrap();
    if m == 3 {
        let _ = ph.phone_accept(mblob(&offer, rest), t);
        return;
    }
    let accept = ph.phone_accept(offer, t).unwrap();
    if m == 4 {
        let _ = pc.desktop_accept(mblob(&accept, rest), t);
        return;
    }
    let confirm = pc.desktop_accept(accept, t).unwrap();
    if m == 5 {
        let _ = ph.phone_confirm(mblob(&confirm, rest), t);
        return;
    }
    ph.phone_confirm(confirm, t).unwrap();
    let _ = pc.sas();
    pc.confirm_sas(t).unwrap();
    ph.confirm_sas(t).unwrap();
    match m {
        6 => {
            let b = ph.seal(KIND_DEVICE_CERT, b"certificate".to_vec()).unwrap();
            let _ = pc.open(mblob(&b, rest));
        }
        7 => {
            if rest.first().map_or(false, |b| b & 1 == 1) {
                // Device request with fuzzer-controlled fields (seed length, type, signature label).
                let seed = rest.get(1..65).map(|s| s.to_vec()).unwrap_or_else(device_seed_generate);
                let ty = rest.get(65).copied().unwrap_or(DEVICE_TYPE_DESKTOP);
                let label = String::from_utf8_lossy(rest.get(66..).unwrap_or(&[])).into_owned();
                if let Ok(req) = pc.device_request(seed, ty, label) {
                    let _ = ph.open_device_request(req);
                }
            } else {
                let req = pc.device_request(device_seed_generate(), DEVICE_TYPE_DESKTOP, "Linux".into()).unwrap();
                let _ = ph.open_device_request(mblob(&req, rest));
            }
        }
        8 => {
            // Plaintext under real encryption: the parsers behind AEAD (malicious linked phone).
            let kind = [KIND_DEVICE_CERT, KIND_MLS_JOIN_REQUESTS, KIND_MLS_JOIN_OFFERS, KIND_ABORT]
                [rest.first().copied().unwrap_or(0) as usize % 4];
            if let Ok(b) = ph.seal(kind, rest.get(1..).unwrap_or(&[]).to_vec()) {
                if let Ok(pt) = pc.open(b) {
                    let _ = device_cert_verify(pt.clone(), "fuzz".into());
                    let _ = mls_join_requests_decode(pt.clone());
                    let _ = mls_join_offers_decode(pt);
                }
            }
        }
        9 | 10 => {
            // History package with fuzzer records: [section][id length][id][body…] separated by 0xA5.
            if let Ok(h) = ph.package_begin(m == 10) {
                let _ = pc.package_receive(h);
                for rec in rest.split(|&b| b == 0xA5) {
                    let (sec, r) = rec.split_first().unwrap_or((&0, &[]));
                    let (&idl, r) = r.split_first().unwrap_or((&0, &[]));
                    let idl = (idl as usize).min(r.len());
                    for b in ph.package_add(*sec, r[..idl].to_vec(), r[idl..].to_vec()).unwrap_or_default() {
                        let _ = pc.package_receive(b);
                    }
                }
                for b in ph.package_finish().unwrap_or_default() {
                    let _ = pc.package_receive(b);
                }
                if let Ok(ack) = pc.package_ack() {
                    let _ = ph.package_check_ack(ack);
                }
            }
        }
        _ => {
            // Real package, mutations in the encrypted blobs.
            if let Ok(h) = ph.package_begin(rest.first().map_or(false, |b| b & 1 == 1)) {
                let mut blobs = vec![h];
                blobs.extend(ph.package_add(1, b"id".to_vec(), b"body".to_vec()).unwrap_or_default());
                blobs.extend(ph.package_finish().unwrap_or_default());
                let target = rest.get(1).copied().unwrap_or(0) as usize % blobs.len();
                for (i, b) in blobs.iter().enumerate() {
                    let b = if i == target { mblob(b, rest.get(2..).unwrap_or(&[])) } else { b.clone() };
                    let _ = pc.package_receive(b);
                }
                if let Ok(ack) = pc.package_ack() {
                    let _ = ph.package_check_ack(mblob(&ack, rest));
                }
            }
        }
    }
});
