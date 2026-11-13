//! Known-answer test (KAT) for the 1:1 v3 / v3s envelope and the v2 file key — an implementation of the
//! protocol formulas independent of Kotlin (sha2 + hkdf directly, not via primitives). Not part of the library: only
//! a test that pins Kotlin `SealV3Test.katMatchesRust` byte for byte.
#![cfg(test)]

use sha2::{Digest, Sha256};

fn part(h: &mut Sha256, x: &[u8]) {
    h.update((x.len() as u32).to_be_bytes());
    h.update(x);
}

fn th(label: &str, parts: &[&[u8]]) -> Vec<u8> {
    let mut h = Sha256::new();
    part(&mut h, label.as_bytes());
    for p in parts {
        part(&mut h, p);
    }
    h.finalize().to_vec()
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &str, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    hkdf::Hkdf::<Sha256>::new(Some(salt), ikm).expand(info.as_bytes(), &mut out).unwrap();
    out
}

#[test]
fn kat_matches_kotlin() {
    let eph: Vec<u8> = (0..32).map(|i| (i + 1) as u8).collect();
    let ct: Vec<u8> = (0..1568usize).map(|i| (i * 7 + 3) as u8).collect();
    let rx: Vec<u8> = (0..32).map(|i| (0x40 + i) as u8).collect();
    let rek: Vec<u8> = (0..1568usize).map(|i| (i * 13 + 5) as u8).collect();
    let ss_x: Vec<u8> = (0..32).map(|i| (0x80 + i) as u8).collect();
    let ss_k: Vec<u8> = (0..32).map(|i| (0xC0 + i) as u8).collect();
    let ikm = [ss_x.as_slice(), ss_k.as_slice()].concat();

    let t = th("umbera-seal-v3/transcript", &[&eph, &ct, &rx, &rek]);
    let okm = hkdf(&ikm, &t, "typex-hybrid-v2/seal", 64);
    let pair = hkdf(&ikm, &t, "typex-hybrid-v2/seal-pair", 32);
    let pair_id = hkdf(&pair, &[], "umbera-seal-v3/pair-id", 8);
    let mk0 = hkdf(&pair, &[], "umbera-seal-v3s/mk", 32);
    let ck1 = hkdf(&pair, &[], "umbera-seal-v3s/ck", 32);
    let hint0 = hkdf(&mk0, &[], "umbera-seal-v3s/hint", 8);
    let ts = th("umbera-seal-v3s/transcript", &[&eph, &rx, &rek, &hint0]);
    let short0 = hkdf(&[ss_x.as_slice(), mk0.as_slice()].concat(), &ts, "typex-hybrid-v2/seal-short", 32);
    let tf = th("umbera-filewrap-v2/transcript", &[&eph, &ct, &rx, &rek]);
    let file = hkdf(&ikm, &tf, "typex-hybrid-v2/file", 32);
    // Direction secret and v2 mailbox address.
    let dir = hkdf(&ikm, &t, "umbera-rendezvous-v2/dir", 32);
    let rid2 = hkdf(&[ss_x.as_slice(), dir.as_slice()].concat(), b"umbera-rendezvous-v2", "rdv|alice|bob", 32);
    // Address rotation: address for epoch 2915 and the own-copy address in the same epoch (copy input — ss_X ‖ ss_K).
    let rid2e = hkdf(&[ss_x.as_slice(), dir.as_slice()].concat(), b"umbera-rendezvous-v2", "rdv-e|alice|bob|2915", 32);
    let self_e = hkdf(&ikm, b"umbera-rendezvous-v2", "rdv-backup-e|alice|bob|2915", 32);
    // Static path hybrid-pq-v3 (eph acting as the sender's static X25519).
    let tst = th("umbera-hybrid-static-v3/transcript", &[&eph, &ct, &rx, &rek]);
    let st = hkdf(&ikm, &tst, "typex-hybrid-v2/static", 64);

    let got = [
        ("TH", hex::encode(&t)), ("OKM", hex::encode(&okm)), ("PAIR", hex::encode(&pair)), ("PAIR_ID", hex::encode(&pair_id)),
        ("MK0", hex::encode(&mk0)), ("CK1", hex::encode(&ck1)), ("HINT0", hex::encode(&hint0)), ("SHORT0", hex::encode(&short0)),
        ("FILE", hex::encode(&file)), ("DIR", hex::encode(&dir)), ("RID2", hex::encode(&rid2)),
        ("RID2E", hex::encode(&rid2e)), ("SELF_E", hex::encode(&self_e)),
        ("STATIC_TH", hex::encode(&tst)), ("STATIC_OKM", hex::encode(&st)),
    ];
    for (k, v) in &got {
        println!("KAT_{k} = \"{v}\"");
    }
    let want = include_str!("../tests/vectors/seal-v3-vectors.txt");
    for (k, v) in &got {
        let line = format!("KAT_{k} = \"{v}\"");
        assert!(want.lines().any(|l| l.trim() == line), "{line} does not match tests/vectors/seal-v3-vectors.txt");
    }
}

/// Device address epochs: recipient address secret R = HKDF(ML-KEM seed, "umbera-dv1/rx", "dv-rx|from|to")
/// and the device-pair address in epoch 2915 = HKDF(ss_X ‖ R, "umbera-dv1/rid-e", "rdv-e|from|to|2915") — Kotlin DeviceRidEpochs.
#[test]
fn kat_device_epochs_match_kotlin() {
    let ss_x: Vec<u8> = (0..32).map(|i| (0x80 + i) as u8).collect();
    let seed: Vec<u8> = (0..32).map(|i| (0xC0 + i) as u8).collect();
    let r = hkdf(&seed, b"umbera-dv1/rx", "dv-rx|alice/primary|bob/pc1", 32);
    let ride = hkdf(&[ss_x.as_slice(), r.as_slice()].concat(), b"umbera-dv1/rid-e", "rdv-e|alice/primary|bob/pc1|2915", 32);
    let got = [("DV_RX", hex::encode(&r)), ("DV_RIDE", hex::encode(&ride))];
    for (k, v) in &got {
        println!("KAT_{k} = \"{v}\"");
    }
    let want = include_str!("../tests/vectors/seal-v3-vectors.txt");
    for (k, v) in &got {
        let line = format!("KAT_{k} = \"{v}\"");
        assert!(want.lines().any(|l| l.trim() == line), "{line} does not match tests/vectors/seal-v3-vectors.txt");
    }
}
