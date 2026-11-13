// A short/garbage X-Wing key is an error, not an application crash (RUSTSEC-2026-0331).
//
// libcrux-kem 0.0.9 panics in `XWingKemDraft06PublicKey::decode` on a public key shorter than 1184 bytes
// (slice `bytes[0..1184]`). Upgrading to 0.0.10 is not possible: openmls_libcrux_crypto 0.4.0 (latest) pins
// hpke-rs-libcrux =0.7.0 → libcrux-kem =0.0.9. So the core provider (src/provider.rs) checks lengths before
// calling libcrux and catches the panic. Here:
//  1. the provider returns an error and does not panic for any key/encapsulation/private-key length;
//  2. the real attack path: a foreign X-Wing KeyPackage with a short init_key, CORRECTLY signed by its author
//     (passes KeyPackageIn::validate) — add_members returns an error and the group stays alive (the core's
//     Mutex is not poisoned: new members can be added, messages flow);
//  3. correct lengths work as before (wire format unchanged) — same provider, a regular group.

use std::panic::{catch_unwind, AssertUnwindSafe};

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    signatures::Signer,
    types::{HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType, HpkeKemType},
    OpenMlsProvider,
};
use tls_codec::{Deserialize as _, Serialize as _, VLBytes};
use umbera_core::provider::{UmberaProvider, XWING_SUITE};
use umbera_core::{mls_suite_xwing, Incoming, MlsClient};

fn xw() -> HpkeConfig {
    HpkeConfig(HpkeKemType::XWingKemDraft6, HpkeKdfType::HkdfSha256, HpkeAeadType::ChaCha20Poly1305)
}

const BAD_PK_LENS: [usize; 9] = [0, 1, 32, 100, 1183, 1184, 1215, 1217, 4096];

#[test]
fn provider_rejects_bad_xwing_lengths_without_panic() {
    let p = UmberaProvider::default();
    let c = p.crypto();
    for len in BAD_PK_LENS {
        let pk = vec![0x5a; len];
        let r = catch_unwind(AssertUnwindSafe(|| c.hpke_seal(xw(), &pk, b"info", b"aad", b"hello")));
        assert!(matches!(r, Ok(Err(_))), "hpke_seal pk {len}: panic or success");
        let r = catch_unwind(AssertUnwindSafe(|| c.hpke_setup_sender_and_export(xw(), &pk, b"info", b"ctx", 32)));
        assert!(matches!(r, Ok(Err(_))), "setup_sender pk {len}: panic or success");
    }
    // Encapsulation and private key of the wrong length (libcrux rejects these anyway, but the check happens before the call).
    let kp = c.derive_hpke_keypair(xw(), &[7u8; 32]).unwrap();
    assert_eq!(kp.public.len(), 1216);
    assert_eq!(kp.private.len(), 32);
    for enc_len in [0usize, 1, 1119, 1121] {
        let ct = HpkeCiphertext { kem_output: vec![1u8; enc_len].into(), ciphertext: vec![2u8; 32].into() };
        let r = catch_unwind(AssertUnwindSafe(|| c.hpke_open(xw(), &ct, &kp.private[..], b"i", b"a")));
        assert!(matches!(r, Ok(Err(_))), "hpke_open enc {enc_len}");
        let r = catch_unwind(AssertUnwindSafe(|| {
            c.hpke_setup_receiver_and_export(xw(), &vec![1u8; enc_len], &kp.private[..], b"i", b"c", 32)
        }));
        assert!(matches!(r, Ok(Err(_))), "setup_receiver enc {enc_len}");
    }
    for sk_len in [0usize, 31, 33, 2400] {
        let sealed = c.hpke_seal(xw(), &kp.public, b"i", b"a", b"x").unwrap();
        let r = catch_unwind(AssertUnwindSafe(|| c.hpke_open(xw(), &sealed, &vec![3u8; sk_len], b"i", b"a")));
        assert!(matches!(r, Ok(Err(_))), "hpke_open sk {sk_len}");
    }
    // Correct lengths — as before.
    let sealed = c.hpke_seal(xw(), &kp.public, b"i", b"a", b"hello").unwrap();
    assert_eq!(sealed.kem_output.as_slice().len(), 1120);
    assert_eq!(c.hpke_open(xw(), &sealed, &kp.private[..], b"i", b"a").unwrap(), b"hello");
    let (enc, s1) = c.hpke_setup_sender_and_export(xw(), &kp.public, b"i", b"c", 32).unwrap();
    let s2 = c.hpke_setup_receiver_and_export(xw(), &enc, &kp.private[..], b"i", b"c", 32).unwrap();
    assert_eq!(&s1[..], &s2[..]);
}

/// Without the guard (bare libcrux provider) — the very panic; the test only records that the guard is needed,
/// and will show when libcrux is fixed (then there is no panic — the guard can stay, it does no harm).
#[test]
fn bare_libcrux_still_panics_on_short_key() {
    let lc = openmls_libcrux_crypto::CryptoProvider::new().unwrap();
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(|| lc.hpke_seal(xw(), &[0u8; 100], b"i", b"a", b"x")));
    std::panic::set_hook(prev);
    eprintln!("libcrux-kem without guard on a 100-byte key: {}", if r.is_err() { "PANIC (guard needed)" } else { "error (fixed upstream)" });
}

/// X-Wing key package with an init_key of length `init_len`, honestly signed with its own key (passes validate).
fn forged_key_package(init_len: usize) -> Vec<u8> {
    let provider = UmberaProvider::default();
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    let cwk = CredentialWithKey {
        credential: BasicCredential::new(b"mallory".to_vec()).into(),
        signature_key: signer.public().into(),
    };
    let bundle = KeyPackage::builder().build(XWING_SUITE, &provider, &signer, cwk).unwrap();
    let raw = bundle.key_package().tls_serialize_detached().unwrap();
    // KeyPackage = version(2) ‖ suite(2) ‖ init_key<V> ‖ leaf_node ‖ extensions ‖ signature<V>.
    let mut rest = &raw[4..];
    let init = VLBytes::tls_deserialize(&mut rest).unwrap();
    assert_eq!(init.as_slice().len(), 1216);
    let sig_len = 66; // Ed25519: 64 bytes + 2-byte varint length
    let middle = &rest[..rest.len() - sig_len];
    let mut tbs = raw[..4].to_vec();
    // Length 1216 is the original (genuine) key: a control that the forgery itself works.
    let init_bytes = if init_len == 1216 { init.as_slice().to_vec() } else { vec![0xab; init_len] };
    tbs.extend(VLBytes::new(init_bytes).tls_serialize_detached().unwrap());
    tbs.extend_from_slice(middle);
    // SignWithLabel(…, "KeyPackageTBS", tbs) — RFC 9420 §5.1.2.
    let mut content = VLBytes::new(b"MLS 1.0 KeyPackageTBS".to_vec()).tls_serialize_detached().unwrap();
    content.extend(VLBytes::new(tbs.clone()).tls_serialize_detached().unwrap());
    let sig = signer.sign(&content).unwrap();
    let mut out = tbs;
    out.extend(VLBytes::new(sig).tls_serialize_detached().unwrap());
    out
}

#[test]
fn short_init_key_in_foreign_key_package_is_an_error_not_a_crash() {
    let xwing = mls_suite_xwing();
    let gid = b"short-key-group-0000000000000000".to_vec();
    let alice = MlsClient::new(b"alice".to_vec()).unwrap();
    alice.create_group_for(gid.clone(), xwing).unwrap();

    for init_len in [0usize, 1, 100, 1183, 1215] {
        let forged = forged_key_package(init_len);
        // The signature is honest — parsing and validation pass (or openmls rejects it itself — also not a crash).
        let info = catch_unwind(AssertUnwindSafe(|| umbera_core::key_package_info(forged.clone())));
        assert!(info.is_ok(), "key_package_info init {init_len}: panic");
        let r = catch_unwind(AssertUnwindSafe(|| alice.add_members(gid.clone(), vec![forged.clone()])));
        match r {
            Ok(Err(_)) => {}
            Ok(Ok(_)) => panic!("add_members init {init_len}: short key accepted"),
            Err(_) => panic!("add_members init {init_len}: PANIC"),
        }
        if init_len == 100 {
            assert!(info.unwrap().is_ok(), "the forgery must pass validate, otherwise the test never reaches libcrux");
        }
    }

    // The group is alive: the epoch did not move, an honest member can be added, messages flow.
    assert_eq!(alice.epoch(gid.clone()).unwrap(), 0);
    let bob = MlsClient::new(b"bob".to_vec()).unwrap();
    let bundle = alice.add_members(gid.clone(), vec![bob.generate_key_package_for(xwing).unwrap()]).unwrap();
    assert_eq!(bob.process_welcome(bundle.welcome).unwrap(), gid);
    let ct = alice.encrypt(gid.clone(), b"still alive".to_vec()).unwrap();
    match bob.process_incoming(gid.clone(), ct).unwrap() {
        Incoming::Application { plaintext, .. } => assert_eq!(plaintext, b"still alive"),
        _ => panic!("expected an application message"),
    }
    // A key package of the correct length built by the same forgery passes — so the rejection above is due to length.
    let ok = forged_key_package(1216);
    assert!(alice.add_members(gid.clone(), vec![ok]).is_ok());
}
