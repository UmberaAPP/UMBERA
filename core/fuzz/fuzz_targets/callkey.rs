#![no_main]
// Second call-key layer (ML-KEM-1024 per frame): offer / answer arrive from the peer in call signalling.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use umbera_core::callkey::{call_pq_finish, call_pq_keypair, call_pq_respond, CALL_PQ_BLOB_LEN};

static KP: OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>)> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let (public, secret, answer) = KP.get_or_init(|| {
        let kp = call_pq_keypair();
        let r = call_pq_respond("fuzz-call".into(), kp.public.clone()).unwrap();
        (kp.public, kp.secret, r.answer)
    });
    let Some((&mode, rest)) = data.split_first() else { return };
    // Blobs of the right length, to pass the length/version check and reach the cryptography itself.
    let sized = |src: &[u8]| -> Vec<u8> {
        let mut v = src.to_vec();
        for (i, b) in rest.iter().enumerate() {
            let j = i % CALL_PQ_BLOB_LEN;
            if j != 0 {
                v[j] ^= *b;
            }
        }
        v
    };
    let id = String::from_utf8_lossy(&rest[..rest.len().min(40)]).into_owned();
    match mode % 4 {
        0 => {
            let _ = call_pq_respond(id, rest.to_vec());
        }
        1 => {
            let _ = call_pq_respond("fuzz-call".into(), sized(public));
        }
        2 => {
            let _ = call_pq_finish("fuzz-call".into(), secret.clone(), public.clone(), sized(answer));
        }
        _ => {
            let _ = call_pq_finish(id, rest.to_vec(), public.clone(), rest.to_vec());
        }
    }
});
