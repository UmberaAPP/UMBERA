#![no_main]
// Welcome / KeyPackage / persisted state from untrusted bytes. A Welcome comes from anyone
// who knows our KeyPackage — no function may panic (a panic in the .so = a crash on the phone).
// Input: the first byte is the mode, then either raw bytes or edits on top of a real Welcome (structured fuzzing:
// random bytes almost never get past the TLS codec parser, edits reach deep).
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use umbera_core::{key_package_info, mls_suite_legacy, mls_suite_xwing, MlsClient};

struct Base {
    joiner_state: Vec<u8>, // recipient state BEFORE joining: every attempt starts from a clean slate
    welcome: Vec<u8>,
    key_package: Vec<u8>,
}

fn base(suite: u16) -> Base {
    let a = MlsClient::new(b"alice".to_vec()).unwrap();
    let b = MlsClient::new(b"bob".to_vec()).unwrap();
    let kp = b.generate_key_package_for(suite).unwrap();
    let joiner_state = b.export_state().unwrap();
    a.create_group_for(b"fuzz-group".to_vec(), suite).unwrap();
    let bundle = a.add_members(b"fuzz-group".to_vec(), vec![kp.clone()]).unwrap();
    Base { joiner_state, welcome: bundle.welcome, key_package: kp }
}

static BASES: OnceLock<[Base; 2]> = OnceLock::new();

/// Edits on top of a sample: triples (u16 offset, byte); the top 2 bits of the byte select the edit kind.
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

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else { return };
    let bases = BASES.get_or_init(|| [base(mls_suite_legacy()), base(mls_suite_xwing())]);
    let b = &bases[(mode & 1) as usize];
    match (mode >> 1) % 4 {
        0 => {
            let joiner = MlsClient::from_state(b.joiner_state.clone()).unwrap();
            let _ = joiner.process_welcome(rest.to_vec());
        }
        1 => {
            let joiner = MlsClient::from_state(b.joiner_state.clone()).unwrap();
            let _ = joiner.process_welcome(mutate(&b.welcome, rest));
        }
        2 => {
            let _ = key_package_info(rest.to_vec());
            let _ = key_package_info(mutate(&b.key_package, rest));
        }
        _ => {
            // On-disk state is untrusted too (corruption, file substitution).
            let _ = MlsClient::from_state(rest.to_vec());
            let _ = MlsClient::from_state(mutate(&b.joiner_state, rest));
        }
    }
});
