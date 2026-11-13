#![no_main]
// Commit / Proposal / group application message from untrusted bytes: process_incoming and process_incoming_with_sender
// on a member already in the group. Every attempt starts from the same persisted state, so that an (unexpectedly)
// accepted Commit does not advance the epoch and crashes stay reproducible.
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use umbera_core::{mls_suite_legacy, mls_suite_xwing, MlsClient};

const GID: &[u8] = b"fuzz-group";

struct Base {
    member_state: Vec<u8>,
    samples: Vec<Vec<u8>>, // [Commit (update), Commit (add), application, Commit (remove)]
}

fn base(suite: u16) -> Base {
    let a = MlsClient::new(b"alice".to_vec()).unwrap();
    let b = MlsClient::new(b"bob".to_vec()).unwrap();
    let c = MlsClient::new(b"carol".to_vec()).unwrap();
    a.create_group_for(GID.to_vec(), suite).unwrap();
    let kb = b.generate_key_package_for(suite).unwrap();
    let w = a.add_members(GID.to_vec(), vec![kb]).unwrap();
    b.process_welcome(w.welcome).unwrap();
    let member_state = b.export_state().unwrap();
    // Samples are Alice's next messages that Bob has not seen yet.
    let a2 = MlsClient::from_state(a.export_state().unwrap()).unwrap();
    let upd = a2.update_keys(GID.to_vec()).unwrap();
    let a3 = MlsClient::from_state(a.export_state().unwrap()).unwrap();
    let kc = c.generate_key_package_for(suite).unwrap();
    let add = a3.add_members(GID.to_vec(), vec![kc]).unwrap().commit;
    let a4 = MlsClient::from_state(a.export_state().unwrap()).unwrap();
    let app = a4.encrypt(GID.to_vec(), b"fuzz application message".to_vec()).unwrap();
    let a5 = MlsClient::from_state(a.export_state().unwrap()).unwrap();
    let rm = a5.remove_members(GID.to_vec(), vec![1]).unwrap();
    Base { member_state, samples: vec![upd, add, app, rm] }
}

static BASES: OnceLock<[Base; 2]> = OnceLock::new();

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
    let msg = match (mode >> 1) % 5 {
        4 => rest.to_vec(),
        k => mutate(&b.samples[k as usize], rest),
    };
    let m = MlsClient::from_state(b.member_state.clone()).unwrap();
    if mode & 0x80 == 0 {
        let _ = m.process_incoming(GID.to_vec(), msg);
    } else {
        let allowed = if mode & 0x40 == 0 { None } else { Some(vec![b"alice".to_vec()]) };
        let _ = m.process_incoming_with_sender(GID.to_vec(), msg, allowed);
    }
    let _ = m.epoch(GID.to_vec());
    let _ = m.members(GID.to_vec());
});
