//! Proof tests for group chats (MLS, RFC 9420): only current members can read a group message.
//!
//! These use the same `MlsClient` that the apps call for every group (src/lib.rs).
//! Run with: cargo test --test proof_groups

use std::sync::Arc;
use umbera_core::{Incoming, MlsClient, MlsError};

fn readable(r: Result<Incoming, MlsError>) -> Option<Vec<u8>> {
    match r {
        Ok(Incoming::Application { plaintext, .. }) => Some(plaintext),
        _ => None,
    }
}

/// Alice creates a group and adds Bob and Carol.
fn group_of_three(gid: &[u8]) -> (Arc<MlsClient>, Arc<MlsClient>, Arc<MlsClient>) {
    let alice = MlsClient::new(b"alice".to_vec()).unwrap();
    let bob = MlsClient::new(b"bob".to_vec()).unwrap();
    let carol = MlsClient::new(b"carol".to_vec()).unwrap();
    alice.create_group(gid.to_vec()).unwrap();
    let b1 = alice.add_members(gid.to_vec(), vec![bob.generate_key_package().unwrap()]).unwrap();
    bob.process_welcome(b1.welcome).unwrap();
    let b2 = alice.add_members(gid.to_vec(), vec![carol.generate_key_package().unwrap()]).unwrap();
    assert!(matches!(bob.process_incoming(gid.to_vec(), b2.commit).unwrap(), Incoming::CommitApplied));
    carol.process_welcome(b2.welcome).unwrap();
    (alice, bob, carol)
}

#[test]
fn every_member_can_read_a_group_message() {
    let gid = b"proof-group-members-read-000001".to_vec();
    let (alice, bob, carol) = group_of_three(&gid);
    let ct = alice.encrypt(gid.clone(), b"meet at 11".to_vec()).unwrap();
    assert_eq!(readable(bob.process_incoming(gid.clone(), ct.clone())), Some(b"meet at 11".to_vec()));
    assert_eq!(readable(carol.process_incoming(gid.clone(), ct)), Some(b"meet at 11".to_vec()));
}

#[test]
fn the_server_only_sees_ciphertext() {
    let gid = b"proof-group-ciphertext-only-0001".to_vec();
    let (alice, _bob, _carol) = group_of_three(&gid);
    let secret = b"the plaintext must never appear on the wire";
    let ct = alice.encrypt(gid.clone(), secret.to_vec()).unwrap();
    assert!(!ct.windows(secret.len()).any(|w| w == secret), "ciphertext must not contain the plaintext");
}

#[test]
fn an_outsider_cannot_read_it() {
    let gid = b"proof-group-outsider-0000000001".to_vec();
    let (alice, _bob, _carol) = group_of_three(&gid);
    let ct = alice.encrypt(gid.clone(), b"members only".to_vec()).unwrap();

    // Eve is not a member. Even with her own group under the very same group id,
    // she cannot decrypt a message of the real group.
    let eve = MlsClient::new(b"eve".to_vec()).unwrap();
    assert_eq!(readable(eve.process_incoming(gid.clone(), ct.clone())), None);
    eve.create_group(gid.clone()).unwrap();
    assert_eq!(readable(eve.process_incoming(gid.clone(), ct)), None);
}

#[test]
fn a_removed_member_cannot_read_new_messages() {
    let gid = b"proof-group-removed-member-00001".to_vec();
    let (alice, bob, carol) = group_of_three(&gid);
    let carol_leaf = alice
        .members(gid.clone())
        .unwrap()
        .into_iter()
        .find(|m| m.identity == b"carol".to_vec())
        .unwrap()
        .leaf_index;

    let commit = alice.remove_members(gid.clone(), vec![carol_leaf]).unwrap();
    assert!(matches!(bob.process_incoming(gid.clone(), commit.clone()).unwrap(), Incoming::CommitApplied));
    // Carol even receives and processes the removal Commit herself.
    let _ = carol.process_incoming(gid.clone(), commit);

    let ct = alice.encrypt(gid.clone(), b"after carol left".to_vec()).unwrap();
    assert_eq!(readable(bob.process_incoming(gid.clone(), ct.clone())), Some(b"after carol left".to_vec()));
    assert_eq!(readable(carol.process_incoming(gid.clone(), ct)), None, "a removed member must not read new epochs");
}

#[test]
fn a_new_member_cannot_read_older_messages() {
    let gid = b"proof-group-new-member-history-1".to_vec();
    let alice = MlsClient::new(b"alice".to_vec()).unwrap();
    let bob = MlsClient::new(b"bob".to_vec()).unwrap();
    alice.create_group(gid.clone()).unwrap();
    let b1 = alice.add_members(gid.clone(), vec![bob.generate_key_package().unwrap()]).unwrap();
    bob.process_welcome(b1.welcome).unwrap();
    let before = alice.encrypt(gid.clone(), b"before dave joined".to_vec()).unwrap();
    assert_eq!(readable(bob.process_incoming(gid.clone(), before.clone())), Some(b"before dave joined".to_vec()));

    let dave = MlsClient::new(b"dave".to_vec()).unwrap();
    let b2 = alice.add_members(gid.clone(), vec![dave.generate_key_package().unwrap()]).unwrap();
    assert!(matches!(bob.process_incoming(gid.clone(), b2.commit).unwrap(), Incoming::CommitApplied));
    dave.process_welcome(b2.welcome).unwrap();
    assert_eq!(readable(dave.process_incoming(gid.clone(), before)), None, "joining must not unlock past epochs");
}

#[test]
fn a_key_update_moves_the_group_to_a_new_epoch() {
    let gid = b"proof-group-key-update-00000001".to_vec();
    let (alice, bob, carol) = group_of_three(&gid);
    let e0 = alice.epoch(gid.clone()).unwrap();
    let commit = bob.update_keys(gid.clone()).unwrap();
    assert!(matches!(alice.process_incoming(gid.clone(), commit.clone()).unwrap(), Incoming::CommitApplied));
    assert!(matches!(carol.process_incoming(gid.clone(), commit).unwrap(), Incoming::CommitApplied));
    assert_eq!(alice.epoch(gid.clone()).unwrap(), e0 + 1);
    let ct = bob.encrypt(gid.clone(), b"fresh keys".to_vec()).unwrap();
    assert_eq!(readable(alice.process_incoming(gid.clone(), ct)), Some(b"fresh keys".to_vec()));
}
