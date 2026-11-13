// Periodic update of one's own leaf (self_update = Commit with UpdatePath) for post-compromise recovery
// (post-compromise security). Each member's app (phone and
// linked desktop each have their own leaf) runs `update_keys` itself every 7 days ±12 h or after 100 own
// messages in the group (GroupRekeyPolicy.kt).
//
// Threat model: the attacker once copied a member's MLS state (stolen backup,
// malware for a minute) and from then on sees ALL ciphertexts (they are also the server). We check:
//  1. until the leaf is updated, the copy reads the conversation (it does, which is why updates are needed);
//  2. after THIS member's update_keys the copy opens no new message from anyone, cannot
//     apply the Commit or later updates, and its epoch secret (the call key) differs;
//  3. an update by ANOTHER member does not heal the compromised one (the path is also encrypted to the stolen leaf), so
//     every member must update their own leaf, not just the admin;
//  4. the same for X-Wing groups and the previous suite; three updates in a row from different members; a Commit
//     that lost a race (two members updated in the same epoch) is replayed and the group converges.

use umbera_core::{mls_suite_legacy, mls_suite_xwing, Incoming, MlsClient};

use std::sync::Arc;

fn client(name: &str) -> Arc<MlsClient> {
    MlsClient::new(name.as_bytes().to_vec()).unwrap()
}

fn kp(c: &MlsClient, suite: u16) -> Vec<u8> {
    c.generate_key_package_for(suite).unwrap()
}

/// alice creates a group with suite `suite` and adds bob and carol.
fn group(suite: u16, gid: &[u8]) -> (Arc<MlsClient>, Arc<MlsClient>, Arc<MlsClient>) {
    let a = client("alice");
    let b = client("bob");
    let c = client("carol");
    a.create_group_for(gid.to_vec(), suite).unwrap();
    let bundle = a.add_members(gid.to_vec(), vec![kp(&b, suite), kp(&c, suite)]).unwrap();
    assert_eq!(b.process_welcome(bundle.welcome.clone()).unwrap(), gid);
    assert_eq!(c.process_welcome(bundle.welcome).unwrap(), gid);
    assert_eq!(a.group_ciphersuite(gid.to_vec()).unwrap(), suite);
    (a, b, c)
}

fn opens(c: &MlsClient, gid: &[u8], msg: &[u8], want: &[u8]) -> bool {
    matches!(c.process_incoming(gid.to_vec(), msg.to_vec()).unwrap(),
        Incoming::Application { plaintext, .. } if plaintext == want)
}

fn applies(c: &MlsClient, gid: &[u8], commit: &[u8]) {
    assert!(matches!(c.process_incoming(gid.to_vec(), commit.to_vec()).unwrap(), Incoming::CommitApplied));
}

/// Stolen state copy: the same blob opened separately (as the attacker would open it).
fn steal(c: &MlsClient) -> Arc<MlsClient> {
    MlsClient::from_state(c.export_state().unwrap()).unwrap()
}

fn secret(c: &MlsClient, gid: &[u8]) -> Vec<u8> {
    c.export_secret(gid.to_vec(), "conf-media".into(), 32).unwrap()
}

fn heals_after_own_update(suite: u16) {
    let gid = format!("pcs-own-{suite}").into_bytes();
    let (a, b, c) = group(suite, &gid);
    let stolen = steal(&b);

    // 1. Before the update the copy reads the conversation.
    let m1 = a.encrypt(gid.clone(), b"before heal".to_vec()).unwrap();
    assert!(opens(&b, &gid, &m1, b"before heal"));
    assert!(opens(&stolen, &gid, &m1, b"before heal"), "a stolen state must read the current epoch (that is the threat)");

    // 2. bob updates HIS OWN leaf.
    let e0 = b.epoch(gid.clone()).unwrap();
    let upd = b.update_keys(gid.clone()).unwrap();
    applies(&a, &gid, &upd);
    applies(&c, &gid, &upd);
    assert_eq!(a.epoch(gid.clone()).unwrap(), e0 + 1);
    assert_eq!(b.epoch(gid.clone()).unwrap(), e0 + 1);
    // The copy cannot apply the Commit of its own leaf (it lacks the new path secrets).
    assert!(!matches!(stolen.process_incoming(gid.clone(), upd.clone()).unwrap(), Incoming::CommitApplied));
    assert_eq!(stolen.epoch(gid.clone()).unwrap(), e0);

    // The copy opens no new message from anyone (including bob himself).
    for (who, text) in [(&a, b"from alice".as_slice()), (&b, b"from bob".as_slice()), (&c, b"from carol".as_slice())] {
        let m = who.encrypt(gid.clone(), text.to_vec()).unwrap();
        for r in [&a, &b, &c] {
            if !Arc::ptr_eq(r, who) {
                assert!(opens(r, &gid, &m, text), "member must read the new epoch");
            }
        }
        assert!(matches!(stolen.process_incoming(gid.clone(), m).unwrap(), Incoming::Ignored), "old epoch must not open the new message");
    }
    assert_ne!(secret(&stolen, &gid), secret(&a, &gid), "epoch secret (conference key) must change");
    assert_eq!(secret(&a, &gid), secret(&b, &gid));
    assert_eq!(secret(&a, &gid), secret(&c, &gid));

    // Later updates miss the copy as well.
    let upd2 = a.update_keys(gid.clone()).unwrap();
    applies(&b, &gid, &upd2);
    applies(&c, &gid, &upd2);
    assert!(!matches!(stolen.process_incoming(gid.clone(), upd2).unwrap(), Incoming::CommitApplied));
    let m = c.encrypt(gid.clone(), b"later".to_vec()).unwrap();
    assert!(opens(&a, &gid, &m, b"later"));
    assert!(matches!(stolen.process_incoming(gid.clone(), m).unwrap(), Incoming::Ignored));
}

#[test]
fn own_update_heals_compromised_state_legacy() {
    heals_after_own_update(mls_suite_legacy());
}

#[test]
fn own_update_heals_compromised_state_xwing() {
    heals_after_own_update(mls_suite_xwing());
}

/// Updating someone else's leaf does not heal the compromised one: the Commit path is also encrypted to the stolen leaf. So
/// every member updates on their own.
fn other_update_does_not_heal(suite: u16) {
    let gid = format!("pcs-other-{suite}").into_bytes();
    let (a, b, c) = group(suite, &gid);
    let stolen = steal(&b);
    let upd = a.update_keys(gid.clone()).unwrap();
    applies(&b, &gid, &upd);
    applies(&c, &gid, &upd);
    applies(&stolen, &gid, &upd);
    let m = c.encrypt(gid.clone(), b"still visible".to_vec()).unwrap();
    assert!(opens(&stolen, &gid, &m, b"still visible"));
    // But after bob's own update, it no longer does.
    let own = b.update_keys(gid.clone()).unwrap();
    applies(&a, &gid, &own);
    applies(&c, &gid, &own);
    let m = c.encrypt(gid.clone(), b"healed".to_vec()).unwrap();
    assert!(opens(&b, &gid, &m, b"healed"));
    assert!(matches!(stolen.process_incoming(gid.clone(), m).unwrap(), Incoming::Ignored));
}

#[test]
fn other_member_update_does_not_heal_legacy() {
    other_update_does_not_heal(mls_suite_legacy());
}

#[test]
fn other_member_update_does_not_heal_xwing() {
    other_update_does_not_heal(mls_suite_xwing());
}

/// Three auto-updates in a row from different members: the suite does not change, everyone keeps chatting.
fn three_rounds(suite: u16) {
    let gid = format!("pcs-rounds-{suite}").into_bytes();
    let (a, b, c) = group(suite, &gid);
    let all = [a.clone(), b.clone(), c.clone()];
    for (round, who) in [&b, &c, &a].into_iter().enumerate() {
        let upd = who.update_keys(gid.clone()).unwrap();
        for r in &all {
            if !Arc::ptr_eq(r, who) {
                applies(r, &gid, &upd);
            }
        }
        for s in &all {
            let text = format!("round {round}").into_bytes();
            let m = s.encrypt(gid.clone(), text.clone()).unwrap();
            for r in &all {
                if !Arc::ptr_eq(r, s) {
                    assert!(opens(r, &gid, &m, &text));
                }
            }
        }
        for r in &all {
            assert_eq!(r.group_ciphersuite(gid.clone()).unwrap(), suite, "self_update must keep the ciphersuite");
            assert!(r.own_leaf_marked(gid.clone()).unwrap());
        }
    }
}

#[test]
fn three_self_updates_in_a_row_legacy() {
    three_rounds(mls_suite_legacy());
}

#[test]
fn three_self_updates_in_a_row_xwing() {
    three_rounds(mls_suite_xwing());
}

/// Race: bob and carol updated in the same epoch. The app keeps the state from before its own Commit
/// (MlsManager.CommitMark) and converges on one branch (smaller hash); the loser rolls back to the state
/// before its Commit, applies the winner and updates again; this is how it looks at the core level.
fn race_replay(suite: u16) {
    let gid = format!("pcs-race-{suite}").into_bytes();
    let (a, b, c) = group(suite, &gid);
    let c_before = c.export_state().unwrap();
    let ub = b.update_keys(gid.clone()).unwrap();
    let uc = c.update_keys(gid.clone()).unwrap();
    // alice received bob's first.
    applies(&a, &gid, &ub);
    // carol has already merged her own Commit: someone else's from the same epoch does not apply.
    assert!(matches!(c.process_incoming(gid.clone(), ub.clone()).unwrap(), Incoming::Ignored));
    // And alice cannot apply carol's Commit (from the same, already passed epoch).
    assert!(matches!(a.process_incoming(gid.clone(), uc).unwrap(), Incoming::Ignored));
    // carol lost: roll back to the state before her Commit, apply the winner, and update again.
    let c = MlsClient::from_state(c_before).unwrap();
    applies(&c, &gid, &ub);
    let again = c.update_keys(gid.clone()).unwrap();
    applies(&a, &gid, &again);
    applies(&b, &gid, &again);
    let m = c.encrypt(gid.clone(), b"converged".to_vec()).unwrap();
    assert!(opens(&a, &gid, &m, b"converged"));
    assert!(opens(&b, &gid, &m, b"converged"));
    assert_eq!(secret(&a, &gid), secret(&c, &gid));
}

#[test]
fn concurrent_self_updates_converge_legacy() {
    race_replay(mls_suite_legacy());
}

#[test]
fn concurrent_self_updates_converge_xwing() {
    race_replay(mls_suite_xwing());
}

/// A member who was offline receives the missed updates in order and catches up with the group.
#[test]
fn offline_member_catches_up_on_queued_updates() {
    let suite = mls_suite_xwing();
    let gid = b"pcs-offline".to_vec();
    let (a, b, c) = group(suite, &gid);
    let mut queued = Vec::new();
    for who in [&a, &b, &a] {
        let u = who.update_keys(gid.clone()).unwrap();
        for r in [&a, &b] {
            if !Arc::ptr_eq(r, who) {
                applies(r, &gid, &u);
            }
        }
        queued.push(u);
    }
    for u in queued {
        applies(&c, &gid, &u);
    }
    assert_eq!(c.epoch(gid.clone()).unwrap(), a.epoch(gid.clone()).unwrap());
    let m = a.encrypt(gid.clone(), b"welcome back".to_vec()).unwrap();
    assert!(opens(&c, &gid, &m, b"welcome back"));
}
