// Compatibility of the new core (OpenMLS 0.9) with the shipped store core (OpenMLS 0.6, commit 19790b64).
//
// The old core is tests/legacy_v06 (a verbatim copy of the store build on openmls 0.6 / rust_crypto 0.3 /
// tls_codec 0.4). Both cores run in the same test process, so this checks real interoperability of
// the libraries rather than a restatement of the format:
//  1. state persisted by the 0.6 core (which is what phones hold) is opened by the new core,
//     and the group keeps working: decryption, Commit, Welcome, add/remove, rekey, export;
//  2. the same against the FROZEN vector tests/vectors/openmls-0.6-state.json (captured from the old core;
//     regenerate: COMPAT_V06_WRITE=1 cargo test --test compat_v06 freeze) — it remains
//     evidence even if the old crates are ever dropped from dev-dependencies;
//  3. mixed groups: members on the old and new core, in any order, create a group,
//     add, remove, rekey and exchange messages — in both directions;
//  4. group size limit in a mixed group: 20 leaves; a malicious Commit beyond the limit is rejected
//     by honest members of both versions;
//  5. device linking (devlink): a desktop on the new core joins a group that has phones on the old one;
//  6. fixed vulnerabilities and behaviour that changed in OpenMLS.

mod legacy_v06;

use legacy_v06 as old;
use umbera_core as new;

use serde_json::{json, Value};

// ---------------------------------------------------------------------------------------------
// Common member interface: the same scenario for the old and the new core.
// ---------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Inc {
    App { plaintext: Vec<u8>, sender: Vec<u8> },
    Commit,
    Rejected,
    Proposal,
    Ignored,
}

impl From<new::Incoming> for Inc {
    fn from(i: new::Incoming) -> Self {
        match i {
            new::Incoming::Application { plaintext, sender_identity } => Inc::App { plaintext, sender: sender_identity },
            new::Incoming::CommitApplied => Inc::Commit,
            new::Incoming::CommitRejected => Inc::Rejected,
            new::Incoming::Proposal => Inc::Proposal,
            new::Incoming::Ignored => Inc::Ignored,
        }
    }
}

impl From<old::Incoming> for Inc {
    fn from(i: old::Incoming) -> Self {
        match i {
            old::Incoming::Application { plaintext, sender_identity } => Inc::App { plaintext, sender: sender_identity },
            old::Incoming::CommitApplied => Inc::Commit,
            old::Incoming::CommitRejected => Inc::Rejected,
            old::Incoming::Proposal => Inc::Proposal,
            old::Incoming::Ignored => Inc::Ignored,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Ver {
    Old,
    New,
}

enum Client {
    Old(std::sync::Arc<old::MlsClient>),
    New(std::sync::Arc<new::MlsClient>),
}

struct Peer {
    name: String,
    c: Client,
}

impl Peer {
    fn create(ver: Ver, name: &str) -> Peer {
        let id = name.as_bytes().to_vec();
        let c = match ver {
            Ver::Old => Client::Old(old::MlsClient::new(id).unwrap()),
            Ver::New => Client::New(new::MlsClient::new(id).unwrap()),
        };
        Peer { name: name.into(), c }
    }
    fn ver(&self) -> Ver {
        match self.c {
            Client::Old(_) => Ver::Old,
            Client::New(_) => Ver::New,
        }
    }
    fn id(&self) -> Vec<u8> {
        self.name.as_bytes().to_vec()
    }
    fn kp(&self) -> Vec<u8> {
        match &self.c {
            Client::Old(c) => c.generate_key_package().unwrap(),
            Client::New(c) => c.generate_key_package().unwrap(),
        }
    }
    fn create_group(&self, gid: &[u8]) {
        match &self.c {
            Client::Old(c) => c.create_group(gid.to_vec()).unwrap(),
            Client::New(c) => c.create_group(gid.to_vec()).unwrap(),
        }
    }
    fn add(&self, gid: &[u8], kps: Vec<Vec<u8>>) -> Result<(Vec<u8>, Vec<u8>), String> {
        match &self.c {
            Client::Old(c) => c.add_members(gid.to_vec(), kps).map(|b| (b.commit, b.welcome)).map_err(|e| format!("{e:?}")),
            Client::New(c) => c.add_members(gid.to_vec(), kps).map(|b| (b.commit, b.welcome)).map_err(|e| format!("{e:?}")),
        }
    }
    fn remove(&self, gid: &[u8], leaves: Vec<u32>) -> Vec<u8> {
        match &self.c {
            Client::Old(c) => c.remove_members(gid.to_vec(), leaves).unwrap(),
            Client::New(c) => c.remove_members(gid.to_vec(), leaves).unwrap(),
        }
    }
    fn update(&self, gid: &[u8]) -> Vec<u8> {
        match &self.c {
            Client::Old(c) => c.update_keys(gid.to_vec()).unwrap(),
            Client::New(c) => c.update_keys(gid.to_vec()).unwrap(),
        }
    }
    fn welcome(&self, w: &[u8]) -> Vec<u8> {
        match &self.c {
            Client::Old(c) => c.process_welcome(w.to_vec()).unwrap(),
            Client::New(c) => c.process_welcome(w.to_vec()).unwrap(),
        }
    }
    fn enc(&self, gid: &[u8], pt: &[u8]) -> Vec<u8> {
        match &self.c {
            Client::Old(c) => c.encrypt(gid.to_vec(), pt.to_vec()).unwrap(),
            Client::New(c) => c.encrypt(gid.to_vec(), pt.to_vec()).unwrap(),
        }
    }
    fn inc(&self, gid: &[u8], m: &[u8]) -> Inc {
        match &self.c {
            Client::Old(c) => c.process_incoming(gid.to_vec(), m.to_vec()).unwrap().into(),
            Client::New(c) => c.process_incoming(gid.to_vec(), m.to_vec()).unwrap().into(),
        }
    }
    fn secret(&self, gid: &[u8]) -> Vec<u8> {
        match &self.c {
            Client::Old(c) => c.export_secret(gid.to_vec(), "conf-media".into(), 32).unwrap(),
            Client::New(c) => c.export_secret(gid.to_vec(), "conf-media".into(), 32).unwrap(),
        }
    }
    fn epoch(&self, gid: &[u8]) -> u64 {
        match &self.c {
            Client::Old(c) => c.epoch(gid.to_vec()).unwrap(),
            Client::New(c) => c.epoch(gid.to_vec()).unwrap(),
        }
    }
    /// (leaf_index, identity), sorted by leaf.
    fn roster(&self, gid: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let mut v: Vec<(u32, Vec<u8>)> = match &self.c {
            Client::Old(c) => c.members(gid.to_vec()).unwrap().into_iter().map(|m| (m.leaf_index, m.identity)).collect(),
            Client::New(c) => c.members(gid.to_vec()).unwrap().into_iter().map(|m| (m.leaf_index, m.identity)).collect(),
        };
        v.sort();
        v
    }
    fn leaf_of(&self, gid: &[u8], who: &Peer) -> u32 {
        self.roster(gid).into_iter().find(|(_, id)| *id == who.id()).unwrap().0
    }
    fn export(&self) -> Vec<u8> {
        match &self.c {
            Client::Old(c) => c.export_state().unwrap(),
            Client::New(c) => c.export_state().unwrap(),
        }
    }
    /// Save and reopen with the same core (app restart).
    fn reload(&mut self) {
        let blob = self.export();
        self.c = match self.ver() {
            Ver::Old => Client::Old(old::MlsClient::from_state(blob).unwrap()),
            Ver::New => Client::New(new::MlsClient::from_state(blob).unwrap()),
        };
    }
    /// App update: the new core opens the old core's state.
    fn upgrade(&mut self) {
        let blob = self.export();
        self.c = Client::New(new::MlsClient::from_state(blob).unwrap());
    }
}

fn app(pt: &[u8], who: &Peer) -> Inc {
    Inc::App { plaintext: pt.to_vec(), sender: who.id() }
}

/// Every member of `group` (except `from`) receives `msg` and returns `want`.
fn deliver(group: &[&Peer], from: &Peer, gid: &[u8], msg: &[u8], want: &Inc) {
    for p in group {
        if p.name == from.name {
            continue;
        }
        assert_eq!(&p.inc(gid, msg), want, "{} ({:?}) ← {} ({:?})", p.name, p.ver(), from.name, from.ver());
    }
}

/// Everyone is in the same epoch, with the same membership and the same exported secret.
fn assert_in_sync(group: &[&Peer], gid: &[u8]) -> Vec<u8> {
    let e = group[0].epoch(gid);
    let r = group[0].roster(gid);
    let s = group[0].secret(gid);
    for p in group {
        assert_eq!(p.epoch(gid), e, "epoch of {}", p.name);
        assert_eq!(p.roster(gid), r, "roster of {}", p.name);
        assert_eq!(p.secret(gid), s, "exported secret of {}", p.name);
    }
    s
}

/// Everyone writes to everyone; one's own echo is Ignored.
fn chat_round(group: &[&Peer], gid: &[u8], tag: &str) {
    for p in group {
        let pt = format!("{tag}: hello from {}", p.name).into_bytes();
        let ct = p.enc(gid, &pt);
        deliver(group, p, gid, &ct, &app(&pt, p));
        assert_eq!(p.inc(gid, &ct), Inc::Ignored, "own echo of {} ({:?})", p.name, p.ver());
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Mixed groups
// ---------------------------------------------------------------------------------------------

/// Full group lifecycle with core versions alternating per `vers`. Each new member is added
/// by the previous one (so every version produces Commits and Welcomes), everyone chats, everyone rekeys,
/// removals are done by different versions, and halfway through everyone "restarts".
fn mixed_life(vers: &[Ver], gid: &[u8]) {
    let mut peers: Vec<Peer> = vers.iter().enumerate().map(|(i, v)| Peer::create(*v, &format!("p{i}-{v:?}"))).collect();
    peers[0].create_group(gid);
    for i in 1..peers.len() {
        let kp = peers[i].kp();
        let (commit, welcome) = peers[i - 1].add(gid, vec![kp]).unwrap();
        let members: Vec<&Peer> = peers[..i].iter().collect();
        deliver(&members, &peers[i - 1], gid, &commit, &Inc::Commit);
        assert_eq!(peers[i].welcome(&welcome), gid.to_vec());
    }
    let all: Vec<&Peer> = peers.iter().collect();
    let s0 = assert_in_sync(&all, gid);
    chat_round(&all, gid, "joined");

    // Restart everyone (each core saves and reopens its own state) — the group survives.
    for p in peers.iter_mut() {
        p.reload();
    }
    let all: Vec<&Peer> = peers.iter().collect();
    chat_round(&all, gid, "reloaded");

    // Rekey by each member in turn.
    let mut last = s0;
    for p in &all {
        let c = p.update(gid);
        deliver(&all, p, gid, &c, &Inc::Commit);
        let s = assert_in_sync(&all, gid);
        assert_ne!(s, last, "secret must rotate on rekey by {}", p.name);
        last = s;
    }
    chat_round(&all, gid, "rekeyed");

    // Removal: the second removes the third, then the last removes the first.
    let victim = 2;
    let leaf = peers[1].leaf_of(gid, &peers[victim]);
    let c = peers[1].remove(gid, vec![leaf]);
    for (i, p) in peers.iter().enumerate() {
        if i == 1 {
            continue;
        }
        // The removed member also applies the Commit about itself (as the old core did) — it reads nothing afterwards.
        p.inc(gid, &c);
    }
    let rest: Vec<&Peer> = peers.iter().enumerate().filter(|(i, _)| *i != victim).map(|(_, p)| p).collect();
    assert_in_sync(&rest, gid);
    let ct = peers[0].enc(gid, b"after remove");
    assert_eq!(peers[victim].inc(gid, &ct), Inc::Ignored, "removed member must not decrypt");
    deliver(&rest, &peers[0], gid, &ct, &app(b"after remove", &peers[0]));

    let last_i = peers.len() - 1;
    let leaf0 = peers[last_i].leaf_of(gid, &peers[0]);
    let c = peers[last_i].remove(gid, vec![leaf0]);
    let rest2: Vec<&Peer> = peers.iter().enumerate().filter(|(i, _)| *i != victim && *i != 0).map(|(_, p)| p).collect();
    deliver(&rest2, &peers[last_i], gid, &c, &Inc::Commit);
    assert_in_sync(&rest2, gid);

    // A newcomer on a different version than the adder, after removals (leaves are reused).
    let adder = rest2[0];
    let nv = if adder.ver() == Ver::Old { Ver::New } else { Ver::Old };
    let newbie = Peer::create(nv, "newbie");
    let (c, w) = adder.add(gid, vec![newbie.kp()]).unwrap();
    deliver(&rest2, adder, gid, &c, &Inc::Commit);
    newbie.welcome(&w);
    let mut fin = rest2.clone();
    fin.push(&newbie);
    assert_in_sync(&fin, gid);
    chat_round(&fin, gid, "final");
}

#[test]
fn mixed_group_old_creator() {
    use Ver::*;
    mixed_life(&[Old, New, Old, New, New, Old], b"mixed-old-creator-gid-0000000001");
}

#[test]
fn mixed_group_new_creator() {
    use Ver::*;
    mixed_life(&[New, Old, New, Old, Old, New], b"mixed-new-creator-gid-0000000001");
}

#[test]
fn mixed_group_one_new_among_old() {
    use Ver::*;
    mixed_life(&[Old, Old, New, Old], b"mixed-one-new-gid-00000000000001");
}

#[test]
fn mixed_group_one_old_among_new() {
    use Ver::*;
    mixed_life(&[New, New, Old, New], b"mixed-one-old-gid-00000000000001");
}

/// Several KeyPackages of different versions in one Commit, and a Commit with a removal and an add back to back.
#[test]
fn mixed_batch_add_both_directions() {
    for (admin_ver, gid) in [(Ver::Old, b"batch-old-admin-000000000000001".to_vec()), (Ver::New, b"batch-new-admin-000000000000001".to_vec())] {
        let admin = Peer::create(admin_ver, "admin");
        admin.create_group(&gid);
        let joiners: Vec<Peer> = (0..6).map(|i| Peer::create(if i % 2 == 0 { Ver::Old } else { Ver::New }, &format!("j{i}"))).collect();
        let (_c, w) = admin.add(&gid, joiners.iter().map(|j| j.kp()).collect()).unwrap();
        for j in &joiners {
            assert_eq!(j.welcome(&w), gid);
        }
        let mut all: Vec<&Peer> = vec![&admin];
        all.extend(joiners.iter());
        assert_in_sync(&all, &gid);
        chat_round(&all, &gid, "batch");
    }
}

// ---------------------------------------------------------------------------------------------
// 1. 0.6 core state is opened by the new core (live, from the old library in the same test run)
// ---------------------------------------------------------------------------------------------

/// Phones update one at a time: in a group on the old core, members switch to the new one one by one
/// (their saved state is opened by the new core), and the group keeps working between switches.
#[test]
fn old_state_upgrades_one_by_one() {
    let gid = b"upgrade-one-by-one-gid-000000001".to_vec();
    let mut peers: Vec<Peer> = (0..5).map(|i| Peer::create(Ver::Old, &format!("u{i}"))).collect();
    peers[0].create_group(&gid);
    let kps: Vec<Vec<u8>> = peers[1..].iter().map(|p| p.kp()).collect();
    let (_c, w) = peers[0].add(&gid, kps).unwrap();
    for p in &peers[1..] {
        p.welcome(&w);
    }
    {
        let all: Vec<&Peer> = peers.iter().collect();
        chat_round(&all, &gid, "all-old");
    }
    for i in 0..peers.len() {
        // A message sent (by the neighbour's old or already new core) BEFORE the recipient updates
        // and delivered after.
        let sender = (i + 1) % peers.len();
        let pending_app = peers[sender].enc(&gid, b"sent before upgrade");
        let secret_before = peers[i].secret(&gid);
        let roster_before = peers[i].roster(&gid);
        let epoch_before = peers[i].epoch(&gid);
        peers[i].upgrade();
        assert_eq!(peers[i].ver(), Ver::New);
        // Key schedule, tree and epoch were read losslessly.
        assert_eq!(peers[i].secret(&gid), secret_before, "exporter after upgrade of u{i}");
        assert_eq!(peers[i].roster(&gid), roster_before);
        assert_eq!(peers[i].epoch(&gid), epoch_before);
        assert_eq!(peers[i].inc(&gid, &pending_app), app(b"sent before upgrade", &peers[sender]), "u{i} reads a message sent before its upgrade");
        let others: Vec<&Peer> = peers.iter().enumerate().filter(|(j, _)| *j != i).map(|(_, p)| p).collect();
        deliver(&others, &peers[sender], &gid, &pending_app, &app(b"sent before upgrade", &peers[sender]));
        let all: Vec<&Peer> = peers.iter().collect();
        chat_round(&all, &gid, &format!("after-upgrade-{i}"));
        let c = peers[i].update(&gid);
        deliver(&all, &peers[i], &gid, &c, &Inc::Commit);
        assert_in_sync(&all, &gid);
    }
    // Everyone on the new core: rekey set the new-core marker, the limit is raised.
    if let Client::New(c) = &peers[0].c {
        assert!(c.own_leaf_marked(gid.clone()).unwrap());
        assert_eq!(c.leaf_limit(gid.clone()).unwrap() as usize, new::MAX_GROUP_LEAVES);
    }
}

/// An invitation started on the old core (KeyPackage issued, Welcome not yet received) completes after
/// the update: the KeyPackage private key from the 0.6 storage is read by the new core. Conversely,
/// an old phone that has not updated yet accepts a Welcome from the new core.
#[test]
fn pending_join_survives_upgrade() {
    let gid = b"pending-join-upgrade-gid-0000001".to_vec();
    let admin = Peer::create(Ver::Old, "admin");
    admin.create_group(&gid);
    let mut joiner = Peer::create(Ver::Old, "joiner");
    let kp = joiner.kp();
    joiner.upgrade(); // app update between issuing the KeyPackage and the Welcome
    let (_c, w) = admin.add(&gid, vec![kp]).unwrap();
    assert_eq!(joiner.welcome(&w), gid);
    chat_round(&[&admin, &joiner], &gid, "pending");

    let mut admin2 = admin;
    admin2.upgrade();
    let late_old = Peer::create(Ver::Old, "late-old");
    let (c, w) = admin2.add(&gid, vec![late_old.kp()]).unwrap();
    assert_eq!(joiner.inc(&gid, &c), Inc::Commit);
    assert_eq!(late_old.welcome(&w), gid);
    let all = [&admin2, &joiner, &late_old];
    assert_in_sync(&all, &gid);
    chat_round(&all, &gid, "pending2");
}

/// Reopening the new state (restarts after the update) — lossless.
#[test]
fn upgraded_state_roundtrips_in_new_format() {
    let gid = b"upgrade-roundtrip-gid-0000000001".to_vec();
    let mut a = Peer::create(Ver::Old, "a");
    let mut b = Peer::create(Ver::Old, "b");
    a.create_group(&gid);
    let (_c, w) = a.add(&gid, vec![b.kp()]).unwrap();
    b.welcome(&w);
    chat_round(&[&a, &b], &gid, "pre");
    a.upgrade();
    b.upgrade();
    for round in 0..3 {
        a.reload();
        b.reload();
        chat_round(&[&a, &b], &gid, &format!("r{round}"));
        let c = a.update(&gid);
        assert_eq!(b.inc(&gid, &c), Inc::Commit);
        assert_in_sync(&[&a, &b], &gid);
    }
}

// ---------------------------------------------------------------------------------------------
// 2. Frozen 0.6 state vector
// ---------------------------------------------------------------------------------------------

const VECTOR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/openmls-0.6-state.json");

/// Snapshot from the old core: three in the group, a fourth waiting for a Welcome, one message and one Commit
/// still undelivered. Runs only with COMPAT_V06_WRITE=1.
#[test]
fn freeze() {
    if std::env::var("COMPAT_V06_WRITE").as_deref() != Ok("1") {
        return;
    }
    let gid = b"frozen-store-group-0123456789abc".to_vec();
    let alice = old::MlsClient::new(b"alice".to_vec()).unwrap();
    let bob = old::MlsClient::new(b"bob".to_vec()).unwrap();
    let carol = old::MlsClient::new(b"carol".to_vec()).unwrap();
    let dave = old::MlsClient::new(b"dave".to_vec()).unwrap();
    alice.create_group(gid.clone()).unwrap();
    let b1 = alice.add_members(gid.clone(), vec![bob.generate_key_package().unwrap()]).unwrap();
    bob.process_welcome(b1.welcome).unwrap();
    let b2 = alice.add_members(gid.clone(), vec![carol.generate_key_package().unwrap()]).unwrap();
    bob.process_incoming(gid.clone(), b2.commit).unwrap();
    carol.process_welcome(b2.welcome).unwrap();
    for (who, c) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
        let ct = c.encrypt(gid.clone(), format!("hi from {who}").into_bytes()).unwrap();
        for o in [&alice, &bob, &carol] {
            o.process_incoming(gid.clone(), ct.clone()).unwrap();
        }
    }
    let dave_kp = dave.generate_key_package().unwrap();
    // Undelivered: alice's message in the current epoch.
    let inflight_app = alice.encrypt(gid.clone(), b"in flight across the upgrade".to_vec()).unwrap();
    let epoch_before = alice.epoch(gid.clone()).unwrap();
    let secret_before = alice.export_secret(gid.clone(), "conf-media".into(), 32).unwrap();
    // alice and bob states are before carol's Commit; carol is already in the next epoch.
    let alice_state = alice.export_state().unwrap();
    let bob_state = bob.export_state().unwrap();
    let inflight_commit = carol.update_keys(gid.clone()).unwrap();
    let secret_after = carol.export_secret(gid.clone(), "conf-media".into(), 32).unwrap();
    let inflight_app2 = carol.encrypt(gid.clone(), b"from carol in the next epoch".to_vec()).unwrap();
    let v = json!({
        "about": "State saved by the core of the store apps 2.0.x (OpenMLS 0.6.0). Read by tests/compat_v06.rs::frozen_store_state_vector.",
        "openmls": "0.6.0",
        "gid": hex::encode(&gid),
        "alice_state": hex::encode(alice_state),
        "bob_state": hex::encode(bob_state),
        "carol_state": hex::encode(carol.export_state().unwrap()),
        "dave_pending_state": hex::encode(dave.export_state().unwrap()),
        "dave_key_package": hex::encode(dave_kp),
        "inflight_app_from_alice": hex::encode(inflight_app),
        "inflight_commit_from_carol": hex::encode(inflight_commit),
        "inflight_app_from_carol": hex::encode(inflight_app2),
        "epoch_before_commit": epoch_before,
        "secret_before_commit": hex::encode(secret_before),
        "secret_after_commit": hex::encode(secret_after),
    });
    std::fs::create_dir_all(std::path::Path::new(VECTOR).parent().unwrap()).unwrap();
    std::fs::write(VECTOR, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
}

fn hx(v: &Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or_else(|| panic!("vector field {k}"))).unwrap()
}

#[test]
fn frozen_store_state_vector() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(VECTOR).expect("tests/vectors/openmls-0.6-state.json")).unwrap();
    let gid = hx(&v, "gid");
    let alice = new::MlsClient::from_state(hx(&v, "alice_state")).unwrap();
    let bob = new::MlsClient::from_state(hx(&v, "bob_state")).unwrap();
    let carol = new::MlsClient::from_state(hx(&v, "carol_state")).unwrap();
    let dave = new::MlsClient::from_state(hx(&v, "dave_pending_state")).unwrap();
    let ep = v["epoch_before_commit"].as_u64().unwrap();

    // Key schedule was read: the same secret for the same epoch the old core computed.
    for c in [&alice, &bob] {
        assert_eq!(c.epoch(gid.clone()).unwrap(), ep);
        assert_eq!(c.export_secret(gid.clone(), "conf-media".into(), 32).unwrap(), hx(&v, "secret_before_commit"));
        assert_eq!(c.members(gid.clone()).unwrap().len(), 3);
    }
    // The old core's undelivered message is decrypted by the new core.
    let got: Inc = bob.process_incoming(gid.clone(), hx(&v, "inflight_app_from_alice")).unwrap().into();
    assert_eq!(got, Inc::App { plaintext: b"in flight across the upgrade".to_vec(), sender: b"alice".to_vec() });
    // The old core's Commit is applied by the new core; epoch and secret match those computed on 0.6.
    for c in [&alice, &bob] {
        let r: Inc = c.process_incoming(gid.clone(), hx(&v, "inflight_commit_from_carol")).unwrap().into();
        assert_eq!(r, Inc::Commit);
        assert_eq!(c.epoch(gid.clone()).unwrap(), ep + 1);
        assert_eq!(c.export_secret(gid.clone(), "conf-media".into(), 32).unwrap(), hx(&v, "secret_after_commit"));
        let r: Inc = c.process_incoming(gid.clone(), hx(&v, "inflight_app_from_carol")).unwrap().into();
        assert_eq!(r, Inc::App { plaintext: b"from carol in the next epoch".to_vec(), sender: b"carol".to_vec() });
    }
    // The group keeps working: add (dave's KeyPackage from the old core, his pending 0.6 state),
    // messaging, removal, rekey.
    let bundle = alice.add_members(gid.clone(), vec![hx(&v, "dave_key_package")]).unwrap();
    for c in [&bob, &carol] {
        assert_eq!(Inc::from(c.process_incoming(gid.clone(), bundle.commit.clone()).unwrap()), Inc::Commit);
    }
    assert_eq!(dave.process_welcome(bundle.welcome).unwrap(), gid);
    let all = [("alice", &alice), ("bob", &bob), ("carol", &carol), ("dave", &dave)];
    for (who, c) in all {
        let pt = format!("post-upgrade from {who}").into_bytes();
        let ct = c.encrypt(gid.clone(), pt.clone()).unwrap();
        for (w2, o) in all {
            let r: Inc = o.process_incoming(gid.clone(), ct.clone()).unwrap().into();
            if w2 == who {
                assert_eq!(r, Inc::Ignored);
            } else {
                assert_eq!(r, Inc::App { plaintext: pt.clone(), sender: who.as_bytes().to_vec() });
            }
        }
    }
    let carol_leaf = alice.members(gid.clone()).unwrap().into_iter().find(|m| m.identity == b"carol").unwrap().leaf_index;
    let rm = alice.remove_members(gid.clone(), vec![carol_leaf]).unwrap();
    for c in [&bob, &dave] {
        assert_eq!(Inc::from(c.process_incoming(gid.clone(), rm.clone()).unwrap()), Inc::Commit);
    }
    let up = dave.update_keys(gid.clone()).unwrap();
    for c in [&alice, &bob] {
        assert_eq!(Inc::from(c.process_incoming(gid.clone(), up.clone()).unwrap()), Inc::Commit);
    }
    let s = alice.export_secret(gid.clone(), "conf-media".into(), 32).unwrap();
    assert_eq!(bob.export_secret(gid.clone(), "conf-media".into(), 32).unwrap(), s);
    assert_eq!(dave.export_secret(gid.clone(), "conf-media".into(), 32).unwrap(), s);
    // And after saving again with the new core.
    let alice2 = new::MlsClient::from_state(alice.export_state().unwrap()).unwrap();
    let ct = alice2.encrypt(gid.clone(), b"after re-save".to_vec()).unwrap();
    assert_eq!(Inc::from(bob.process_incoming(gid.clone(), ct).unwrap()), Inc::App { plaintext: b"after re-save".to_vec(), sender: b"alice".to_vec() });
}

// ---------------------------------------------------------------------------------------------
// 4. Group size limit in a mixed group
// ---------------------------------------------------------------------------------------------

/// Our core's state → provider and signer for a specific OpenMLS version (for a "malicious
/// admin" that builds a Commit bypassing the limit check).
mod raw {
    use serde_json::Value;

    pub fn parts(blob: &[u8]) -> (Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>) {
        let v: Value = serde_json::from_slice(blob).unwrap();
        let storage = v["storage"]
            .as_array()
            .unwrap()
            .iter()
            .map(|kv| (hex::decode(kv[0].as_str().unwrap()).unwrap(), hex::decode(kv[1].as_str().unwrap()).unwrap()))
            .collect();
        let signer = v["signer"].as_array().unwrap().iter().map(|b| b.as_u64().unwrap() as u8).collect();
        (storage, signer)
    }

    /// An "add kp" Commit without our limit check — built by the new core (OpenMLS 0.9).
    pub fn new_unchecked_add(blob: &[u8], gid: &[u8], kp: &[u8]) -> Vec<u8> {
        use openmls::prelude::*;
        use openmls_basic_credential::SignatureKeyPair;
        use openmls_rust_crypto::OpenMlsRustCrypto;
        use tls_codec::{Deserialize as _, Serialize as _};
        let (storage, signer) = parts(blob);
        let provider = OpenMlsRustCrypto::default();
        provider.storage().values.write().unwrap().extend(storage);
        let signer = SignatureKeyPair::tls_deserialize_exact(&signer).unwrap();
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(gid)).unwrap().unwrap();
        let kp = KeyPackageIn::tls_deserialize_exact(kp).unwrap().validate(provider.crypto(), ProtocolVersion::Mls10).unwrap();
        let (commit, _w, _i) = group.add_members(&provider, &signer, &[kp]).unwrap();
        commit.tls_serialize_detached().unwrap()
    }

    /// The same, built by the old core (OpenMLS 0.6).
    pub fn old_unchecked_add(blob: &[u8], gid: &[u8], kp: &[u8]) -> Vec<u8> {
        use openmls_basic_credential_v06::SignatureKeyPair;
        use openmls_rust_crypto_v06::OpenMlsRustCrypto;
        use openmls_v06::prelude::*;
        use tls_codec_v04::{Deserialize as _, Serialize as _};
        let (storage, signer) = parts(blob);
        let provider = OpenMlsRustCrypto::default();
        provider.storage().values.write().unwrap().extend(storage);
        let signer = SignatureKeyPair::tls_deserialize_exact(&signer).unwrap();
        let mut group = MlsGroup::load(provider.storage(), &GroupId::from_slice(gid)).unwrap().unwrap();
        let kp = KeyPackageIn::tls_deserialize_exact(kp).unwrap().validate(provider.crypto(), ProtocolVersion::Mls10).unwrap();
        let (commit, _w, _i) = group.add_members(&provider, &signer, &[kp]).unwrap();
        commit.tls_serialize_detached().unwrap()
    }
}

/// A 20-leaf group, old and new mixed. An honest admin of either version does not add a 21st
/// (old leaves lack the new-core marker, so the limit is 20 even for the new core). A malicious
/// Commit beyond the limit, built by either version, is rejected by honest members of both versions,
/// their epoch does not advance, and the group keeps working.
#[test]
fn mixed_group_member_cap() {
    let gid = b"mixed-cap-gid-000000000000000001".to_vec();
    let old_admin = Peer::create(Ver::Old, "old-admin");
    old_admin.create_group(&gid);
    let new_admin = Peer::create(Ver::New, "new-admin");
    let honest_old = Peer::create(Ver::Old, "honest-old");
    let honest_new = Peer::create(Ver::New, "honest-new");
    let core = vec![old_admin, new_admin, honest_old, honest_new];
    for i in 1..core.len() {
        let (c, w) = core[0].add(&gid, vec![core[i].kp()]).unwrap();
        let ms: Vec<&Peer> = core[..i].iter().collect();
        deliver(&ms, &core[0], &gid, &c, &Inc::Commit);
        core[i].welcome(&w);
    }
    // The remaining 16 slots are filled by a new admin (newcomers alternate versions).
    let mut fillers = Vec::new();
    for i in core.len()..old::MAX_GROUP_MEMBERS {
        let f = Peer::create(if i % 2 == 0 { Ver::New } else { Ver::Old }, &format!("f{i}"));
        let (c, w) = core[1].add(&gid, vec![f.kp()]).unwrap();
        let all: Vec<&Peer> = core.iter().chain(fillers.iter()).collect();
        deliver(&all, &core[1], &gid, &c, &Inc::Commit);
        f.welcome(&w);
        fillers.push(f);
    }
    let all: Vec<&Peer> = core.iter().collect();
    assert_in_sync(&all, &gid);
    assert_eq!(core[0].roster(&gid).len(), old::MAX_GROUP_MEMBERS);

    let extra_new = Peer::create(Ver::New, "extra-new");
    let extra_old = Peer::create(Ver::Old, "extra-old");
    // Honest admins of both versions refuse.
    assert!(core[0].add(&gid, vec![extra_old.kp()]).is_err(), "old admin must refuse #21");
    assert!(core[0].add(&gid, vec![extra_new.kp()]).is_err(), "old admin must refuse #21 (new kp)");
    assert!(core[1].add(&gid, vec![extra_new.kp()]).is_err(), "new admin must refuse #21 while old leaves exist");
    assert!(core[1].add(&gid, vec![extra_old.kp()]).is_err(), "new admin must refuse #21 (old kp)");

    // Malicious Commits beyond the limit.
    let evil_by_old = raw::old_unchecked_add(&core[0].export(), &gid, &extra_new.kp());
    let evil_by_new = raw::new_unchecked_add(&core[1].export(), &gid, &extra_new.kp());
    let epoch = core[2].epoch(&gid);
    for evil in [&evil_by_old, &evil_by_new] {
        for judge in [&core[2], &core[3]] {
            assert_eq!(judge.inc(&gid, evil), Inc::Rejected, "{} must reject an over-cap commit", judge.name);
            assert_eq!(judge.epoch(&gid), epoch);
            assert_eq!(judge.roster(&gid).len(), old::MAX_GROUP_MEMBERS);
        }
    }
    // The group works after the rejection: a regular message and an honest Commit.
    let honest: Vec<&Peer> = core.iter().chain(fillers.iter()).collect();
    let ct = core[0].enc(&gid, b"still alive");
    deliver(&honest, &core[0], &gid, &ct, &app(b"still alive", &core[0]));
    let c = core[3].update(&gid);
    deliver(&honest, &core[3], &gid, &c, &Inc::Commit);
    assert_in_sync(&honest, &gid);
}

// ---------------------------------------------------------------------------------------------
// 5. Device linking: a desktop (new core) joins a group with old phones
// ---------------------------------------------------------------------------------------------

#[test]
fn devlink_pc_joins_group_with_old_phones() {
    use new::devlink::mlsjoin::{mls_join_offers_decode, mls_join_offers_encode, mls_sibling_verify_key_package, MlsJoinOffer};
    let gid = b"devlink-mixed-gid-00000000000001".to_vec();
    // The group was created by a phone on the old core; a second old phone is a member.
    let creator = Peer::create(Ver::Old, "old-phone-a");
    creator.create_group(&gid);
    let other_old = Peer::create(Ver::Old, "old-phone-b");
    // Our phone updated to the new core after joining the group.
    let mut phone = Peer::create(Ver::Old, "phone-primary");
    let (c, w) = creator.add(&gid, vec![other_old.kp()]).unwrap();
    let _ = c;
    other_old.welcome(&w);
    let (c, w) = creator.add(&gid, vec![phone.kp()]).unwrap();
    assert_eq!(other_old.inc(&gid, &c), Inc::Commit);
    phone.welcome(&w);
    phone.upgrade();
    let Client::New(phone_c) = &phone.c else { unreachable!() };

    // Desktop: its own leaf with its own memberId, KeyPackage with the new-core marker, link signature.
    let pc_id = b"pc-device-leaf".to_vec();
    let pc = new::MlsClient::new(pc_id.clone()).unwrap();
    let pc_kp = pc.generate_key_package().unwrap();
    let dev_sig = pc.sibling_sign(gid.clone(), phone.id(), pc_id.clone()).unwrap();
    let offer = MlsJoinOffer { gid: gid.clone(), device_member_id: pc_id.clone(), key_package: pc_kp.clone(), device_sibling_sig: dev_sig.clone() };
    let offer = mls_join_offers_decode(mls_join_offers_encode(vec![offer]).unwrap()).unwrap().remove(0);
    assert!(mls_sibling_verify_key_package(phone.id(), offer.clone()));

    // The phone signs the link and adds the desktop; old phones accept a Commit with a leaf
    // advertising the 0xF0D1 marker unknown to them.
    let prim_sig = phone_c.sibling_sign(gid.clone(), phone.id(), pc_id.clone()).unwrap();
    let bundle = phone_c.add_members(gid.clone(), vec![offer.key_package]).unwrap();
    assert_eq!(creator.inc(&gid, &bundle.commit), Inc::Commit);
    assert_eq!(other_old.inc(&gid, &bundle.commit), Inc::Commit);
    assert_eq!(pc.process_welcome(bundle.welcome).unwrap(), gid);

    // The link is verified against the group tree: phone and desktop (new core), group partly on the old one.
    for v in [phone_c, &pc] {
        assert!(v.sibling_verify(gid.clone(), phone.id(), pc_id.clone(), prim_sig.clone(), dev_sig.clone()).unwrap());
        assert!(!v.sibling_verify(gid.clone(), phone.id(), pc_id.clone(), dev_sig.clone(), prim_sig.clone()).unwrap());
    }
    // While the group has old leaves, the limit is 20.
    assert_eq!(pc.leaf_limit(gid.clone()).unwrap() as usize, new::LEGACY_LEAF_CAP);

    // The desktop chats with old phones in both directions and rekeys.
    let pc_peer = Peer { name: String::from_utf8(pc_id.clone()).unwrap(), c: Client::New(pc.clone()) };
    let all = [&creator, &other_old, &phone, &pc_peer];
    assert_in_sync(&all, &gid);
    chat_round(&all, &gid, "pc");
    let c = pc_peer.update(&gid);
    deliver(&all, &pc_peer, &gid, &c, &Inc::Commit);
    assert_in_sync(&all, &gid);
    // Desktop restart — the link still verifies.
    let pc2 = new::MlsClient::from_state(pc.export_state().unwrap()).unwrap();
    assert!(pc2.sibling_verify(gid.clone(), phone.id(), pc_id, prim_sig, dev_sig).unwrap());
}

/// Unlinking a desktop: the desktop leaf is removed by its own phone — not an admin, a regular member.
/// Old phones accept such a Commit, the group continues without the desktop leaf; the desktop can no longer read the group.
#[test]
fn devlink_pc_leaf_removed_by_its_phone_with_old_phones() {
    let gid = b"devlink-unlink-gid-0000000000001".to_vec();
    let admin = Peer::create(Ver::Old, "old-admin");
    admin.create_group(&gid);
    let other_old = Peer::create(Ver::Old, "old-member");
    let (_, w) = admin.add(&gid, vec![other_old.kp()]).unwrap();
    other_old.welcome(&w);
    let phone = Peer::create(Ver::New, "phone-new");
    let (c, w) = admin.add(&gid, vec![phone.kp()]).unwrap();
    assert_eq!(other_old.inc(&gid, &c), Inc::Commit);
    phone.welcome(&w);
    let Client::New(phone_c) = &phone.c else { unreachable!() };

    // The phone adds its desktop (a regular member, not an admin).
    let pc_id = b"pc-leaf-unlink".to_vec();
    let pc = new::MlsClient::new(pc_id.clone()).unwrap();
    let bundle = phone_c.add_members(gid.clone(), vec![pc.generate_key_package().unwrap()]).unwrap();
    for p in [&admin, &other_old] { assert_eq!(p.inc(&gid, &bundle.commit), Inc::Commit); }
    pc.process_welcome(bundle.welcome).unwrap();
    let pc_peer = Peer { name: String::from_utf8(pc_id.clone()).unwrap(), c: Client::New(pc.clone()) };
    let with_pc = [&admin, &other_old, &phone, &pc_peer];
    assert_in_sync(&with_pc, &gid);
    chat_round(&with_pc, &gid, "before-unlink");

    // Unlinking: the phone removes the desktop leaf with its own Commit.
    let leaf = phone.leaf_of(&gid, &pc_peer);
    let rm = phone.remove(&gid, vec![leaf]);
    for p in [&admin, &other_old] { assert_eq!(p.inc(&gid, &rm), Inc::Commit, "{} accepts the phone's removal of its pc leaf", p.name); }
    // The desktop receives the Commit and sees it is no longer in the group.
    assert_eq!(pc_peer.inc(&gid, &rm), Inc::Commit);
    assert!(pc_peer.roster(&gid).iter().all(|(_, id)| id != &pc_id), "pc sees itself removed");
    let rest = [&admin, &other_old, &phone];
    assert_in_sync(&rest, &gid);
    assert_eq!(admin.roster(&gid).len(), 3);
    // The desktop cannot decrypt a new message sent after unlinking.
    let ct = admin.enc(&gid, b"after unlink");
    deliver(&[&other_old, &phone], &admin, &gid, &ct, &app(b"after unlink", &admin));
    assert!(!matches!(pc_peer.inc(&gid, &ct), Inc::App { .. }), "removed pc must not read new messages");
    chat_round(&rest, &gid, "after-unlink");
}

/// No room: the group has 20 leaves and a phone on the old core — the desktop cannot join (rejected by the phone
/// and by old members), the group stays intact; once the old member leaves, the desktop joins.
#[test]
fn devlink_pc_waits_for_room_with_old_phones() {
    let gid = b"devlink-full-gid-000000000000001".to_vec();
    let admin = Peer::create(Ver::New, "new-admin");
    admin.create_group(&gid);
    let old_member = Peer::create(Ver::Old, "old-member");
    let (_, w) = admin.add(&gid, vec![old_member.kp()]).unwrap();
    old_member.welcome(&w);
    let mut members = vec![old_member];
    for i in 2..old::MAX_GROUP_MEMBERS {
        let p = Peer::create(Ver::New, &format!("n{i}"));
        let (c, w) = admin.add(&gid, vec![p.kp()]).unwrap();
        for m in &members { assert_eq!(m.inc(&gid, &c), Inc::Commit); }
        p.welcome(&w);
        members.push(p);
    }
    assert_eq!(admin.roster(&gid).len(), old::MAX_GROUP_MEMBERS);
    let Client::New(phone_c) = &members[1].c else { unreachable!() };
    assert_eq!(phone_c.leaf_limit(gid.clone()).unwrap() as usize, new::LEGACY_LEAF_CAP);
    let pc = new::MlsClient::new(b"pc-waits".to_vec()).unwrap();
    assert!(phone_c.add_members(gid.clone(), vec![pc.generate_key_package().unwrap()]).is_err(), "no room: the phone refuses to add its pc");
    // The old member leaves (an admin removes the leaf) — there is room, all remaining members are on the new core.
    let leaf = admin.leaf_of(&gid, &members[0]);
    let rm = admin.remove(&gid, vec![leaf]);
    for m in &members[1..] { assert_eq!(m.inc(&gid, &rm), Inc::Commit); }
    assert_eq!(phone_c.leaf_limit(gid.clone()).unwrap() as usize, new::MAX_GROUP_LEAVES);
    let bundle = phone_c.add_members(gid.clone(), vec![pc.generate_key_package().unwrap()]).unwrap();
    assert_eq!(admin.inc(&gid, &bundle.commit), Inc::Commit);
    assert_eq!(pc.process_welcome(bundle.welcome).unwrap(), gid);
}

// ---------------------------------------------------------------------------------------------
// 6. OpenMLS fixes and changed behaviour
// ---------------------------------------------------------------------------------------------

/// GHSA-qr9h-x63w-vqfm (fixed in 0.7.1): the secret tree is persisted after decryption,
/// so the same ciphertext cannot be decrypted a second time — neither immediately nor after a restart.
/// The old core (for comparison) decrypted the replay — that was the vulnerability.
#[test]
fn replay_is_rejected_after_fix() {
    let gid = b"replay-gid-000000000000000000001".to_vec();
    for sender_ver in [Ver::Old, Ver::New] {
        let a = Peer::create(sender_ver, "a");
        let mut b = Peer::create(Ver::New, "b");
        let mut legacy = Peer::create(Ver::Old, "legacy");
        a.create_group(&gid);
        let (_c, w) = a.add(&gid, vec![b.kp(), legacy.kp()]).unwrap();
        b.welcome(&w);
        legacy.welcome(&w);
        let ct = a.enc(&gid, b"once");
        assert_eq!(b.inc(&gid, &ct), app(b"once", &a));
        assert_eq!(b.inc(&gid, &ct), Inc::Ignored, "replay must not decrypt");
        b.reload();
        assert_eq!(b.inc(&gid, &ct), Inc::Ignored, "replay after restart must not decrypt");
        // Old core — the replay went through (the 0.6 vulnerability that motivated the upgrade).
        assert_eq!(legacy.inc(&gid, &ct), app(b"once", &a));
        legacy.reload();
        assert_eq!(legacy.inc(&gid, &ct), app(b"once", &a), "0.6 accepted replays (GHSA-qr9h-x63w-vqfm)");
    }
}

/// Messages from one sender in reverse order: 0.6 accepted any order. On 0.9 the default window
/// is 5, so the core sets its own window (OUT_OF_ORDER_TOLERANCE), including for groups loaded from
/// 0.6 state.
#[test]
fn out_of_order_delivery_like_before() {
    let gid = b"reorder-gid-00000000000000000001".to_vec();
    let n = 300usize;
    for (sender_ver, receiver_from_old_state) in [(Ver::Old, false), (Ver::New, false), (Ver::Old, true), (Ver::New, true)] {
        let a = Peer::create(sender_ver, "a");
        let mut b = Peer::create(if receiver_from_old_state { Ver::Old } else { Ver::New }, "b");
        a.create_group(&gid);
        let (_c, w) = a.add(&gid, vec![b.kp()]).unwrap();
        b.welcome(&w);
        if receiver_from_old_state {
            b.upgrade();
        }
        let cts: Vec<Vec<u8>> = (0..n).map(|i| a.enc(&gid, format!("m{i}").as_bytes())).collect();
        // Newest first, the rest from the end, with a restart in the middle.
        for (k, i) in (0..n).rev().enumerate() {
            if k == n / 2 {
                b.reload();
            }
            assert_eq!(b.inc(&gid, &cts[i]), app(format!("m{i}").as_bytes(), &a), "m{i} (sender {sender_ver:?}, from old state {receiver_from_old_state})");
        }
    }
    // The window is bounded: older than OUT_OF_ORDER_TOLERANCE is rejected (rather than keeping keys forever).
    let a = Peer::create(Ver::New, "a");
    let b = Peer::create(Ver::New, "b");
    a.create_group(&gid);
    let (_c, w) = a.add(&gid, vec![b.kp()]).unwrap();
    b.welcome(&w);
    // Generations 0, 1, …, 1000: after generation 1000 the head is at 1001; generation 1 is exactly at the edge
    // of the window (1000 behind), generation 0 is past it.
    let first = a.enc(&gid, b"first");
    let second = a.enc(&gid, b"second");
    for _ in 2..new::OUT_OF_ORDER_TOLERANCE {
        a.enc(&gid, b"skipped");
    }
    let newest = a.enc(&gid, b"newest");
    assert_eq!(b.inc(&gid, &newest), app(b"newest", &a));
    assert_eq!(b.inc(&gid, &first), Inc::Ignored, "older than the window");
    assert_eq!(b.inc(&gid, &second), app(b"second", &a), "at the edge of the window");
}

/// Echo of one's own Commit (the relay returned it to the sender) — Ignored in both versions, epoch unchanged.
#[test]
fn own_commit_echo_is_ignored() {
    let gid = b"own-commit-echo-gid-000000000001".to_vec();
    for v in [Ver::Old, Ver::New] {
        let a = Peer::create(v, "a");
        let b = Peer::create(Ver::New, "b");
        a.create_group(&gid);
        let (c, w) = a.add(&gid, vec![b.kp()]).unwrap();
        b.welcome(&w);
        let e = a.epoch(&gid);
        assert_eq!(a.inc(&gid, &c), Inc::Ignored);
        assert_eq!(a.epoch(&gid), e);
        let up = b.update(&gid);
        assert_eq!(b.inc(&gid, &up), Inc::Ignored);
        assert_eq!(a.inc(&gid, &up), Inc::Commit);
        assert_in_sync(&[&a, &b], &gid);
    }
}

/// Garbage and truncated messages — Ignored/parse error, as before, with no panic and no state
/// corruption (including truncated Commit ciphertexts: new tag length checks).
#[test]
fn truncated_messages_do_not_break_the_group() {
    let gid = b"truncated-gid-000000000000000001".to_vec();
    let a = Peer::create(Ver::New, "a");
    let b = Peer::create(Ver::New, "b");
    let c = Peer::create(Ver::Old, "c");
    a.create_group(&gid);
    let (_x, w) = a.add(&gid, vec![b.kp(), c.kp()]).unwrap();
    b.welcome(&w);
    c.welcome(&w);
    let commit = a.update(&gid);
    let Client::New(bc) = &b.c else { unreachable!() };
    for cut in [1usize, 2, 8, 16, 31, 32, 33] {
        let m = &commit[..commit.len() - cut];
        match bc.process_incoming(gid.clone(), m.to_vec()) {
            Ok(r) => assert_eq!(Inc::from(r), Inc::Ignored, "cut {cut}"),
            Err(_) => {} // did not parse as MlsMessage — same as on 0.6
        }
    }
    assert_eq!(b.inc(&gid, &commit), Inc::Commit);
    assert_eq!(c.inc(&gid, &commit), Inc::Commit);
    assert_in_sync(&[&a, &b, &c], &gid);
}

/// Member state with a short-lived KeyPackage (`secs` seconds): this way the test gets in seconds
/// what in real life happens after 84 days — a leaf never updated since it was
/// added becomes "expired". Returns (new state, KeyPackage).
fn short_lived_kp(peer: &Peer, secs: u64) -> (Peer, Vec<u8>) {
    let blob = peer.export();
    let mut v: Value = serde_json::from_slice(&blob).unwrap();
    let (storage, signer) = raw::parts(&blob);
    let (values, kp): (Vec<(Vec<u8>, Vec<u8>)>, Vec<u8>) = match peer.ver() {
        Ver::Old => {
            use openmls_basic_credential_v06::SignatureKeyPair;
            use openmls_rust_crypto_v06::OpenMlsRustCrypto;
            use openmls_v06::prelude::*;
            use tls_codec_v04::{Deserialize as _, Serialize as _};
            let provider = OpenMlsRustCrypto::default();
            provider.storage().values.write().unwrap().extend(storage);
            let signer = SignatureKeyPair::tls_deserialize_exact(&signer).unwrap();
            let cwk = CredentialWithKey { credential: BasicCredential::new(peer.id()).into(), signature_key: signer.public().into() };
            let b = KeyPackage::builder()
                .key_package_lifetime(Lifetime::new(secs))
                .build(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &provider, &signer, cwk)
                .unwrap();
            let kp = b.key_package().tls_serialize_detached().unwrap();
            let vals = provider.storage().values.read().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            (vals, kp)
        }
        Ver::New => {
            use openmls::prelude::*;
            use openmls_basic_credential::SignatureKeyPair;
            use openmls_rust_crypto::OpenMlsRustCrypto;
            use tls_codec::{Deserialize as _, Serialize as _};
            let provider = OpenMlsRustCrypto::default();
            provider.storage().values.write().unwrap().extend(storage);
            let signer = SignatureKeyPair::tls_deserialize_exact(&signer).unwrap();
            let cwk = CredentialWithKey { credential: BasicCredential::new(peer.id()).into(), signature_key: signer.public().into() };
            let b = KeyPackage::builder()
                .key_package_lifetime(Lifetime::new(secs))
                .build(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &provider, &signer, cwk)
                .unwrap();
            let kp = b.key_package().tls_serialize_detached().unwrap();
            let vals = provider.storage().values.read().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            (vals, kp)
        }
    };
    v["storage"] = Value::Array(values.into_iter().map(|(k, x)| json!([hex::encode(k), hex::encode(x)])).collect());
    let blob = serde_json::to_vec(&v).unwrap();
    let c = match peer.ver() {
        Ver::Old => Client::Old(old::MlsClient::from_state(blob).unwrap()),
        Ver::New => Client::New(new::MlsClient::from_state(blob).unwrap()),
    };
    (Peer { name: peer.name.clone(), c }, kp)
}

/// A group older than 84 days where someone never committed: their leaf is "expired". On 0.6 newcomers
/// could join; OpenMLS 0.7+ rejects the join by default. The core skips this check on join —
/// a newcomer on the new core joins as before, from an admin of either version.
#[test]
fn join_group_with_never_updated_expired_leaf() {
    for admin_ver in [Ver::Old, Ver::New] {
        for quiet_ver in [Ver::Old, Ver::New] {
            let gid = format!("expired-leaf-{admin_ver:?}-{quiet_ver:?}-gid-0001").into_bytes();
            let admin = Peer::create(admin_ver, "admin");
            admin.create_group(&gid);
            let (quiet, kp) = short_lived_kp(&Peer::create(quiet_ver, "quiet"), 2);
            let (_c, w) = admin.add(&gid, vec![kp]).unwrap();
            quiet.welcome(&w);
            std::thread::sleep(std::time::Duration::from_secs(4));
            for joiner_ver in [Ver::New, Ver::Old] {
                let joiner = Peer::create(joiner_ver, &format!("joiner-{joiner_ver:?}"));
                let (c, w) = admin.add(&gid, vec![joiner.kp()]).unwrap();
                assert_eq!(quiet.inc(&gid, &c), Inc::Commit);
                assert_eq!(joiner.welcome(&w), gid, "joiner {joiner_ver:?} admin {admin_ver:?} quiet {quiet_ver:?}");
                chat_round(&[&admin, &quiet, &joiner], &gid, "expired-leaf");
                let leaf = admin.leaf_of(&gid, &joiner);
                let rm = admin.remove(&gid, vec![leaf]);
                assert_eq!(quiet.inc(&gid, &rm), Inc::Commit);
            }
        }
    }
}

/// X-Wing: the store core cannot parse an X-Wing ciphersuite KeyPackage, so the new
/// app sends both packages and an old admin takes the legacy one. The old core returns an error on the
/// X-Wing package (does not panic) and its group stays intact; the new core's legacy package (with X-Wing
/// advertised in capabilities) is added by the old core as usual.
#[test]
fn old_core_rejects_xwing_key_package_and_takes_legacy_one() {
    let gid = b"compat-xwing-old-admin-000000001".to_vec();
    let admin = Peer::create(Ver::Old, "old-admin");
    admin.create_group(&gid);
    let joiner = new::MlsClient::new(b"new-joiner".to_vec()).unwrap();
    let xkp = joiner.generate_key_package_for(new::mls_suite_xwing()).unwrap();
    assert!(admin.add(&gid, vec![xkp]).is_err());
    assert_eq!(admin.epoch(&gid), 0);
    let lkp = joiner.generate_key_package_for(new::mls_suite_legacy()).unwrap();
    let (_commit, welcome) = admin.add(&gid, vec![lkp]).unwrap();
    assert_eq!(joiner.process_welcome(welcome).unwrap(), gid);
    let ct = joiner.encrypt(gid.clone(), b"to old admin".to_vec()).unwrap();
    assert_eq!(admin.inc(&gid, &ct), app(b"to old admin", &Peer::create(Ver::New, "new-joiner")));
    // Not everyone in a group with an old leaf advertised X-Wing — it cannot be migrated.
    assert!(!joiner.members_support(gid.clone(), new::mls_suite_xwing()).unwrap());
}

// ---------------------------------------------------------------------------------------------
// 7. Periodic leaf updates: new members (a phone, a linked desktop — each has
//    its own leaf) update their own leaves, old ones (store core) do not update themselves but apply
//    others' updates. Three automatic updates in a row — all in one epoch, messaging in both directions.
// ---------------------------------------------------------------------------------------------

#[test]
fn periodic_self_updates_with_old_members() {
    let gid = b"pcs-mixed".to_vec();
    let peers = vec![
        Peer::create(Ver::Old, "old-android"),
        Peer::create(Ver::New, "new-android"),
        Peer::create(Ver::New, "new-iphone"),
        Peer::create(Ver::New, "linked-pc"),
    ];
    // The group is created by the old version (as store groups are), which adds everyone.
    peers[0].create_group(&gid);
    for i in 1..peers.len() {
        let (commit, welcome) = peers[0].add(&gid, vec![peers[i].kp()]).unwrap();
        let members: Vec<&Peer> = peers[..i].iter().collect();
        deliver(&members, &peers[0], &gid, &commit, &Inc::Commit);
        peers[i].welcome(&welcome);
    }
    let all: Vec<&Peer> = peers.iter().collect();
    let mut last = assert_in_sync(&all, &gid);
    for (round, who) in [1usize, 3, 2].into_iter().enumerate() {
        let c = peers[who].update(&gid);
        deliver(&all, &peers[who], &gid, &c, &Inc::Commit);
        let s = assert_in_sync(&all, &gid);
        assert_ne!(s, last, "round {round}: epoch secret must rotate");
        last = s;
        chat_round(&all, &gid, &format!("auto-update {round}"));
    }
}
