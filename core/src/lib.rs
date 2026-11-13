// umbera_core — anonymous group crypto core (MLS, RFC 9420).
//
// Shared Rust core: ONE implementation powers Android (uniffi→Kotlin) now and iOS
// (uniffi→Swift) later. It does ONLY cryptography (no network): create groups, add/
// remove members (producing Commit+Welcome), process incoming handshake/application
// messages, encrypt/decrypt application payloads, export per-call media secrets, and
// serialize/restore the whole group state for our SQLCipher store.
//
// The transport (anonymous pairwise-rendezvous fan-out) lives in Kotlin/Swift; this
// crate is transport-agnostic — it hands back opaque bytes to send and consumes opaque
// bytes received.

use std::sync::Mutex;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

uniffi::setup_scaffolding!();

// AMF message-franking crypto (verifiable abuse reports; server stays blind). See amf.rs.
// pub so an offline moderation tool can call amf_judge/amf_commit (that tool holds the judge private key).
pub mod amf;

// audit C-7: metadata scrubbing for outgoing PDFs. Not cryptography — it lives here
// because neither platform ships a PDF writer, and one copy cannot drift. See pdf.rs.
pub mod pdf;

// KMP-prep phase 6: 1:1 crypto primitives (Argon2id, AES-GCM, X25519, secp256k1,
// Ed25519, HKDF, SHA-256/PBKDF2, ML-KEM, ML-DSA). See primitives.rs.
pub mod primitives;

// Linked devices: QR linking, device certificate, transfer bundle,
// Communities vault root, desktop joining MLS groups as a separate leaf. See devlink/mod.rs.
pub mod devlink;

// Provider with X-Wing for new groups; the legacy suite stays on plain RustCrypto.
pub mod provider;

// Hybrid call-frame key (X25519 + ML-KEM-1024) delivered over the message channel.
pub mod callkey;
// Reference implementation of the v3 / v3s envelope and the v2 file key (tests only, not part of the library).
mod sealv3;
use provider::{UmberaProvider, LEGACY_SUITE, XWING_SUITE};

/// Default suite wherever no suite is chosen explicitly (legacy FFI calls): X25519 + AES-128-GCM +
/// SHA-256 + Ed25519 — what all store builds use. New groups and key packages for X-Wing
/// are created via explicit `*_for(suite)` calls; the app picks the suite from members' capabilities.
const CIPHERSUITE: Ciphersuite = LEGACY_SUITE;

/// Legacy suite code (0x0001), exposed to the app.
#[uniffi::export]
pub fn mls_suite_legacy() -> u16 {
    LEGACY_SUITE as u16
}

/// X-Wing suite code (0x004D, X25519 + ML-KEM-768), exposed to the app.
#[uniffi::export]
pub fn mls_suite_xwing() -> u16 {
    XWING_SUITE as u16
}

fn suite_from(code: u16) -> R<Ciphersuite> {
    match code {
        c if c == LEGACY_SUITE as u16 => Ok(LEGACY_SUITE),
        c if c == XWING_SUITE as u16 => Ok(XWING_SUITE),
        c => Err(MlsError::Generic(format!("unsupported ciphersuite 0x{c:04x}"))),
    }
}

/// What is known about a key package before adding it: suite and its leaf's memberId (signature verified).
#[derive(uniffi::Record)]
pub struct KeyPackageInfo {
    pub ciphersuite: u16,
    pub identity: Vec<u8>,
    /// The core supports X-Wing (the leaf advertised the suite in its capabilities).
    pub supports_xwing: bool,
}

/// Parse and validate a key package (signature, lifetime, suite) without a group.
#[uniffi::export]
pub fn key_package_info(key_package: Vec<u8>) -> R<KeyPackageInfo> {
    let provider = UmberaProvider::default();
    let kp = KeyPackageIn::tls_deserialize_exact(&key_package)
        .mls()?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .mls()?;
    let leaf = kp.leaf_node();
    Ok(KeyPackageInfo {
        ciphersuite: kp.ciphersuite() as u16,
        identity: leaf.credential().serialized_content().to_vec(),
        supports_xwing: supports_suite(leaf.capabilities(), XWING_SUITE),
    })
}

/// Hard cap on group membership, enforced at the CRYPTO layer (audit finding #1).
///
/// The blind relay has no notion of a "group" — it only forwards opaque pairwise
/// rendezvous entries — so it physically cannot enforce a member cap without learning
/// which rendezvous belong to one group, which would break anonymity (Law 0). Instead
/// every honest client enforces the cap on its own MLS state: it REFUSES to merge any
/// Commit that would push the group past this size (the epoch does not advance), so a
/// malicious admin cannot force the (cap+1)-th member onto honest devices. The server
/// learns nothing — anonymity is untouched.
///
/// Linked devices: a person now has up to 5 leaves (phone + 4 desktops), so
/// the core limit counts LEAVES: up to [MAX_GROUP_LEAVES]; the app counts the "20 people" limit per person
/// (leaves of one account are tied by sibling signatures, devlink::mlsjoin). But phones on the old
/// core (20-leaf limit) reject a Commit that takes the group above 20 leaves: their epoch
/// diverges and the group breaks for them. Hence more than [LEGACY_LEAF_CAP] leaves
/// are allowed only if ALL leaves of the group (and those being added) advertise the
/// [MULTI_DEVICE_CAPABILITY] extension in capabilities, i.e. run the new core. Otherwise the old limit of 20 applies. The rule
/// is the same on the sender (add_members) and the receiver (process_incoming).
pub const MAX_GROUP_MEMBERS: usize = LEGACY_LEAF_CAP;

/// Leaf limit while any member lacks the new-core marker (= the old limit).
pub const LEGACY_LEAF_CAP: usize = 20;

/// Leaf limit when all leaves run the new core: 20 people × (phone + 4 desktops).
pub const MAX_GROUP_LEAVES: usize = 100;

/// "Core supports linked devices" marker in a leaf's capabilities: an extension type from the
/// private-use range (RFC 9420 §17.3, 0xF000–0xFFFF). Old clients parse it
/// as an unknown type and ignore it.
pub const MULTI_DEVICE_CAPABILITY: u16 = 0xF0D1;

/// "Core supports X-Wing groups" marker in a leaf's capabilities, RFC 9420 private range.
///
/// Advertising the X-Wing suite (0x004D) in capabilities does NOT prove support: the store-build core
/// (OpenMLS 0.6) lists it by default even though its provider cannot do X-Wing
/// (`openmls_rust_crypto` 0.3: "XWing is not supported"). So only this marker counts — it is set
/// only by a core with an X-Wing provider (src/provider.rs). Old cores skip the unknown extension.
pub const XWING_CAPABILITY: u16 = 0xF0D2;

/// Suites a leaf advertises: exactly the openmls default list of the store-build core (without this,
/// openmls 0.9 with the PQ feature would advertise a dozen draft suites we do not implement).
const OUR_SUITES: [Ciphersuite; 4] = [
    LEGACY_SUITE,
    Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    XWING_SUITE,
];

fn our_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&OUR_SUITES),
        Some(&[ExtensionType::Unknown(MULTI_DEVICE_CAPABILITY), ExtensionType::Unknown(XWING_CAPABILITY)]),
        None,
        None,
    )
}

fn has_xwing_marker(caps: &Capabilities) -> bool {
    caps.extensions().contains(&ExtensionType::Unknown(XWING_CAPABILITY))
}

/// Whether a leaf actually supports [suite]: legacy — all leaves; X-Wing — only with the [XWING_CAPABILITY] marker.
fn supports_suite(caps: &Capabilities, suite: Ciphersuite) -> bool {
    match suite {
        XWING_SUITE => has_xwing_marker(caps) && caps.ciphersuites().iter().any(|c| *c == VerifiableCiphersuite::from(suite)),
        _ => caps.ciphersuites().iter().any(|c| *c == VerifiableCiphersuite::from(suite)),
    }
}

/// Whether all current leaves of the group support [suite].
fn all_leaves_support(group: &MlsGroup, suite: Ciphersuite) -> R<bool> {
    let v = serde_json::to_value(group.export_ratchet_tree()).mls()?;
    let nodes: Vec<Option<Node>> = serde_json::from_value(v).mls()?;
    Ok(nodes.iter().all(|n| match n {
        Some(Node::LeafNode(l)) => supports_suite(l.capabilities(), suite),
        _ => true,
    }))
}

fn has_marker(caps: &Capabilities) -> bool {
    caps.extensions().contains(&ExtensionType::Unknown(MULTI_DEVICE_CAPABILITY))
}

/// Whether all current leaves of the group advertise the new-core marker.
fn all_leaves_marked(group: &MlsGroup) -> R<bool> {
    // MlsGroup has no public access to other members' leaves; the tree is exported
    // as a public type and parsed back into public Node/LeafNode (serde of the same openmls).
    let v = serde_json::to_value(group.export_ratchet_tree()).mls()?;
    let nodes: Vec<Option<Node>> = serde_json::from_value(v).mls()?;
    Ok(nodes.iter().all(|n| match n {
        Some(Node::LeafNode(l)) => has_marker(l.capabilities()),
        _ => true,
    }))
}

/// How many leaves are allowed after a Commit.
fn leaf_limit(group: &MlsGroup, added_all_marked: bool) -> R<usize> {
    Ok(if added_all_marked && all_leaves_marked(group)? { MAX_GROUP_LEAVES } else { LEGACY_LEAF_CAP })
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MlsError {
    #[error("mls: {0}")]
    Generic(String),
}
type R<T> = Result<T, MlsError>;

/// `.mls()?` turns any error into [MlsError] without the reflexive-From conflict a
/// blanket `impl From` would cause.
trait IntoMls<T> {
    fn mls(self) -> R<T>;
}
impl<T, E: std::fmt::Display> IntoMls<T> for Result<T, E> {
    fn mls(self) -> R<T> {
        self.map_err(|e| MlsError::Generic(e.to_string()))
    }
}

/// What `add_members` hands back: the Commit to fan out to EXISTING members, and the
/// Welcome to send to the NEW members (both already MLS-encrypted).
/// Anti-equivocation: recompute the public "quant address" from a peer's classical
/// (secp256k1) + Dilithium public keys, EXACTLY as the server computes it, so a client can check
/// resolved keys against an address it got out of band: raw = BLAKE3(classical || dilithium); checksum = BLAKE3(raw)[:4];
/// address = "quant" + base58(raw || checksum).
///
/// The client uses this to verify, with ZERO trust in any server, that the keys a (possibly malicious)
/// peer-home-server returned actually hash to the address the user obtained out-of-band. A mismatch ⇒ the
/// server tried to substitute keys ⇒ reject. Inputs are hex (as the server returns them).
#[uniffi::export]
pub fn quant_address(classical_hex: String, dilithium_hex: String) -> Result<String, MlsError> {
    let cb = unhex(classical_hex.trim())?;
    let db = unhex(dilithium_hex.trim())?;
    let mut h = blake3::Hasher::new();
    h.update(&cb);
    h.update(&db);
    let raw = h.finalize();
    let raw = raw.as_bytes(); // 32 bytes
    let cs = blake3::hash(raw);
    let mut payload = Vec::with_capacity(36);
    payload.extend_from_slice(raw);
    payload.extend_from_slice(&cs.as_bytes()[..4]);
    Ok(format!("quant{}", bs58::encode(payload).into_string()))
}

#[derive(uniffi::Record)]
pub struct CommitBundle {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// Classified result of feeding an inbound MLS message to the group.
#[derive(uniffi::Enum)]
pub enum Incoming {
    /// A decrypted application payload (a real chat message/control).
    ///
    /// `sender_identity` is the AUTHENTICATED sender: the credential OpenMLS verified
    /// while decrypting, whose serialized content is that member's leaf id (the same
    /// bytes `members()` returns as `identity`, i.e. the app's memberId).
    ///
    /// It exists because MLS on its own only proves "SOME member of this epoch sent
    /// this". The application layer used to take the sender from a field inside the
    /// decrypted payload — a value the sender picks freely — and gate admin actions on
    /// it, so any member could claim to be an admin (audit K-1). Handing the verified
    /// identity out lets the caller reject a payload whose claimed sender isn't the one
    /// MLS authenticated.
    Application {
        plaintext: Vec<u8>,
        sender_identity: Vec<u8>,
    },
    /// A membership change (Commit) was applied; the epoch advanced.
    CommitApplied,
    /// A Commit was REFUSED because it would push the group past MAX_GROUP_MEMBERS
    /// (audit finding #1). It was NOT merged — the epoch did not advance — so a hostile
    /// admin cannot force an over-cap member onto this honest client.
    CommitRejected,
    /// A proposal was stored (awaiting a Commit). Nothing to show yet.
    Proposal,
    /// Our own message echoed back / not for us / stale epoch — ignore.
    Ignored,
}

#[derive(uniffi::Record)]
pub struct MemberInfo {
    pub leaf_index: u32,
    pub identity: Vec<u8>,
}

/// Persisted identity+groups blob (everything needed to resume on a fresh device).
#[derive(Serialize, Deserialize)]
struct PersistState {
    identity: Vec<u8>,
    signer: Vec<u8>, // SignatureKeyPair tls-serialized
    storage: Vec<(String, String)>, // MemoryStorage key→value (hex)
}

/// One MLS identity + its groups. uniffi Object (Arc on the Kotlin/Swift side).
#[derive(uniffi::Object)]
pub struct MlsClient {
    inner: Mutex<Inner>,
}

struct Inner {
    provider: UmberaProvider,
    signer: SignatureKeyPair,
    identity: Vec<u8>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
/// Panic-free hex parsing: odd length and any non-hex character (including non-ASCII) is an error, not a slice
/// through the middle of a character (`&s[i..i + 2]` used to panic on `from_state` / `quant_address`).
fn unhex(s: &str) -> R<Vec<u8>> {
    fn nib(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    }
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return Err(MlsError::Generic("hex: odd length".into()));
    }
    b.chunks_exact(2)
        .map(|p| match (nib(p[0]), nib(p[1])) {
            (Some(h), Some(l)) => Ok(h << 4 | l),
            _ => Err(MlsError::Generic("hex: invalid digit".into())),
        })
        .collect()
}

// Private helpers (NOT exported over FFI).
impl MlsClient {
    /// Core lock that never fails permanently. uniffi turns a Rust panic into an FFI error, but
    /// a panic under `lock().unwrap()` poisoned the Mutex, and EVERY subsequent call (all groups) failed until the
    /// process restarted: one panic while parsing a foreign frame = remote denial of service of the group core.
    ///
    /// Deliberate: after a panic we clear the poison and continue. The state is the in-memory openmls store; a group
    /// is reloaded from it on every call (`load_group`) rather than kept between calls, so an interrupted
    /// call loses only its own unwritten `MlsGroup`. Store writes are per key (one insert into a HashMap under its own
    /// RwLock), so a half-written key cannot occur; if a panic hits between writes of one operation, only that
    /// group fails (its `load_group` returns an error), the rest keep working. Persisting to disk (export_state) —
    /// always from this same store.
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|poisoned| {
            self.inner.clear_poison();
            poisoned.into_inner()
        })
    }

    fn cwk(g: &Inner) -> CredentialWithKey {
        let credential = BasicCredential::new(g.identity.clone());
        CredentialWithKey {
            credential: credential.into(),
            signature_key: g.signer.public().into(),
        }
    }

    fn load_group(g: &Inner, gid: &[u8]) -> R<MlsGroup> {
        let mut group = MlsGroup::load(g.provider.storage(), &GroupId::from_slice(gid))
            .mls()?
            .ok_or_else(|| MlsError::Generic("group not found".into()))?;
        // Groups created before OpenMLS 0.9 (and by the store-build core) keep the default window —
        // 5 messages. Apply our window on first load; leave the rest of the config untouched.
        if *group.configuration().sender_ratchet_configuration() != sender_ratchet_config() {
            let cfg = with_our_ratchet(group.configuration())?;
            group.set_configuration(g.provider.storage(), &cfg).mls()?;
        }
        Ok(group)
    }
}

/// Sender ratchet window (SenderRatchetConfiguration) for all our groups.
///
/// OpenMLS 0.7.1 fixed GHSA-qr9h-x63w-vqfm: after decryption the secret tree is persisted and
/// the used key is erased (replaying the same ciphertext no longer decrypts — that is
/// the fix). Side effect: a late message from a sender decrypts only if
/// it lags the newest one received from that sender by at most `out_of_order_tolerance`.
/// The default is 5. On 0.6 keys were not persisted and any order worked. Our transport
/// does not guarantee ordering (multiple delivery paths, offline queue), so the window is 1000, same as
/// the forward distance: anything the receiver could decrypt "ahead" it can also decrypt late.
/// Cost: up to 1000 keys per sender in the state, and only for messages actually skipped;
/// received ones are kept as an empty marker.
pub const OUT_OF_ORDER_TOLERANCE: u32 = 1000;
/// Forward distance — the OpenMLS default (as on 0.6).
pub const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;

fn sender_ratchet_config() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(OUT_OF_ORDER_TOLERANCE, MAXIMUM_FORWARD_DISTANCE)
}

/// The same group config, but with our ratchet window. Via serde: MlsGroupJoinConfig has no
/// "from existing" constructor, and this way all fields (wire format, padding, past epochs…) carry over
/// as is, even if OpenMLS adds new ones.
fn with_our_ratchet(c: &MlsGroupJoinConfig) -> R<MlsGroupJoinConfig> {
    let mut v = serde_json::to_value(c).mls()?;
    let obj = v
        .as_object_mut()
        .ok_or_else(|| MlsError::Generic("join config: not an object".into()))?;
    obj.insert(
        "sender_ratchet_configuration".into(),
        serde_json::to_value(sender_ratchet_config()).mls()?,
    );
    serde_json::from_value(v).mls()
}

#[uniffi::export]
impl MlsClient {
    /// Brand-new identity. `identity` = our stable per-group leaf id bytes (memberId).
    #[uniffi::constructor]
    pub fn new(identity: Vec<u8>) -> R<std::sync::Arc<MlsClient>> {
        let provider = UmberaProvider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).mls()?;
        signer.store(provider.storage()).mls()?;
        Ok(std::sync::Arc::new(MlsClient {
            inner: Mutex::new(Inner {
                provider,
                signer,
                identity,
            }),
        }))
    }

    /// Restore from a previously exported state blob (see [export_state]).
    #[uniffi::constructor]
    pub fn from_state(blob: Vec<u8>) -> R<std::sync::Arc<MlsClient>> {
        let st: PersistState = serde_json::from_slice(&blob).mls()?;
        let provider = UmberaProvider::default();
        {
            let store = provider.storage();
            let mut map = store
                .values
                .write()
                .map_err(|_| MlsError::Generic("storage lock".into()))?;
            for (k, v) in &st.storage {
                map.insert(unhex(k)?, unhex(v)?);
            }
        }
        let signer = SignatureKeyPair::tls_deserialize_exact(&st.signer).mls()?;
        Ok(std::sync::Arc::new(MlsClient {
            inner: Mutex::new(Inner {
                provider,
                signer,
                identity: st.identity,
            }),
        }))
    }

    /// Same leaf (memberId and Ed25519 signing key), but without groups or packages: for moving a group to another
    /// suite. The signing key is unchanged, so device-link (sibling) signatures still verify
    /// against the leaf keys of the new tree.
    pub fn spawn_same_identity(&self) -> R<std::sync::Arc<MlsClient>> {
        let g = self.lock();
        let provider = UmberaProvider::default();
        let signer = SignatureKeyPair::tls_deserialize_exact(&g.signer.tls_serialize_detached().mls()?).mls()?;
        signer.store(provider.storage()).mls()?;
        Ok(std::sync::Arc::new(MlsClient {
            inner: Mutex::new(Inner {
                provider,
                signer,
                identity: g.identity.clone(),
            }),
        }))
    }

    /// Serialize the whole identity+groups for our SQLCipher store.
    pub fn export_state(&self) -> R<Vec<u8>> {
        let g = self.lock();
        let storage: Vec<(String, String)> = {
            let map = g
                .provider
                .storage()
                .values
                .read()
                .map_err(|_| MlsError::Generic("storage lock".into()))?;
            map.iter().map(|(k, v)| (hex(k), hex(v))).collect()
        };
        let st = PersistState {
            identity: g.identity.clone(),
            signer: g.signer.tls_serialize_detached().mls()?,
            storage,
        };
        serde_json::to_vec(&st).mls()
    }

    /// Our Ed25519 signature public key (identifies our leaf to peers).
    pub fn signature_public_key(&self) -> Vec<u8> {
        self.lock().signer.public().to_vec()
    }

    /// Produce a fresh KeyPackage (serialized) to hand to whoever will add us to a group.
    pub fn generate_key_package(&self) -> R<Vec<u8>> {
        self.generate_key_package_for(CIPHERSUITE as u16)
    }

    /// Key package in suite [suite] ([mls_suite_legacy] or [mls_suite_xwing]). The same leaf (memberId and
    /// signing key) can issue packages in both suites: the inviter picks the one that fits the group.
    pub fn generate_key_package_for(&self, suite: u16) -> R<Vec<u8>> {
        let suite = suite_from(suite)?;
        let g = self.lock();
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(our_capabilities())
            .build(suite, &g.provider, &g.signer, Self::cwk(&g))
            .mls()?;
        bundle.key_package().tls_serialize_detached().mls()
    }

    /// Group suite (RFC 9420 code).
    pub fn group_ciphersuite(&self, gid: Vec<u8>) -> R<u16> {
        let g = self.lock();
        let group = Self::load_group(&g, &gid)?;
        Ok(group.ciphersuite() as u16)
    }

    /// Whether all leaves of the group advertise support for [suite] (i.e. every member runs a core that
    /// supports it). The app uses this to decide whether the group can be moved to X-Wing.
    pub fn members_support(&self, gid: Vec<u8>, suite: u16) -> R<bool> {
        let suite = suite_from(suite)?;
        let g = self.lock();
        let group = Self::load_group(&g, &gid)?;
        all_leaves_support(&group, suite)
    }

    /// Create a new group with our chosen 32-byte group id (`gid`). We become the
    /// single initial member (admin handled at the app layer, not by MLS).
    pub fn create_group(&self, gid: Vec<u8>) -> R<()> {
        self.create_group_for(gid, CIPHERSUITE as u16)
    }

    /// New group in suite [suite]. No state may exist under the same gid in this client.
    pub fn create_group_for(&self, gid: Vec<u8>, suite: u16) -> R<()> {
        let suite = suite_from(suite)?;
        let g = self.lock();
        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(suite)
            .capabilities(our_capabilities())
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(sender_ratchet_config())
            .build();
        MlsGroup::new_with_group_id(
            &g.provider,
            &g.signer,
            &cfg,
            GroupId::from_slice(&gid),
            Self::cwk(&g),
        )
        .mls()?;
        Ok(())
    }

    /// Add members by their serialized KeyPackages → returns Commit (for existing
    /// members) + Welcome (for the new ones). We merge our own commit immediately.
    pub fn add_members(&self, gid: Vec<u8>, key_packages: Vec<Vec<u8>>) -> R<CommitBundle> {
        let g = self.lock();
        let mut group = Self::load_group(&g, &gid)?;
        // CRYPTO-LEVEL MEMBERSHIP CAP (audit finding #1): an honest admin fails CLOSED —
        // it will not even produce a Commit that takes the group past the cap, so it can
        // never create the over-cap fork honest members would reject anyway.
        let current = group.members().count();
        if current + key_packages.len() > MAX_GROUP_LEAVES {
            return Err(MlsError::Generic(format!(
                "group member cap ({}) exceeded: {} + {}",
                MAX_GROUP_LEAVES,
                current,
                key_packages.len()
            )));
        }
        let mut kps = Vec::with_capacity(key_packages.len());
        for raw in &key_packages {
            let kp_in = KeyPackageIn::tls_deserialize_exact(raw).mls()?;
            let kp = kp_in
                .validate(g.provider.crypto(), ProtocolVersion::Mls10)
                .mls()?;
            if kp.ciphersuite() != group.ciphersuite() {
                return Err(MlsError::Generic(format!(
                    "key package ciphersuite 0x{:04x} does not match the group (0x{:04x})",
                    kp.ciphersuite() as u16,
                    group.ciphersuite() as u16
                )));
            }
            kps.push(kp);
        }
        let added_marked = kps.iter().all(|k| has_marker(k.leaf_node().capabilities()));
        let limit = leaf_limit(&group, added_marked)?;
        if current + kps.len() > limit {
            return Err(MlsError::Generic(format!(
                "group member cap ({}) exceeded: {} + {} (members on an old app version keep the cap at {})",
                limit,
                current,
                kps.len(),
                LEGACY_LEAF_CAP
            )));
        }
        let (commit, welcome, _info) = group.add_members(&g.provider, &g.signer, &kps).mls()?;
        group.merge_pending_commit(&g.provider).mls()?;
        Ok(CommitBundle {
            commit: commit.tls_serialize_detached().mls()?,
            welcome: welcome.tls_serialize_detached().mls()?,
        })
    }

    /// Remove members by leaf index → Commit to fan out. We merge our own commit.
    pub fn remove_members(&self, gid: Vec<u8>, leaf_indices: Vec<u32>) -> R<Vec<u8>> {
        let g = self.lock();
        let mut group = Self::load_group(&g, &gid)?;
        let idx: Vec<LeafNodeIndex> = leaf_indices.iter().map(|i| LeafNodeIndex::new(*i)).collect();
        let (commit, _welcome, _info) = group.remove_members(&g.provider, &g.signer, &idx).mls()?;
        group.merge_pending_commit(&g.provider).mls()?;
        commit.tls_serialize_detached().mls()
    }

    /// Plain rekey (post-compromise security) with no membership change → Commit.
    pub fn update_keys(&self, gid: Vec<u8>) -> R<Vec<u8>> {
        let g = self.lock();
        let mut group = Self::load_group(&g, &gid)?;
        // OpenMLS 0.7+: self_update returns a CommitMessageBundle instead of a (commit, welcome, info) tuple.
        let bundle = group
            // Rekey also advertises the new-core marker in our leaf (a leaf created by the old
            // core before the upgrade gets it here).
            .self_update(&g.provider, &g.signer, LeafNodeParameters::builder().with_capabilities(our_capabilities()).build())
            .mls()?;
        let commit = bundle.commit().tls_serialize_detached().mls()?;
        group.merge_pending_commit(&g.provider).mls()?;
        Ok(commit)
    }

    /// Join a group from a Welcome we received → returns the group id we joined.
    pub fn process_welcome(&self, welcome_bytes: Vec<u8>) -> R<Vec<u8>> {
        let g = self.lock();
        let msg = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).mls()?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Generic("not a welcome".into())),
        };
        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(sender_ratchet_config())
            .build();
        // OpenMLS 0.7+ on join checks the lifetime of tree leaves that have never been
        // updated since being added — by default 84 days from KeyPackage issuance. 0.6 had no such
        // check. A member who has not committed for a long time (the app does not call update_keys
        // on its own) would otherwise permanently block every newcomer on the new core. KeyPackage lifetime
        // is still checked when adding (KeyPackageIn::validate in add_members), and signatures and
        // everything else in the tree as well; only this check is skipped, as before the upgrade.
        let staged = StagedWelcome::build_from_welcome(&g.provider, &cfg, welcome)
            .mls()?
            .skip_lifetime_validation()
            .build()
            .mls()?;
        let group = staged.into_group(&g.provider).mls()?;
        Ok(group.group_id().as_slice().to_vec())
    }

    /// Encrypt an application payload (chat message / control) for the group.
    pub fn encrypt(&self, gid: Vec<u8>, plaintext: Vec<u8>) -> R<Vec<u8>> {
        let g = self.lock();
        let mut group = Self::load_group(&g, &gid)?;
        let out = group.create_message(&g.provider, &g.signer, &plaintext).mls()?;
        out.tls_serialize_detached().mls()
    }

    /// Feed an inbound MLS message to a group: decrypts application payloads and
    /// applies membership Commits. Classifies the outcome.
    pub fn process_incoming(&self, gid: Vec<u8>, message: Vec<u8>) -> R<Incoming> {
        self.process_incoming_inner(gid, message, None).map(|(inc, _)| inc)
    }

    /// Same as `process_incoming`, plus the sender's leaf (Application, Commit, Proposal
    /// from a member; `None` — external sender or the frame was not processed).
    ///
    /// `allowed_handshake_senders`: if set, a Commit/Proposal is accepted only when the credential of the sender's
    /// leaf (verified by OpenMLS) is in this list. Otherwise the Commit is NOT merged (the epoch does not advance) —
    /// `CommitRejected`, a Proposal — `Ignored`. This lets the app bind a Commit to the ML-DSA signer of the envelope:
    /// a member with a valid PQ signature of their own cannot push through another leaf's Commit. `None` — no check, as before.
    /// Application messages are not restricted by this list (their leaf is checked by the app).
    pub fn process_incoming_with_sender(
        &self,
        gid: Vec<u8>,
        message: Vec<u8>,
        allowed_handshake_senders: Option<Vec<Vec<u8>>>,
    ) -> R<IncomingWithSender> {
        self.process_incoming_inner(gid, message, allowed_handshake_senders.as_deref())
            .map(|(incoming, sender)| IncomingWithSender { incoming, sender })
    }

    /// Derive a fresh symmetric secret bound to the current epoch (e.g. a conference
    /// media key). Rotates automatically every time the group rekeys.
    pub fn export_secret(&self, gid: Vec<u8>, label: String, length: u32) -> R<Vec<u8>> {
        let g = self.lock();
        let group = Self::load_group(&g, &gid)?;
        group
            // OpenMLS 0.7+: the exporter needs only the crypto provider (#1786), the secret is the same.
            .export_secret(g.provider.crypto(), &label, &[], length as usize)
            .mls()
    }

    /// Current epoch number (advances on every membership change / rekey).
    pub fn epoch(&self, gid: Vec<u8>) -> R<u64> {
        let g = self.lock();
        let group = Self::load_group(&g, &gid)?;
        Ok(group.epoch().as_u64())
    }

    /// Member identities (leaf credential bytes = memberIds) + their leaf indices.
    pub fn members(&self, gid: Vec<u8>) -> R<Vec<MemberInfo>> {
        let g = self.lock();
        let group = Self::load_group(&g, &gid)?;
        let mut out = Vec::new();
        for m in group.members() {
            out.push(MemberInfo {
                leaf_index: m.index.u32(),
                identity: m.credential.serialized_content().to_vec(),
            });
        }
        Ok(out)
    }

    /// How many leaves the group may have right now: 100 if all leaves run the new core (the
    /// MULTI_DEVICE_CAPABILITY marker), otherwise 20. The app uses this to decide whether
    /// desktops can be added: if they do not fit into 20 leaves and someone is still on an old version, wait.
    pub fn leaf_limit(&self, gid: Vec<u8>) -> R<u32> {
        let g = self.lock();
        let group = Self::load_group(&g, &gid)?;
        Ok(leaf_limit(&group, true)? as u32)
    }

    /// Whether our leaf carries the new-core marker. If not, run update_keys (rekey) and send the
    /// Commit: after it the leaf advertises the marker.
    pub fn own_leaf_marked(&self, gid: Vec<u8>) -> R<bool> {
        let g = self.lock();
        let group = Self::load_group(&g, &gid)?;
        // The "new-core marker" now means both the linked-devices marker and advertised X-Wing: a leaf lacking
        // either (issued by an old core) advertises both after a rekey.
        Ok(group
            .own_leaf_node()
            .map(|l| has_marker(l.capabilities()) && supports_suite(l.capabilities(), XWING_SUITE))
            .unwrap_or(false))
    }
}

#[cfg(test)]
impl MlsClient {
    /// KeyPackage as the old core makes it (without the new marker) — for compatibility tests.
    pub(crate) fn legacy_key_package(&self) -> R<Vec<u8>> {
        let g = self.lock();
        // As in the store-build core: default suites (X-Wing is in the list!), no new-core markers.
        let store_caps = Capabilities::new(None, Some(&OUR_SUITES), None, None, None);
        let bundle = KeyPackage::builder()
            .leaf_node_capabilities(store_caps)
            .build(CIPHERSUITE, &g.provider, &g.signer, Self::cwk(&g))
            .mls()?;
        bundle.key_package().tls_serialize_detached().mls()
    }
}


/// Sender leaf of an incoming frame: tree index and credential (identity), verified
/// by OpenMLS (leaf signature).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SenderLeaf {
    pub leaf_index: u32,
    pub identity: Vec<u8>,
}

/// Result of `process_incoming_with_sender`.
#[derive(uniffi::Record)]
pub struct IncomingWithSender {
    pub incoming: Incoming,
    pub sender: Option<SenderLeaf>,
}

impl MlsClient {
    fn process_incoming_inner(
        &self,
        gid: Vec<u8>,
        message: Vec<u8>,
        allowed_handshake_senders: Option<&[Vec<u8>]>,
    ) -> R<(Incoming, Option<SenderLeaf>)> {
        let g = self.lock();

        let mut group = Self::load_group(&g, &gid)?;
        let msg = MlsMessageIn::tls_deserialize_exact(&message).mls()?;
        let protocol = match msg.try_into_protocol_message() {
            Ok(p) => p,
            Err(_) => return Ok((Incoming::Ignored, None)),
        };
        let processed = match group.process_message(&g.provider, protocol) {
            Ok(p) => p,
            Err(_) => return Ok((Incoming::Ignored, None)),
        };
        // Capture the authenticated sender BEFORE consuming the message: into_content()
        // drops everything except the payload, which is exactly how the sender identity
        // came to be taken from attacker-chosen JSON instead (audit K-1).
        let sender_identity = processed.credential().serialized_content().to_vec();
        // Sender leaf for Commit/Proposal too (the "leaf ↔ ML-DSA signer" check in Kotlin).
        let sender = match processed.sender() {
            Sender::Member(leaf) => Some(SenderLeaf { leaf_index: leaf.u32(), identity: sender_identity.clone() }),
            _ => None,
        };
        // Commit/Proposal only from a leaf in the list (if set). Checked BEFORE merging.
        let handshake_ok = match allowed_handshake_senders {
            None => true,
            Some(list) => sender.as_ref().map(|s| list.iter().any(|a| a == &s.identity)).unwrap_or(false),
        };
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(_) if !handshake_ok => Ok((Incoming::CommitRejected, sender)),
            ProcessedMessageContent::ProposalMessage(_) | ProcessedMessageContent::ExternalJoinProposalMessage(_)
                if !handshake_ok => Ok((Incoming::Ignored, sender)),
            ProcessedMessageContent::ApplicationMessage(app) => Ok((Incoming::Application {
                plaintext: app.into_bytes(),
                sender_identity,
            }, sender)),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                // CRYPTO-LEVEL MEMBERSHIP CAP (audit finding #1): inspect the staged
                // commit's NET membership effect BEFORE merging. If it would push the
                // group past MAX_GROUP_MEMBERS, refuse it — do NOT merge, so the epoch
                // does not advance on this honest client. A malicious admin therefore
                // cannot force the (cap+1)-th member onto honest devices; the blind
                // server never sees the group, so anonymity is untouched.
                let current = group.members().count();
                let adds = staged.add_proposals().count();
                let removes = staged.remove_proposals().count();
                let resulting = current.saturating_add(adds).saturating_sub(removes);
                // Same rule as on the sender: more than 20 leaves only if all leaves
                // and all added ones run the new core; more than 100 — never.
                let added_marked = staged
                    .add_proposals()
                    .all(|p| has_marker(p.add_proposal().key_package().leaf_node().capabilities()));
                let limit = if resulting > LEGACY_LEAF_CAP { leaf_limit(&group, added_marked)? } else { LEGACY_LEAF_CAP };
                if resulting > limit {
                    // Drop the staged commit unmerged; epoch stays put.
                    return Ok((Incoming::CommitRejected, sender));
                }
                group.merge_staged_commit(&g.provider, *staged).mls()?;
                Ok((Incoming::CommitApplied, sender))
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok((Incoming::Proposal, sender)),
            // OpenMLS 0.9 no longer returns an error for our own echo but yields these two
            // variants. On 0.6 both were a process_message error → Ignored; we keep that:
            //  • OwnPrivateMessage — our own encrypted message came back from the relay;
            //    it cannot be decrypted and its sender is not verified (#2099) — just skip it;
            //  • OwnPendingCommit — our Commit matching a pending one. We merge our Commits right
            //    on creation (add/remove/update_keys), so we never have a pending one; if one does
            //    exist (a Commit built bypassing our methods), its fate is up to whoever built it.
            ProcessedMessageContent::OwnPrivateMessage | ProcessedMessageContent::OwnPendingCommit => {
                Ok((Incoming::Ignored, None))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A panic under the lock (as while parsing a foreign frame) does not disable the core until restart —
    /// the next call clears the poison; groups and signing keep working.
    #[test]
    fn panic_under_lock_does_not_disable_the_core() {
        let gid = b"poison-recovery-group-0001".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        alice.create_group(gid.clone()).unwrap();
        let pk = alice.signature_public_key();
        let a = alice.clone();
        let r = std::thread::spawn(move || {
            let _g = a.lock();
            panic!("panic while parsing a foreign frame");
        })
        .join();
        assert!(r.is_err());
        assert!(alice.inner.is_poisoned(), "the check must start with a poisoned lock");
        assert_eq!(alice.signature_public_key(), pk);
        assert!(!alice.inner.is_poisoned());
        assert_eq!(alice.members(gid.clone()).unwrap().len(), 1);
        assert!(!alice.encrypt(gid.clone(), b"hello".to_vec()).unwrap().is_empty());
        assert!(!alice.export_state().unwrap().is_empty());
    }

    /// Corrupted hex is an error, not a panic (odd length, non-ASCII, garbage).
    #[test]
    fn unhex_rejects_malformed_without_panic() {
        assert_eq!(unhex("00ff7A").unwrap(), vec![0x00, 0xff, 0x7a]);
        assert!(unhex("").unwrap().is_empty());
        for bad in ["0", "abc", "zz", "a\u{e9}b", "\u{e9}\u{e9}", "\u{1F600}", "0g", " 0"] {
            assert!(unhex(bad).is_err(), "{bad:?}");
        }
        assert!(quant_address("abc".into(), "00".into()).is_err());
        assert!(quant_address("a\u{e9}b".into(), "00".into()).is_err());
        let blob = br#"{"identity":[1],"signer":[],"storage":[["abc","00"]]}"#.to_vec();
        assert!(MlsClient::from_state(blob).is_err());
        let blob = br#"{"identity":[1],"signer":[],"storage":[["a\u00e9b","00"]]}"#.to_vec();
        assert!(MlsClient::from_state(blob).is_err());
        assert!(MlsClient::from_state(vec![0xff, 0xff, 0xff, 0xff]).is_err());
    }

    /// With a member on the old core the limit is 20 leaves (otherwise their epoch falls behind);
    /// when everyone is on the new core — up to 100 leaves; the receiver applies the same rule.
    #[test]
    fn leaf_cap_depends_on_every_member_running_the_new_core() {
        let gid = b"cap-multidevice-group-0001".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        alice.create_group(gid.clone()).unwrap();
        assert!(alice.own_leaf_marked(gid.clone()).unwrap());
        // Bob is on the old core (leaf without the marker).
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        let b = alice.add_members(gid.clone(), vec![bob.legacy_key_package().unwrap()]).unwrap();
        bob.process_welcome(b.welcome).unwrap();
        assert!(!bob.own_leaf_marked(gid.clone()).unwrap());
        assert_eq!(alice.leaf_limit(gid.clone()).unwrap(), LEGACY_LEAF_CAP as u32);
        let carol = MlsClient::new(b"carol".to_vec()).unwrap();
        let c = alice.add_members(gid.clone(), vec![carol.generate_key_package().unwrap()]).unwrap();
        carol.process_welcome(c.welcome).unwrap();
        assert!(matches!(bob.process_incoming(gid.clone(), c.commit).unwrap(), Incoming::CommitApplied));
        for i in 4..=LEGACY_LEAF_CAP {
            let m = MlsClient::new(format!("m{i}").into_bytes()).unwrap();
            let cb = alice.add_members(gid.clone(), vec![m.generate_key_package().unwrap()]).unwrap();
            for peer in [&bob, &carol] {
                assert!(matches!(peer.process_incoming(gid.clone(), cb.commit.clone()).unwrap(), Incoming::CommitApplied));
            }
        }
        // 21st leaf while a member is on the old core — rejected by the sender.
        let pc = MlsClient::new(b"pc".to_vec()).unwrap();
        let pc_kp = pc.generate_key_package().unwrap();
        assert!(alice.add_members(gid.clone(), vec![pc_kp.clone()]).is_err());
        // Bob updated the app and did a rekey: now all leaves run the new core.
        let up = bob.update_keys(gid.clone()).unwrap();
        assert!(bob.own_leaf_marked(gid.clone()).unwrap());
        assert!(matches!(alice.process_incoming(gid.clone(), up.clone()).unwrap(), Incoming::CommitApplied));
        assert!(matches!(carol.process_incoming(gid.clone(), up).unwrap(), Incoming::CommitApplied));
        assert_eq!(alice.leaf_limit(gid.clone()).unwrap(), MAX_GROUP_LEAVES as u32);
        let cb = alice.add_members(gid.clone(), vec![pc_kp]).unwrap();
        for peer in [&bob, &carol] {
            assert!(matches!(peer.process_incoming(gid.clone(), cb.commit.clone()).unwrap(), Incoming::CommitApplied));
        }
        pc.process_welcome(cb.welcome).unwrap();
        assert_eq!(bob.members(gid.clone()).unwrap().len(), LEGACY_LEAF_CAP + 1);
        // A new member on the old core is not added to a 21-leaf group…
        let old = MlsClient::new(b"old".to_vec()).unwrap();
        assert!(alice.add_members(gid.clone(), vec![old.legacy_key_package().unwrap()]).is_err());
        // …and a malicious Commit with such an add is rejected by honest members.
        let evil = {
            let g = alice.inner.lock().unwrap();
            let mut group = MlsClient::load_group(&g, &gid).unwrap();
            let kp = KeyPackageIn::tls_deserialize_exact(&old.legacy_key_package().unwrap())
                .unwrap()
                .validate(g.provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            let (commit, _w, _i) = group.add_members(&g.provider, &g.signer, &[kp]).unwrap();
            commit.tls_serialize_detached().unwrap()
        };
        assert!(matches!(bob.process_incoming(gid.clone(), evil).unwrap(), Incoming::CommitRejected));
    }

    /// Up to 100 leaves when everyone is on the new core; the 101st is rejected.
    #[test]
    fn hundred_leaves_when_all_members_are_new() {
        let gid = b"cap-multidevice-group-0100".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        alice.create_group(gid.clone()).unwrap();
        let kps: Vec<Vec<u8>> = (2..=MAX_GROUP_LEAVES)
            .map(|i| MlsClient::new(format!("d{i}").into_bytes()).unwrap().generate_key_package().unwrap())
            .collect();
        alice.add_members(gid.clone(), kps).unwrap();
        assert_eq!(alice.members(gid.clone()).unwrap().len(), MAX_GROUP_LEAVES);
        let extra = MlsClient::new(b"d101".to_vec()).unwrap().generate_key_package().unwrap();
        assert!(alice.add_members(gid, vec![extra]).is_err());
    }

    fn app_bytes(inc: Incoming) -> Vec<u8> {
        app_parts(inc).0
    }

    fn app_parts(inc: Incoming) -> (Vec<u8>, Vec<u8>) {
        match inc {
            Incoming::Application {
                plaintext,
                sender_identity,
            } => (plaintext, sender_identity),
            _ => panic!("expected application message"),
        }
    }

    #[test]
    fn full_group_roundtrip() {
        let gid = b"group-id-0123456789-abcdef-0001".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        let carol = MlsClient::new(b"carol".to_vec()).unwrap();

        // Alice creates the group, adds Bob.
        alice.create_group(gid.clone()).unwrap();
        let bob_kp = bob.generate_key_package().unwrap();
        let bundle = alice.add_members(gid.clone(), vec![bob_kp]).unwrap();
        let joined = bob.process_welcome(bundle.welcome).unwrap();
        assert_eq!(joined, gid, "bob joined the right group");

        // Alice → Bob application message decrypts correctly.
        let ct = alice.encrypt(gid.clone(), b"hello bob".to_vec()).unwrap();
        let got = app_bytes(bob.process_incoming(gid.clone(), ct).unwrap());
        assert_eq!(got, b"hello bob");

        // Bob → Alice the other direction.
        let ct2 = bob.encrypt(gid.clone(), b"hi alice".to_vec()).unwrap();
        let got2 = app_bytes(alice.process_incoming(gid.clone(), ct2).unwrap());
        assert_eq!(got2, b"hi alice");

        // Add Carol: Alice commits, Bob applies the commit, Carol joins via welcome.
        let carol_kp = carol.generate_key_package().unwrap();
        let bundle2 = alice.add_members(gid.clone(), vec![carol_kp]).unwrap();
        matches!(
            bob.process_incoming(gid.clone(), bundle2.commit).unwrap(),
            Incoming::CommitApplied
        );
        carol.process_welcome(bundle2.welcome).unwrap();
        assert_eq!(alice.members(gid.clone()).unwrap().len(), 3);

        // After the membership change (new epoch), Alice→{Bob,Carol} still decrypts.
        let ct3 = alice.encrypt(gid.clone(), b"welcome carol".to_vec()).unwrap();
        let to_bob = app_bytes(bob.process_incoming(gid.clone(), ct3.clone()).unwrap());
        let to_carol = app_bytes(carol.process_incoming(gid.clone(), ct3).unwrap());
        assert_eq!(to_bob, b"welcome carol");
        assert_eq!(to_carol, b"welcome carol");

        // Persistence round-trip: export Alice's state, restore, keep talking.
        let blob = alice.export_state().unwrap();
        let alice2 = MlsClient::from_state(blob).unwrap();
        let ct4 = alice2.encrypt(gid.clone(), b"after reload".to_vec()).unwrap();
        let got4 = app_bytes(bob.process_incoming(gid.clone(), ct4).unwrap());
        assert_eq!(got4, b"after reload");
    }

    /// AUTHENTICATED SENDER (audit K-1). The application layer decides admin rights from a
    /// `sender` field the sender itself writes into the plaintext, so it can only be trusted
    /// once it is checked against the identity MLS itself authenticated. This proves the FFI
    /// hands that identity out, and that it is the *real* sender rather than any peer the
    /// attacker might want to impersonate.
    /// Commit and Proposal also return the sender leaf (index + credential), and it is the real sender.
    #[test]
    fn commits_and_proposals_carry_the_sender_leaf() {
        let gid = b"sender-leaf-group-id-0123456789ab".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        let carol = MlsClient::new(b"carol".to_vec()).unwrap();
        alice.create_group(gid.clone()).unwrap();
        let b1 = alice.add_members(gid.clone(), vec![bob.generate_key_package().unwrap()]).unwrap();
        bob.process_welcome(b1.welcome).unwrap();
        let b2 = alice.add_members(gid.clone(), vec![carol.generate_key_package().unwrap()]).unwrap();
        let r = bob.process_incoming_with_sender(gid.clone(), b2.commit, None).unwrap();
        let (inc, sender) = (r.incoming, r.sender);
        assert!(matches!(inc, Incoming::CommitApplied));
        let s = sender.expect("commit sender leaf");
        assert_eq!(s.identity, b"alice".to_vec());
        assert_eq!(s.leaf_index, 0, "alice created the group: leaf 0");
        carol.process_welcome(b2.welcome).unwrap();

        // Commit from Bob (updating his leaf): for Carol the sender is Bob, not Alice.
        let up = bob.update_keys(gid.clone()).unwrap();
        let r2 = carol.process_incoming_with_sender(gid.clone(), up.clone(), None).unwrap();
        let (inc2, s2) = (r2.incoming, r2.sender);
        assert!(matches!(alice.process_incoming(gid.clone(), up).unwrap(), Incoming::CommitApplied));
        assert!(matches!(inc2, Incoming::CommitApplied));
        let s2 = s2.expect("bob commit sender");
        assert_eq!(s2.identity, b"bob".to_vec());
        assert_eq!(s2.leaf_index, 1);

        // Application message — the same leaf as in Incoming::Application.
        let ct = carol.encrypt(gid.clone(), b"hi".to_vec()).unwrap();
        let r3 = alice.process_incoming_with_sender(gid.clone(), ct, None).unwrap();
        let (inc3, s3) = (r3.incoming, r3.sender);
        let (_, id) = app_parts(inc3);
        let s3 = s3.unwrap();
        assert_eq!(s3.identity, id);
        assert_eq!(s3.identity, b"carol".to_vec());
        assert_eq!(s3.leaf_index, 2);

        // Garbage — no sender.
        let (inc4, s4) = alice
            .process_incoming_with_sender(gid.clone(), vec![0u8; 8], None)
            .map_or((Incoming::Ignored, None), |x| (x.incoming, x.sender));
        assert!(matches!(inc4, Incoming::Ignored));
        assert!(s4.is_none());
    }

    /// Another leaf's Commit under "own" PQ signature is not merged (epoch unchanged); a Commit from a leaf in the
    /// list is merged; application messages are not restricted by the list.
    #[test]
    fn handshake_sender_guard_rejects_commit_of_other_leaf() {
        let gid = b"sender-guard-group-id-0123456789a".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        let carol = MlsClient::new(b"carol".to_vec()).unwrap();
        alice.create_group(gid.clone()).unwrap();
        let b1 = alice.add_members(gid.clone(), vec![bob.generate_key_package().unwrap()]).unwrap();
        bob.process_welcome(b1.welcome).unwrap();
        let b2 = alice.add_members(gid.clone(), vec![carol.generate_key_package().unwrap()]).unwrap();
        carol.process_welcome(b2.welcome).unwrap();
        bob.process_incoming(gid.clone(), b2.commit).unwrap();

        // Alice's Commit, but the envelope signer (by PQ) is Bob: Carol's list = Bob's leaves.
        let up = alice.update_keys(gid.clone()).unwrap();
        let e0 = carol.epoch(gid.clone()).unwrap();
        let r = carol.process_incoming_with_sender(gid.clone(), up.clone(), Some(vec![b"bob".to_vec()])).unwrap();
        assert!(matches!(r.incoming, Incoming::CommitRejected));
        assert_eq!(r.sender.unwrap().identity, b"alice".to_vec());
        assert_eq!(carol.epoch(gid.clone()).unwrap(), e0, "rejected commit must not advance the epoch");
        // An empty list is also a rejection.
        let r0 = bob.process_incoming_with_sender(gid.clone(), up.clone(), Some(vec![])).unwrap();
        assert!(matches!(r0.incoming, Incoming::CommitRejected));
        assert_eq!(bob.epoch(gid.clone()).unwrap(), e0);

        // The same leaf in the list — the Commit is applied.
        let up2 = bob.update_keys(gid.clone()).unwrap();
        let r2 = carol.process_incoming_with_sender(gid.clone(), up2, Some(vec![b"bob".to_vec()])).unwrap();
        // Bob and Carol both rejected Alice's Commit and stayed on e0 — Bob's Commit applies at Carol's epoch.
        assert!(matches!(r2.incoming, Incoming::CommitApplied));
        assert_eq!(carol.epoch(gid.clone()).unwrap(), e0 + 1);

        // Application message from Bob with the list "alice only" decrypts (the list is not for application messages).
        let ct = bob.encrypt(gid.clone(), b"hi".to_vec()).unwrap();
        let r3 = carol.process_incoming_with_sender(gid.clone(), ct, Some(vec![b"alice".to_vec()])).unwrap();
        let (pt, id) = app_parts(r3.incoming);
        assert_eq!(pt, b"hi".to_vec());
        assert_eq!(id, b"bob".to_vec());
    }

    #[test]
    fn application_messages_carry_the_authenticated_sender() {
        let gid = b"sender-auth-group-id-01234567890".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        let carol = MlsClient::new(b"carol".to_vec()).unwrap();

        alice.create_group(gid.clone()).unwrap();
        let bundle = alice
            .add_members(gid.clone(), vec![bob.generate_key_package().unwrap()])
            .unwrap();
        bob.process_welcome(bundle.welcome).unwrap();
        let bundle2 = alice
            .add_members(gid.clone(), vec![carol.generate_key_package().unwrap()])
            .unwrap();
        assert!(matches!(
            bob.process_incoming(gid.clone(), bundle2.commit).unwrap(),
            Incoming::CommitApplied
        ));
        carol.process_welcome(bundle2.welcome).unwrap();

        // Bob is a plain member. Whatever he claims inside the plaintext, the identity the
        // receiver gets back is Bob's own credential — never Alice's.
        let forged = br#"{"sender":"alice","t":"role","content":"bob|ADMIN"}"#.to_vec();
        let ct = bob.encrypt(gid.clone(), forged.clone()).unwrap();
        let (plaintext, sender) = app_parts(carol.process_incoming(gid.clone(), ct).unwrap());
        assert_eq!(plaintext, forged, "payload still decrypts verbatim");
        assert_eq!(sender, b"bob".to_vec(), "identity is the authenticated sender");
        assert_ne!(sender, b"alice".to_vec(), "impersonation must not be possible");

        // And the honest case still reports the honest sender.
        let ct2 = alice.encrypt(gid.clone(), b"hi".to_vec()).unwrap();
        let (_, sender2) = app_parts(carol.process_incoming(gid.clone(), ct2).unwrap());
        assert_eq!(sender2, b"alice".to_vec());
    }

    /// CRYPTO-LEVEL MEMBERSHIP CAP (audit finding #1). Proves the cap is enforced by the
    /// MLS layer on EVERY honest client, not by the blind server:
    ///   (1) an honest admin fails closed — it will not produce an over-cap Commit; and
    ///   (2) when a MALICIOUS admin crafts an over-cap Commit anyway (driving openmls
    ///       directly, bypassing our add guard), an honest member REFUSES to merge it and
    ///       its epoch does not advance — so the (cap+1)-th member can never be forced on.
    #[test]
    fn member_cap_enforced_at_crypto_layer() {
        let gid = b"cap-test-group-id-0123456789-001".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        alice.create_group(gid.clone()).unwrap();

        // Bob is a real existing member (#2) who will judge the over-cap Commit.
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        // Bob on the old core: the group limit stays at 20 leaves.
        let bob_kp = bob.legacy_key_package().unwrap();
        let b = alice.add_members(gid.clone(), vec![bob_kp]).unwrap();
        bob.process_welcome(b.welcome).unwrap();

        // Fill the group up to exactly the cap (members 3..=MAX). Bob applies each Commit
        // so he stays at the same epoch as Alice.
        for i in 3..=MAX_GROUP_MEMBERS {
            let m = MlsClient::new(format!("m{}", i).into_bytes()).unwrap();
            let kp = m.generate_key_package().unwrap();
            let cb = alice.add_members(gid.clone(), vec![kp]).unwrap();
            assert!(matches!(
                bob.process_incoming(gid.clone(), cb.commit).unwrap(),
                Incoming::CommitApplied
            ));
        }
        assert_eq!(alice.members(gid.clone()).unwrap().len(), MAX_GROUP_MEMBERS);
        assert_eq!(bob.members(gid.clone()).unwrap().len(), MAX_GROUP_MEMBERS);

        // The (cap+1)-th candidate.
        let evil = MlsClient::new(b"member-21".to_vec()).unwrap();
        let evil_kp = evil.generate_key_package().unwrap();

        // (1) HONEST ADMIN fails closed: it won't even produce an over-cap Commit.
        assert!(
            alice.add_members(gid.clone(), vec![evil_kp.clone()]).is_err(),
            "honest admin must refuse to add the (cap+1)-th member"
        );

        // (2) MALICIOUS ADMIN: craft an over-cap Commit by driving openmls directly,
        // bypassing our add_members guard, then feed it to honest member Bob.
        let evil_commit = {
            let g = alice.inner.lock().unwrap();
            let mut group = MlsClient::load_group(&g, &gid).unwrap();
            let kp_in = KeyPackageIn::tls_deserialize_exact(&evil_kp).unwrap();
            let kp = kp_in
                .validate(g.provider.crypto(), ProtocolVersion::Mls10)
                .unwrap();
            let (commit, _welcome, _info) =
                group.add_members(&g.provider, &g.signer, &[kp]).unwrap();
            commit.tls_serialize_detached().unwrap()
        };

        let epoch_before = bob.epoch(gid.clone()).unwrap();
        // Honest Bob REFUSES the over-cap Commit.
        assert!(
            matches!(
                bob.process_incoming(gid.clone(), evil_commit).unwrap(),
                Incoming::CommitRejected
            ),
            "honest member must reject an over-cap Commit"
        );
        // Its epoch did NOT advance and its roster stays at the cap.
        assert_eq!(bob.epoch(gid.clone()).unwrap(), epoch_before);
        assert_eq!(bob.members(gid.clone()).unwrap().len(), MAX_GROUP_MEMBERS);
    }

    /// X-Wing: a group in the X25519 + ML-KEM-768 suite behaves like a legacy one — add,
    /// messaging both ways, remove, rekey, save and restore, epoch secret.
    #[test]
    fn xwing_group_full_life() {
        let x = mls_suite_xwing();
        let gid = b"xwing-group-0123456789abcdef0001".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        let carol = MlsClient::new(b"carol".to_vec()).unwrap();
        alice.create_group_for(gid.clone(), x).unwrap();
        assert_eq!(alice.group_ciphersuite(gid.clone()).unwrap(), x);
        let kp = bob.generate_key_package_for(x).unwrap();
        let info = key_package_info(kp.clone()).unwrap();
        assert_eq!(info.ciphersuite, x);
        assert_eq!(info.identity, b"bob".to_vec());
        assert!(info.supports_xwing);
        let b = alice.add_members(gid.clone(), vec![kp]).unwrap();
        assert_eq!(bob.process_welcome(b.welcome).unwrap(), gid);
        assert_eq!(bob.group_ciphersuite(gid.clone()).unwrap(), x);
        let ct = alice.encrypt(gid.clone(), b"pq hello".to_vec()).unwrap();
        assert_eq!(app_bytes(bob.process_incoming(gid.clone(), ct).unwrap()), b"pq hello");
        let ct = bob.encrypt(gid.clone(), b"pq back".to_vec()).unwrap();
        assert_eq!(app_bytes(alice.process_incoming(gid.clone(), ct).unwrap()), b"pq back");
        let c = alice.add_members(gid.clone(), vec![carol.generate_key_package_for(x).unwrap()]).unwrap();
        assert!(matches!(bob.process_incoming(gid.clone(), c.commit).unwrap(), Incoming::CommitApplied));
        carol.process_welcome(c.welcome).unwrap();
        let up = carol.update_keys(gid.clone()).unwrap();
        for p in [&alice, &bob] {
            assert!(matches!(p.process_incoming(gid.clone(), up.clone()).unwrap(), Incoming::CommitApplied));
        }
        let s = [&alice, &bob, &carol].map(|p| p.export_secret(gid.clone(), "conf".into(), 32).unwrap());
        assert!(s[0] == s[1] && s[1] == s[2]);
        assert!(alice.members_support(gid.clone(), x).unwrap());
        let bob_leaf = alice.members(gid.clone()).unwrap().into_iter().find(|m| m.identity == b"bob").unwrap().leaf_index;
        let rm = alice.remove_members(gid.clone(), vec![bob_leaf]).unwrap();
        assert!(matches!(carol.process_incoming(gid.clone(), rm).unwrap(), Incoming::CommitApplied));
        let carol2 = MlsClient::from_state(carol.export_state().unwrap()).unwrap();
        let ct = carol2.encrypt(gid.clone(), b"after reload".to_vec()).unwrap();
        assert_eq!(app_bytes(alice.process_incoming(gid.clone(), ct).unwrap()), b"after reload");
        assert_eq!(carol2.group_ciphersuite(gid.clone()).unwrap(), x);
    }

    /// Moving a group to X-Wing with the same leaf: a new group with the same gid and signing keys; links still verify.
    #[test]
    fn regroup_to_xwing_keeps_leaf_signature_keys() {
        let (l, x) = (mls_suite_legacy(), mls_suite_xwing());
        let gid = b"regroup-group-0123456789abcdef01".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        alice.create_group(gid.clone()).unwrap();
        let b = alice.add_members(gid.clone(), vec![bob.generate_key_package_for(l).unwrap()]).unwrap();
        bob.process_welcome(b.welcome).unwrap();
        let sig = bob.sibling_sign(gid.clone(), b"bob".to_vec(), b"alice".to_vec()).unwrap();
        // Bob publishes an X-Wing package from a "twin" of his leaf in advance.
        let bob2 = bob.spawn_same_identity().unwrap();
        assert_eq!(bob2.signature_public_key(), bob.signature_public_key());
        let kp = bob2.generate_key_package_for(x).unwrap();
        let alice2 = alice.spawn_same_identity().unwrap();
        alice2.create_group_for(gid.clone(), x).unwrap();
        let w = alice2.add_members(gid.clone(), vec![kp]).unwrap().welcome;
        assert_eq!(bob2.process_welcome(w).unwrap(), gid);
        assert_eq!(bob2.group_ciphersuite(gid.clone()).unwrap(), x);
        let ct = bob2.encrypt(gid.clone(), b"after regroup".to_vec()).unwrap();
        assert_eq!(app_bytes(alice2.process_incoming(gid.clone(), ct).unwrap()), b"after regroup");
        // A signature made by the previous leaf verifies against the new tree.
        let sig2 = alice2.sibling_sign(gid.clone(), b"bob".to_vec(), b"alice".to_vec()).unwrap();
        assert!(alice2.sibling_verify(gid.clone(), b"bob".to_vec(), b"alice".to_vec(), sig, sig2).unwrap());
    }

    /// A package of the wrong suite is not added to the group (an error, not group corruption); legacy and X-Wing
    /// packages of one client are different packages of the same leaf.
    #[test]
    fn suites_do_not_mix() {
        let (l, x) = (mls_suite_legacy(), mls_suite_xwing());
        let gid = b"suite-mix-group-0123456789abcd01".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        alice.create_group_for(gid.clone(), x).unwrap();
        let legacy = bob.generate_key_package_for(l).unwrap();
        assert_eq!(key_package_info(legacy.clone()).unwrap().ciphersuite, l);
        assert!(key_package_info(legacy.clone()).unwrap().supports_xwing);
        assert!(alice.add_members(gid.clone(), vec![legacy]).is_err());
        assert_eq!(alice.epoch(gid.clone()).unwrap(), 0);
        let gid2 = b"suite-mix-group-0123456789abcd02".to_vec();
        alice.create_group(gid2.clone()).unwrap();
        assert_eq!(alice.group_ciphersuite(gid2.clone()).unwrap(), l);
        assert!(alice.add_members(gid2.clone(), vec![bob.generate_key_package_for(x).unwrap()]).is_err());
        assert!(alice.generate_key_package_for(0x0002).is_err());
        // An old-core leaf does not advertise X-Wing: a group with it cannot be moved.
        let old = MlsClient::new(b"old".to_vec()).unwrap();
        let b = alice.add_members(gid2.clone(), vec![old.legacy_key_package().unwrap()]).unwrap();
        old.process_welcome(b.welcome).unwrap();
        assert!(!alice.members_support(gid2.clone(), x).unwrap());
        assert!(!old.own_leaf_marked(gid2.clone()).unwrap());
        // Upgraded and did a rekey — now advertises it.
        let up = old.update_keys(gid2.clone()).unwrap();
        assert!(matches!(alice.process_incoming(gid2.clone(), up).unwrap(), Incoming::CommitApplied));
        assert!(alice.members_support(gid2.clone(), x).unwrap());
        assert!(old.own_leaf_marked(gid2).unwrap());
    }

    /// The leaf limit also holds in X-Wing groups (100 when everyone is on the new core).
    #[test]
    fn xwing_hundred_leaves_and_sizes() {
        let x = mls_suite_xwing();
        let gid = b"xwing-cap-group-0123456789abcd01".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        alice.create_group_for(gid.clone(), x).unwrap();
        let peers: Vec<_> = (2..=MAX_GROUP_LEAVES).map(|i| MlsClient::new(format!("d{i}").into_bytes()).unwrap()).collect();
        let kps: Vec<Vec<u8>> = peers.iter().map(|p| p.generate_key_package_for(x).unwrap()).collect();
        let kp_len = kps[0].len();
        let b = alice.add_members(gid.clone(), kps).unwrap();
        assert_eq!(alice.members(gid.clone()).unwrap().len(), MAX_GROUP_LEAVES);
        peers[0].process_welcome(b.welcome.clone()).unwrap();
        let up = peers[0].update_keys(gid.clone()).unwrap();
        eprintln!("X-Wing: KeyPackage {kp_len} B, Welcome for {} leaves {} B, Commit with path {} B", MAX_GROUP_LEAVES, b.welcome.len(), up.len());
        // The relay envelope is up to 1 MiB after double base64; a Welcome with the whole tree must fit.
        assert!(b.welcome.len() * 16 / 9 < 1024 * 1024);
        let extra = MlsClient::new(b"d101".to_vec()).unwrap().generate_key_package_for(x).unwrap();
        assert!(alice.add_members(gid, vec![extra]).is_err());
    }

    /// The Rust quant_address must match the server's output BYTE-FOR-BYTE, else the
    /// client's zero-trust address↔keys check would falsely accept/reject. Reference computed from
    /// the server's reference implementation.
    #[test]
    fn quant_address_matches_backend() {
        let got = quant_address(
            "0374e364c795619762574ae2f1fb5b75".to_string(),
            "cafebabedeadbeef00112233".to_string(),
        )
        .unwrap();
        assert_eq!(got, "quant2dcE7nu1UsMEi4wqzzsj92SUDGbMJaYCyEhwxBpcPbcHNRbU4X");
    }
}
