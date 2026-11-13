// TEST copy of the MLS core from the STORE build (commit 19790b64: Android 2.0.3 (221), iOS 2.0.1 (100)),
// on OpenMLS 0.6.0 / openmls_rust_crypto 0.3.0 / tls_codec 0.4. Needed to check, within a single cargo test run,
// compatibility of the new core (OpenMLS 0.9) with the old one: persisted state and mixed groups.
// The code is verbatim from the store build; only uniffi attributes, non-MLS modules and
// quant_address were removed. The release build never sees this copy: openmls 0.6 is a dev-dependency only.
#![allow(dead_code)]

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

use openmls_v06::prelude::*;
use openmls_basic_credential_v06::SignatureKeyPair;
use openmls_rust_crypto_v06::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use tls_codec_v04::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};





/// Single ciphersuite for v1: X25519 + AES-128-GCM + SHA-256 + Ed25519 (MLS mandatory-
/// to-implement). Hybrid-PQ (Kyber) is a later ciphersuite swap; the FFI is unchanged.
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Hard cap on group membership, enforced at the CRYPTO layer (audit finding #1).
///
/// The blind relay has no notion of a "group" — it only forwards opaque pairwise
/// rendezvous entries — so it physically cannot enforce a member cap without learning
/// which rendezvous belong to one group, which would break anonymity (Law 0). Instead
/// every honest client enforces the cap on its own MLS state: it REFUSES to merge any
/// Commit that would push the group past this size (the epoch does not advance), so a
/// malicious admin cannot force the (cap+1)-th member onto honest devices. The server
/// learns nothing — anonymity is untouched.
pub const MAX_GROUP_MEMBERS: usize = 20;

#[derive(Debug)]
pub enum MlsError {
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


pub struct CommitBundle {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// Classified result of feeding an inbound MLS message to the group.

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

pub struct MlsClient {
    inner: Mutex<Inner>,
}

struct Inner {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    identity: Vec<u8>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn unhex(s: &str) -> R<Vec<u8>> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).mls())
        .collect()
}

// Private helpers (NOT exported over FFI).
impl MlsClient {
    fn cwk(g: &Inner) -> CredentialWithKey {
        let credential = BasicCredential::new(g.identity.clone());
        CredentialWithKey {
            credential: credential.into(),
            signature_key: g.signer.public().into(),
        }
    }

    fn load_group(g: &Inner, gid: &[u8]) -> R<MlsGroup> {
        MlsGroup::load(g.provider.storage(), &GroupId::from_slice(gid))
            .mls()?
            .ok_or_else(|| MlsError::Generic("group not found".into()))
    }
}

impl MlsClient {
    /// Brand-new identity. `identity` = our stable per-group leaf id bytes (memberId).
    pub fn new(identity: Vec<u8>) -> R<std::sync::Arc<MlsClient>> {
        let provider = OpenMlsRustCrypto::default();
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
    pub fn from_state(blob: Vec<u8>) -> R<std::sync::Arc<MlsClient>> {
        let st: PersistState = serde_json::from_slice(&blob).mls()?;
        let provider = OpenMlsRustCrypto::default();
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

    /// Serialize the whole identity+groups for our SQLCipher store.
    pub fn export_state(&self) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
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
        self.inner.lock().unwrap().signer.public().to_vec()
    }

    /// Produce a fresh KeyPackage (serialized) to hand to whoever will add us to a group.
    pub fn generate_key_package(&self) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &g.provider, &g.signer, Self::cwk(&g))
            .mls()?;
        bundle.key_package().tls_serialize_detached().mls()
    }

    /// Create a new group with our chosen 32-byte group id (`gid`). We become the
    /// single initial member (admin handled at the app layer, not by MLS).
    pub fn create_group(&self, gid: Vec<u8>) -> R<()> {
        let g = self.inner.lock().unwrap();
        let cfg = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
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
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;
        // CRYPTO-LEVEL MEMBERSHIP CAP (audit finding #1): an honest admin fails CLOSED —
        // it will not even produce a Commit that takes the group past the cap, so it can
        // never create the over-cap fork honest members would reject anyway.
        let current = group.members().count();
        if current + key_packages.len() > MAX_GROUP_MEMBERS {
            return Err(MlsError::Generic(format!(
                "group member cap ({}) exceeded: {} + {}",
                MAX_GROUP_MEMBERS,
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
            kps.push(kp);
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
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;
        let idx: Vec<LeafNodeIndex> = leaf_indices.iter().map(|i| LeafNodeIndex::new(*i)).collect();
        let (commit, _welcome, _info) = group.remove_members(&g.provider, &g.signer, &idx).mls()?;
        group.merge_pending_commit(&g.provider).mls()?;
        commit.tls_serialize_detached().mls()
    }

    /// Plain rekey (post-compromise security) with no membership change → Commit.
    pub fn update_keys(&self, gid: Vec<u8>) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;
        let (commit, _welcome, _info) = group
            .self_update(&g.provider, &g.signer, LeafNodeParameters::default())
            .mls()?;
        group.merge_pending_commit(&g.provider).mls()?;
        commit.tls_serialize_detached().mls()
    }

    /// Join a group from a Welcome we received → returns the group id we joined.
    pub fn process_welcome(&self, welcome_bytes: Vec<u8>) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let msg = MlsMessageIn::tls_deserialize_exact(&welcome_bytes).mls()?;
        let welcome = match msg.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(MlsError::Generic("not a welcome".into())),
        };
        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(&g.provider, &cfg, welcome, None).mls()?;
        let group = staged.into_group(&g.provider).mls()?;
        Ok(group.group_id().as_slice().to_vec())
    }

    /// Encrypt an application payload (chat message / control) for the group.
    pub fn encrypt(&self, gid: Vec<u8>, plaintext: Vec<u8>) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;
        let out = group.create_message(&g.provider, &g.signer, &plaintext).mls()?;
        out.tls_serialize_detached().mls()
    }

    /// Feed an inbound MLS message to a group: decrypts application payloads and
    /// applies membership Commits. Classifies the outcome.
    pub fn process_incoming(&self, gid: Vec<u8>, message: Vec<u8>) -> R<Incoming> {
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;
        let msg = MlsMessageIn::tls_deserialize_exact(&message).mls()?;
        let protocol = match msg.try_into_protocol_message() {
            Ok(p) => p,
            Err(_) => return Ok(Incoming::Ignored),
        };
        let processed = match group.process_message(&g.provider, protocol) {
            Ok(p) => p,
            Err(_) => return Ok(Incoming::Ignored),
        };
        // Capture the authenticated sender BEFORE consuming the message: into_content()
        // drops everything except the payload, which is exactly how the sender identity
        // came to be taken from attacker-chosen JSON instead (audit K-1).
        let sender_identity = processed.credential().serialized_content().to_vec();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Incoming::Application {
                plaintext: app.into_bytes(),
                sender_identity,
            }),
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
                if resulting > MAX_GROUP_MEMBERS {
                    // Drop the staged commit unmerged; epoch stays put.
                    return Ok(Incoming::CommitRejected);
                }
                group.merge_staged_commit(&g.provider, *staged).mls()?;
                Ok(Incoming::CommitApplied)
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(Incoming::Proposal),
        }
    }

    /// Derive a fresh symmetric secret bound to the current epoch (e.g. a conference
    /// media key). Rotates automatically every time the group rekeys.
    pub fn export_secret(&self, gid: Vec<u8>, label: String, length: u32) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let group = Self::load_group(&g, &gid)?;
        group
            .export_secret(&g.provider, &label, &[], length as usize)
            .mls()
    }

    /// Current epoch number (advances on every membership change / rekey).
    pub fn epoch(&self, gid: Vec<u8>) -> R<u64> {
        let g = self.inner.lock().unwrap();
        let group = Self::load_group(&g, &gid)?;
        Ok(group.epoch().as_u64())
    }

    /// Member identities (leaf credential bytes = memberIds) + their leaf indices.
    pub fn members(&self, gid: Vec<u8>) -> R<Vec<MemberInfo>> {
        let g = self.inner.lock().unwrap();
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
}

