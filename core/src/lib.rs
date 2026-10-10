//! Umbera core: MLS (RFC 9420) group messaging engine exposed over UniFFI.

use std::sync::Mutex;

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

uniffi::setup_scaffolding!();

pub mod amf;

pub mod pdf;

pub mod primitives;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

pub const MAX_GROUP_MEMBERS: usize = 20;

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum MlsError {
    #[error("mls: {0}")]
    Generic(String),
}
type R<T> = Result<T, MlsError>;

trait IntoMls<T> {
    fn mls(self) -> R<T>;
}
impl<T, E: std::fmt::Display> IntoMls<T> for Result<T, E> {
    fn mls(self) -> R<T> {
        self.map_err(|e| MlsError::Generic(e.to_string()))
    }
}

#[uniffi::export]
pub fn quant_address(classical_hex: String, dilithium_hex: String) -> Result<String, MlsError> {
    let cb = unhex(classical_hex.trim())?;
    let db = unhex(dilithium_hex.trim())?;
    let mut h = blake3::Hasher::new();
    h.update(&cb);
    h.update(&db);
    let raw = h.finalize();
    let raw = raw.as_bytes();
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

#[derive(uniffi::Enum)]
pub enum Incoming {
    Application {
        plaintext: Vec<u8>,
        sender_identity: Vec<u8>,
    },

    CommitApplied,

    CommitRejected,

    Proposal,

    Ignored,
}

#[derive(uniffi::Record)]
pub struct MemberInfo {
    pub leaf_index: u32,
    pub identity: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct PersistState {
    identity: Vec<u8>,
    signer: Vec<u8>,
    storage: Vec<(String, String)>,
}

#[derive(uniffi::Object)]
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

#[uniffi::export]
impl MlsClient {
    #[uniffi::constructor]
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

    #[uniffi::constructor]
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

    pub fn signature_public_key(&self) -> Vec<u8> {
        self.inner.lock().unwrap().signer.public().to_vec()
    }

    pub fn generate_key_package(&self) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &g.provider, &g.signer, Self::cwk(&g))
            .mls()?;
        bundle.key_package().tls_serialize_detached().mls()
    }

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

    pub fn add_members(&self, gid: Vec<u8>, key_packages: Vec<Vec<u8>>) -> R<CommitBundle> {
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;

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

    pub fn remove_members(&self, gid: Vec<u8>, leaf_indices: Vec<u32>) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;
        let idx: Vec<LeafNodeIndex> = leaf_indices.iter().map(|i| LeafNodeIndex::new(*i)).collect();
        let (commit, _welcome, _info) = group.remove_members(&g.provider, &g.signer, &idx).mls()?;
        group.merge_pending_commit(&g.provider).mls()?;
        commit.tls_serialize_detached().mls()
    }

    pub fn update_keys(&self, gid: Vec<u8>) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;
        let (commit, _welcome, _info) = group
            .self_update(&g.provider, &g.signer, LeafNodeParameters::default())
            .mls()?;
        group.merge_pending_commit(&g.provider).mls()?;
        commit.tls_serialize_detached().mls()
    }

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

    pub fn encrypt(&self, gid: Vec<u8>, plaintext: Vec<u8>) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let mut group = Self::load_group(&g, &gid)?;
        let out = group.create_message(&g.provider, &g.signer, &plaintext).mls()?;
        out.tls_serialize_detached().mls()
    }

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

        let sender_identity = processed.credential().serialized_content().to_vec();
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(Incoming::Application {
                plaintext: app.into_bytes(),
                sender_identity,
            }),
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                let current = group.members().count();
                let adds = staged.add_proposals().count();
                let removes = staged.remove_proposals().count();
                let resulting = current.saturating_add(adds).saturating_sub(removes);
                if resulting > MAX_GROUP_MEMBERS {
                    return Ok(Incoming::CommitRejected);
                }
                group.merge_staged_commit(&g.provider, *staged).mls()?;
                Ok(Incoming::CommitApplied)
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(Incoming::Proposal),
        }
    }

    pub fn export_secret(&self, gid: Vec<u8>, label: String, length: u32) -> R<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        let group = Self::load_group(&g, &gid)?;
        group
            .export_secret(&g.provider, &label, &[], length as usize)
            .mls()
    }

    pub fn epoch(&self, gid: Vec<u8>) -> R<u64> {
        let g = self.inner.lock().unwrap();
        let group = Self::load_group(&g, &gid)?;
        Ok(group.epoch().as_u64())
    }

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

#[cfg(test)]
mod tests {
    use super::*;

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

        alice.create_group(gid.clone()).unwrap();
        let bob_kp = bob.generate_key_package().unwrap();
        let bundle = alice.add_members(gid.clone(), vec![bob_kp]).unwrap();
        let joined = bob.process_welcome(bundle.welcome).unwrap();
        assert_eq!(joined, gid, "bob joined the right group");

        let ct = alice.encrypt(gid.clone(), b"hello bob".to_vec()).unwrap();
        let got = app_bytes(bob.process_incoming(gid.clone(), ct).unwrap());
        assert_eq!(got, b"hello bob");

        let ct2 = bob.encrypt(gid.clone(), b"hi alice".to_vec()).unwrap();
        let got2 = app_bytes(alice.process_incoming(gid.clone(), ct2).unwrap());
        assert_eq!(got2, b"hi alice");

        let carol_kp = carol.generate_key_package().unwrap();
        let bundle2 = alice.add_members(gid.clone(), vec![carol_kp]).unwrap();
        matches!(
            bob.process_incoming(gid.clone(), bundle2.commit).unwrap(),
            Incoming::CommitApplied
        );
        carol.process_welcome(bundle2.welcome).unwrap();
        assert_eq!(alice.members(gid.clone()).unwrap().len(), 3);

        let ct3 = alice.encrypt(gid.clone(), b"welcome carol".to_vec()).unwrap();
        let to_bob = app_bytes(bob.process_incoming(gid.clone(), ct3.clone()).unwrap());
        let to_carol = app_bytes(carol.process_incoming(gid.clone(), ct3).unwrap());
        assert_eq!(to_bob, b"welcome carol");
        assert_eq!(to_carol, b"welcome carol");

        let blob = alice.export_state().unwrap();
        let alice2 = MlsClient::from_state(blob).unwrap();
        let ct4 = alice2.encrypt(gid.clone(), b"after reload".to_vec()).unwrap();
        let got4 = app_bytes(bob.process_incoming(gid.clone(), ct4).unwrap());
        assert_eq!(got4, b"after reload");
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

        let forged = br#"{"sender":"alice","t":"role","content":"bob|ADMIN"}"#.to_vec();
        let ct = bob.encrypt(gid.clone(), forged.clone()).unwrap();
        let (plaintext, sender) = app_parts(carol.process_incoming(gid.clone(), ct).unwrap());
        assert_eq!(plaintext, forged, "payload still decrypts verbatim");
        assert_eq!(sender, b"bob".to_vec(), "identity is the authenticated sender");
        assert_ne!(sender, b"alice".to_vec(), "impersonation must not be possible");

        let ct2 = alice.encrypt(gid.clone(), b"hi".to_vec()).unwrap();
        let (_, sender2) = app_parts(carol.process_incoming(gid.clone(), ct2).unwrap());
        assert_eq!(sender2, b"alice".to_vec());
    }

    #[test]
    fn member_cap_enforced_at_crypto_layer() {
        let gid = b"cap-test-group-id-0123456789-001".to_vec();
        let alice = MlsClient::new(b"alice".to_vec()).unwrap();
        alice.create_group(gid.clone()).unwrap();

        let bob = MlsClient::new(b"bob".to_vec()).unwrap();
        let bob_kp = bob.generate_key_package().unwrap();
        let b = alice.add_members(gid.clone(), vec![bob_kp]).unwrap();
        bob.process_welcome(b.welcome).unwrap();

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

        let evil = MlsClient::new(b"member-21".to_vec()).unwrap();
        let evil_kp = evil.generate_key_package().unwrap();

        assert!(
            alice.add_members(gid.clone(), vec![evil_kp.clone()]).is_err(),
            "honest admin must refuse to add the (cap+1)-th member"
        );

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

        assert!(
            matches!(
                bob.process_incoming(gid.clone(), evil_commit).unwrap(),
                Incoming::CommitRejected
            ),
            "honest member must reject an over-cap Commit"
        );

        assert_eq!(bob.epoch(gid.clone()).unwrap(), epoch_before);
        assert_eq!(bob.members(gid.clone()).unwrap().len(), MAX_GROUP_MEMBERS);
    }

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
