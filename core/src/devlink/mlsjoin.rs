// MLS on a linked device: every device is ITS OWN group leaf, not a copy of the phone's
// keys. MLS state must not be copied: two devices sharing one leaf would diverge
// in the ratchet (same generation, nonce reuse) and break the group and its secrecy.
//
// How a desktop joins the phone's groups:
//  1. Phone → desktop (KIND_MLS_JOIN_REQUESTS): a list of {gid, the phone's memberId in the group}.
//  2. For each group the desktop creates a separate MlsClient with a FRESH random memberId
//     (as MlsManager.beginJoin: groups are not linkable to each other), makes a KeyPackage and
//     signs the "sibling" link sibling(gid, phone memberId, desktop memberId) with its
//     leaf key → desktop → phone (KIND_MLS_JOIN_OFFERS).
//  3. The phone verifies the link against the leaf key from the KeyPackage (mls_sibling_verify_key_package),
//     co-signs it with its own leaf (sibling_sign), adds the KeyPackage to the group
//     (add_members → Commit to members) and puts the Welcome into the bundle (SECTION_MLS_WELCOME,
//     id = desktop memberId). To the group it sends a control message "leaf X is my
//     device" with both signatures; any member checks it with sibling_verify against the
//     leaf keys in the current tree and shows both leaves as one person.
// The link is signed with leaf keys of this group only and only for this group, so
// it does not reveal that the same people are in another group (group anonymity is preserved).

use openmls::prelude::*;
use crate::provider::UmberaProvider;
use openmls_traits::signatures::Signer as _;
use tls_codec::Deserialize as _;

use super::codec::{Rd, W};
use super::{LinkError, DOMAIN, LR};
use crate::{MlsClient, MlsError};

const ID_MAX: usize = 64;
const GID_MAX: usize = 255;
const KP_MAX: usize = 64 * 1024;
const LIST_MAX: usize = 1024;

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct MlsJoinRequest {
    pub gid: Vec<u8>,
    pub primary_member_id: Vec<u8>,
}

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct MlsJoinOffer {
    pub gid: Vec<u8>,
    pub device_member_id: Vec<u8>,
    pub key_package: Vec<u8>,
    /// Link signature with the desktop leaf key (Ed25519 MLS, 64 B).
    pub device_sibling_sig: Vec<u8>,
}

fn check_ids(gid: &[u8], a: &[u8], b: &[u8]) -> LR<()> {
    if gid.is_empty() || gid.len() > GID_MAX || a.is_empty() || a.len() > ID_MAX || b.is_empty() || b.len() > ID_MAX {
        return Err(LinkError::Malformed("mls sibling: id lengths".into()));
    }
    if a == b {
        return Err(LinkError::Malformed("mls sibling: device and primary are the same leaf".into()));
    }
    Ok(())
}

pub(crate) fn sibling_message(gid: &[u8], primary: &[u8], device: &[u8]) -> LR<Vec<u8>> {
    check_ids(gid, primary, device)?;
    let mut w = W::new();
    w.raw(DOMAIN).raw(b"/mls-sibling").b8(gid).b8(primary).b8(device);
    Ok(w.done())
}

fn ed25519_ok(crypto: &impl openmls_traits::crypto::OpenMlsCrypto, msg: &[u8], pk: &[u8], sig: &[u8]) -> bool {
    crypto.verify_signature(SignatureScheme::ED25519, msg, pk, sig).is_ok()
}

#[uniffi::export]
pub fn mls_join_requests_encode(requests: Vec<MlsJoinRequest>) -> LR<Vec<u8>> {
    if requests.len() > LIST_MAX {
        return Err(LinkError::Malformed("too many groups".into()));
    }
    let mut w = W::new();
    w.u16(requests.len() as u16);
    for r in &requests {
        if r.gid.is_empty() || r.gid.len() > GID_MAX || r.primary_member_id.is_empty() || r.primary_member_id.len() > ID_MAX {
            return Err(LinkError::Malformed("join request: id lengths".into()));
        }
        w.b8(&r.gid).b8(&r.primary_member_id);
    }
    Ok(w.done())
}

#[uniffi::export]
pub fn mls_join_requests_decode(bytes: Vec<u8>) -> LR<Vec<MlsJoinRequest>> {
    let mut r = Rd::new(&bytes, "join requests");
    let n = r.u16()? as usize;
    if n > LIST_MAX {
        return Err(LinkError::Malformed("too many groups".into()));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let gid = r.b8(GID_MAX)?.to_vec();
        let primary_member_id = r.b8(ID_MAX)?.to_vec();
        if gid.is_empty() || primary_member_id.is_empty() {
            return Err(LinkError::Malformed("join request: empty id".into()));
        }
        out.push(MlsJoinRequest { gid, primary_member_id });
    }
    r.end()?;
    Ok(out)
}

#[uniffi::export]
pub fn mls_join_offers_encode(offers: Vec<MlsJoinOffer>) -> LR<Vec<u8>> {
    if offers.len() > LIST_MAX {
        return Err(LinkError::Malformed("too many groups".into()));
    }
    let mut w = W::new();
    w.u16(offers.len() as u16);
    for o in &offers {
        if o.gid.is_empty() || o.gid.len() > GID_MAX || o.device_member_id.is_empty() || o.device_member_id.len() > ID_MAX
            || o.key_package.is_empty() || o.key_package.len() > KP_MAX || o.device_sibling_sig.len() != 64
        {
            return Err(LinkError::Malformed("join offer: field lengths".into()));
        }
        w.b8(&o.gid).b8(&o.device_member_id).b32(&o.key_package).b8(&o.device_sibling_sig);
    }
    Ok(w.done())
}

#[uniffi::export]
pub fn mls_join_offers_decode(bytes: Vec<u8>) -> LR<Vec<MlsJoinOffer>> {
    let mut r = Rd::new(&bytes, "join offers");
    let n = r.u16()? as usize;
    if n > LIST_MAX {
        return Err(LinkError::Malformed("too many groups".into()));
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let gid = r.b8(GID_MAX)?.to_vec();
        let device_member_id = r.b8(ID_MAX)?.to_vec();
        let key_package = r.b32(KP_MAX)?.to_vec();
        let device_sibling_sig = r.b8(64)?.to_vec();
        if gid.is_empty() || device_member_id.is_empty() || key_package.is_empty() || device_sibling_sig.len() != 64 {
            return Err(LinkError::Malformed("join offer: field lengths".into()));
        }
        out.push(MlsJoinOffer { gid, device_member_id, key_package, device_sibling_sig });
    }
    r.end()?;
    Ok(out)
}

/// Phone, before add_members: the KeyPackage is valid (signature, ciphersuite), its leaf carries
/// the claimed desktop memberId, and the link is signed with the key of exactly this leaf.
#[uniffi::export]
pub fn mls_sibling_verify_key_package(primary_member_id: Vec<u8>, offer: MlsJoinOffer) -> bool {
    let Ok(msg) = sibling_message(&offer.gid, &primary_member_id, &offer.device_member_id) else { return false };
    let provider = UmberaProvider::default();
    let Ok(kp_in) = KeyPackageIn::tls_deserialize_exact(&offer.key_package) else { return false };
    let Ok(kp) = kp_in.validate(provider.crypto(), ProtocolVersion::Mls10) else { return false };
    let leaf = kp.leaf_node();
    if leaf.credential().serialized_content() != offer.device_member_id.as_slice() {
        return false;
    }
    ed25519_ok(provider.crypto(), &msg, leaf.signature_key().as_slice(), &offer.device_sibling_sig)
}

#[uniffi::export]
impl MlsClient {
    /// Sign the "sibling" link with our own leaf key. Our memberId must be one of the
    /// two (the phone signs as primary, the desktop as device). Group membership is not required:
    /// the desktop signs before joining; an MlsClient has one leaf key for its whole lifetime.
    pub fn sibling_sign(&self, gid: Vec<u8>, primary_member_id: Vec<u8>, device_member_id: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let g = self.inner.lock().unwrap();
        if g.identity != primary_member_id && g.identity != device_member_id {
            return Err(MlsError::Generic("sibling: our memberId is neither primary nor device".into()));
        }
        let msg = sibling_message(&gid, &primary_member_id, &device_member_id).map_err(|e| MlsError::Generic(e.to_string()))?;
        g.signer.sign(&msg).map_err(|e| MlsError::Generic(format!("sibling sign: {e:?}")))
    }

    /// Verify the link against leaf keys in the CURRENT group tree: both leaves exist,
    /// carry these memberIds, and both signatures are valid.
    pub fn sibling_verify(
        &self,
        gid: Vec<u8>,
        primary_member_id: Vec<u8>,
        device_member_id: Vec<u8>,
        primary_sig: Vec<u8>,
        device_sig: Vec<u8>,
    ) -> Result<bool, MlsError> {
        let Ok(msg) = sibling_message(&gid, &primary_member_id, &device_member_id) else { return Ok(false) };
        let g = self.inner.lock().unwrap();
        let group = MlsClient::load_group(&g, &gid)?;
        let key_of = |id: &[u8]| {
            group
                .members()
                .find(|m| m.credential.serialized_content() == id)
                .map(|m| m.signature_key)
        };
        let (Some(pk_p), Some(pk_d)) = (key_of(&primary_member_id), key_of(&device_member_id)) else { return Ok(false) };
        let a = ed25519_ok(g.provider.crypto(), &msg, &pk_p, &primary_sig);
        let b = ed25519_ok(g.provider.crypto(), &msg, &pk_d, &device_sig);
        Ok(a & b)
    }
}
