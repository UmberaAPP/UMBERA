// Communities on a linked device: the membership vault root instead of account keys.
//
// The phone derives the vault keys (communities/app CommCrypto.vaultKeys / vaultKeysEpoch) as
//   HKDF-SHA256(IKM = account_X25519 ‖ account_ML-KEM_seed, salt, info)
//   = HKDF-Expand(HKDF-Extract(salt, IKM), info)          (RFC 5869)
// Hence PRK = HKDF-Extract(salt, IKM) is the "vault root": from it the address, signing key
// and encryption key of the vault for ANY epoch are derived, byte for byte as on the phone, while the account
// private keys cannot be recovered from it (HMAC is one-way). The desktop receives two roots:
// v3 (per-epoch vault — the primary one) and v2 (old epoch-less vault — read-only during migration).
// Channel pseudonym keys live in the vault itself, so the desktop joins channels under the same
// pseudonyms as the phone, and the Communities server still does not know whose vault it is.

use hkdf::Hkdf;
use sha2::Sha256;

use super::{LinkError, LR};

const SALT_V2: &[u8] = b"umbera-comm-vault-v2";
const SALT_V3: &[u8] = b"umbera-comm-vault-v3";

#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct CommVaultRoots {
    pub v3: Vec<u8>,
    pub v2: Vec<u8>,
}

/// The same three keys as CommCrypto.VaultKeys.
#[derive(uniffi::Record, Clone, Debug, PartialEq, Eq)]
pub struct CommVaultKeys {
    pub id: Vec<u8>,
    pub auth_seed: Vec<u8>,
    pub enc_key: Vec<u8>,
}

fn extract(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.to_vec()
}

fn keys(root: &[u8], suffix: &str) -> LR<CommVaultKeys> {
    if root.len() != 32 {
        return Err(LinkError::Crypto("vault root must be 32 bytes".into()));
    }
    let h = Hkdf::<Sha256>::from_prk(root).map_err(|_| LinkError::Crypto("vault root must be 32 bytes".into()))?;
    let one = |label: &str| {
        let mut o = vec![0u8; 32];
        h.expand(format!("{label}{suffix}").as_bytes(), &mut o).expect("hkdf len");
        o
    };
    Ok(CommVaultKeys { id: one("vault-id"), auth_seed: one("vault-auth"), enc_key: one("vault-key") })
}

/// Phone: vault roots from the account private keys (X25519 32 B, ML-KEM seed 64 B).
#[uniffi::export]
pub fn comm_vault_roots(account_x25519_private: Vec<u8>, account_mlkem_seed: Vec<u8>) -> LR<CommVaultRoots> {
    if account_x25519_private.len() != 32 || account_mlkem_seed.len() != 64 {
        return Err(LinkError::Crypto("vault inputs must be 32 + 64 bytes".into()));
    }
    let ikm = zeroize::Zeroizing::new([account_x25519_private, account_mlkem_seed].concat());
    Ok(CommVaultRoots { v3: extract(SALT_V3, &ikm), v2: extract(SALT_V2, &ikm) })
}

/// Vault keys for epoch `epoch` from the v3 root (= CommCrypto.vaultKeysEpoch).
#[uniffi::export]
pub fn comm_vault_epoch_keys(root_v3: Vec<u8>, epoch: u32) -> LR<CommVaultKeys> {
    keys(&root_v3, &format!("/{epoch}"))
}

/// Keys of the old epoch-less vault from the v2 root (= CommCrypto.vaultKeys).
#[uniffi::export]
pub fn comm_vault_legacy_keys(root_v2: Vec<u8>) -> LR<CommVaultKeys> {
    keys(&root_v2, "")
}

/// SECTION_COMM_VAULT record body: v3 ‖ v2 (64 B).
#[uniffi::export]
pub fn comm_vault_record_body(roots: CommVaultRoots) -> LR<Vec<u8>> {
    if roots.v3.len() != 32 || roots.v2.len() != 32 {
        return Err(LinkError::Malformed("vault roots must be 32 bytes each".into()));
    }
    Ok([roots.v3, roots.v2].concat())
}

#[uniffi::export]
pub fn comm_vault_record_parse(body: Vec<u8>) -> LR<CommVaultRoots> {
    if body.len() != 64 {
        return Err(LinkError::Malformed("vault record must be 64 bytes".into()));
    }
    Ok(CommVaultRoots { v3: body[..32].to_vec(), v2: body[32..].to_vec() })
}
