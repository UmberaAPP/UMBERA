// MLS core crypto provider: the existing RustCrypto for everything except the X-Wing KEM.
//
// Groups use one of two ciphersuites:
//   • legacy   MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001) — used by all store builds;
//   • X-Wing   MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519 (0x004D) — X25519 + ML-KEM-768 in a single KEM.
// `openmls_rust_crypto` 0.6 has no X-Wing, while `openmls_libcrux_crypto` 0.4 (formally verified libcrux,
// Cryspen) provides it. So that legacy groups compute THE SAME bytes as in store builds, the whole
// legacy suite and everything shared (HKDF, HMAC, hash, AEAD, Ed25519 signatures, randomness) goes through RustCrypto
// as before; only HPKE with the X-Wing KEM (seal/open/export/key pair derivation) goes through libcrux. ChaCha20-
// Poly1305, SHA-256 and Ed25519 of the X-Wing suite are handled by RustCrypto itself.
//
// Storage is the same MemoryStorage: the persisted state format does not change.

use openmls_libcrux_crypto::CryptoProvider as Libcrux;
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        AeadType, Ciphersuite, CryptoError, ExporterSecret, HashType, HpkeCiphertext, HpkeConfig, HpkeKemType,
        HpkeKeyPair, KemOutput, SignatureScheme,
    },
    OpenMlsProvider,
};
use tls_codec::SecretVLBytes;

/// Legacy ciphersuite (all store builds before X-Wing).
pub const LEGACY_SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
/// Post-quantum hybrid: X-Wing (X25519 + ML-KEM-768), ChaCha20-Poly1305, SHA-256, Ed25519.
pub const XWING_SUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

pub struct UmberaCrypto {
    rc: RustCrypto,
    lc: Libcrux,
}

impl UmberaCrypto {
    fn new() -> Self {
        // libcrux checks CPU instruction support and seeds its DRBG from the OS; a failure here is
        // a platform fault, not a data fault, and the core cannot work without it anyway.
        Self { rc: RustCrypto::default(), lc: Libcrux::new().expect("libcrux provider") }
    }

    fn xwing(config: &HpkeConfig) -> bool {
        config.0 == HpkeKemType::XWingKemDraft6
    }
}

// RUSTSEC-2026-0331: libcrux-kem 0.0.9 PANICS (panic, slice `bytes[0..1184]`) on
// an X-Wing public key shorter than 1184 bytes — `XWingKemDraft06PublicKey::decode` from `kem_encaps` in hpke-rs-libcrux.
// Public keys come from other people: the init_key of a foreign KeyPackage (Welcome on add) and the
// encryption keys of tree leaves/nodes (UpdatePath of our Commit). The fix in libcrux-kem 0.0.10 pulls in
// hpke-rs 0.8 and all of libcrux 0.0.9→0.0.10, while the latest openmls_libcrux_crypto (0.4.0) requires hpke-rs ^0.7 and
// libcrux-kem =0.0.9 (via hpke-rs-libcrux =0.7.0) — upgrading is impossible without a fork of the provider.
// Therefore: (1) lengths are checked BEFORE calling libcrux — an X-Wing key is exactly 1216 bytes (ML-KEM-768 1184 + X25519 32),
// a ciphertext exactly 1120 (1088 + 32), a private key is a 32-byte seed; libcrux rejects other lengths with an
// error anyway, so nothing changes for valid data (the wire format is the same); (2) every libcrux
// call is wrapped in catch_unwind: any other panic inside libcrux becomes a CryptoError instead of unwinding through
// openmls while the core's Mutex is held (a poisoned Mutex would break the client until restart).
pub(crate) const XWING_PK_LEN: usize = 1184 + 32;
pub(crate) const XWING_ENC_LEN: usize = 1088 + 32;
pub(crate) const XWING_SK_LEN: usize = 32;

fn len_ok(got: usize, want: usize, err: CryptoError) -> Result<(), CryptoError> {
    if got == want { Ok(()) } else { Err(err) }
}

/// Call libcrux without letting panics escape: panic → [err].
fn no_panic<T>(err: CryptoError, f: impl FnOnce() -> Result<T, CryptoError>) -> Result<T, CryptoError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(Err(err))
}

impl OpenMlsCrypto for UmberaCrypto {
    fn supports(&self, ciphersuite: Ciphersuite) -> Result<(), CryptoError> {
        match ciphersuite {
            XWING_SUITE => self.lc.supports(ciphersuite),
            _ => self.rc.supports(ciphersuite),
        }
    }

    fn supported_ciphersuites(&self) -> Vec<Ciphersuite> {
        let mut v = self.rc.supported_ciphersuites();
        v.push(XWING_SUITE);
        v
    }

    fn hkdf_extract(&self, hash_type: HashType, salt: &[u8], ikm: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        self.rc.hkdf_extract(hash_type, salt, ikm)
    }

    fn hmac(&self, hash_type: HashType, key: &[u8], message: &[u8]) -> Result<SecretVLBytes, CryptoError> {
        self.rc.hmac(hash_type, key, message)
    }

    fn hkdf_expand(&self, hash_type: HashType, prk: &[u8], info: &[u8], okm_len: usize) -> Result<SecretVLBytes, CryptoError> {
        self.rc.hkdf_expand(hash_type, prk, info, okm_len)
    }

    fn hash(&self, hash_type: HashType, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.rc.hash(hash_type, data)
    }

    fn aead_encrypt(&self, alg: AeadType, key: &[u8], data: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.rc.aead_encrypt(alg, key, data, nonce, aad)
    }

    fn aead_decrypt(&self, alg: AeadType, key: &[u8], ct_tag: &[u8], nonce: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.rc.aead_decrypt(alg, key, ct_tag, nonce, aad)
    }

    fn signature_key_gen(&self, alg: SignatureScheme) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.rc.signature_key_gen(alg)
    }

    fn verify_signature(&self, alg: SignatureScheme, data: &[u8], pk: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        self.rc.verify_signature(alg, data, pk, signature)
    }

    fn sign(&self, alg: SignatureScheme, data: &[u8], key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.rc.sign(alg, data, key)
    }

    fn hpke_seal(&self, config: HpkeConfig, pk_r: &[u8], info: &[u8], aad: &[u8], ptxt: &[u8]) -> Result<HpkeCiphertext, CryptoError> {
        if Self::xwing(&config) {
            len_ok(pk_r.len(), XWING_PK_LEN, CryptoError::InvalidPublicKey)?;
            no_panic(CryptoError::HpkeEncryptionError, || self.lc.hpke_seal(config, pk_r, info, aad, ptxt))
        } else {
            self.rc.hpke_seal(config, pk_r, info, aad, ptxt)
        }
    }

    fn hpke_open(&self, config: HpkeConfig, input: &HpkeCiphertext, sk_r: &[u8], info: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if Self::xwing(&config) {
            len_ok(input.kem_output.as_slice().len(), XWING_ENC_LEN, CryptoError::HpkeDecryptionError)?;
            len_ok(sk_r.len(), XWING_SK_LEN, CryptoError::HpkeDecryptionError)?;
            no_panic(CryptoError::HpkeDecryptionError, || self.lc.hpke_open(config, input, sk_r, info, aad))
        } else {
            self.rc.hpke_open(config, input, sk_r, info, aad)
        }
    }

    fn hpke_setup_sender_and_export(
        &self,
        config: HpkeConfig,
        pk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<(KemOutput, ExporterSecret), CryptoError> {
        if Self::xwing(&config) {
            len_ok(pk_r.len(), XWING_PK_LEN, CryptoError::InvalidPublicKey)?;
            no_panic(CryptoError::SenderSetupError, || {
                self.lc.hpke_setup_sender_and_export(config, pk_r, info, exporter_context, exporter_length)
            })
        } else {
            self.rc.hpke_setup_sender_and_export(config, pk_r, info, exporter_context, exporter_length)
        }
    }

    fn hpke_setup_receiver_and_export(
        &self,
        config: HpkeConfig,
        enc: &[u8],
        sk_r: &[u8],
        info: &[u8],
        exporter_context: &[u8],
        exporter_length: usize,
    ) -> Result<ExporterSecret, CryptoError> {
        if Self::xwing(&config) {
            len_ok(enc.len(), XWING_ENC_LEN, CryptoError::ReceiverSetupError)?;
            len_ok(sk_r.len(), XWING_SK_LEN, CryptoError::ReceiverSetupError)?;
            no_panic(CryptoError::ReceiverSetupError, || {
                self.lc.hpke_setup_receiver_and_export(config, enc, sk_r, info, exporter_context, exporter_length)
            })
        } else {
            self.rc.hpke_setup_receiver_and_export(config, enc, sk_r, info, exporter_context, exporter_length)
        }
    }

    fn derive_hpke_keypair(&self, config: HpkeConfig, ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
        if Self::xwing(&config) {
            no_panic(CryptoError::CryptoLibraryError, || self.lc.derive_hpke_keypair(config, ikm))
        } else {
            self.rc.derive_hpke_keypair(config, ikm)
        }
    }
}

/// Core provider: [UmberaCrypto] + the existing RustCrypto randomness and storage.
pub struct UmberaProvider {
    crypto: UmberaCrypto,
    storage: MemoryStorage,
}

impl Default for UmberaProvider {
    fn default() -> Self {
        Self { crypto: UmberaCrypto::new(), storage: MemoryStorage::default() }
    }
}

impl OpenMlsProvider for UmberaProvider {
    type CryptoProvider = UmberaCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto.rc
    }
}
