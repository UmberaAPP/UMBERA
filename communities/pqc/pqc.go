// Package pqc — hybrid (classical + post-quantum) cryptography for Communities, as in the main
// messenger: signature = ed25519 AND ML-DSA-65 (FIPS 204), encryption to a key = X25519 AND
// ML-KEM-1024 (FIPS 203). Breaking one half (including by a quantum computer — ed25519/X25519)
// yields nothing: verification requires both signatures, the envelope key is derived from both secrets.
//
// A member's keys (separate per channel) are derived on the phone from two 32-byte secrets:
//
//	seed     — ed25519 seed (RFC 8032). Only SHA-512(seed) is ever exposed, so the seed cannot
//	           be recovered even from the public key with Shor's algorithm.
//	encPriv  — X25519 private key.
//	dsaSeed  = HKDF-SHA256(seed, salt = "umbera-comm-keys-v2", info = "mldsa65", 32)   → ML-DSA-65 ξ
//	kemSeed  = HKDF-SHA256(seed, salt = "umbera-comm-keys-v2", info = "mlkem1024", 64) → ML-KEM-1024 d‖z
//
// PQ keys are derived from seed, NOT from encPriv: a quantum adversary recovers the X25519 private key
// from the public key, but not the ed25519 seed.
//
// A member's public encryption key (enc_key) = X25519_pub(32) ‖ ML-KEM-1024_pub(1568) = 1600 bytes.
package pqc

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"golang.org/x/crypto/hkdf"
)

const (
	EdPubSize  = ed25519.PublicKeySize // 32
	EdSigSize  = ed25519.SignatureSize // 64
	DSAPubSize = mldsa65.PublicKeySize // 1952
	DSASigSize = mldsa65.SignatureSize // 3309
	KEMPubSize = mlkem1024.PublicKeySize
	KEMCtSize  = mlkem1024.CiphertextSize // 1568
	EncPubSize = 32 + KEMPubSize          // 1600
	// HybridSigSize — the signature inside ciphertexts: ed25519(64) ‖ ML-DSA-65(3309).
	HybridSigSize = EdSigSize + DSASigSize

	keysSalt = "umbera-comm-keys-v2"
)

// EncKey — the private half of a member's encryption key.
type EncKey struct {
	X   *ecdh.PrivateKey
	KEM *mlkem1024.PrivateKey
	Pub []byte // X25519_pub ‖ ML-KEM_pub (1600)
}

// Member — all keys of a pseudonym (on the server used only in tests and reference vectors).
type Member struct {
	EdPriv ed25519.PrivateKey
	EdPub  ed25519.PublicKey
	DSA    *mldsa65.PrivateKey
	DSAPub []byte
	Enc    *EncKey
}

func derive(seed []byte, info string, n int) []byte {
	out := make([]byte, n)
	_, _ = io.ReadFull(hkdf.New(sha256.New, seed, []byte(keysSalt), []byte(info)), out)
	return out
}

// DSASeed / KEMSeed — PQ secrets derived from the ed25519 seed (see the package header).
func DSASeed(seed []byte) []byte { return derive(seed, "mldsa65", mldsa65.SeedSize) }
func KEMSeed(seed []byte) []byte { return derive(seed, "mlkem1024", mlkem1024.KeySeedSize) }

// DeriveMember — pseudonym keys from seed (32) and encPriv (32), as on the phone (CommCrypto.kt).
func DeriveMember(seed, encPriv []byte) (*Member, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("seed must be 32 bytes")
	}
	edPriv := ed25519.NewKeyFromSeed(seed)
	var ds [mldsa65.SeedSize]byte
	copy(ds[:], DSASeed(seed))
	dpub, dpriv := mldsa65.NewKeyFromSeed(&ds)
	enc, err := DeriveEnc(seed, encPriv)
	if err != nil {
		return nil, err
	}
	return &Member{EdPriv: edPriv, EdPub: edPriv.Public().(ed25519.PublicKey), DSA: dpriv, DSAPub: dpub.Bytes(), Enc: enc}, nil
}

// DeriveEnc — hybrid encryption key: X25519 from encPriv, ML-KEM-1024 from seed.
func DeriveEnc(seed, encPriv []byte) (*EncKey, error) {
	x, err := ecdh.X25519().NewPrivateKey(encPriv)
	if err != nil {
		return nil, err
	}
	kpub, kpriv := mlkem1024.NewKeyFromSeed(KEMSeed(seed))
	kb, _ := kpub.MarshalBinary()
	return &EncKey{X: x, KEM: kpriv, Pub: append(append([]byte{}, x.PublicKey().Bytes()...), kb...)}, nil
}

// Sign — hybrid signature: (ed25519, deterministic ML-DSA-65, empty context).
func (m *Member) Sign(msg []byte) (ed, pq []byte) {
	ed = ed25519.Sign(m.EdPriv, msg)
	pq = make([]byte, DSASigSize)
	if err := mldsa65.SignTo(m.DSA, msg, nil, false, pq); err != nil {
		panic(err) // only on a wrong buffer length
	}
	return ed, pq
}

// SignConcat — ed25519(64) ‖ ML-DSA-65(3309), the signature format inside ciphertexts.
func (m *Member) SignConcat(msg []byte) []byte {
	ed, pq := m.Sign(msg)
	return append(ed, pq...)
}

// ParseDSAPub — ML-DSA-65 public key (1952 bytes).
func ParseDSAPub(b []byte) (*mldsa65.PublicKey, error) {
	if len(b) != DSAPubSize {
		return nil, errors.New("bad ml-dsa-65 public key")
	}
	pk := new(mldsa65.PublicKey)
	if err := pk.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return pk, nil
}

// Verify — both signatures must be valid (fail closed): ed25519 with edPub and ML-DSA-65 with dsaPub.
func Verify(edPub, dsaPub, msg, edSig, pqSig []byte) bool {
	if len(edPub) != EdPubSize || len(edSig) != EdSigSize || len(pqSig) != DSASigSize {
		return false
	}
	pk, err := ParseDSAPub(dsaPub)
	if err != nil {
		return false
	}
	ok1 := ed25519.Verify(edPub, msg, edSig)
	ok2 := mldsa65.Verify(pk, msg, nil, pqSig)
	return ok1 && ok2
}

// VerifyConcat — verifies a signature in SignConcat format.
func VerifyConcat(edPub, dsaPub, msg, sig []byte) bool {
	if len(sig) != HybridSigSize {
		return false
	}
	return Verify(edPub, dsaPub, msg, sig[:EdSigSize], sig[EdSigSize:])
}

// ValidEncPub — a member's public encryption key: X25519(32) ‖ ML-KEM-1024(1568), both parts valid.
func ValidEncPub(b []byte) bool {
	if len(b) != EncPubSize {
		return false
	}
	if _, err := ecdh.X25519().NewPublicKey(b[:32]); err != nil {
		return false
	}
	var pk mlkem1024.PublicKey
	return pk.Unpack(b[32:]) == nil
}
