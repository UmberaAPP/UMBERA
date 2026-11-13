package app.umbera.communities.crypto

import app.umbera.core.crypto.RustCore
import app.umbera.core.crypto.secureRandomBytes
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Communities protocol, identical to the server. All primitives come from the shared
 * Rust core (RustCore), so Android and iPhone produce byte-for-byte identical results.
 *
 * ALL asymmetric crypto is HYBRID classical + post-quantum, as in the messenger:
 * signature = ed25519 AND ML-DSA-65 (FIPS 204), public-key encryption = X25519 AND ML-KEM-1024 (FIPS 203).
 * Symmetric primitives (AES-256-GCM, HKDF-SHA256, SHA-256) are not broken by a quantum computer and stay as is.
 * Go ↔ phone reference vectors: communities/pqc/testdata/pq-vectors.json (checked by PqVectorsActivity).
 *
 * Pseudonym keys (separate per channel) derive from two 32-byte secrets, seed (ed25519) and encPriv (X25519):
 *    ML-DSA-65 ξ   = HKDF-SHA256(seed, salt = "umbera-comm-keys-v2", info = "mldsa65", 32)
 *    ML-KEM-1024 d‖z = HKDF-SHA256(seed, salt = "umbera-comm-keys-v2", info = "mlkem1024", 64)
 *    (from seed, not from encPriv: a quantum adversary recovers the X25519 private key from the public one,
 *    but not the ed25519 seed; only SHA-512(seed) is ever exposed).
 *    enc_pub = X25519_pub(32) ‖ ML-KEM-1024_pub(1568) = 1600 bytes.
 *
 * Formats (version 2):
 *  - request signature: string "UMBERA-COMM-v2\n" + nonce + "\n" + method + "\n" + path?query + "\n" + time +
 *    "\n" + hex(sha256(body)); headers X-Member-Sig = ed25519, X-Member-PQSig = ML-DSA-65 (3309 B),
 *    X-Member-PQKey = ML-DSA-65 key (1952 B), until the server has pinned it to the pseudonym key.
 *  - envelope (seal): 0x02 ‖ eph_pub(32) ‖ mlkem_ct(1568) ‖ iv(12) ‖ AES-256-GCM(k, pt, aad="umbera-comm-seal-v2"),
 *    k = HKDF-SHA256(ikm = X25519(eph, rcpt) ‖ ML-KEM-1024 shared secret,
 *    salt = eph_pub ‖ sha256(mlkem_ct) ‖ sha256(rcpt_enc_pub), info = "umbera-comm-seal-v2"); +1629 bytes
 *  - private channel post/comment: 0x02 ‖ salt(16) ‖ iv(12) ‖ AES-256-GCM(post_key,
 *    ed25519(64) ‖ ML-DSA-65(3309) ‖ JSON, aad = "umbera-comm-post-v1" ‖ channel_id(16) ‖ epoch(4 BE)),
 *    post_key = HKDF(channel key, salt, "umbera-comm-post-v1"); signatures over "UMBERA-COMM-POSTSIG-v2\n" ‖ id ‖ "\n" ‖ JSON
 *  - private channel metadata (title, rules, topics…): 0x01 ‖ iv(12) ‖ AES-256-GCM(
 *    HKDF(channel key, empty, "umbera-comm-meta-v1/<purpose>"), JSON, aad = "umbera-comm-meta-v1")
 *    (the channel id is not yet known at creation, so it is not in aad; the purpose is in the key)
 *  - multi-recipient message (applicant answers for the team): 0x03 ‖ n ‖ n×(pseudonym key(32) ‖ seal(cek)) ‖ iv(12) ‖ AES-GCM(cek, pt, "umbera-comm-multi-v2")
 *  - private channel file: header 0x01 ‖ prefix(8), 1 MiB chunks: AES-GCM(file_key, chunk,
 *    iv = prefix ‖ index(4 BE), aad = "umbera-comm-file-v1" ‖ index(4) ‖ last(1))
 */
object CommCrypto {
    const val SIG_DOMAIN = "UMBERA-COMM-v2"
    private const val KEYS_SALT = "umbera-comm-keys-v2"
    private const val SEAL_INFO = "umbera-comm-seal-v2"
    private const val SEAL_VERSION: Byte = 2
    private const val POST_INFO = "umbera-comm-post-v1"
    private const val POST_VERSION: Byte = 2
    private const val POSTSIG = "UMBERA-COMM-POSTSIG-v2\n"
    private const val MULTI_INFO = "umbera-comm-multi-v2"
    private const val MULTI_VERSION: Byte = 3
    const val ED_SIG = 64
    const val DSA_SIG = 3309
    const val DSA_PUB = 1952
    const val KEM_CT = 1568
    const val KEM_PUB = 1568
    const val ENC_PUB = 32 + KEM_PUB
    const val HYBRID_SIG = ED_SIG + DSA_SIG
    const val SEAL_OVERHEAD = 1 + 32 + KEM_CT + 12 + 16
    private const val FILE_INFO = "umbera-comm-file-v1"
    const val FILE_CHUNK = 1 shl 20

    fun random(n: Int): ByteArray = secureRandomBytes(n)

    fun sha256(b: ByteArray): ByteArray = RustCore.sha256(b)

    fun hex(b: ByteArray): String {
        val d = "0123456789abcdef"
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xff
            sb.append(d[v shr 4]).append(d[v and 15])
        }
        return sb.toString()
    }

    fun hkdf(ikm: ByteArray, salt: ByteArray, info: String, len: Int = 32): ByteArray =
        RustCore.hkdfSha256(ikm, salt, info.encodeToByteArray(), len.toUInt())

    // ---------- Request signing ----------

    fun signedString(method: String, pathAndQuery: String, ts: Long, nonce: String, body: ByteArray): ByteArray =
        buildString {
            append(SIG_DOMAIN).append('\n')
            append(nonce).append('\n')
            append(method).append('\n')
            append(pathAndQuery).append('\n')
            append(ts).append('\n')
            append(hex(sha256(body)))
        }.encodeToByteArray()

    // ---------- Pseudonym keys (hybrid) ----------

    fun dsaSeed(seed: ByteArray): ByteArray = hkdf(seed, KEYS_SALT.encodeToByteArray(), "mldsa65", 32)

    fun kemSeed(seed: ByteArray): ByteArray = hkdf(seed, KEYS_SALT.encodeToByteArray(), "mlkem1024", 64)

    fun publicFromSeed(seed: ByteArray): ByteArray = RustCore.ed25519PublicFromSeed(seed)

    fun dsaPublic(dsaSeed: ByteArray): ByteArray = RustCore.mldsa65PublicKey(dsaSeed)

    fun x25519Public(priv: ByteArray): ByteArray = RustCore.x25519PublicKey(priv)

    /** Hybrid private encryption key: X25519 (encPriv) + ML-KEM-1024 (seed d‖z, 64 B). */
    class EncPrivate(val x25519: ByteArray, val kemSeed: ByteArray) {
        /** X25519_pub(32) ‖ ML-KEM-1024_pub(1568). */
        val pub: ByteArray by lazy { RustCore.x25519PublicKey(x25519) + RustCore.mlkem1024PublicKey(kemSeed) }
    }

    /** Pseudonym encryption key: X25519 from encPriv, ML-KEM-1024 from the ed25519 seed. */
    fun encPrivate(seed: ByteArray, encPriv: ByteArray) = EncPrivate(encPriv, kemSeed(seed))

    /** Hybrid signature: ed25519 (64) and deterministic ML-DSA-65 (3309) over the same message. */
    fun signHybrid(seed: ByteArray, msg: ByteArray): Pair<ByteArray, ByteArray> =
        RustCore.ed25519Sign(msg, seed) to RustCore.mldsa65Sign(msg, dsaSeed(seed))

    /** Both signatures must be valid (fail closed). */
    fun verifyHybrid(edPub: ByteArray, dsaPub: ByteArray, msg: ByteArray, edSig: ByteArray, dsaSig: ByteArray): Boolean {
        if (edPub.size != 32 || dsaPub.size != DSA_PUB || edSig.size != ED_SIG || dsaSig.size != DSA_SIG) return false
        val ok1 = RustCore.ed25519Verify(edPub, msg, edSig)
        val ok2 = RustCore.mldsa65Verify(msg, dsaSig, dsaPub)
        return ok1 && ok2
    }

    fun validEncPub(pub: ByteArray): Boolean =
        pub.size == ENC_PUB && RustCore.mlkem1024ValidatePublicKey(pub.copyOfRange(32, ENC_PUB))

    // ---------- Envelope to a hybrid key (X25519 + ML-KEM-1024) ----------

    private fun x25519(priv: ByteArray, pub: ByteArray): ByteArray {
        val s = RustCore.x25519SharedSecret(priv, pub)
        require(s.any { it != 0.toByte() }) { "x25519 low-order point" }
        return s
    }

    private fun sealKey(ssX: ByteArray, ssKem: ByteArray, ephPub: ByteArray, ct: ByteArray, rcptPub: ByteArray): ByteArray =
        hkdf(ssX + ssKem, ephPub + sha256(ct) + sha256(rcptPub), SEAL_INFO)

    fun seal(rcptPub: ByteArray, pt: ByteArray): ByteArray {
        require(validEncPub(rcptPub)) { "bad recipient key" }
        val eph = random(32)
        val ephPub = RustCore.x25519PublicKey(eph)
        val ssX = x25519(eph, rcptPub.copyOfRange(0, 32))
        val kem = RustCore.mlkem1024Encapsulate(rcptPub.copyOfRange(32, ENC_PUB))
        val k = sealKey(ssX, kem.sharedSecret, ephPub, kem.ciphertext, rcptPub)
        val iv = random(12)
        return byteArrayOf(SEAL_VERSION) + ephPub + kem.ciphertext + iv + RustCore.aes256GcmEncrypt(k, iv, pt, SEAL_INFO.encodeToByteArray())
    }

    fun open(k: EncPrivate, box: ByteArray): ByteArray {
        require(box.size >= SEAL_OVERHEAD && box[0] == SEAL_VERSION) { "bad box" }
        val ephPub = box.copyOfRange(1, 33)
        val ct = box.copyOfRange(33, 33 + KEM_CT)
        val ssX = x25519(k.x25519, ephPub)
        val ssKem = RustCore.mlkem1024Decapsulate(ct, k.kemSeed)
        val key = sealKey(ssX, ssKem, ephPub, ct, k.pub)
        val ivAt = 33 + KEM_CT
        return RustCore.aes256GcmDecrypt(key, box.copyOfRange(ivAt, ivAt + 12), box.copyOfRange(ivAt + 12, box.size), SEAL_INFO.encodeToByteArray())
    }

    // ---------- Channel key in an envelope: key(32) ‖ generation(4 BE) ----------

    fun channelKeyEnvelope(rcptEncPub: ByteArray, key: ByteArray, epoch: Int): ByteArray = seal(rcptEncPub, key + be32(epoch))

    fun openChannelKey(priv: EncPrivate, env: ByteArray): Pair<ByteArray, Int> {
        val pt = open(priv, env)
        require(pt.size == 36) { "bad channel key" }
        return pt.copyOfRange(0, 32) to readBe32(pt, 32)
    }

    // ---------- Private channel posts and comments ----------

    class Sealed(val body: ByteArray, val postKey: ByteArray)

    private fun postSigMessage(channelId: ByteArray, json: ByteArray) =
        POSTSIG.encodeToByteArray() + uuidString(channelId).encodeToByteArray() + "\n".encodeToByteArray() + json

    /** salt/iv are set only by reference vectors; random in normal operation. */
    fun encryptPost(
        authorSeed: ByteArray, channelId: ByteArray, channelKey: ByteArray, epoch: Int, json: ByteArray,
        salt: ByteArray = random(16), iv: ByteArray = random(12),
    ): Sealed {
        val (ed, pq) = signHybrid(authorSeed, postSigMessage(channelId, json))
        val pk = hkdf(channelKey, salt, POST_INFO)
        val ct = RustCore.aes256GcmEncrypt(pk, iv, ed + pq + json, postAad(channelId, epoch))
        return Sealed(byteArrayOf(POST_VERSION) + salt + iv + ct, pk)
    }

    /** Decrypt without verifying signatures (only to learn whom to ask for the author's key). */
    fun peekPost(enc: ByteArray, channelId: ByteArray, channelKey: ByteArray, epoch: Int): ByteArray? = runCatching {
        require(enc.size > 1 + 16 + 12 + 16 + HYBRID_SIG && enc[0] == POST_VERSION)
        val pk = hkdf(channelKey, enc.copyOfRange(1, 17), POST_INFO)
        val pt = RustCore.aes256GcmDecrypt(pk, enc.copyOfRange(17, 29), enc.copyOfRange(29, enc.size), postAad(channelId, epoch))
        pt.copyOfRange(HYBRID_SIG, pt.size)
    }.getOrNull()

    /**
     * Decrypt and verify BOTH author signatures (ed25519 with authorPub, ML-DSA-65 with authorDsaPub).
     * Returns JSON, or null on forgery / wrong key.
     */
    fun decryptPost(enc: ByteArray, channelId: ByteArray, channelKey: ByteArray, epoch: Int, authorPub: ByteArray, authorDsaPub: ByteArray): ByteArray? = runCatching {
        require(enc.size > 1 + 16 + 12 + 16 + HYBRID_SIG && enc[0] == POST_VERSION)
        val pk = hkdf(channelKey, enc.copyOfRange(1, 17), POST_INFO)
        val pt = RustCore.aes256GcmDecrypt(pk, enc.copyOfRange(17, 29), enc.copyOfRange(29, enc.size), postAad(channelId, epoch))
        val json = pt.copyOfRange(HYBRID_SIG, pt.size)
        val ok = verifyHybrid(authorPub, authorDsaPub, postSigMessage(channelId, json), pt.copyOfRange(0, ED_SIG), pt.copyOfRange(ED_SIG, HYBRID_SIG))
        if (!ok) return null
        json
    }.getOrNull()

    /** Key of a single post, for a verifiable report (only this post is disclosed). */
    fun postKeyOf(enc: ByteArray, channelKey: ByteArray): ByteArray = hkdf(channelKey, enc.copyOfRange(1, 17), POST_INFO)

    private fun postAad(channelId: ByteArray, epoch: Int) = POST_INFO.encodeToByteArray() + channelId + be32(epoch)

    // ---------- Private channel metadata ----------

    private val META_AAD = "umbera-comm-meta-v1".encodeToByteArray()

    fun encryptMeta(channelKey: ByteArray, purpose: String, json: ByteArray): ByteArray {
        val k = hkdf(channelKey, ByteArray(0), "umbera-comm-meta-v1/$purpose")
        val iv = random(12)
        return byteArrayOf(1) + iv + RustCore.aes256GcmEncrypt(k, iv, json, META_AAD)
    }

    fun decryptMeta(channelKey: ByteArray, purpose: String, enc: ByteArray): ByteArray? = runCatching {
        require(enc.size > 1 + 12 + 16 && enc[0] == 1.toByte())
        val k = hkdf(channelKey, ByteArray(0), "umbera-comm-meta-v1/$purpose")
        RustCore.aes256GcmDecrypt(k, enc.copyOfRange(1, 13), enc.copyOfRange(13, enc.size), META_AAD)
    }.getOrNull()

    // ---------- Multi-recipient message ----------

    /** recipients: (pseudonym key(32), enc_pub(1600)). */
    fun sealMulti(recipients: List<Pair<ByteArray, ByteArray>>, pt: ByteArray): ByteArray {
        require(recipients.isNotEmpty() && recipients.size <= 50)
        val cek = random(32)
        var out = byteArrayOf(MULTI_VERSION, recipients.size.toByte())
        for ((memberKey, encPub) in recipients) {
            require(memberKey.size == 32)
            out += memberKey + seal(encPub, cek)
        }
        val iv = random(12)
        return out + iv + RustCore.aes256GcmEncrypt(cek, iv, pt, MULTI_INFO.encodeToByteArray())
    }

    fun openMulti(myMemberKey: ByteArray, myEnc: EncPrivate, box: ByteArray): ByteArray? = runCatching {
        require(box.size > 2 && box[0] == MULTI_VERSION)
        val n = box[1].toInt() and 0xff
        val sealLen = SEAL_OVERHEAD + 32
        var p = 2
        var cek: ByteArray? = null
        repeat(n) {
            val mk = box.copyOfRange(p, p + 32)
            if (mk.contentEquals(myMemberKey)) cek = open(myEnc, box.copyOfRange(p + 32, p + 32 + sealLen))
            p += 32 + sealLen
        }
        val k = cek ?: return null
        RustCore.aes256GcmDecrypt(k, box.copyOfRange(p, p + 12), box.copyOfRange(p + 12, box.size), MULTI_INFO.encodeToByteArray())
    }.getOrNull()

    // ---------- Private channel files ----------

    class FileKey(val key: ByteArray, val prefix: ByteArray)

    fun newFileKey() = FileKey(random(32), random(8))

    fun encryptedSize(plain: Long): Long {
        val chunks = if (plain == 0L) 1 else (plain + FILE_CHUNK - 1) / FILE_CHUNK
        return 9 + plain + chunks * 16
    }

    fun fileHeader(fk: FileKey): ByteArray = byteArrayOf(1) + fk.prefix

    fun encryptChunk(fk: FileKey, index: Int, last: Boolean, chunk: ByteArray): ByteArray =
        RustCore.aes256GcmEncrypt(fk.key, fk.prefix + be32(index), chunk, fileAad(index, last))

    fun decryptChunk(fk: FileKey, index: Int, last: Boolean, ct: ByteArray): ByteArray =
        RustCore.aes256GcmDecrypt(fk.key, fk.prefix + be32(index), ct, fileAad(index, last))

    private fun fileAad(index: Int, last: Boolean) = FILE_INFO.encodeToByteArray() + be32(index) + byteArrayOf(if (last) 1 else 0)

    // ---------- Membership vault ----------

    class VaultKeys(val id: ByteArray, val authSeed: ByteArray, val encKey: ByteArray)

    /**
     * Vault keys from TWO account secrets (both recoverable from the seed phrase): the X25519 private key and
     * the ML-KEM-1024 seed (64 B). X25519 alone is not enough: a quantum adversary would recover it from the account
     * public key and find/read the vault; the ML-KEM seed cannot be recovered that way.
     */
    fun vaultKeys(accountX25519Private: ByteArray, accountMlkemSeed: ByteArray): VaultKeys {
        require(accountX25519Private.size == 32 && accountMlkemSeed.size == 64)
        val ikm = accountX25519Private + accountMlkemSeed
        val salt = "umbera-comm-vault-v2".encodeToByteArray()
        return VaultKeys(
            id = hkdf(ikm, salt, "vault-id"),
            authSeed = hkdf(ikm, salt, "vault-auth"),
            encKey = hkdf(ikm, salt, "vault-key"),
        )
    }

    /**
     * Epoch vault: the address, signing key and encryption key change every
     * month (epoch = months since 2026-01). The vault has no permanent address: the old one is deleted after
     * the new one is written; from the seed phrase the phone finds the latest epoch by searching backwards.
     */
    fun vaultKeysEpoch(accountX25519Private: ByteArray, accountMlkemSeed: ByteArray, epoch: Int): VaultKeys {
        require(accountX25519Private.size == 32 && accountMlkemSeed.size == 64 && epoch >= 0)
        val ikm = accountX25519Private + accountMlkemSeed
        val salt = "umbera-comm-vault-v3".encodeToByteArray()
        return VaultKeys(
            id = hkdf(ikm, salt, "vault-id/$epoch"),
            authSeed = hkdf(ikm, salt, "vault-auth/$epoch"),
            encKey = hkdf(ikm, salt, "vault-key/$epoch"),
        )
    }

    fun vaultSeal(k: VaultKeys, json: ByteArray): ByteArray {
        val iv = random(12)
        return iv + RustCore.aes256GcmEncrypt(k.encKey, iv, json, k.id)
    }

    fun vaultOpen(k: VaultKeys, blob: ByteArray): ByteArray =
        RustCore.aes256GcmDecrypt(k.encKey, blob.copyOfRange(0, 12), blob.copyOfRange(12, blob.size), k.id)

    // ---------- Private channel invite link: preview by the key after # ----------

    fun encryptPreview(linkSecret: ByteArray, json: ByteArray): ByteArray {
        val k = hkdf(linkSecret, ByteArray(0), "umbera-comm-preview-v1")
        val iv = random(12)
        return byteArrayOf(1) + iv + RustCore.aes256GcmEncrypt(k, iv, json, ByteArray(0))
    }

    fun decryptPreview(linkSecret: ByteArray, enc: ByteArray): ByteArray? = runCatching {
        val k = hkdf(linkSecret, ByteArray(0), "umbera-comm-preview-v1")
        RustCore.aes256GcmDecrypt(k, enc.copyOfRange(1, 13), enc.copyOfRange(13, enc.size), ByteArray(0))
    }.getOrNull()

    // ---------- Helpers ----------

    fun be32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    fun readBe32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
            ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)

    /** UUID → 16 bytes and back (like uuid[:] in Go). */
    fun uuidBytes(s: String): ByteArray {
        val h = s.replace("-", "")
        require(h.length == 32)
        return ByteArray(16) { h.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    }

    fun uuidString(b: ByteArray): String {
        val h = hex(b)
        return "${h.substring(0, 8)}-${h.substring(8, 12)}-${h.substring(12, 16)}-${h.substring(16, 20)}-${h.substring(20)}"
    }

    @OptIn(ExperimentalEncodingApi::class)
    fun b64url(b: ByteArray): String = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT).encode(b)

    @OptIn(ExperimentalEncodingApi::class)
    fun unb64url(s: String): ByteArray = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL).decode(s)

    @OptIn(ExperimentalEncodingApi::class)
    fun b64(b: ByteArray): String = Base64.encode(b)

    @OptIn(ExperimentalEncodingApi::class)
    fun unb64(s: String): ByteArray = Base64.decode(s)
}
