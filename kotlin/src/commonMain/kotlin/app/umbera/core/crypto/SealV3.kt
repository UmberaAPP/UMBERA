package app.umbera.core.crypto

import app.umbera.core.util.B64
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Sealed 1:1 envelope v3 and file-key wrapping v2 — a hybrid key bound to the
 * transcript.
 *
 * Full envelope v3 (same composition as v2: ephemeral X25519 + ML-KEM-1024 capsule), but
 *   TH  = SHA-256( part("umbera-seal-v3/transcript") ‖ part(eph_pk) ‖ part(ct) ‖ part(rcpt_x) ‖ part(rcpt_ek) )
 *   OKM = HKDF-SHA256(ss_X25519 ‖ ss_ML-KEM, salt = TH, info = "typex-hybrid-v2/seal", 64), k_aes = OKM[0..32)
 *   AAD = "umbera-seal-v3"
 * part(x) = u32be(len(x)) ‖ x — same as transcript() in core/src/callkey.rs.
 * A full v3 carries no plaintext sender PQ keys (ML-KEM 1568 B and ML-DSA 1952 B, present in every v2 envelope):
 * the recipient uses pinned/directory keys (the ML-DSA key is needed only for a legacy hybrid-pq-v2
 * payload — then it is included as before).
 *
 * The short envelope v3s is a size optimisation (no capsule on every message): no ML-KEM capsule.
 * The PQ secret comes from the pair secret S of the last full envelope acknowledged by the recipient (`sa` field inside the ciphertext):
 *   S       = HKDF(ss_X25519 ‖ ss_ML-KEM of the full one, salt = TH, info = "typex-hybrid-v2/seal-pair", 32)
 *   C_0 = S; mk_i = HKDF(C_i, info = "umbera-seal-v3s/mk"); C_{i+1} = HKDF(C_i, info = "umbera-seal-v3s/ck")
 *   hint_i  = HKDF(mk_i, info = "umbera-seal-v3s/hint", 8)    — lets the recipient find the chain without trial decryption
 *   TH_s    = SHA-256( part("umbera-seal-v3s/transcript") ‖ part(eph_pk) ‖ part(rcpt_x) ‖ part(rcpt_ek) ‖ part(hint_i) )
 *   k_aes   = HKDF(ss_X25519(eph, rcpt) ‖ mk_i, salt = TH_s, info = "typex-hybrid-v2/seal-short", 32), AAD "umbera-seal-v3s"
 * Ephemeral X25519 in every envelope (classical forward secrecy as before); the chain C_i is one-way, the sender
 * keeps only the next link (past mk cannot be derived from it). The recipient keeps the window's mk until the chain expires
 * (≤ [RECV_MAX_AGE_MS], [rxAccept]) so that a replay of the same envelope (push + poll) still opens. Hence forward secrecy
 * of the PQ half of short envelopes at the recipient is per chain window, not per message (an earlier comment
 * wrongly said "the recipient erases the used mk_i"). The content underneath is also ratcheted with its own forward secrecy.
 * At most [SHORT_PER_FULL] short ones per full one, no longer than [PAIR_MAX_AGE_MS] and at most [RECV_WINDOW] in a row
 * without an incoming message from the peer — then a full one again.
 */
object SealV3 {
    const val VERSION = "v3"
    const val VERSION_SHORT = "v3s"
    /** One full per 50 envelopes: 49 short ones from the pair secret. */
    const val SHORT_PER_FULL = 49
    const val PAIR_MAX_AGE_MS = 24L * 3600_000L
    /** How many links ahead the recipient keeps ready (gaps/reordering in transit). */
    const val RECV_WINDOW = 16
    /** How many pair secrets from one sender the recipient keeps (lossless full → short transition). */
    const val RECV_KEEP = 8
    const val RECV_MAX_AGE_MS = 7L * 24 * 3600_000L

    const val HINT_LEN = 8
    private const val X25519_LEN = 32

    val AAD_FULL = "umbera-seal-v3".encodeToByteArray()
    val AAD_SHORT = "umbera-seal-v3s".encodeToByteArray()
    private val TH_FULL = "umbera-seal-v3/transcript".encodeToByteArray()
    private val TH_SHORT = "umbera-seal-v3s/transcript".encodeToByteArray()
    private val TH_FILE = "umbera-filewrap-v2/transcript".encodeToByteArray()
    private val INFO_SEAL = "typex-hybrid-v2/seal".encodeToByteArray()
    private val INFO_PAIR = "typex-hybrid-v2/seal-pair".encodeToByteArray()
    private val INFO_SHORT = "typex-hybrid-v2/seal-short".encodeToByteArray()
    private val INFO_FILE = "typex-hybrid-v2/file".encodeToByteArray()
    private val INFO_MK = "umbera-seal-v3s/mk".encodeToByteArray()
    private val INFO_CK = "umbera-seal-v3s/ck".encodeToByteArray()
    private val INFO_HINT = "umbera-seal-v3s/hint".encodeToByteArray()
    private val INFO_ID = "umbera-seal-v3/pair-id".encodeToByteArray()
    private val INFO_DIR = "umbera-rendezvous-v2/dir".encodeToByteArray()
    val AAD_FILE = "umbera-filewrap-v2".encodeToByteArray()

    /**
     * `hybrid-pq-v3` payload — the static path (HybridKeyExchange with the sender's static
     * X25519, the fallback to the ratchet) with the same transcript binding:
     *   TH  = SHA-256( part("umbera-hybrid-static-v3/transcript") ‖ part(sender_x) ‖ part(ct) ‖ part(rcpt_x) ‖ part(rcpt_ek) )
     *   OKM = HKDF-SHA256(ss_X25519(static) ‖ ss_ML-KEM, salt = TH, info = "typex-hybrid-v2/static", 64), k_aes = OKM[0..32)
     *   AAD = "umbera-hybrid-pq-v3"
     * Accepted under the same WIRE_CAP_SEAL_V3 bit (no store build has advertised the bit yet — its meaning
     * "accepts envelope v3, file key v2 and hybrid-pq-v3" is fixed before the first advertisement).
     */
    const val PAYLOAD_STATIC_V3 = "hybrid-pq-v3"
    private val TH_STATIC = "umbera-hybrid-static-v3/transcript".encodeToByteArray()
    private val INFO_STATIC = "typex-hybrid-v2/static".encodeToByteArray()
    val AAD_STATIC = "umbera-hybrid-pq-v3".encodeToByteArray()

    private fun u32(v: Int) = byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())
    private fun part(x: ByteArray) = u32(x.size) + x
    private fun th(label: ByteArray, vararg parts: ByteArray): ByteArray {
        var acc = part(label)
        for (p in parts) acc += part(p)
        return RustCore.sha256(acc)
    }
    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, n: Int) = RustCore.hkdfSha256(ikm, salt, info, n.toUInt())

    private fun checkLens(eph: ByteArray, rcptX: ByteArray, rcptEk: ByteArray) {
        require(eph.size == X25519_LEN) { "seal v3: eph ${eph.size}" }
        require(rcptX.size == X25519_LEN) { "seal v3: rcpt_x ${rcptX.size}" }
        require(rcptEk.size == Kyber1024.PUBLIC_KEY_SIZE) { "seal v3: rcpt_ek ${rcptEk.size}" }
    }

    private fun checkSs(ss: ByteArray) { require(ss.size == X25519_LEN && ss.any { it != 0.toByte() }) { "seal v3: low-order X25519" } }

    fun transcriptFull(eph: ByteArray, ct: ByteArray, rcptX: ByteArray, rcptEk: ByteArray): ByteArray {
        checkLens(eph, rcptX, rcptEk)
        require(ct.size == Kyber1024.CIPHERTEXT_SIZE) { "seal v3: ct ${ct.size}" }
        return th(TH_FULL, eph, ct, rcptX, rcptEk)
    }

    /** OKM(64) of a full envelope: [0..32) is the AES key (the rest is reserve, as in v2). */
    fun fullOkm(ssX: ByteArray, ssKem: ByteArray, th: ByteArray): ByteArray { checkSs(ssX); return hkdf(ssX + ssKem, th, INFO_SEAL, 64) }

    /** Pair secret from a full envelope (its own info — independent of this envelope's AES key). */
    fun pairSecret(ssX: ByteArray, ssKem: ByteArray, th: ByteArray): ByteArray { checkSs(ssX); return hkdf(ssX + ssKem, th, INFO_PAIR, 32) }

    /**
     * Direction secret for the v2 mailbox address — from the same full envelope (the capsule is already sent, 0 extra bytes),
     * own info: not derivable from the pair secret or the AES key and vice versa.
     */
    fun dirSecret(ssX: ByteArray, ssKem: ByteArray, th: ByteArray): ByteArray { checkSs(ssX); return hkdf(ssX + ssKem, th, INFO_DIR, 32) }

    fun pairId(s: ByteArray): String = hex(hkdf(s, ByteArray(0), INFO_ID, 8))

    fun chainMk(ck: ByteArray): ByteArray = hkdf(ck, ByteArray(0), INFO_MK, 32)
    fun chainNext(ck: ByteArray): ByteArray = hkdf(ck, ByteArray(0), INFO_CK, 32)
    fun hint(mk: ByteArray): ByteArray = hkdf(mk, ByteArray(0), INFO_HINT, HINT_LEN)

    fun transcriptShort(eph: ByteArray, rcptX: ByteArray, rcptEk: ByteArray, hint: ByteArray): ByteArray {
        checkLens(eph, rcptX, rcptEk)
        require(hint.size == HINT_LEN) { "seal v3s: hint ${hint.size}" }
        return th(TH_SHORT, eph, rcptX, rcptEk, hint)
    }

    fun shortKey(ssX: ByteArray, mk: ByteArray, th: ByteArray): ByteArray { checkSs(ssX); return hkdf(ssX + mk, th, INFO_SHORT, 32) }

    fun transcriptFile(eph: ByteArray, kct: ByteArray, rcptX: ByteArray, rcptEk: ByteArray): ByteArray {
        checkLens(eph, rcptX, rcptEk)
        require(kct.size == Kyber1024.CIPHERTEXT_SIZE) { "filewrap v2: kct ${kct.size}" }
        return th(TH_FILE, eph, kct, rcptX, rcptEk)
    }

    fun fileKey(ssX: ByteArray, ssKem: ByteArray, th: ByteArray): ByteArray { checkSs(ssX); return hkdf(ssX + ssKem, th, INFO_FILE, 32) }

    /** Transcript of the static path (`hybrid-pq-v3`): the sender's static X25519 instead of an ephemeral one. */
    fun transcriptStatic(senderX: ByteArray, ct: ByteArray, rcptX: ByteArray, rcptEk: ByteArray): ByteArray {
        checkLens(senderX, rcptX, rcptEk)
        require(ct.size == Kyber1024.CIPHERTEXT_SIZE) { "hybrid-pq-v3: ct ${ct.size}" }
        return th(TH_STATIC, senderX, ct, rcptX, rcptEk)
    }

    fun staticOkm(ssX: ByteArray, ssKem: ByteArray, th: ByteArray): ByteArray { checkSs(ssX); return hkdf(ssX + ssKem, th, INFO_STATIC, 64) }

    // ── pair secret state ────────────────────────────────────────────────────────────────────

    /** Sender → peer: secret from the last full one (awaiting acknowledgement) and the active chain. */
    @Serializable
    data class TxState(
        @SerialName("p") val pending: List<TxPending> = emptyList(), // newest first, at most 3
        @SerialName("a") val active: TxChain? = null,
        /** Short ones in a row without an incoming message from the peer (carrying its `sa` for our chain). */
        @SerialName("o") val sinceIn: Int = 0,
        /** Time (peer's clock) of the peer's last message carrying `sa` for our chain.
         *  A message without `sa` older than that is a replay (a malicious server re-delivers an old message), it does not drop the chain.
         *  Device storage only, never on the wire; 0 means state from a previous version (behaves as before). */
        @SerialName("at") val ackTs: Long = 0,
    )

    @Serializable
    data class TxPending(
        @SerialName("i") val id: String, @SerialName("s") val secret: String, @SerialName("t") val createdMs: Long, @SerialName("r") val rcpt: String,
        @SerialName("d") val dir: String? = null, // direction secret (base64)
    )

    /** Active chain: next link [ck] (index [n]), bound to the recipient's keys [rcpt]. */
    @Serializable
    data class TxChain(@SerialName("i") val id: String, @SerialName("c") val ck: String, @SerialName("n") val n: Int, @SerialName("t") val createdMs: Long, @SerialName("r") val rcpt: String)

    /** Recipient ← peer: up to [RECV_KEEP] chains; each has the window's ready mk (index → mk) and the next link. */
    @Serializable
    data class RxState(@SerialName("c") val chains: List<RxChain> = emptyList())

    @Serializable
    data class RxChain(
        @SerialName("i") val id: String,
        @SerialName("c") val ck: String,          // link with index [next]
        @SerialName("n") val next: Int,
        @SerialName("k") val keys: Map<Int, String> = emptyMap(), // index → "mk(base64):hint(hex)"
        @SerialName("h") val highest: Int = -1,   // highest accepted index
        @SerialName("t") val createdMs: Long,
        @SerialName("u") val usedMs: Long,
        @SerialName("d") val dir: String? = null, // direction secret (base64)
    )

    /** Fingerprint of the recipient's keys (the pair secret is valid only for them). */
    fun rcptTag(rcptX: ByteArray, rcptEk: ByteArray): String = hex(RustCore.sha256(part(rcptX) + part(rcptEk))).take(32)

    /** New pair secret at the recipient: mk window [RECV_WINDOW] ahead. */
    fun rxNew(s: ByteArray, now: Long, dir: ByteArray? = null): RxChain =
        rxFill(RxChain(pairId(s), B64.encode(s), 0, emptyMap(), -1, now, now, dir?.let { B64.encode(it) }))

    /** Top up the window: mk for indices up to min(highest accepted + [RECV_WINDOW], [SHORT_PER_FULL] − 1). */
    fun rxFill(c: RxChain): RxChain {
        var ck = B64.decode(c.ck)
        var next = c.next
        val keys = c.keys.toMutableMap()
        val upto = minOf(c.highest + RECV_WINDOW, SHORT_PER_FULL - 1)
        while (next <= upto) {
            val mk = chainMk(ck)
            keys[next] = B64.encode(mk) + ":" + hex(hint(mk))
            ck = chainNext(ck)
            next++
        }
        return c.copy(ck = B64.encode(ck), next = next, keys = keys)
    }

    /** Index [n] accepted: slide the window. mk is not erased until the chain expires (≤ 7 days): a replay of the same envelope
     *  (push + poll) must open; outer-layer secrecy at the recipient is, as in v2, provided by its long-term keys. */
    fun rxAccept(c: RxChain, n: Int, now: Long): RxChain = rxFill(c.copy(highest = maxOf(c.highest, n), usedMs = now))

    /** Find the index and mk by hint. */
    fun rxFind(c: RxChain, hintHex: String): Pair<Int, ByteArray>? {
        for ((n, v) in c.keys) {
            val i = v.indexOf(':')
            if (i > 0 && v.regionMatches(i + 1, hintHex, 0, hintHex.length) && v.length == i + 1 + hintHex.length) return n to B64.decode(v.substring(0, i))
        }
        return null
    }

    fun hex(b: ByteArray): String = b.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0) { "hex" }
        return ByteArray(s.length / 2) { i -> s.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
}
