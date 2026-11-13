package app.umbera.core.crypto

import app.umbera.core.util.B64

/**
 * The safety number is IDENTICAL for both peers.
 *
 * Previously one's own fingerprint was sha256(secp256k1 ‖ Dilithium) and the peer's was
 * sha256(secp256k1): the two numbers never matched, QR verification failed,
 * and the X25519 encryption key was not part of the number at all (the server could swap it unnoticed).
 *
 * Now the identity fingerprint = sha256(secp256k1 ‖ X25519) — exactly the keys that
 * are pinned (SecureKeyStoreCommon.checkAndPinPeerKey) and that messages and calls
 * are sealed to; number = sha256(smaller fingerprint ‖ larger), identical on both sides.
 */
object SafetyNumber {

    fun identity(secp256k1: ByteArray, x25519: ByteArray): String =
        HashUtils.sha256(secp256k1 + x25519).toHexLower()

    /** Peer fingerprint from directory keys (secp256k1 — hex, X25519 — base64). */
    fun identity(secp256k1Hex: String, x25519B64: String): String? = runCatching {
        require(secp256k1Hex.length % 2 == 0 && secp256k1Hex.isNotEmpty())
        val secp = secp256k1Hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        identity(secp, B64.decode(x25519B64))
    }.getOrNull()

    /** Own fingerprint from own keys; null — no keys. */
    fun mine(store: SecureKeyStoreCommon): String? {
        val secp = store.getSecp256k1PublicKey() ?: return null
        val x = store.getX25519PublicKey() ?: return null
        return identity(secp, x)
    }

    fun combined(a: String, b: String): String =
        HashUtils.sha256Hex(if (a < b) a + b else b + a)

    // ── Safety number v2 with post-quantum keys ─────────────────────────────
    // v1 covered only secp256k1 ‖ X25519: the server could swap the peer's ML-DSA / ML-KEM, and
    // comparing numbers would not reveal it. v2 = SHA-256(label ‖ for each key: length (4 bytes BE) ‖
    // key) over secp256k1, X25519, ML-DSA-65, ML-KEM-1024. Lengths in the hash rule out "end of one
    // key = start of another" ambiguity. Number length is unchanged (it is a hash). v2 only if BOTH have PQ keys,
    // SecurityRollout.safetyNumberV2 is on AND the peer has announced it computes v2 itself (the
    // MessageEncryption.WIRE_CAP_SAFETY_V2 bit in its message): the code must match on both sides, and
    // 2.0.3 / 2.0.1 compute v1 and do not send the bit — with them the code is v1 byte for byte, as before.

    const val V1 = 1
    const val V2 = 2
    private val V2_LABEL = "umbera-safety-number-v2".encodeToByteArray()

    fun identityV2(secp256k1: ByteArray, x25519: ByteArray, mlDsaPk: ByteArray, mlKemPk: ByteArray): String {
        var buf = V2_LABEL
        for (k in listOf(secp256k1, x25519, mlDsaPk, mlKemPk)) buf += lenBE(k.size) + k
        return HashUtils.sha256(buf).toHexLower()
    }

    /** One side's keys (all raw bytes; PQ keys may be absent). */
    class Keys(val secp256k1: ByteArray, val x25519: ByteArray, val mlDsaPk: ByteArray?, val mlKemPk: ByteArray?) {
        val hasPq: Boolean get() = (mlDsaPk?.isNotEmpty() == true) && (mlKemPk?.isNotEmpty() == true)
    }

    /** Peer keys from the directory: secp256k1 — hex, X25519 — base64, ML-KEM/ML-DSA — hex (or base64). */
    fun peerKeys(secp256k1Hex: String, x25519B64: String, kyberPk: String?, dilithiumPk: String?): Keys? = runCatching {
        Keys(hexOrNull(secp256k1Hex)!!, B64.decode(x25519B64), anyBytes(dilithiumPk), anyBytes(kyberPk))
    }.getOrNull()

    fun myKeys(store: SecureKeyStoreCommon): Keys? {
        // A linked desktop has no account keys of its own — the account public keys come from the link bundle
        // (same as the phone's), so the code on the desktop is the same as on the phone.
        if (store.getLinkedDeviceId() != null) store.getLinkedAccountKeys()?.let { a ->
            return Keys(a.secp256k1, a.x25519, a.mldsa65, a.mlkem)
        }
        val secp = store.getSecp256k1PublicKey() ?: return null
        val x = store.getX25519PublicKey() ?: return null
        return Keys(secp, x, store.getDilithiumPublicKey(), store.getKyberPublicKey())
    }

    /** Whether to announce the "I compute code v2" bit to peers (MessageEncryption.localWireCaps): the switch and own PQ keys. */
    fun announcesV2(store: SecureKeyStoreCommon): Boolean =
        SecurityRollout.safetyNumberV2 && myKeys(store)?.hasPq == true

    /** Pair number and its version. Identical for both: [v2Enabled] — v2 on BOTH sides (own switch and the peer's bit). */
    data class PairNumber(val number: String, val version: Int)

    fun forPair(mine: Keys, peer: Keys, v2Enabled: Boolean = SecurityRollout.safetyNumberV2): PairNumber =
        if (v2Enabled && mine.hasPq && peer.hasPq) {
            PairNumber(combined(identityV2(mine.secp256k1, mine.x25519, mine.mlDsaPk!!, mine.mlKemPk!!),
                identityV2(peer.secp256k1, peer.x25519, peer.mlDsaPk!!, peer.mlKemPk!!)), V2)
        } else {
            PairNumber(combined(identity(mine.secp256k1, mine.x25519), identity(peer.secp256k1, peer.x25519)), V1)
        }

    /** What to show when the pair number differs from the one seen before. */
    enum class Change { NONE, UPDATED_TO_V2, KEY_CHANGED }

    /**
     * A v1→v2 transition by an upgraded peer is a calm "safety number updated", not an alarm,
     * but only if the classical part is unchanged (the v1 number over current keys equals the previous one). Changed
     * secp256k1/X25519 is a key change, as before. Key pinning (checkAndPinPeerKey) is unaffected.
     */
    fun classify(previous: PairNumber?, current: PairNumber, currentV1Number: String): Change = when {
        previous == null || previous == current -> Change.NONE
        previous.version == V1 && current.version == V2 && previous.number == currentV1Number -> Change.UPDATED_TO_V2
        else -> Change.KEY_CHANGED
    }

    // ── Verification QR with version, and screen state ─────────────────────────────────────────────
    // v1 QR — the bare number (as always: an old scanner compares the whole string). v2 QR — "usn2:" + number:
    // an old scanner sees a mismatch (and its numbers are v1 — they differ anyway), a new one understands both.
    private const val QR_V2_PREFIX = "usn2:"

    fun qrPayload(p: PairNumber): String = if (p.version == V2) QR_V2_PREFIX + p.number else p.number

    fun parseQr(scanned: String): PairNumber? {
        val t = scanned.trim()
        val (v, n) = if (t.startsWith(QR_V2_PREFIX)) V2 to t.removePrefix(QR_V2_PREFIX) else V1 to t
        if (n.length != 64 || !n.all { it in "0123456789abcdef" }) return null
        return PairNumber(n, v)
    }

    /** Whether a scanned QR matches the pair number — strictly the same version and the same number. */
    fun scanMatches(scanned: String, current: PairNumber): Boolean = parseQr(scanned) == current

    /**
     * What to show on the verification screen: the pair number, the peer fingerprint (for "verified": v1 — as
     * before, v2 — over PQ keys, so after the transition verification must be redone) and the transition banner.
     * [v1Number] — the v1 code over the same keys, [v2Candidate] — the v2 code if it can be computed (PQ keys on both
     * sides and own switch), even when the peer's bit has not arrived yet: for verifying a QR of the other version ([checkScan]).
     */
    class ScreenNumber(
        val pair: PairNumber, val peerFingerprint: String, val change: Change,
        val v1Number: String = if (pair.version == V1) pair.number else "", val v2Candidate: PairNumber? = null,
    ) {
        val qr: String get() = qrPayload(pair)
        val version: Int get() = pair.version
    }

    fun forScreen(
        store: SecureKeyStoreCommon, userId: String, secp256k1Hex: String, x25519B64: String,
        v2Enabled: Boolean = SecurityRollout.safetyNumberV2,
    ): ScreenNumber? {
        val mine = myKeys(store) ?: return null
        val peerClassic = peerKeys(secp256k1Hex, x25519B64, null, null) ?: return null
        val peer = Keys(peerClassic.secp256k1, peerClassic.x25519, store.getPeerDilithium(userId), store.getPeerKyber(userId))
        // v2 only when the peer has announced it computes v2: otherwise its screen shows v1 and the codes would differ.
        val cur = forPair(mine, peer, v2Enabled && store.peerSafetyV2(userId))
        val v1 = if (cur.version == V1) cur.number else forPair(mine, peer, false).number
        val candidate = if (cur.version == V2) cur else forPair(mine, peer, v2Enabled).takeIf { it.version == V2 }
        val prev = store.getLastSafetyNumber(userId)?.let { s ->
            s.substringBefore(':').toIntOrNull()?.let { PairNumber(s.substringAfter(':'), it) }
        }
        val change = classify(prev, cur, v1)
        // Keep the "updated" banner until re-verified: do not overwrite the remembered v1 until confirmation.
        if (change != Change.UPDATED_TO_V2) store.saveLastSafetyNumber(userId, "${cur.version}:${cur.number}")
        val fp = if (cur.version == V2) identityV2(peer.secp256k1, peer.x25519, peer.mlDsaPk!!, peer.mlKemPk!!)
            else identity(peer.secp256k1, peer.x25519)
        return ScreenNumber(cur, fp, change, v1, candidate)
    }

    /** Result of verifying a scanned QR. */
    enum class Scan {
        /** Same version, same code — confirm. */
        MATCH,
        /** Their QR is v2 and matches our v2 over the same keys (their bit has not reached us yet): this is proof
         *  stronger than the bit — remember that they compute v2, the screen switches to v2 and is confirmed. */
        MATCH_V2,
        /** Their QR is the old v1 and matches our v1: the previous keys were not swapped, but they have not yet received
         *  a message from us after the upgrade and show v1 — do not confirm, calmly ask to verify again. */
        PEER_ON_V1,
        /** No match. */
        MISMATCH,
    }

    fun checkScan(store: SecureKeyStoreCommon, userId: String, scanned: String, sn: ScreenNumber): Scan {
        val got = parseQr(scanned) ?: return Scan.MISMATCH
        return when {
            got == sn.pair -> Scan.MATCH
            got.version == V2 && sn.pair.version == V1 && got == sn.v2Candidate -> {
                store.markPeerSafetyV2(userId); Scan.MATCH_V2
            }
            got.version == V1 && sn.pair.version == V2 && got.number == sn.v1Number -> Scan.PEER_ON_V1
            else -> Scan.MISMATCH
        }
    }

    /** After verification (QR or "mark as verified") — accept the current number, the banner goes away. */
    fun acknowledge(store: SecureKeyStoreCommon, userId: String, sn: ScreenNumber) =
        store.saveLastSafetyNumber(userId, "${sn.pair.version}:${sn.pair.number}")

    private fun lenBE(n: Int) = byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())

    private fun hexOrNull(h: String?): ByteArray? {
        if (h.isNullOrEmpty() || h.length % 2 != 0 || !h.all { it in "0123456789abcdefABCDEF" }) return null
        return h.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun anyBytes(v: String?): ByteArray? {
        if (v.isNullOrBlank()) return null
        return hexOrNull(v) ?: runCatching { B64.decode(v) }.getOrNull()
    }

    private fun ByteArray.toHexLower(): String =
        joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
}
