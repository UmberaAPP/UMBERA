package app.umbera.core.crypto

// Verification of key-transparency proofs for peer keys.

object KeyTransparencyVerifier {
    enum class Result { OK, KEY_MISMATCH, MISMATCH, UNVERIFIED }
    data class Entry(
        val userId: String,
        val publicKey: String,
        val x25519PublicKey: String,
        val index: Int,
        val treeSize: Int,
        val kyberPublicKey: String = "",
        val cryptoVersion: String = "",
        val leafVersion: Int = LEAF_VERSION_LEGACY,
    )
    const val LEAF_VERSION_LEGACY = 1
    const val LEAF_VERSION_CAPS = 2
    data class ProofNode(val hash: String, val isRight: Boolean)
    data class Sth(
        val treeSize: Int, val rootHash: String, val timestamp: Long, val signature: String, val publicKey: String,
        val pqSignature: String? = null, val pqPublicKey: String? = null,
    )
    private val LEAF_PREFIX = byteArrayOf(0x00)
    private val NODE_PREFIX = byteArrayOf(0x01)
    private fun sha256(vararg parts: ByteArray): ByteArray {
        var combined = ByteArray(0)
        for (p in parts) combined += p
        return RustCore.sha256(combined)
    }
    private fun hashLeaf(data: String): String = sha256(LEAF_PREFIX, data.encodeToByteArray()).toHexLocal()
    private fun hashNode(leftHex: String, rightHex: String): String =
        sha256(NODE_PREFIX, leftHex.hexLocal(), rightHex.hexLocal()).toHexLocal()
    private fun ByteArray.toHexLocal(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    private fun String.hexLocal(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    internal fun canonicalLeaf(e: Entry): String {
        val base = "${e.index}|${e.userId}|${e.publicKey}|${e.x25519PublicKey}"
        return if (e.leafVersion >= LEAF_VERSION_CAPS) {
            base + "|" + e.kyberPublicKey + "|" + e.cryptoVersion
        } else {
            base
        }
    }
    private fun verifyInclusion(leafHash: String, proof: List<ProofNode>, rootHash: String): Boolean {
        var cur = leafHash
        for (p in proof) {
            cur = if (p.isRight) hashNode(cur, p.hash) else hashNode(p.hash, cur)
        }
        return cur.equals(rootHash, ignoreCase = true)
    }
    private fun sthMessage(s: Sth): ByteArray =
        "KT-STH-v1|${s.treeSize}|${s.rootHash}|${s.timestamp}".encodeToByteArray()
    private fun verifySthSignature(s: Sth): Boolean = try {
        RustCore.ed25519Verify(s.publicKey.hexLocal(), sthMessage(s), s.signature.hexLocal())
    } catch (e: Exception) {
        false
    }
    internal fun sthPqMessage(s: Sth): ByteArray =
        "KT-STH-PQ-v1|${s.treeSize}|${s.rootHash}|${s.timestamp}|${s.publicKey}".encodeToByteArray()
    private fun verifySthPqSignature(s: Sth): Boolean = try {
        val sig = s.pqSignature?.let { app.umbera.core.util.B64.decode(it) }
        val pub = s.pqPublicKey?.let { app.umbera.core.util.B64.decode(it) }
        sig != null && pub != null && Dilithium3.verify(sthPqMessage(s), sig, pub)
    } catch (e: Exception) {
        false
    }
    internal fun sthAuthentic(sth: Sth, pinnedKtPublicKeyHex: String?, pinnedKtPqPublicKeyB64: String?): Boolean {
        if (!verifySthSignature(sth)) return false
        if (pinnedKtPublicKeyHex != null && !pinnedKtPublicKeyHex.equals(sth.publicKey, ignoreCase = true)) return false
        if (!SecurityRollout.ktPqSth) return true
        val hasPq = !sth.pqSignature.isNullOrEmpty() && !sth.pqPublicKey.isNullOrEmpty()
        if (!hasPq) return pinnedKtPqPublicKeyB64 == null
        if (!verifySthPqSignature(sth)) return false
        if (pinnedKtPqPublicKeyB64 != null && pinnedKtPqPublicKeyB64 != sth.pqPublicKey) return false
        return true
    }

    data class Absence(
        val userId: String, val treeSize: Int, val rootHash: String, val createdAtMs: Long, val timestamp: Long,
        val signature: String, val publicKey: String,
        val pqSignature: String? = null, val pqPublicKey: String? = null,
    )
    internal fun absenceMessage(a: Absence): ByteArray =
        "KT-ABSENT-v1|${a.userId}|${a.treeSize}|${a.rootHash}|${a.createdAtMs}|${a.timestamp}".encodeToByteArray()
    internal fun absencePqMessage(a: Absence): ByteArray =
        "KT-ABSENT-PQ-v1|${a.userId}|${a.treeSize}|${a.rootHash}|${a.createdAtMs}|${a.timestamp}|${a.publicKey}".encodeToByteArray()
    fun verifyAbsence(a: Absence, askedUserId: String, pinnedKtPublicKeyHex: String?, pinnedKtPqPublicKeyB64: String? = null): Boolean {
        if (a.userId != askedUserId) return false
        if (pinnedKtPublicKeyHex != null && !pinnedKtPublicKeyHex.equals(a.publicKey, ignoreCase = true)) return false
        val edOk = try {
            RustCore.ed25519Verify(a.publicKey.hexLocal(), absenceMessage(a), a.signature.hexLocal())
        } catch (e: Exception) { false }
        if (!edOk) return false
        if (!SecurityRollout.ktPqSth) return true
        val hasPq = !a.pqSignature.isNullOrEmpty() && !a.pqPublicKey.isNullOrEmpty()
        if (!hasPq) return pinnedKtPqPublicKeyB64 == null
        if (pinnedKtPqPublicKeyB64 != null && pinnedKtPqPublicKeyB64 != a.pqPublicKey) return false
        return try {
            Dilithium3.verify(absencePqMessage(a), app.umbera.core.util.B64.decode(a.pqSignature!!), app.umbera.core.util.B64.decode(a.pqPublicKey!!))
        } catch (e: Exception) { false }
    }

    fun verify(
        entry: Entry,
        proof: List<ProofNode>,
        sth: Sth,
        servedPublicKeyHex: String,
        servedX25519Base64: String,
        pinnedKtPublicKeyHex: String?,
        pinnedKtPqPublicKeyB64: String? = null,
    ): Result {
        if (!sthAuthentic(sth, pinnedKtPublicKeyHex, pinnedKtPqPublicKeyB64)) return Result.MISMATCH
        if (entry.index < 0 || entry.index >= sth.treeSize) return Result.MISMATCH
        if (!verifyInclusion(hashLeaf(canonicalLeaf(entry)), proof, sth.rootHash)) return Result.MISMATCH

        if (!entry.publicKey.equals(servedPublicKeyHex, ignoreCase = true)) return Result.KEY_MISMATCH
        if (entry.x25519PublicKey != servedX25519Base64) return Result.KEY_MISMATCH
        return Result.OK
    }
}
