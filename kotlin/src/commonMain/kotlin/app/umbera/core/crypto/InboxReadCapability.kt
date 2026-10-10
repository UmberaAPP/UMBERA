package app.umbera.core.crypto

// Read capability for anonymous inboxes.

import app.umbera.core.util.B64

object InboxReadCapability {
    private val seedSalt = Labels.INBOX_READ
    private val seedInfo = "inbox-seed".encodeToByteArray()

    fun proofMessage(rid: String, since: Long, nowSec: Long): ByteArray =
        Labels.INBOX_READ + "|$rid|$since|$nowSec".encodeToByteArray()

    private fun seed(x25519Private: ByteArray): ByteArray =
        AesGcm.deriveKeyHKDF(x25519Private, seedSalt, seedInfo)

    fun verifyPublicKeyHex(x25519Private: ByteArray?): String? {
        val priv = x25519Private ?: return null
        return runCatching {
            RustCore.ed25519PublicFromSeed(seed(priv))
                .joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
        }.getOrNull()
    }

    fun proof(x25519Private: ByteArray?, rid: String, since: Long, nowSec: Long): String? {
        val priv = x25519Private ?: return null
        val sig = runCatching {
            RustCore.ed25519Sign(proofMessage(rid, since, nowSec), seed(priv))
        }.getOrNull() ?: return null
        return "$nowSec.${B64.encode(sig)}"
    }
}
