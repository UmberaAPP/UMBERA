package app.umbera.core.meet

import app.umbera.core.crypto.AesGcm
import app.umbera.core.crypto.RustCore
import app.umbera.core.crypto.secureRandomBytes
import app.umbera.core.util.rawDeflate
import app.umbera.core.util.rawInflate

/**
 * Encryption for link-based conferences.
 *
 * From the room key K (256 bits, only in the link fragment) HKDF-SHA256 (salt `umbera-meet-v1`) derives:
 * - `meta` — the room description key (name and flags), stored opaquely by the server;
 * - `sig`  — the in-room signalling key.
 * Box: `[1] ‖ iv(12) ‖ AES-256-GCM( [1] ‖ deflate(JSON) ‖ zeros up to a multiple of 64 )`, AAD — domain and room number.
 * A symmetric 256-bit key is not broken by a quantum computer (Grover — 128 bits); there is no asymmetric exchange
 * in the room. Media keys for each pair are separate, via hybrid X25519 + ML-KEM-1024 ([app.umbera.core.webrtc.CallFrameE2ee]),
 * one capsule per pair per join, not in every message.
 */
object MeetCrypto {
    private val SALT = "umbera-meet-v1".encodeToByteArray()
    private const val FORMAT: Byte = 1
    private const val PAD = 64
    const val MAX_PLAIN = 256 * 1024

    class Keys(val meta: ByteArray, val sig: ByteArray)

    fun keys(roomKey: ByteArray): Keys {
        require(roomKey.size == MeetLinks.KEY_BYTES)
        return Keys(
            meta = RustCore.hkdfSha256(roomKey, SALT, "meta".encodeToByteArray(), 32u),
            sig = RustCore.hkdfSha256(roomKey, SALT, "sig".encodeToByteArray(), 32u),
        )
    }

    private fun aad(kind: String, room: String) = "umbera-meet-v1|$kind|$room".encodeToByteArray()

    private fun pack(json: String): ByteArray {
        val z = rawDeflate(json.encodeToByteArray())
        val len = 1 + z.size
        val out = ByteArray(len + (PAD - len % PAD) % PAD)
        out[0] = FORMAT
        z.copyInto(out, 1)
        return out
    }

    private fun unpack(b: ByteArray): String {
        require(b.isNotEmpty() && b.size % PAD == 0 && b[0] == FORMAT) { "meet: format" }
        val z = b.copyOfRange(1, b.size)
        val (plain, used) = rawInflate(z, MAX_PLAIN)
        for (i in used until z.size) require(z[i] == 0.toByte()) { "meet: tail" }
        return plain.decodeToString()
    }

    private fun seal(key: ByteArray, aad: ByteArray, json: String): ByteArray {
        val e = AesGcm.encrypt(pack(json), key, aad)
        return byteArrayOf(FORMAT) + e.iv + e.ciphertext
    }

    private fun open(key: ByteArray, aad: ByteArray, box: ByteArray): String? = runCatching {
        require(box.size > 1 + 12 + 16 && box[0] == FORMAT)
        val iv = box.copyOfRange(1, 13)
        val ct = box.copyOfRange(13, box.size)
        unpack(AesGcm.decrypt(AesGcm.EncryptedData(ct, iv), key, aad))
    }.getOrNull()

    fun sealSignal(k: Keys, room: String, json: String) = seal(k.sig, aad("sig", room), json)
    fun openSignal(k: Keys, room: String, box: ByteArray) = open(k.sig, aad("sig", room), box)
    fun sealMeta(k: Keys, room: String, json: String) = seal(k.meta, aad("meta", room), json)
    fun openMeta(k: Keys, room: String, box: ByteArray) = open(k.meta, aad("meta", room), box)

    fun sha256(b: ByteArray): ByteArray = RustCore.sha256(b)
    fun random(n: Int): ByteArray = secureRandomBytes(n)
}
