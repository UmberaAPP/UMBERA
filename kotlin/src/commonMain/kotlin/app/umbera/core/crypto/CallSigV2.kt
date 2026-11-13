package app.umbera.core.crypto

import app.umbera.core.util.rawDeflate
import app.umbera.core.util.rawInflate
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Single-layer call signalling — `callsig-v2`.
 *
 * Legacy format (still sent to everyone without the [MessageEncryption.WIRE_CAP_CALLSIG_V2] bit): SDP → v1 (X25519 +
 * AES-GCM + secp256k1, hex fields, JSON) → into `enc` of the {t,cid,vid,enc,ts} envelope → v1 again in hex → sealed
 * v3/v2 envelope. An offer is 53 KB.
 *
 * New: body [Body] (type, call, video, `ts`, plaintext data, capabilities and pair-secret acknowledgements —
 * the same fields that travelled in the outer v1) → JSON → raw deflate → zero padding to 256 → secp256k1 signature over
 * `DOMAIN ‖ sender ‖ 0 ‖ recipient ‖ 0 ‖ blob` → [MessageEncryption.EncryptedPayload] with version=[PAYLOAD] and the blob
 * in base64 → the same v3/v3s envelope (X25519 + ML-KEM-1024, transcript-bound) as the outer layer before. There is
 * one encryption layer — the outer envelope; the signature is the same (same sender secp256k1 key, verified against the pinned one),
 * but is now bound to the recipient explicitly (previously implicitly: it signed a ciphertext to the recipient's key).
 */
object CallSigV2 {
    const val PAYLOAD = "callsig-v2"
    private const val DOMAIN = "umbera-callsig-v2"
    /** First blob byte: body format (1 = raw deflate JSON). */
    private const val FORMAT_DEFLATE: Byte = 1
    /** Padding step (as addPadding in the legacy format — 256). */
    const val PAD = 256
    /** Limit on the inflated body: an SDP with video and screen sharing is a few KB; 256 KB leaves headroom without a "bomb". */
    const val MAX_BODY = 256 * 1024

    @Serializable
    data class Body(
        @SerialName("t") val t: String,
        @SerialName("cid") val cid: String,
        @SerialName("vid") val vid: Boolean = false,
        @SerialName("ts") val ts: Long,
        /** SDP / ICE envelope / marker (share "1"/"0", reject "busy"); null — a signal without data (hangup, end…). */
        @SerialName("d") val d: String? = null,
        @SerialName("cap") val caps: Int? = null,
        @SerialName("sa") val sealAck: String? = null,
        @SerialName("rd") val ridDir: String? = null,
        @SerialName("ra") val ridAck: String? = null,
    )

    /** Body → blob: [FORMAT_DEFLATE] ‖ deflate(JSON) ‖ zeros (1..[PAD]) up to a multiple of [PAD]. */
    fun pack(bodyJson: String): ByteArray {
        val z = rawDeflate(bodyJson.encodeToByteArray())
        val len = 1 + z.size
        val total = len + (PAD - len % PAD)
        val out = ByteArray(total)
        out[0] = FORMAT_DEFLATE
        z.copyInto(out, 1)
        return out
    }

    /** blob → body JSON. Strict: known format, the stream has ended, only zeros after it, size a multiple of [PAD]. */
    fun unpack(blob: ByteArray): String {
        require(blob.size >= PAD && blob.size % PAD == 0) { "callsig: size ${blob.size}" }
        require(blob[0] == FORMAT_DEFLATE) { "callsig: format ${blob[0]}" }
        val z = blob.copyOfRange(1, blob.size)
        val (plain, used) = rawInflate(z, MAX_BODY)
        for (i in used until z.size) require(z[i] == 0.toByte()) { "callsig: tail" }
        return plain.decodeToString()
    }

    /** What is signed: domain, from, to, blob (zero separators — ids contain no \u0000). */
    fun signedBytes(senderId: String, recipientId: String, blob: ByteArray): ByteArray =
        (DOMAIN + "\u0000" + senderId + "\u0000" + recipientId + "\u0000").encodeToByteArray() + blob
}
