package app.umbera.core.webrtc

import app.umbera.core.crypto.CallFrameKeys
import app.umbera.core.crypto.CallPq
import app.umbera.core.util.B64

/**
 * Second, post-quantum call layer.
 *
 * WebRTC DTLS-SRTP agrees on a key via ECDHE — a conversation recorded today can be decrypted by a quantum computer
 * tomorrow. Therefore frames (audio, camera, screen sharing) are encrypted once more — with a key from a hybrid
 * X25519 + ML-KEM-1024 exchange (core, core/src/callkey.rs). The exchange runs inside the SDP, and the SDP inside
 * the call signalling E2E envelope (the same hybrid envelope as messages). Every new connection (a call, a transfer
 * to another device, every pair in a conference) gets its own exchange and its own keys.
 *
 * Capability negotiation: the offer carries a session-level line `a=x-umbera-pq:<base64 public>`,
 * the answer — `a=x-umbera-pq:<base64 answer>`. Old versions do not send the line, and WebRTC skips unknown
 * `a=` lines — with an old peer the call proceeds as before, without the second layer.
 *
 * Frame format — FrameCryptor (AES-GCM, key via PBKDF2-SHA256 from the material, salt [FRAME_SALT]), identical across
 * Android (stream-webrtc) and desktop (webrtc-java, PcFrameCryptor).
 */
object CallFrameE2ee {
    const val ATTR = "a=x-umbera-pq:"

    /** FrameCryptor frame key salt (PBKDF2): Umbera-specific, the same on all platforms. */
    val FRAME_SALT: ByteArray = "umbera-call-v1/frame-salt".encodeToByteArray()

    /** Capability line from the SDP (without the newline) or null. */
    fun extract(sdp: String): ByteArray? =
        sdp.lineSequence().map { it.trimEnd('\r') }.firstOrNull { it.startsWith(ATTR) }
            ?.removePrefix(ATTR)?.let { runCatching { B64.decode(it) }.getOrNull() }

    /** SDP without our line — WebRTC gets exactly what the peer sent. */
    fun strip(sdp: String): String {
        if (!sdp.contains(ATTR)) return sdp
        return sdp.split("\r\n").filterNot { it.startsWith(ATTR) }.joinToString("\r\n")
    }

    /** Insert the line at session level — before the first `m=`. */
    fun attach(sdp: String, blob: ByteArray): String {
        val clean = strip(sdp)
        val line = ATTR + B64.encode(blob)
        val idx = clean.indexOf("\r\nm=")
        return if (idx < 0) clean.trimEnd() + "\r\n" + line + "\r\n" else clean.substring(0, idx + 2) + line + "\r\n" + clean.substring(idx + 2)
    }

    /**
     * Exchange state for one connection pair. Initiator: [offer] → line in the offer; [onAnswer] — keys.
     * Responder: [onOffer] returns the answer line and the keys at once.
     */
    class Negotiation(private val callId: String) {
        private var secret: ByteArray? = null
        private var public: ByteArray? = null
        var keys: CallFrameKeys? = null
            private set

        /** Own offer: an ephemeral pair for this connection. */
        fun offer(): ByteArray {
            val kp = CallPq.keypair()
            secret = kp.secret; public = kp.public; keys = null
            return kp.public
        }

        /** Peer's offer with our line: answer + keys. null — no line or it is malformed. */
        fun onOffer(blob: ByteArray): ByteArray? = runCatching {
            val r = CallPq.respond(callId, blob)
            keys = r.keys
            secret = null; public = null
            r.answer
        }.getOrNull()

        /** Peer's answer: keys (null — answer without the line: old version, layer disabled). */
        fun onAnswer(blob: ByteArray?): CallFrameKeys? {
            val s = secret ?: return null
            val p = public ?: return null
            if (blob == null) { secret = null; public = null; return null }
            return runCatching { CallPq.finish(callId, s, p, blob) }.getOrNull().also {
                keys = it
                s.fill(0); secret = null; public = null
            }
        }

        /** Awaiting the answer to our offer. */
        fun awaitingAnswer(): Boolean = secret != null
    }
}
