package app.umbera.core.webrtc

import app.umbera.core.util.Log
import dev.onvoid.webrtc.RTCEncodedAudioFrame
import dev.onvoid.webrtc.RTCEncodedFrame
import dev.onvoid.webrtc.RTCEncodedFrameTransformer
import dev.onvoid.webrtc.RTCEncodedVideoFrame
import dev.onvoid.webrtc.RTCPeerConnection
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Second call layer on desktop: frame encryption in exactly the FrameCryptor format used by
 * Android (stream-webrtc-android 1.3.x, GetStream/webrtc branch patch/m125, api/crypto/frame_crypto_transformer.cc),
 * so desktop and phone understand each other's frames. webrtc-java provides `setTransform` on sender and receiver for this.
 *
 * Frame: [clear part N bytes][AES-GCM(ciphertext ‖ tag 16)][IV 12][12][key index = 0]
 *   N: audio 1 (Opus TOC); VP8 10 for a key frame, 3 otherwise; H.264 up to the second byte of the first
 *   slice (IDR or non-IDR) after the start code; AV1, VP9 and others 0. The clear part is the AAD.
 *   H.264: everything after the clear part goes through RBSP escaping (otherwise start codes could appear
 *   inside the ciphertext); on receive the reverse, if the data contains 00 00 03.
 *   IV = ssrc ‖ RTP timestamp ‖ (timestamp − ssrc frame counter mod 0xFFFF), all 32-bit big-endian.
 *   AES-128 key = PBKDF2-HMAC-SHA256(32 B material from the X25519+ML-KEM exchange, salt [CallFrameE2ee.FRAME_SALT], 100 000, 16 B).
 * A frame that fails to open is dropped (as in FrameCryptor): no garbage reaches the decoder.
 */
class PcFrameCryptor(sendMaterial: ByteArray, recvMaterial: ByteArray) {
    private val sendKey = SecretKeySpec(derive(sendMaterial), "AES")
    private val recvKey = SecretKeySpec(derive(recvMaterial), "AES")
    private val sendCounts = ConcurrentHashMap<Long, Int>()
    private val attachedSenders = ConcurrentHashMap.newKeySet<String>()
    private val attachedReceivers = ConcurrentHashMap.newKeySet<String>()

    @Volatile var framesOut = 0L; private set
    @Volatile var framesIn = 0L; private set
    @Volatile var framesDropped = 0L; private set
    /** Total encryption and decryption time, ns (for load measurement). */
    @Volatile var cryptoNanos = 0L; private set

    private val encrypt = RTCEncodedFrameTransformer { f -> runCatching { encryptFrame(f) }.onFailure { f.drop(); framesDropped++ } }
    private val decrypt = RTCEncodedFrameTransformer { f -> runCatching { decryptFrame(f) }.onFailure { f.drop(); framesDropped++ } }

    /** Attach encryption to all senders and receivers of the connection that are not yet in the list. */
    fun attach(pc: RTCPeerConnection) {
        runCatching {
            for (s in pc.senders) if (attachedSenders.add(s.id)) s.setTransform(encrypt)
            for (r in pc.receivers) if (attachedReceivers.add(r.id)) r.setTransform(decrypt)
        }.onFailure { Log.w("PcFrameCryptor", "attach: ${it.message}") }
    }

    private fun encryptFrame(f: RTCEncodedFrame) {
        val t0 = System.nanoTime()
        val data = f.data.toBytes()
        if (data.isEmpty()) return
        val h264 = isH264(f)
        val n = unencryptedBytes(f, data)
        val ssrc = f.ssrc
        val ts = f.timestamp
        val count = sendCounts.merge(ssrc, 1, Int::plus)!! - 1
        val iv = ByteBuffer.allocate(IV_LEN).putInt(ssrc.toInt()).putInt(ts.toInt()).putInt((ts - (count % 0xFFFF)).toInt()).array()
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, sendKey, GCMParameterSpec(128, iv))
        c.updateAAD(data, 0, n)
        val ct = c.doFinal(data, n, data.size - n)
        val tail = ByteArrayOutputStream(ct.size + IV_LEN + 2).apply { write(ct); write(iv); write(IV_LEN); write(0) }.toByteArray()
        val out = ByteArrayOutputStream(data.size + 40)
        out.write(data, 0, n)
        if (h264) writeRbsp(tail, out) else out.write(tail)
        f.setData(out.toByteArray())
        framesOut++
        cryptoNanos += System.nanoTime() - t0
    }

    private fun decryptFrame(f: RTCEncodedFrame) {
        val t0 = System.nanoTime()
        val data = f.data.toBytes()
        if (data.size < 2) { f.drop(); framesDropped++; return }
        val n = unencryptedBytes(f, data)
        val ivLen = data[data.size - 2].toInt() and 0xFF
        val keyIndex = data[data.size - 1].toInt() and 0xFF
        if (ivLen != IV_LEN || keyIndex != 0 || data.size < n + 16 + IV_LEN + 2) { f.drop(); framesDropped++; return }
        // As in FrameCryptor: the IV is taken from the received (escaped) bytes, the rest after unescaping.
        val iv = data.copyOfRange(data.size - 2 - ivLen, data.size - 2)
        var enc = data.copyOfRange(n, data.size)
        if (isH264(f) && needsRbspUnescaping(enc)) enc = parseRbsp(enc)
        val payload = enc.copyOfRange(0, enc.size - ivLen - 2)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, recvKey, GCMParameterSpec(128, iv))
        c.updateAAD(data, 0, n)
        val pt = runCatching { c.doFinal(payload) }.getOrNull() ?: run { f.drop(); framesDropped++; return }
        f.setData(data.copyOfRange(0, n) + pt)
        framesIn++
        cryptoNanos += System.nanoTime() - t0
    }

    companion object {
        const val IV_LEN = 12
        private const val PBKDF2_ITERATIONS = 100_000

        /** AES-128 frame key from the material, as DeriveKeys(material, ratchet_salt, 128) in FrameCryptor. */
        fun derive(material: ByteArray): ByteArray = pbkdf2(material, CallFrameE2ee.FRAME_SALT, PBKDF2_ITERATIONS, 16)

        /** PBKDF2-HMAC-SHA256 over raw password bytes (as PKCS5_PBKDF2_HMAC in BoringSSL). */
        fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int, len: Int): ByteArray {
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(password, "HmacSHA256"))
            val out = ByteArray(len)
            var block = 1
            var pos = 0
            while (pos < len) {
                mac.update(salt)
                mac.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(), (block ushr 8).toByte(), block.toByte()))
                var u = mac.doFinal()
                val t = u.copyOf()
                repeat(iterations - 1) {
                    u = mac.doFinal(u)
                    for (i in t.indices) t[i] = (t[i].toInt() xor u[i].toInt()).toByte()
                }
                val take = minOf(t.size, len - pos)
                System.arraycopy(t, 0, out, pos, take)
                pos += take
                block++
            }
            return out
        }

        private fun ByteBuffer.toBytes(): ByteArray {
            val d = duplicate()
            d.rewind()
            return ByteArray(d.remaining()).also { d.get(it) }
        }

        private fun mime(f: RTCEncodedFrame): String = runCatching { f.mimeType }.getOrNull()?.lowercase().orEmpty()

        private fun isH264(f: RTCEncodedFrame) = f is RTCEncodedVideoFrame && mime(f).endsWith("/h264")

        /** How many frame bytes to leave in the clear, as get_unencrypted_bytes in FrameCryptor m125. */
        fun unencryptedBytes(f: RTCEncodedFrame, data: ByteArray): Int = when (f) {
            is RTCEncodedAudioFrame -> minOf(1, data.size)
            is RTCEncodedVideoFrame -> when {
                mime(f).endsWith("/vp8") -> minOf(if (f.isKeyFrame) 10 else 3, data.size)
                mime(f).endsWith("/h264") -> h264Unencrypted(data)
                else -> 0
            }
            else -> 0
        }

        /** First H.264 slice (IDR = 5 or non-IDR = 1): its start + 2; no slice: 0. */
        fun h264Unencrypted(data: ByteArray): Int {
            for (start in naluStarts(data)) {
                if (start >= data.size) continue
                val type = data[start].toInt() and 0x1F
                if (type == 5 || type == 1) return minOf(start + 2, data.size)
            }
            return 0
        }

        /** NALU starts after 00 00 01 start codes (as H264::FindNaluIndices). */
        fun naluStarts(data: ByteArray): List<Int> {
            val out = ArrayList<Int>()
            val end = data.size - 3
            var i = 0
            while (i < end) {
                val b2 = data[i + 2].toInt() and 0xFF
                when {
                    b2 > 1 -> i += 3
                    b2 == 1 -> { if (data[i + 1].toInt() == 0 && data[i].toInt() == 0) out.add(i + 3); i += 3 }
                    else -> i++
                }
            }
            return out
        }

        fun writeRbsp(src: ByteArray, out: ByteArrayOutputStream) {
            var zeros = 0
            for (b in src) {
                val v = b.toInt() and 0xFF
                if (v <= 3 && zeros >= 2) { out.write(3); zeros = 0 }
                out.write(v)
                if (v == 0) zeros++ else zeros = 0
            }
        }

        fun parseRbsp(src: ByteArray): ByteArray {
            val out = ByteArrayOutputStream(src.size)
            var i = 0
            while (i < src.size) {
                if (src.size - i >= 3 && src[i].toInt() == 0 && src[i + 1].toInt() == 0 && src[i + 2].toInt() == 3) {
                    out.write(0); out.write(0); i += 3
                } else { out.write(src[i].toInt()); i++ }
            }
            return out.toByteArray()
        }

        fun needsRbspUnescaping(d: ByteArray): Boolean {
            for (i in 0 until d.size - 3) if (d[i].toInt() == 0 && d[i + 1].toInt() == 0 && d[i + 2].toInt() == 3) return true
            return false
        }
    }
}
