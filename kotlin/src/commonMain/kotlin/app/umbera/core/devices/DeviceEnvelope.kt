package app.umbera.core.devices

import app.umbera.core.crypto.AesGcm
import app.umbera.core.crypto.DeviceLinkCore
import app.umbera.core.crypto.DevicePublicKeys
import app.umbera.core.crypto.Dilithium3
import app.umbera.core.crypto.Kyber1024
import app.umbera.core.crypto.RustCore
import app.umbera.core.crypto.Secp256k1
import app.umbera.core.crypto.X25519
import app.umbera.core.util.B64
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/*
 * Linked devices: encryption to EVERY device of both sides (client-side fan-out, as
 * Signal/WhatsApp do).
 *
 * Device = account + device id. The phone is "primary": its keys are the account keys
 * (X25519 + ML-KEM-1024 for encryption, secp256k1 + ML-DSA-65 for signing). A desktop has keys from
 * its own seed (DeviceLinkCore), signed by the phone (a certificate, verified against the account
 * address). The desktop holds no account keys.
 *
 * Envelope to a single device ("udv1:"):
 *   outer layer — ephemeral X25519 + ML-KEM-1024 to the recipient device's keys, AES-256-GCM
 *     (hides the sender from the server, like sealed sender; hybrid — secure while either part holds);
 *   inside — a body signed by the sender device (hybrid: both signatures required);
 *   the body carries either a double-ratchet message of this device pair (v4: ML-KEM in the root), or, while
 *     the ratchet cannot send yet (responder before the first message) and for device-level
 *     control messages, plaintext under the outer layer.
 */

/** Device address: account + device id ("primary" — the phone). */
data class DeviceAddr(val userId: String, val deviceId: String) {
    val key: String get() = "$userId/$deviceId"
    val isPrimary: Boolean get() = deviceId == DeviceAddr.PRIMARY

    companion object {
        const val PRIMARY = "primary"
    }
}

/** How to verify a device signature. */
sealed interface DeviceVerifier {
    /** Phone: account keys secp256k1 (65/33 B) + ML-DSA-65 (1952 B). */
    class Account(val secp256k1: ByteArray, val mldsa65: ByteArray) : DeviceVerifier

    /** Desktop: the device's Ed25519 + ML-DSA-65 from a verified certificate. */
    class Linked(val keys: DevicePublicKeys) : DeviceVerifier
}

/** A peer's device (or another own device) that can be encrypted to. */
class RemoteDevice(
    val addr: DeviceAddr,
    val x25519: ByteArray,
    val mlkem: ByteArray,
    val verifier: DeviceVerifier,
)

/** This device: encryption keys and signing. */
class LocalDevice(
    val addr: DeviceAddr,
    val x25519Private: ByteArray,
    val x25519Public: ByteArray,
    val mlkemPublic: ByteArray,
    val mlkemSeed: ByteArray,
    private val signer: (ByteArray) -> ByteArray,
) {
    val isPrimary: Boolean get() = addr.isPrimary
    fun sign(message: ByteArray): ByteArray = signer(message)

    companion object {
        /** Phone: account keys. Signature = secp256k1 (r‖s, 64) ‖ ML-DSA-65 (3309). */
        fun primary(
            userId: String,
            x25519Private: ByteArray, x25519Public: ByteArray,
            kyberPublic: ByteArray, kyberSeed: ByteArray,
            secp256k1Private: ByteArray, dilithiumSeed: ByteArray,
        ) = LocalDevice(
            DeviceAddr(userId, DeviceAddr.PRIMARY), x25519Private, x25519Public, kyberPublic, kyberSeed,
        ) { msg ->
            Secp256k1.sign(DeviceEnvelope.SIG_DOMAIN + msg, secp256k1Private).toByteArray() +
                Dilithium3.sign(DeviceEnvelope.SIG_DOMAIN + msg, dilithiumSeed).bytes
        }

        /** Desktop: keys from the device seed (DeviceLinkCore). */
        fun linked(userId: String, deviceId: String, deviceSeed: ByteArray): LocalDevice {
            val pub = DeviceLinkCore.devicePublicKeys(deviceSeed)
            val enc = DeviceLinkCore.deviceEncryptionKeys(deviceSeed)
            return LocalDevice(DeviceAddr(userId, deviceId), enc.x25519Private, pub.x25519, pub.mlkem1024, enc.mlkem1024Seed) { msg ->
                DeviceLinkCore.deviceSign(deviceSeed, DeviceEnvelope.SIG_CONTEXT, msg)
            }
        }
    }
}

/** Removed outer layer: body and signature (not yet verified). */
class OpenedEnvelope(val body: DvBody, internal val signedMessage: ByteArray, internal val signature: ByteArray)

/** Envelope parse/verification error: such an envelope is rejected (and does not break the channel). */
class DeviceEnvelopeException(message: String) : Exception(message)

/** Double-ratchet message of a device pair (header fields as in ratchet-v4 of 1:1 chats). */
@Serializable
data class DvRatchet(
    @SerialName("dh") val dh: String,
    @SerialName("pn") val pn: Int,
    @SerialName("n") val n: Int,
    @SerialName("kp") val kp: String? = null,
    @SerialName("kc") val kc: String? = null,
    @SerialName("kt") val kt: String? = null,
    @SerialName("ct") val ct: String,
    @SerialName("iv") val iv: String,
)

/**
 * Envelope body (signed as a whole). [k] — kind:
 *  - "msg"   message to the peer (conversation with [fu] on the recipient side);
 *  - "out"   copy of MY sent message to my other device, conversation with [c];
 *  - "relay" a desktop asks its phone to deliver a message to peer [c] running an old version
 *            (no devices in the directory / old client) — the phone sends it the legacy way;
 *  - "sys"   device-level control message ([d] — JSON [DvSys]), always without the ratchet.
 */
@Serializable
data class DvBody(
    @SerialName("v") val v: Int = 1,
    @SerialName("fu") val fromUser: String,
    @SerialName("fd") val fromDevice: String,
    @SerialName("tu") val toUser: String,
    @SerialName("td") val toDevice: String,
    @SerialName("k") val kind: String,
    @SerialName("id") val id: String,
    @SerialName("ts") val ts: Long,
    @SerialName("c") val conv: String? = null,
    @SerialName("n") val nick: String? = null,
    @SerialName("r") val ratchet: DvRatchet? = null,
    @SerialName("d") val direct: String? = null,
    /**
     * Device address epochs: the address secret of this envelope's recipient→sender (32 B, base64) — "write to my epoch
     * addresses" (DeviceRidEpochs). Only in an offer (first envelope of a pair / control "rk"); old builds skip the field.
     */
    @SerialName("rk") val ridKey: String? = null,
)

@Serializable
internal data class DvSigned(@SerialName("b") val body: String, @SerialName("s") val sig: String)

object DeviceEnvelope {
    const val PREFIX = "udv1:"
    internal const val SIG_CONTEXT = "umbera-dv1/sig"
    internal val SIG_DOMAIN = "umbera-dv1/sig|".encodeToByteArray()
    private val SEAL_LABEL = "umbera-dv1/seal".encodeToByteArray()
    private val KEY_INFO = "umbera-dv1/key".encodeToByteArray()
    private const val IV_LEN = 12

    private val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true; encodeDefaults = false; explicitNulls = false }

    fun isEnvelope(s: String): Boolean = s.startsWith(PREFIX)

    private fun lp(b: ByteArray): ByteArray = byteArrayOf(
        (b.size ushr 24).toByte(), (b.size ushr 16).toByte(), (b.size ushr 8).toByte(), b.size.toByte(),
    ) + b

    /** Outer-layer transcript: label, ephemeral key, ML-KEM ciphertext, recipient keys and address. */
    private fun transcript(eph: ByteArray, kemCt: ByteArray, toX: ByteArray, toKem: ByteArray, to: DeviceAddr): ByteArray =
        RustCore.sha256(lp(SEAL_LABEL) + lp(eph) + lp(kemCt) + lp(toX) + lp(RustCore.sha256(toKem)) + lp(to.key.encodeToByteArray()))

    /** Sign [body] with this device's key and seal it to device [to]. */
    fun seal(me: LocalDevice, to: RemoteDevice, body: DvBody): String {
        require(body.fromUser == me.addr.userId && body.fromDevice == me.addr.deviceId) { "body sender is not this device" }
        require(body.toUser == to.addr.userId && body.toDevice == to.addr.deviceId) { "body recipient mismatch" }
        val bodyJson = json.encodeToString(DvBody.serializer(), body)
        val sig = me.sign(bodyJson.encodeToByteArray())
        val inner = json.encodeToString(DvSigned.serializer(), DvSigned(bodyJson, B64.encode(sig))).encodeToByteArray()
        val eph = X25519.generateKeyPair()
        val ssx = X25519.computeSharedSecret(eph.privateKey, to.x25519)
        val kem = Kyber1024.encapsulate(to.mlkem)
        val th = transcript(eph.publicKey, kem.ciphertext, to.x25519, to.mlkem, to.addr)
        val key = RustCore.hkdfSha256(ssx + kem.sharedSecret, th, KEY_INFO, 32u)
        val enc = AesGcm.encrypt(inner, key, th)
        return PREFIX + B64.encode(eph.publicKey + kem.ciphertext + enc.iv + enc.ciphertext)
    }

    /** Remove the outer layer with this device's keys. The signature is NOT yet verified: see [verify]. */
    fun open(me: LocalDevice, wire: String): OpenedEnvelope {
        if (!isEnvelope(wire)) throw DeviceEnvelopeException("not a device envelope")
        val raw = runCatching { B64.decode(wire.removePrefix(PREFIX)) }.getOrNull() ?: throw DeviceEnvelopeException("bad base64")
        val head = 32 + Kyber1024.CIPHERTEXT_SIZE + IV_LEN
        if (raw.size <= head + 16) throw DeviceEnvelopeException("short envelope")
        val eph = raw.copyOfRange(0, 32)
        val ct = raw.copyOfRange(32, 32 + Kyber1024.CIPHERTEXT_SIZE)
        val iv = raw.copyOfRange(32 + Kyber1024.CIPHERTEXT_SIZE, head)
        val body = raw.copyOfRange(head, raw.size)
        val inner = try {
            val ssx = X25519.computeSharedSecret(me.x25519Private, eph)
            val ssk = Kyber1024.decapsulate(ct, me.mlkemSeed)
            val th = transcript(eph, ct, me.x25519Public, me.mlkemPublic, me.addr)
            val key = RustCore.hkdfSha256(ssx + ssk, th, KEY_INFO, 32u)
            AesGcm.decrypt(AesGcm.EncryptedData(body, iv), key, th)
        } catch (e: Exception) {
            throw DeviceEnvelopeException("outer layer does not open: ${e.message}")
        }
        val signed = runCatching { json.decodeFromString(DvSigned.serializer(), inner.decodeToString()) }.getOrNull()
            ?: throw DeviceEnvelopeException("bad inner")
        val parsed = runCatching { json.decodeFromString(DvBody.serializer(), signed.body) }.getOrNull()
            ?: throw DeviceEnvelopeException("bad body")
        if (parsed.v != 1) throw DeviceEnvelopeException("unknown version ${parsed.v}")
        if (parsed.toUser != me.addr.userId || parsed.toDevice != me.addr.deviceId) {
            throw DeviceEnvelopeException("envelope addressed to another device")
        }
        val sig = runCatching { B64.decode(signed.sig) }.getOrNull() ?: throw DeviceEnvelopeException("bad signature encoding")
        return OpenedEnvelope(parsed, signed.body.encodeToByteArray(), sig)
    }

    /**
     * Verify the body signature by device [from].
     * The sender in the body must equal [from].
     */
    fun verify(opened: OpenedEnvelope, from: RemoteDevice): Boolean {
        val body = opened.body
        if (body.fromUser != from.addr.userId || body.fromDevice != from.addr.deviceId) return false
        val msg = opened.signedMessage
        val sig = opened.signature
        return when (val v = from.verifier) {
            is DeviceVerifier.Account -> {
                if (sig.size != 64 + Dilithium3.SIGNATURE_SIZE) return false
                val ecdsa = sig.copyOfRange(0, 64)
                val pq = sig.copyOfRange(64, sig.size)
                runCatching { Secp256k1.verify(SIG_DOMAIN + msg, Secp256k1.Signature.fromByteArray(ecdsa), v.secp256k1) }.getOrDefault(false) &&
                    runCatching { Dilithium3.verify(SIG_DOMAIN + msg, pq, v.mldsa65) }.getOrDefault(false)
            }
            is DeviceVerifier.Linked -> runCatching { DeviceLinkCore.deviceVerify(v.keys, SIG_CONTEXT, msg, sig) }.getOrDefault(false)
        }
    }

    /** Rendezvous address for a device pair (from → to): from the X25519 shared secret — the server cannot compute it. */
    fun rid(me: LocalDevice, other: RemoteDevice, from: DeviceAddr, to: DeviceAddr): String {
        val shared = X25519.computeSharedSecret(me.x25519Private, other.x25519)
        val out = AesGcm.deriveKeyHKDF(shared, "umbera-dv1/rid".encodeToByteArray(), "rdv|${from.key}|${to.key}".encodeToByteArray())
        return out.joinToString("") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }
    }
}
