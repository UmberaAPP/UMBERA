package app.umbera.core.crypto

// Hybrid X25519 + ML-KEM wrapping of per-file keys.

import app.umbera.core.util.B64
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

object HybridFileKeyWrap {
    private val SALT = Labels.FILE_WRAP
    private val INFO = "file-key-wrap".encodeToByteArray()
    @Serializable
    data class Wrapped(
        @SerialName("eph") val ephX25519Pub: String,
        @SerialName("kct") val kyberCiphertext: String,
        @SerialName("w")   val wrap: String,
        @SerialName("v")   val version: Int? = null,
    )
    private fun combined(x25519Shared: ByteArray, kyberShared: ByteArray): ByteArray =
        RustCore.hkdfSha256(x25519Shared + kyberShared, SALT, INFO, 32u)
    fun wrap(fileKey: ByteArray, recipientX25519Pub: ByteArray, recipientKyberPub: ByteArray, v2: Boolean = false): Wrapped {
        if (v2) return wrapV2(fileKey, recipientX25519Pub, recipientKyberPub)
        val eph = X25519.generateKeyPair()
        val x25519Shared = X25519.computeSharedSecret(eph.privateKey, recipientX25519Pub)
        val kem = Kyber1024.encapsulate(recipientKyberPub)
        val enc = AesGcm.encrypt(fileKey, combined(x25519Shared, kem.sharedSecret))
        return Wrapped(
            ephX25519Pub = eph.publicKey.toHex(),
            kyberCiphertext = kem.ciphertext.toHex(),
            wrap = enc.toBase64()
        )
    }
    fun unwrap(
        w: Wrapped, myX25519Priv: ByteArray, myKyberPriv: ByteArray,
        myX25519Pub: ByteArray? = null, myKyberPub: ByteArray? = null,
    ): ByteArray {
        when (w.version) {
            null -> {}
            2 -> return unwrapV2(w, myX25519Priv, myKyberPriv,
                myX25519Pub ?: RustCore.x25519PublicKey(myX25519Priv), requireNotNull(myKyberPub) { "file wrap v2: own ML-KEM key" })
            else -> throw IllegalArgumentException("file wrap: unknown version ${w.version}")
        }
        val x25519Shared = X25519.computeSharedSecret(myX25519Priv, w.ephX25519Pub.hexToBytes())
        val kyberShared = Kyber1024.decapsulate(w.kyberCiphertext.hexToBytes(), myKyberPriv)
        return AesGcm.decrypt(AesGcm.EncryptedData.fromBase64(w.wrap), combined(x25519Shared, kyberShared))
    }
    private fun wrapV2(fileKey: ByteArray, rcptX: ByteArray, rcptEk: ByteArray): Wrapped {
        val eph = X25519.generateKeyPair()
        val ssX = X25519.computeSharedSecret(eph.privateKey, rcptX)
        val kem = Kyber1024.encapsulate(rcptEk)
        val k = SealV3.fileKey(ssX, kem.sharedSecret, SealV3.transcriptFile(eph.publicKey, kem.ciphertext, rcptX, rcptEk))
        val iv = AesGcm.generateIv()
        val e = AesGcm.encryptWithTag(fileKey, k, iv, SealV3.AAD_FILE)
        return Wrapped(eph.publicKey.toHex(), kem.ciphertext.toHex(), B64.encode(iv + e.ciphertext + e.authTag), version = 2)
    }
    private fun unwrapV2(w: Wrapped, myXPriv: ByteArray, myKyberPriv: ByteArray, myXPub: ByteArray, myKyberPub: ByteArray): ByteArray {
        val eph = w.ephX25519Pub.hexToBytes()
        val kct = w.kyberCiphertext.hexToBytes()
        val ssX = X25519.computeSharedSecret(myXPriv, eph)
        val ssKem = Kyber1024.decapsulate(kct, myKyberPriv)
        val k = SealV3.fileKey(ssX, ssKem, SealV3.transcriptFile(eph, kct, myXPub, myKyberPub))
        val b = B64.decode(w.wrap)
        require(b.size == 12 + 32 + 16) { "file wrap v2: length ${b.size}" }
        return AesGcm.decryptWithTag(b.copyOfRange(12, 44), b.copyOfRange(44, 60), b.copyOfRange(0, 12), k, SealV3.AAD_FILE)
    }
    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
