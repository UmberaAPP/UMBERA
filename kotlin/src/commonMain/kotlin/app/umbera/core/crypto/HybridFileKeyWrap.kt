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
        @SerialName("w")   val wrap: String
    )

    private fun combined(x25519Shared: ByteArray, kyberShared: ByteArray): ByteArray =
        RustCore.hkdfSha256(x25519Shared + kyberShared, SALT, INFO, 32u)

    fun wrap(fileKey: ByteArray, recipientX25519Pub: ByteArray, recipientKyberPub: ByteArray): Wrapped {
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

    fun unwrap(w: Wrapped, myX25519Priv: ByteArray, myKyberPriv: ByteArray): ByteArray {
        val x25519Shared = X25519.computeSharedSecret(myX25519Priv, w.ephX25519Pub.hexToBytes())
        val kyberShared = Kyber1024.decapsulate(w.kyberCiphertext.hexToBytes(), myKyberPriv)
        return AesGcm.decrypt(AesGcm.EncryptedData.fromBase64(w.wrap), combined(x25519Shared, kyberShared))
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
