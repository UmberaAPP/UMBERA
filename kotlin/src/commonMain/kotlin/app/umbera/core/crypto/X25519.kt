package app.umbera.core.crypto

// X25519 key agreement.

import kotlinx.serialization.Serializable

object X25519 {
    private val LOW_ORDER_POINTS = listOf(
        ByteArray(32) { 0 },

        byteArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),

        parseHex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
        parseHex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
        parseHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),

        parseHex("0000000000000000000000000000000000000000000000000000000000000000"),
        parseHex("0000000000000000000000000000000000000000000000000000000000000080"),
        parseHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
    )

    private fun parseHex(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    @Serializable

    data class KeyPair(
        val privateKey: ByteArray,
        val publicKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as KeyPair
            return privateKey.contentEquals(other.privateKey) && publicKey.contentEquals(other.publicKey)
        }

        override fun hashCode(): Int {
            var result = privateKey.contentHashCode()
            result = 31 * result + publicKey.contentHashCode()
            return result
        }
    }

    fun generateKeyPair(): KeyPair {
        val privateKey = secureRandomBytes(32)
        return KeyPair(
            privateKey = privateKey,
            publicKey = getPublicKey(privateKey)
        )
    }

    fun getPublicKey(privateKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "Private key must be 32 bytes" }
        return RustCore.x25519PublicKey(privateKey)
    }

    fun validatePublicKey(publicKey: ByteArray) {
        require(publicKey.size == 32) { "Public key must be 32 bytes" }

        for (lowOrderPoint in LOW_ORDER_POINTS) {
            if (publicKey.contentEquals(lowOrderPoint)) {
                throw IllegalArgumentException("Invalid public key: low-order point detected")
            }
        }

        if (publicKey.all { it == 0.toByte() }) {
            throw IllegalArgumentException("Invalid public key: all zeros")
        }
    }

    fun isValidPublicKey(publicKey: ByteArray): Boolean {
        return try {
            validatePublicKey(publicKey)
            true
        } catch (e: IllegalArgumentException) {
            false
        }
    }

    fun computeSharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(privateKey.size == 32) { "Private key must be 32 bytes" }
        require(publicKey.size == 32) { "Public key must be 32 bytes" }

        validatePublicKey(publicKey)

        val sharedSecret = RustCore.x25519SharedSecret(privateKey, publicKey)

        if (sharedSecret.all { it == 0.toByte() }) {
            throw SecurityException("Computed shared secret is invalid (all zeros)")
        }

        return sharedSecret
    }

    fun deriveAesKey(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val sharedSecret = computeSharedSecret(privateKey, publicKey)
        return AesGcm.deriveKey(sharedSecret)
    }

    fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
