package app.umbera.core.crypto

// ML-KEM-1024 (FIPS 203) key encapsulation.

object Kyber1024 {
    private const val SHARED_SECRET_SIZE = 32

    const val PUBLIC_KEY_SIZE = 1568
    const val PRIVATE_KEY_SIZE = 64
    const val CIPHERTEXT_SIZE = 1568

    data class KyberPublicKeyData(
        val encoded: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as KyberPublicKeyData
            return encoded.contentEquals(other.encoded)
        }

        override fun hashCode(): Int = encoded.contentHashCode()

        fun toHex(): String = encoded.toHex()

        companion object {
            fun fromHex(hex: String): KyberPublicKeyData = KyberPublicKeyData(hex.hexToByteArray())
        }
    }

    data class KyberPrivateKeyData(
        val encoded: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as KyberPrivateKeyData
            return encoded.contentEquals(other.encoded)
        }

        override fun hashCode(): Int = encoded.contentHashCode()

        fun toHex(): String = encoded.toHex()

        companion object {
            fun fromHex(hex: String): KyberPrivateKeyData = KyberPrivateKeyData(hex.hexToByteArray())
        }
    }

    data class KyberKeyPair(
        val publicKey: KyberPublicKeyData,
        val privateKey: KyberPrivateKeyData
    )

    data class Encapsulation(
        val ciphertext: ByteArray,
        val sharedSecret: ByteArray
    ) {
        init {
            require(sharedSecret.size == SHARED_SECRET_SIZE) {
                "Shared secret must be $SHARED_SECRET_SIZE bytes"
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as Encapsulation
            return ciphertext.contentEquals(other.ciphertext) &&
                    sharedSecret.contentEquals(other.sharedSecret)
        }

        override fun hashCode(): Int {
            var result = ciphertext.contentHashCode()
            result = 31 * result + sharedSecret.contentHashCode()
            return result
        }

        fun ciphertextHex(): String = ciphertext.toHex()
        fun sharedSecretHex(): String = sharedSecret.toHex()
    }

    fun generateKeyPair(): KyberKeyPair {
        val kp = RustCore.mlkem1024GenerateKeypair()
        return KyberKeyPair(
            publicKey = KyberPublicKeyData(kp.publicKey),
            privateKey = KyberPrivateKeyData(kp.privateKey)
        )
    }

    fun encapsulate(recipientPublicKey: KyberPublicKeyData): Encapsulation {
        val enc = RustCore.mlkem1024Encapsulate(recipientPublicKey.encoded)
        return Encapsulation(
            ciphertext = enc.ciphertext,
            sharedSecret = enc.sharedSecret
        )
    }

    fun encapsulate(recipientPublicKeyBytes: ByteArray): Encapsulation {
        return encapsulate(KyberPublicKeyData(recipientPublicKeyBytes))
    }

    fun decapsulate(ciphertext: ByteArray, privateKey: KyberPrivateKeyData): ByteArray {
        return RustCore.mlkem1024Decapsulate(ciphertext, privateKey.encoded)
    }

    fun decapsulate(ciphertext: ByteArray, privateKeyBytes: ByteArray): ByteArray {
        return decapsulate(ciphertext, KyberPrivateKeyData(privateKeyBytes))
    }

    fun decapsulateHex(ciphertextHex: String, privateKey: KyberPrivateKeyData): ByteArray {
        return decapsulate(ciphertextHex.hexToByteArray(), privateKey)
    }

    fun isValidPublicKey(publicKeyBytes: ByteArray): Boolean {
        return RustCore.mlkem1024ValidatePublicKey(publicKeyBytes)
    }

    fun isValidPrivateKey(privateKeyBytes: ByteArray): Boolean {
        return privateKeyBytes.size == PRIVATE_KEY_SIZE
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.hexToByteArray(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
