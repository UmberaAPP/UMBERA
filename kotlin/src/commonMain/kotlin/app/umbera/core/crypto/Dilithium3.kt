package app.umbera.core.crypto

// ML-DSA-65 (FIPS 204) signatures.

object Dilithium3 {
    const val PUBLIC_KEY_SIZE = 1952
    const val PRIVATE_KEY_SIZE = 32
    const val SIGNATURE_SIZE = 3309

    data class DilithiumPublicKey(
        val encoded: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as DilithiumPublicKey
            return encoded.contentEquals(other.encoded)
        }

        override fun hashCode(): Int = encoded.contentHashCode()

        fun toHex(): String = encoded.toHex()

        companion object {
            fun fromHex(hex: String): DilithiumPublicKey = DilithiumPublicKey(hex.hexToByteArray())
        }
    }

    data class DilithiumPrivateKey(
        val encoded: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as DilithiumPrivateKey
            return encoded.contentEquals(other.encoded)
        }

        override fun hashCode(): Int = encoded.contentHashCode()

        fun toHex(): String = encoded.toHex()

        companion object {
            fun fromHex(hex: String): DilithiumPrivateKey = DilithiumPrivateKey(hex.hexToByteArray())
        }
    }

    data class DilithiumKeyPair(
        val publicKey: DilithiumPublicKey,
        val privateKey: DilithiumPrivateKey
    )

    data class DilithiumSignature(
        val bytes: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as DilithiumSignature
            return bytes.contentEquals(other.bytes)
        }

        override fun hashCode(): Int = bytes.contentHashCode()

        fun toHex(): String = bytes.toHex()

        companion object {
            fun fromHex(hex: String): DilithiumSignature = DilithiumSignature(hex.hexToByteArray())
        }
    }

    fun generateKeyPair(): DilithiumKeyPair {
        val kp = RustCore.mldsa65GenerateKeypair()
        return DilithiumKeyPair(
            publicKey = DilithiumPublicKey(kp.publicKey),
            privateKey = DilithiumPrivateKey(kp.privateKey)
        )
    }

    fun sign(message: ByteArray, privateKey: DilithiumPrivateKey): DilithiumSignature {
        return DilithiumSignature(RustCore.mldsa65Sign(message, privateKey.encoded))
    }

    fun sign(message: ByteArray, privateKeyBytes: ByteArray): DilithiumSignature {
        return sign(message, DilithiumPrivateKey(privateKeyBytes))
    }

    fun signHex(messageHex: String, privateKey: DilithiumPrivateKey): DilithiumSignature {
        return sign(messageHex.hexToByteArray(), privateKey)
    }

    fun verify(
        message: ByteArray,
        signature: DilithiumSignature,
        publicKey: DilithiumPublicKey
    ): Boolean {
        return RustCore.mldsa65Verify(message, signature.bytes, publicKey.encoded)
    }

    fun verify(
        message: ByteArray,
        signatureBytes: ByteArray,
        publicKeyBytes: ByteArray
    ): Boolean {
        return verify(
            message,
            DilithiumSignature(signatureBytes),
            DilithiumPublicKey(publicKeyBytes)
        )
    }

    fun verifyHex(
        messageHex: String,
        signatureHex: String,
        publicKeyHex: String
    ): Boolean {
        return verify(
            messageHex.hexToByteArray(),
            DilithiumSignature.fromHex(signatureHex),
            DilithiumPublicKey.fromHex(publicKeyHex)
        )
    }

    fun isValidPublicKey(publicKeyBytes: ByteArray): Boolean {
        return publicKeyBytes.size == PUBLIC_KEY_SIZE
    }

    fun isValidPrivateKey(privateKeyBytes: ByteArray): Boolean {
        return privateKeyBytes.size == PRIVATE_KEY_SIZE
    }

    fun generateFingerprint(publicKey: DilithiumPublicKey): String {
        return RustCore.sha256(publicKey.encoded).toHex()
    }

    fun generateFingerprint(publicKeyBytes: ByteArray): String {
        return generateFingerprint(DilithiumPublicKey(publicKeyBytes))
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.hexToByteArray(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
