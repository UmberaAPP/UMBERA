package app.umbera.core.crypto

// secp256k1 ECDSA signatures.

object Secp256k1 {
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

    data class Signature(
        val r: ByteArray,
        val s: ByteArray
    ) {
        fun toByteArray(): ByteArray = r + s

        fun toHexString(): String = toByteArray().toHex()

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as Signature
            return r.contentEquals(other.r) && s.contentEquals(other.s)
        }

        override fun hashCode(): Int {
            var result = r.contentHashCode()
            result = 31 * result + s.contentHashCode()
            return result
        }

        companion object {
            fun fromByteArray(data: ByteArray): Signature {
                require(data.size == 64) { "Signature must be 64 bytes" }
                return Signature(
                    r = data.copyOfRange(0, 32),
                    s = data.copyOfRange(32, 64)
                )
            }

            fun fromHexString(hex: String): Signature = fromByteArray(hex.hexToBytes())
        }
    }

    fun generateKeyPair(): KeyPair {
        while (true) {
            val privateKey = secureRandomBytes(32)
            try {
                return KeyPair(privateKey, getPublicKey(privateKey))
            } catch (e: app.umbera.core.crypto.RustCoreException) {
            }
        }
    }

    fun getPublicKey(privateKey: ByteArray): ByteArray =
        RustCore.secp256k1PublicKey(privateKey)

    fun sign(message: ByteArray, privateKey: ByteArray): Signature {
        val hash = sha256(message)
        return signHash(hash, privateKey)
    }

    fun signHash(hash: ByteArray, privateKey: ByteArray): Signature {
        require(hash.size == 32) { "Hash must be 32 bytes (SHA-256)" }

        val rs = RustCore.secp256k1SignHash(hash, privateKey)
        return Signature.fromByteArray(rs)
    }

    fun verify(message: ByteArray, signature: Signature, publicKey: ByteArray): Boolean {
        val hash = sha256(message)
        return verifyHash(hash, signature, publicKey)
    }

    fun verifyHash(hash: ByteArray, signature: Signature, publicKey: ByteArray): Boolean {
        require(hash.size == 32) { "Hash must be 32 bytes" }

        return RustCore.secp256k1VerifyHash(hash, signature.toByteArray(), publicKey)
    }

    fun generateFingerprint(publicKey: ByteArray): String {
        return sha256(publicKey).toHex()
    }

    private fun sha256(data: ByteArray): ByteArray = RustCore.sha256(data)

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
