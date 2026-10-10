package app.umbera.core.crypto

// Hybrid key exchange: X25519 combined with ML-KEM-1024.

object HybridKeyExchange {
    private const val INFO = "key-derivation"
    private const val OUTPUT_SIZE = 64

    data class HybridPublicKey(
        val x25519: ByteArray,
        val kyber: ByteArray
    ) {
        init {
            require(x25519.size == 32) { "X25519 public key must be 32 bytes" }
            require(kyber.isNotEmpty()) { "Kyber public key cannot be empty" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as HybridPublicKey
            return x25519.contentEquals(other.x25519) && kyber.contentEquals(other.kyber)
        }

        override fun hashCode(): Int {
            var result = x25519.contentHashCode()
            result = 31 * result + kyber.contentHashCode()
            return result
        }

        fun toHex(): String = x25519.toHex() + ":" + kyber.toHex()

        fun x25519Hex(): String = x25519.toHex()
        fun kyberHex(): String = kyber.toHex()

        companion object {
            fun fromHex(hex: String): HybridPublicKey {
                val parts = hex.split(":")
                require(parts.size == 2) { "Invalid hybrid public key format" }
                return HybridPublicKey(
                    x25519 = parts[0].hexToByteArray(),
                    kyber = parts[1].hexToByteArray()
                )
            }

            fun fromComponents(x25519Hex: String, kyberHex: String): HybridPublicKey {
                return HybridPublicKey(
                    x25519 = x25519Hex.hexToByteArray(),
                    kyber = kyberHex.hexToByteArray()
                )
            }
        }
    }

    data class HybridPrivateKey(
        val x25519: ByteArray,
        val kyber: ByteArray
    ) {
        init {
            require(x25519.size == 32) { "X25519 private key must be 32 bytes" }
            require(kyber.isNotEmpty()) { "Kyber private key cannot be empty" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as HybridPrivateKey
            return x25519.contentEquals(other.x25519) && kyber.contentEquals(other.kyber)
        }

        override fun hashCode(): Int {
            var result = x25519.contentHashCode()
            result = 31 * result + kyber.contentHashCode()
            return result
        }

        fun toHex(): String = x25519.toHex() + ":" + kyber.toHex()

        fun x25519Hex(): String = x25519.toHex()
        fun kyberHex(): String = kyber.toHex()

        companion object {
            fun fromHex(hex: String): HybridPrivateKey {
                val parts = hex.split(":")
                require(parts.size == 2) { "Invalid hybrid private key format" }
                return HybridPrivateKey(
                    x25519 = parts[0].hexToByteArray(),
                    kyber = parts[1].hexToByteArray()
                )
            }

            fun fromComponents(x25519Hex: String, kyberHex: String): HybridPrivateKey {
                return HybridPrivateKey(
                    x25519 = x25519Hex.hexToByteArray(),
                    kyber = kyberHex.hexToByteArray()
                )
            }
        }
    }

    data class HybridKeyPair(
        val publicKey: HybridPublicKey,
        val privateKey: HybridPrivateKey
    )

    data class HybridSharedSecret(
        val bytes: ByteArray
    ) {
        init {
            require(bytes.size == OUTPUT_SIZE) { "Shared secret must be $OUTPUT_SIZE bytes" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as HybridSharedSecret
            return bytes.contentEquals(other.bytes)
        }

        override fun hashCode(): Int = bytes.contentHashCode()

        fun toHex(): String = bytes.toHex()

        fun getAesKey(): ByteArray = bytes.copyOfRange(0, 32)

        fun getHmacKey(): ByteArray = bytes.copyOfRange(32, 64)

        fun deriveKey(info: String, length: Int = 32): ByteArray {
            return hkdfExpand(bytes, info.encodeToByteArray(), length)
        }
    }

    data class HybridEncapsulation(
        val kyberCiphertext: ByteArray,
        val sharedSecret: HybridSharedSecret
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as HybridEncapsulation
            return kyberCiphertext.contentEquals(other.kyberCiphertext) &&
                    sharedSecret == other.sharedSecret
        }

        override fun hashCode(): Int {
            var result = kyberCiphertext.contentHashCode()
            result = 31 * result + sharedSecret.hashCode()
            return result
        }

        fun kyberCiphertextHex(): String = kyberCiphertext.toHex()
    }

    fun generateKeyPair(): HybridKeyPair {
        val x25519KeyPair = X25519.generateKeyPair()

        val kyberKeyPair = Kyber1024.generateKeyPair()

        return HybridKeyPair(
            publicKey = HybridPublicKey(
                x25519 = x25519KeyPair.publicKey,
                kyber = kyberKeyPair.publicKey.encoded
            ),
            privateKey = HybridPrivateKey(
                x25519 = x25519KeyPair.privateKey,
                kyber = kyberKeyPair.privateKey.encoded
            )
        )
    }

    fun encapsulate(
        senderPrivateKey: HybridPrivateKey,
        recipientPublicKey: HybridPublicKey
    ): HybridEncapsulation {
        val x25519SharedSecret = X25519.computeSharedSecret(
            senderPrivateKey.x25519,
            recipientPublicKey.x25519
        )

        val kyberEncapsulation = Kyber1024.encapsulate(recipientPublicKey.kyber)

        val combinedSecret = combineSecrets(x25519SharedSecret, kyberEncapsulation.sharedSecret)

        return HybridEncapsulation(
            kyberCiphertext = kyberEncapsulation.ciphertext,
            sharedSecret = combinedSecret
        )
    }

    fun decapsulate(
        recipientPrivateKey: HybridPrivateKey,
        senderPublicKey: HybridPublicKey,
        kyberCiphertext: ByteArray
    ): HybridSharedSecret {
        val x25519SharedSecret = X25519.computeSharedSecret(
            recipientPrivateKey.x25519,
            senderPublicKey.x25519
        )

        val kyberSharedSecret = Kyber1024.decapsulate(
            kyberCiphertext,
            recipientPrivateKey.kyber
        )

        return combineSecrets(x25519SharedSecret, kyberSharedSecret)
    }

    private fun combineSecrets(
        x25519Secret: ByteArray,
        kyberSecret: ByteArray
    ): HybridSharedSecret {
        val inputKeyMaterial = x25519Secret + kyberSecret

        val output = RustCore.hkdfSha256(
            inputKeyMaterial, Labels.HYBRID, INFO.encodeToByteArray(), OUTPUT_SIZE.toUInt()
        )

        return HybridSharedSecret(output)
    }

    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray =

        RustCore.hkdfSha256Expand(prk, info, length.toUInt())

    fun generateFingerprint(publicKey: HybridPublicKey): String {
        val combined = publicKey.x25519 + publicKey.kyber
        return RustCore.sha256(combined).toHex()
    }

    fun isValidKeyPair(keyPair: HybridKeyPair): Boolean {
        return try {
            val x25519Test = X25519.computeSharedSecret(
                keyPair.privateKey.x25519,
                keyPair.publicKey.x25519
            )

            val kyberEncap = Kyber1024.encapsulate(keyPair.publicKey.kyber)
            val kyberDecap = Kyber1024.decapsulate(
                kyberEncap.ciphertext,
                keyPair.privateKey.kyber
            )

            kyberEncap.sharedSecret.contentEquals(kyberDecap)
        } catch (e: Exception) {
            false
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.hexToByteArray(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
