package app.umbera.core.crypto

// Hybrid signatures: Ed25519 combined with ML-DSA-65.

object HybridSignature {
    private const val VERSION = "hybrid-sig-v1"

    data class HybridPublicKey(
        val secp256k1: ByteArray,
        val dilithium: ByteArray
    ) {
        init {
            require(secp256k1.size == 65) { "Secp256k1 public key must be 65 bytes" }
            require(dilithium.isNotEmpty()) { "Dilithium public key cannot be empty" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as HybridPublicKey
            return secp256k1.contentEquals(other.secp256k1) &&
                    dilithium.contentEquals(other.dilithium)
        }

        override fun hashCode(): Int {
            var result = secp256k1.contentHashCode()
            result = 31 * result + dilithium.contentHashCode()
            return result
        }

        fun toHex(): String = secp256k1.toHex() + ":" + dilithium.toHex()

        fun secp256k1Hex(): String = secp256k1.toHex()
        fun dilithiumHex(): String = dilithium.toHex()

        companion object {
            fun fromHex(hex: String): HybridPublicKey {
                val parts = hex.split(":")
                require(parts.size == 2) { "Invalid hybrid public key format" }
                return HybridPublicKey(
                    secp256k1 = parts[0].hexToByteArray(),
                    dilithium = parts[1].hexToByteArray()
                )
            }

            fun fromComponents(secp256k1Hex: String, dilithiumHex: String): HybridPublicKey {
                return HybridPublicKey(
                    secp256k1 = secp256k1Hex.hexToByteArray(),
                    dilithium = dilithiumHex.hexToByteArray()
                )
            }
        }
    }

    data class HybridPrivateKey(
        val secp256k1: ByteArray,
        val dilithium: ByteArray
    ) {
        init {
            require(secp256k1.size == 32) { "Secp256k1 private key must be 32 bytes" }
            require(dilithium.isNotEmpty()) { "Dilithium private key cannot be empty" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as HybridPrivateKey
            return secp256k1.contentEquals(other.secp256k1) &&
                    dilithium.contentEquals(other.dilithium)
        }

        override fun hashCode(): Int {
            var result = secp256k1.contentHashCode()
            result = 31 * result + dilithium.contentHashCode()
            return result
        }

        fun toHex(): String = secp256k1.toHex() + ":" + dilithium.toHex()

        fun secp256k1Hex(): String = secp256k1.toHex()
        fun dilithiumHex(): String = dilithium.toHex()

        companion object {
            fun fromHex(hex: String): HybridPrivateKey {
                val parts = hex.split(":")
                require(parts.size == 2) { "Invalid hybrid private key format" }
                return HybridPrivateKey(
                    secp256k1 = parts[0].hexToByteArray(),
                    dilithium = parts[1].hexToByteArray()
                )
            }

            fun fromComponents(secp256k1Hex: String, dilithiumHex: String): HybridPrivateKey {
                return HybridPrivateKey(
                    secp256k1 = secp256k1Hex.hexToByteArray(),
                    dilithium = dilithiumHex.hexToByteArray()
                )
            }
        }
    }

    data class HybridKeyPair(
        val publicKey: HybridPublicKey,
        val privateKey: HybridPrivateKey
    )

    data class HybridSig(
        val version: String = VERSION,
        val secp256k1: ByteArray,
        val dilithium: ByteArray
    ) {
        init {
            require(secp256k1.size == 64) { "Secp256k1 signature must be 64 bytes" }
            require(dilithium.isNotEmpty()) { "Dilithium signature cannot be empty" }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as HybridSig
            return version == other.version &&
                    secp256k1.contentEquals(other.secp256k1) &&
                    dilithium.contentEquals(other.dilithium)
        }

        override fun hashCode(): Int {
            var result = version.hashCode()
            result = 31 * result + secp256k1.contentHashCode()
            result = 31 * result + dilithium.contentHashCode()
            return result
        }

        fun toHex(): String = "$version:${secp256k1.toHex()}:${dilithium.toHex()}"

        fun secp256k1Hex(): String = secp256k1.toHex()
        fun dilithiumHex(): String = dilithium.toHex()

        fun totalSize(): Int = secp256k1.size + dilithium.size

        companion object {
            fun fromHex(hex: String): HybridSig {
                val parts = hex.split(":")
                require(parts.size == 3) { "Invalid hybrid signature format" }
                return HybridSig(
                    version = parts[0],
                    secp256k1 = parts[1].hexToByteArray(),
                    dilithium = parts[2].hexToByteArray()
                )
            }

            fun fromComponents(
                secp256k1Hex: String,
                dilithiumHex: String,
                version: String = VERSION
            ): HybridSig {
                return HybridSig(
                    version = version,
                    secp256k1 = secp256k1Hex.hexToByteArray(),
                    dilithium = dilithiumHex.hexToByteArray()
                )
            }
        }
    }

    fun generateKeyPair(): HybridKeyPair {
        val secp256k1KeyPair = Secp256k1.generateKeyPair()

        val dilithiumKeyPair = Dilithium3.generateKeyPair()

        return HybridKeyPair(
            publicKey = HybridPublicKey(
                secp256k1 = secp256k1KeyPair.publicKey,
                dilithium = dilithiumKeyPair.publicKey.encoded
            ),
            privateKey = HybridPrivateKey(
                secp256k1 = secp256k1KeyPair.privateKey,
                dilithium = dilithiumKeyPair.privateKey.encoded
            )
        )
    }

    fun sign(message: ByteArray, privateKey: HybridPrivateKey): HybridSig {
        val secp256k1Signature = Secp256k1.sign(message, privateKey.secp256k1)
        val secp256k1Bytes = secp256k1Signature.r + secp256k1Signature.s

        val dilithiumSignature = Dilithium3.sign(message, privateKey.dilithium)

        return HybridSig(
            version = VERSION,
            secp256k1 = secp256k1Bytes,
            dilithium = dilithiumSignature.bytes
        )
    }

    fun signHex(messageHex: String, privateKey: HybridPrivateKey): HybridSig {
        return sign(messageHex.hexToByteArray(), privateKey)
    }

    fun signString(message: String, privateKey: HybridPrivateKey): HybridSig {
        return sign(message.encodeToByteArray(), privateKey)
    }

    fun verify(
        message: ByteArray,
        signature: HybridSig,
        publicKey: HybridPublicKey
    ): Boolean {
        val secp256k1Sig = Secp256k1.Signature(
            r = signature.secp256k1.copyOfRange(0, 32),
            s = signature.secp256k1.copyOfRange(32, 64)
        )
        val secp256k1Valid = Secp256k1.verify(message, secp256k1Sig, publicKey.secp256k1)

        if (!secp256k1Valid) {
            return false
        }

        val dilithiumValid = Dilithium3.verify(
            message,
            signature.dilithium,
            publicKey.dilithium
        )

        return dilithiumValid
    }

    fun verifyHex(
        messageHex: String,
        signatureHex: String,
        publicKeyHex: String
    ): Boolean {
        return verify(
            messageHex.hexToByteArray(),
            HybridSig.fromHex(signatureHex),
            HybridPublicKey.fromHex(publicKeyHex)
        )
    }

    fun verifyString(
        message: String,
        signature: HybridSig,
        publicKey: HybridPublicKey
    ): Boolean {
        return verify(message.encodeToByteArray(), signature, publicKey)
    }

    fun verifyClassicalOnly(
        message: ByteArray,
        signature: HybridSig,
        publicKey: HybridPublicKey
    ): Boolean {
        val secp256k1Sig = Secp256k1.Signature(
            r = signature.secp256k1.copyOfRange(0, 32),
            s = signature.secp256k1.copyOfRange(32, 64)
        )
        return Secp256k1.verify(message, secp256k1Sig, publicKey.secp256k1)
    }

    fun verifyPostQuantumOnly(
        message: ByteArray,
        signature: HybridSig,
        publicKey: HybridPublicKey
    ): Boolean {
        return Dilithium3.verify(message, signature.dilithium, publicKey.dilithium)
    }

    fun generateFingerprint(publicKey: HybridPublicKey): String {
        val combined = publicKey.secp256k1 + publicKey.dilithium
        return RustCore.sha256(combined).toHex()
    }

    fun isValidKeyPair(keyPair: HybridKeyPair): Boolean {
        return try {
            val testMessage = "hybrid-signature-test".encodeToByteArray()
            val signature = sign(testMessage, keyPair.privateKey)
            verify(testMessage, signature, keyPair.publicKey)
        } catch (e: Exception) {
            false
        }
    }

    fun upgradeFromClassical(
        secp256k1PublicKey: ByteArray,
        secp256k1PrivateKey: ByteArray
    ): HybridKeyPair {
        val dilithiumKeyPair = Dilithium3.generateKeyPair()

        return HybridKeyPair(
            publicKey = HybridPublicKey(
                secp256k1 = secp256k1PublicKey,
                dilithium = dilithiumKeyPair.publicKey.encoded
            ),
            privateKey = HybridPrivateKey(
                secp256k1 = secp256k1PrivateKey,
                dilithium = dilithiumKeyPair.privateKey.encoded
            )
        )
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.hexToByteArray(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
