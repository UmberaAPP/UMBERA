package app.umbera.core.crypto


/**
 * Hybrid Key Exchange combining X25519 (classical) and Kyber-1024 (post-quantum)
 *
 * This provides defense-in-depth:
 * - X25519: Proven classical security, fast
 * - Kyber-1024: Post-quantum security (NIST Level 5)
 *
 * If either algorithm is broken, the other still protects the key exchange.
 *
 * Combined shared secret derivation:
 * HKDF-SHA256(X25519_secret || Kyber_secret, salt="typex-hybrid-v1", info="key-derivation")
 *
 * Output: 64 bytes (can derive multiple keys from this)
 */
object HybridKeyExchange {

    private const val SALT = "typex-hybrid-v1"
    private const val INFO = "key-derivation"
    private const val OUTPUT_SIZE = 64  // 64 bytes = 512 bits

    /**
     * Hybrid public key containing both classical and post-quantum components
     */
    data class HybridPublicKey(
        val x25519: ByteArray,      // 32 bytes
        val kyber: ByteArray        // raw ML-KEM-1024 encapsulation key (1568 bytes, FIPS 203)
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

    /**
     * Hybrid private key containing both classical and post-quantum components
     */
    data class HybridPrivateKey(
        val x25519: ByteArray,      // 32 bytes
        val kyber: ByteArray        // ML-KEM-1024 private-key seed d||z (64 bytes, FIPS 203)
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

    /**
     * Hybrid key pair
     */
    data class HybridKeyPair(
        val publicKey: HybridPublicKey,
        val privateKey: HybridPrivateKey
    )

    /**
     * Hybrid shared secret (64 bytes)
     */
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

        /**
         * Get AES-256 key from the shared secret (first 32 bytes)
         */
        fun getAesKey(): ByteArray = bytes.copyOfRange(0, 32)

        /**
         * Get HMAC key from the shared secret (last 32 bytes)
         */
        fun getHmacKey(): ByteArray = bytes.copyOfRange(32, 64)

        /**
         * Derive a specific key using HKDF with custom info
         */
        fun deriveKey(info: String, length: Int = 32): ByteArray {
            return hkdfExpand(bytes, info.encodeToByteArray(), length)
        }
    }

    /**
     * Encapsulation result for hybrid key exchange
     * Contains ciphertext from Kyber KEM and the derived shared secret
     */
    data class HybridEncapsulation(
        val kyberCiphertext: ByteArray,  // 1568 bytes - to send to recipient
        val sharedSecret: HybridSharedSecret  // 64 bytes - derived key material
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

    /**
     * Generate a new hybrid key pair (X25519 + Kyber-1024)
     *
     * @return HybridKeyPair containing both key types
     */
    fun generateKeyPair(): HybridKeyPair {
        // Generate X25519 key pair
        val x25519KeyPair = X25519.generateKeyPair()

        // Generate Kyber-1024 key pair
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

    /**
     * Sender: Encapsulate to create shared secret for recipient
     *
     * This performs:
     * 1. X25519 ECDH with sender's private key and recipient's public key
     * 2. Kyber KEM encapsulation with recipient's public key
     * 3. Combines both secrets using HKDF
     *
     * @param senderPrivateKey Sender's hybrid private key (for X25519 ECDH)
     * @param recipientPublicKey Recipient's hybrid public key
     * @return HybridEncapsulation containing Kyber ciphertext and shared secret
     */
    fun encapsulate(
        senderPrivateKey: HybridPrivateKey,
        recipientPublicKey: HybridPublicKey
    ): HybridEncapsulation {
        // 1. X25519 ECDH
        val x25519SharedSecret = X25519.computeSharedSecret(
            senderPrivateKey.x25519,
            recipientPublicKey.x25519
        )

        // 2. Kyber KEM Encapsulate
        val kyberEncapsulation = Kyber1024.encapsulate(recipientPublicKey.kyber)

        // 3. Combine secrets using HKDF
        val combinedSecret = combineSecrets(x25519SharedSecret, kyberEncapsulation.sharedSecret)

        return HybridEncapsulation(
            kyberCiphertext = kyberEncapsulation.ciphertext,
            sharedSecret = combinedSecret
        )
    }

    /**
     * Recipient: Decapsulate to derive the same shared secret
     *
     * This performs:
     * 1. X25519 ECDH with recipient's private key and sender's public key
     * 2. Kyber KEM decapsulation with recipient's private key
     * 3. Combines both secrets using HKDF
     *
     * @param recipientPrivateKey Recipient's hybrid private key
     * @param senderPublicKey Sender's hybrid public key (for X25519 ECDH)
     * @param kyberCiphertext The Kyber ciphertext received from sender
     * @return HybridSharedSecret (same as sender derived)
     */
    fun decapsulate(
        recipientPrivateKey: HybridPrivateKey,
        senderPublicKey: HybridPublicKey,
        kyberCiphertext: ByteArray
    ): HybridSharedSecret {
        // 1. X25519 ECDH
        val x25519SharedSecret = X25519.computeSharedSecret(
            recipientPrivateKey.x25519,
            senderPublicKey.x25519
        )

        // 2. Kyber KEM Decapsulate
        val kyberSharedSecret = Kyber1024.decapsulate(
            kyberCiphertext,
            recipientPrivateKey.kyber
        )

        // 3. Combine secrets using HKDF
        return combineSecrets(x25519SharedSecret, kyberSharedSecret)
    }

    /**
     * `hybrid-pq-v3` — the same static path, but the combiner is bound to the transcript
     * (SealV3.transcriptStatic: sender's static X25519, ML-KEM encapsulation, both recipient keys).
     */
    fun encapsulateV3(
        senderPrivateKey: HybridPrivateKey,
        senderX25519Public: ByteArray,
        recipientPublicKey: HybridPublicKey,
    ): HybridEncapsulation {
        val ssX = X25519.computeSharedSecret(senderPrivateKey.x25519, recipientPublicKey.x25519)
        val kem = Kyber1024.encapsulate(recipientPublicKey.kyber)
        val th = SealV3.transcriptStatic(senderX25519Public, kem.ciphertext, recipientPublicKey.x25519, recipientPublicKey.kyber)
        return HybridEncapsulation(kyberCiphertext = kem.ciphertext, sharedSecret = HybridSharedSecret(SealV3.staticOkm(ssX, kem.sharedSecret, th)))
    }

    /** `hybrid-pq-v3` recipient: the recipient keys in the transcript are OWN ([recipient].publicKey), not from the envelope. */
    fun decapsulateV3(
        recipient: HybridKeyPair,
        senderX25519Public: ByteArray,
        kyberCiphertext: ByteArray,
    ): HybridSharedSecret {
        val th = SealV3.transcriptStatic(senderX25519Public, kyberCiphertext, recipient.publicKey.x25519, recipient.publicKey.kyber)
        val ssX = X25519.computeSharedSecret(recipient.privateKey.x25519, senderX25519Public)
        val ssK = Kyber1024.decapsulate(kyberCiphertext, recipient.privateKey.kyber)
        return HybridSharedSecret(SealV3.staticOkm(ssX, ssK, th))
    }

    /**
     * Combine X25519 and Kyber shared secrets using HKDF
     *
     * @param x25519Secret The X25519 ECDH shared secret (32 bytes)
     * @param kyberSecret The Kyber KEM shared secret (32 bytes)
     * @return Combined HybridSharedSecret (64 bytes)
     */
    private fun combineSecrets(
        x25519Secret: ByteArray,
        kyberSecret: ByteArray
    ): HybridSharedSecret {
        // Concatenate: X25519 || Kyber
        val inputKeyMaterial = x25519Secret + kyberSecret

        // HKDF-SHA256 in the shared Rust core (byte-identical to the previous
        // BC HKDFBytesGenerator — locked by the hybrid_exchange golden).
        val output = RustCore.hkdfSha256(
            inputKeyMaterial, SALT.encodeToByteArray(), INFO.encodeToByteArray(), OUTPUT_SIZE.toUInt()
        )

        return HybridSharedSecret(output)
    }

    /**
     * HKDF-Expand for deriving additional keys
     */
    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray =
        // RFC 5869 expand-only in the Rust core — byte-identical to BC's
        // skipExtractParameters (RFC A.1 known-answer in the Rust tests).
        RustCore.hkdfSha256Expand(prk, info, length.toUInt())

    /**
     * Generate fingerprint for a hybrid public key
     * SHA-256(X25519_pub || Kyber_pub)
     */
    fun generateFingerprint(publicKey: HybridPublicKey): String {
        val combined = publicKey.x25519 + publicKey.kyber
        return RustCore.sha256(combined).toHex()
    }

    /**
     * Verify hybrid key pair is valid
     */
    fun isValidKeyPair(keyPair: HybridKeyPair): Boolean {
        return try {
            // Verify X25519 by attempting ECDH with self
            val x25519Test = X25519.computeSharedSecret(
                keyPair.privateKey.x25519,
                keyPair.publicKey.x25519
            )

            // Verify Kyber by encapsulate/decapsulate round trip
            val kyberEncap = Kyber1024.encapsulate(keyPair.publicKey.kyber)
            val kyberDecap = Kyber1024.decapsulate(
                kyberEncap.ciphertext,
                keyPair.privateKey.kyber
            )

            // Verify Kyber round-trip produces same secret
            kyberEncap.sharedSecret.contentEquals(kyberDecap)
        } catch (e: Exception) {
            false
        }
    }

    // Extension functions for hex conversion
    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.hexToByteArray(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
