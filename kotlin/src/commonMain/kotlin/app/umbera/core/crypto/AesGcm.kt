package app.umbera.core.crypto

// AES-256-GCM authenticated encryption.

import app.umbera.core.util.B64

object AesGcm {
    private const val KEY_SIZE = 32
    private const val IV_SIZE = 12
    private const val TAG_SIZE = 128

    data class EncryptedData(
        val ciphertext: ByteArray,
        val iv: ByteArray,
        val tag: ByteArray? = null
    ) {
        fun toByteArray(): ByteArray = iv + ciphertext

        fun toBase64(): String = B64.encode(toByteArray())

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as EncryptedData
            return ciphertext.contentEquals(other.ciphertext) && iv.contentEquals(other.iv)
        }

        override fun hashCode(): Int {
            var result = ciphertext.contentHashCode()
            result = 31 * result + iv.contentHashCode()
            return result
        }

        companion object {
            fun fromByteArray(data: ByteArray): EncryptedData {
                require(data.size > IV_SIZE) { "Data too short" }
                return EncryptedData(
                    iv = data.copyOfRange(0, IV_SIZE),
                    ciphertext = data.copyOfRange(IV_SIZE, data.size)
                )
            }

            fun fromBase64(base64: String): EncryptedData {
                val data = B64.decode(base64)
                return fromByteArray(data)
            }
        }
    }

    fun generateKey(): ByteArray = secureRandomBytes(KEY_SIZE)

    fun generateIv(): ByteArray = secureRandomBytes(IV_SIZE)

    fun deriveKey(sharedSecret: ByteArray, info: ByteArray = "aes-key".encodeToByteArray()): ByteArray {
        val salt = HashUtils.sha256(Labels.AES_KDF)
        return deriveKeyHKDF(sharedSecret, salt, info)
    }

    fun deriveKeyHKDF(sharedSecret: ByteArray, salt: ByteArray, info: ByteArray): ByteArray =
        RustCore.hkdfSha256(sharedSecret, salt, info, KEY_SIZE.toUInt())

    fun encrypt(
        plaintext: ByteArray,
        key: ByteArray,
        additionalData: ByteArray? = null
    ): EncryptedData {
        require(key.size == KEY_SIZE) { "Key must be 32 bytes" }

        val iv = generateIv()

        val ciphertext = RustCore.aes256GcmEncrypt(key, iv, plaintext, additionalData ?: ByteArray(0))
        return EncryptedData(ciphertext, iv)
    }

    fun encryptString(
        plaintext: String,
        key: ByteArray,
        additionalData: ByteArray? = null
    ): EncryptedData {
        return encrypt(plaintext.encodeToByteArray(), key, additionalData)
    }

    fun decrypt(
        encryptedData: EncryptedData,
        key: ByteArray,
        additionalData: ByteArray? = null
    ): ByteArray {
        require(key.size == KEY_SIZE) { "Key must be 32 bytes" }

        return RustCore.aes256GcmDecrypt(key, encryptedData.iv, encryptedData.ciphertext, additionalData ?: ByteArray(0))
    }

    fun decryptString(
        encryptedData: EncryptedData,
        key: ByteArray,
        additionalData: ByteArray? = null
    ): String {
        return decrypt(encryptedData, key, additionalData).decodeToString()
    }

    fun encryptWithKeyExchange(
        plaintext: ByteArray,
        senderPrivateKey: ByteArray,
        recipientPublicKey: ByteArray
    ): EncryptedData {
        val sharedSecret = X25519.computeSharedSecret(senderPrivateKey, recipientPublicKey)
        val aesKey = deriveKey(sharedSecret)
        return encrypt(plaintext, aesKey)
    }

    fun decryptWithKeyExchange(
        encryptedData: EncryptedData,
        recipientPrivateKey: ByteArray,
        senderPublicKey: ByteArray
    ): ByteArray {
        val sharedSecret = X25519.computeSharedSecret(recipientPrivateKey, senderPublicKey)
        val aesKey = deriveKey(sharedSecret)
        return decrypt(encryptedData, aesKey)
    }

    data class EncryptedWithTag(
        val ciphertext: ByteArray,
        val authTag: ByteArray,
        val iv: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false
            other as EncryptedWithTag
            return ciphertext.contentEquals(other.ciphertext) &&
                   authTag.contentEquals(other.authTag) &&
                   iv.contentEquals(other.iv)
        }

        override fun hashCode(): Int {
            var result = ciphertext.contentHashCode()
            result = 31 * result + authTag.contentHashCode()
            result = 31 * result + iv.contentHashCode()
            return result
        }
    }

    fun encryptWithTag(
        plaintext: ByteArray,
        key: ByteArray,
        iv: ByteArray,
        additionalData: ByteArray? = null
    ): EncryptedWithTag {
        require(key.size == KEY_SIZE) { "Key must be 32 bytes" }
        require(iv.size == IV_SIZE) { "IV must be 12 bytes" }

        val ciphertextWithTag = RustCore.aes256GcmEncrypt(key, iv, plaintext, additionalData ?: ByteArray(0))
        val tagLength = TAG_SIZE / 8
        val ciphertext = ciphertextWithTag.copyOfRange(0, ciphertextWithTag.size - tagLength)
        val authTag = ciphertextWithTag.copyOfRange(ciphertextWithTag.size - tagLength, ciphertextWithTag.size)

        return EncryptedWithTag(ciphertext, authTag, iv)
    }

    fun decryptWithTag(
        ciphertext: ByteArray,
        authTag: ByteArray,
        iv: ByteArray,
        key: ByteArray,
        additionalData: ByteArray? = null
    ): ByteArray {
        require(key.size == KEY_SIZE) { "Key must be 32 bytes" }
        require(iv.size == IV_SIZE) { "IV must be 12 bytes" }
        require(authTag.size == TAG_SIZE / 8) { "AuthTag must be 16 bytes" }

        val ciphertextWithTag = ciphertext + authTag
        return RustCore.aes256GcmDecrypt(key, iv, ciphertextWithTag, additionalData ?: ByteArray(0))
    }
}
