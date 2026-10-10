package app.umbera.core.crypto

// Hashing helpers (SHA-256, HMAC, HKDF).

import app.umbera.core.util.B64

object HashUtils {
    fun sha256(data: ByteArray): ByteArray = RustCore.sha256(data)

    fun sha256(data: String): ByteArray {
        return sha256(data.encodeToByteArray())
    }

    fun sha256Hex(data: String): String {
        return sha256(data).toHex()
    }

    fun hashEmailSecure(email: String, pepper: String): String {
        val normalizedEmail = email.lowercase().trim()

        val combined = "$pepper:$normalizedEmail"
        return sha256Hex(combined)
    }

    fun generateFingerprint(publicKey: ByteArray): String {
        return sha256(publicKey).toHex()
    }

    fun formatFingerprint(fingerprint: String): String {
        return fingerprint.chunked(4).joinToString(" ")
    }

    fun pbkdf2(
        password: String,
        salt: ByteArray,
        iterations: Int = 100000,
        keyLength: Int = 32
    ): ByteArray = RustCore.pbkdf2HmacSha256(password, salt, iterations.toUInt(), keyLength.toUInt())

    fun argon2id(password: String, salt: ByteArray, keyLength: Int = 32): ByteArray =
        RustCore.argon2idDerive(password, salt, keyLength.toUInt())

    fun generateSalt(length: Int = 32): ByteArray = secureRandomBytes(length)

    fun encryptKeyBackup(
        privateKeys: Map<String, ByteArray>,
        password: String
    ): String {
        val salt = generateSalt()

        val key = argon2id(password, salt)

        val keysJson = privateKeys.entries.joinToString(";") {
            "${it.key}:${it.value.toHex()}"
        }

        val encrypted = AesGcm.encrypt(keysJson.encodeToByteArray(), key)

        return "v2:${salt.toHex()}:${encrypted.iv.toHex()}:${encrypted.ciphertext.toBase64()}"
    }

    fun decryptKeyBackup(
        encryptedBackup: String,
        password: String
    ): Map<String, ByteArray> {
        val parts = encryptedBackup.split(":")

        val salt: ByteArray
        val iv: ByteArray
        val ciphertext: ByteArray
        val key: ByteArray
        if (parts.size == 4 && parts[0] == "v2") {
            salt = parts[1].hexToBytes()
            iv = parts[2].hexToBytes()
            ciphertext = parts[3].fromBase64()
            key = argon2id(password, salt)
        } else {
            require(parts.size == 3) { "Invalid backup format" }
            salt = parts[0].hexToBytes()
            iv = parts[1].hexToBytes()
            ciphertext = parts[2].fromBase64()
            key = pbkdf2(password, salt)
        }
        val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
        val decrypted = AesGcm.decrypt(encryptedData, key)

        val keysJson = decrypted.decodeToString()
        return keysJson.split(";")
            .filter { it.contains(":") }
            .associate {
                val keyParts = it.split(":")
                keyParts[0] to keyParts[1].hexToBytes()
            }
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.toBase64(): String = B64.encode(this)
    private fun String.fromBase64(): ByteArray = B64.decode(this)
}
