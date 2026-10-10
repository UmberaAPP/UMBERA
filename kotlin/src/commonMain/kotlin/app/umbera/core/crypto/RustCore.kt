package app.umbera.core.crypto

// Platform-neutral facade over the Rust cryptographic core.

expect object RustCore {
    fun sha256(data: ByteArray): ByteArray
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: UInt): ByteArray
    fun hkdfSha256Expand(prk: ByteArray, info: ByteArray, length: UInt): ByteArray
    fun pbkdf2HmacSha256(password: String, salt: ByteArray, iterations: UInt, keyLength: UInt): ByteArray
    fun argon2idDerive(password: String, salt: ByteArray, keyLength: UInt): ByteArray

    fun aes256GcmEncrypt(key: ByteArray, iv: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray
    fun aes256GcmDecrypt(key: ByteArray, iv: ByteArray, ciphertextWithTag: ByteArray, aad: ByteArray): ByteArray

    fun x25519PublicKey(privateKey: ByteArray): ByteArray
    fun x25519SharedSecret(privateKey: ByteArray, publicKey: ByteArray): ByteArray
    fun secp256k1PublicKey(privateKey: ByteArray): ByteArray
    fun secp256k1SignHash(hash: ByteArray, privateKey: ByteArray): ByteArray
    fun secp256k1VerifyHash(hash: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean
    fun ed25519Verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    fun ed25519PublicFromSeed(seed: ByteArray): ByteArray

    fun ed25519Sign(message: ByteArray, seed: ByteArray): ByteArray

    fun pdfStripMetadata(data: ByteArray): ByteArray

    fun mlkem1024GenerateKeypair(): PqKeyPair
    fun mlkem1024PublicKey(privateKeySeed: ByteArray): ByteArray
    fun mlkem1024Encapsulate(publicKey: ByteArray): KemEncapsulation
    fun mlkem1024Decapsulate(ciphertext: ByteArray, privateKeySeed: ByteArray): ByteArray
    fun mlkem1024ValidatePublicKey(publicKey: ByteArray): Boolean
    fun mldsa65GenerateKeypair(): PqKeyPair
    fun mldsa65PublicKey(privateKeySeed: ByteArray): ByteArray
    fun mldsa65Sign(message: ByteArray, privateKeySeed: ByteArray): ByteArray
    fun mldsa65Verify(message: ByteArray, signature: ByteArray, publicKey: ByteArray): Boolean

    fun quantAddress(classicalHex: String, dilithiumHex: String): String
}

class PqKeyPair(
    val publicKey: ByteArray,
    val privateKey: ByteArray,
)

class KemEncapsulation(
    val ciphertext: ByteArray,
    val sharedSecret: ByteArray,
)

class RustCoreException(message: String) : Exception(message)

expect fun secureRandomBytes(size: Int): ByteArray
