package app.umbera.core.crypto

// Device-local key storage used by the protocol layer. Implementations keep
// private keys in the platform secure enclave / keystore; nothing here ever
// leaves the device.
interface LocalKeyStore {
    fun getUserId(): String?
    fun getNickname(): String?

    fun getX25519PrivateKey(): ByteArray?
    fun getX25519PublicKey(): ByteArray?
    fun getSecp256k1PrivateKey(): ByteArray?
    fun getSecp256k1PublicKey(): ByteArray?
    fun getHybridExchangeKeyPair(): HybridKeyExchange.HybridKeyPair?
    fun getHybridSignatureKeyPair(): HybridSignature.HybridKeyPair?

    fun isHybridCryptoEnabled(): Boolean
    fun isRatchetEnabled(): Boolean

    fun getFileNumberCounter(conversationId: String): Int
    fun saveFileNumberCounter(conversationId: String, counter: Int)
    fun getAllFileNumberCounters(): Map<String, Int>
}
