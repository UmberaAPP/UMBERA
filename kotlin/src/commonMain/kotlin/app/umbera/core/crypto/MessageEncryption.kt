package app.umbera.core.crypto

// Message encryption pipeline: sealed sender, hybrid key agreement, ratchet.

import app.umbera.core.util.WireJson
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

import app.umbera.core.util.B64
import app.umbera.core.util.Log
import app.umbera.core.util.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

class MessageEncryption(
    private val secureKeyStorage: LocalKeyStore,
    private val ratchetStorage: DoubleRatchet.RatchetStorage
) {
    companion object {
        private const val TAG = "MessageEncryption"
        const val VERSION_LEGACY = "v1"
        const val VERSION_HYBRID_PQ = "v2"
    }

    private val json = WireJson.json

    private val doubleRatchet = DoubleRatchet(ratchetStorage)

    private val ratchetOpLock = app.umbera.core.util.SyncLock()

    private fun ensureRatchetSessionLocked(peerId: String, peerX25519Pub: ByteArray): Boolean {
        if (ratchetStorage.getState(peerId) != null) return true
        val myId = secureKeyStorage.getUserId() ?: return false
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return false
        val myPub = secureKeyStorage.getX25519PublicKey() ?: X25519.getPublicKey(myPriv)
        val root = X25519.computeSharedSecret(myPriv, peerX25519Pub)
        if (myId < peerId) {
            doubleRatchet.initializeSender(peerId, root, peerX25519Pub)
        } else {
            doubleRatchet.initializeReceiver(peerId, root, X25519.KeyPair(myPriv, myPub))
        }
        return true
    }

    fun encryptMessageRatchet(
        content: String,
        recipientId: String,
        recipientX25519PublicKey: ByteArray,
        type: String = "text",
        fileId: String? = null,
        fileName: String? = null,
        fileSize: Long? = null,
        mimeType: String? = null,
        replyId: String? = null,
        replyContent: String? = null,
        replySenderName: String? = null
    ): EncryptedPayload? {
        return ratchetOpLock.withLock {
            encryptMessageRatchetLocked(
                content, recipientId, recipientX25519PublicKey, type, fileId, fileName,
                fileSize, mimeType, replyId, replyContent, replySenderName
            )
        }
    }

    private fun encryptMessageRatchetLocked(
        content: String,
        recipientId: String,
        recipientX25519PublicKey: ByteArray,
        type: String,
        fileId: String?,
        fileName: String?,
        fileSize: Long?,
        mimeType: String?,
        replyId: String?,
        replyContent: String?,
        replySenderName: String?
    ): EncryptedPayload? {
        if (!ensureRatchetSessionLocked(recipientId, recipientX25519PublicKey)) return null
        val state = ratchetStorage.getState(recipientId) ?: return null
        if (state.sendingChainKey == null) return null
        val nonce = secureRandomBytes(16)
        val payload = MessagePayload(
            type = type,
            content = addPadding(content),
            timestamp = Clock.System.now().toEpochMilliseconds(),
            nonce = nonce.toHex(),
            fileId = fileId, fileName = fileName, fileSize = fileSize, mimeType = mimeType,
            replyId = replyId, replyContent = replyContent, replySenderName = replySenderName
        )
        val enc = doubleRatchet.encrypt(recipientId, json.encodeToString(payload).encodeToByteArray())
        return EncryptedPayload(
            encryptedData = enc.ciphertext.ciphertext.toHex(),
            iv = enc.ciphertext.iv.toHex(),
            signature = "",
            version = "ratchet-v3",
            ratchetHeader = RatchetHeader(
                dh = enc.header.dhPublicKey.toHex(),
                pn = enc.header.previousChainLength,
                n = enc.header.messageNumber
            )
        )
    }

    fun resetRatchetSession(peerId: String) {
        ratchetOpLock.withLock { runCatching { ratchetStorage.deleteState(peerId) } }
    }

    fun hasRatchetSession(peerId: String): Boolean = ratchetStorage.getState(peerId) != null

    fun decryptMessageRatchet(payload: EncryptedPayload, peerId: String, peerX25519PublicKey: ByteArray): MessagePayload =
        ratchetOpLock.withLock { decryptMessageRatchetLocked(payload, peerId, peerX25519PublicKey) }

    private fun decryptMessageRatchetLocked(payload: EncryptedPayload, peerId: String, peerX25519PublicKey: ByteArray): MessagePayload {
        val priorState = ratchetStorage.getState(peerId)
        ensureRatchetSessionLocked(peerId, peerX25519PublicKey)
        val h = payload.ratchetHeader ?: throw IllegalStateException("ratchet-v3 payload missing header")
        val ctHex = payload.encryptedData.ifEmpty { payload.ciphertext }
        val enc = DoubleRatchet.EncryptedMessage(
            header = DoubleRatchet.MessageHeader(
                dhPublicKey = h.dh.hexToBytes(),
                previousChainLength = h.pn,
                messageNumber = h.n
            ),
            ciphertext = AesGcm.EncryptedData(ctHex.hexToBytes(), payload.iv.hexToBytes())
        )
        val plaintext = try {
            doubleRatchet.decrypt(peerId, enc)
        } catch (e: Exception) {
            priorState ?: throw e
            adoptRestartedSession(peerId, peerX25519PublicKey, priorState, enc) ?: throw e
        }
        val mp = json.decodeFromString<MessagePayload>(plaintext.decodeToString())
        return mp.copy(content = removePadding(mp.content))
    }

    private fun adoptRestartedSession(
        peerId: String,
        peerX25519Pub: ByteArray,
        staleState: DoubleRatchet.RatchetState,
        enc: DoubleRatchet.EncryptedMessage
    ): ByteArray? {
        val myId = secureKeyStorage.getUserId() ?: return null

        val peerIsInitiator = peerId < myId
        if (!DoubleRatchet.isPossibleSessionRestart(staleState, enc.header, peerIsInitiator)) return null
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return null
        val myPub = secureKeyStorage.getX25519PublicKey() ?: X25519.getPublicKey(myPriv)
        val scratch = object : DoubleRatchet.RatchetStorage {
            var st: DoubleRatchet.RatchetState? = null
            override fun saveState(sessionId: String, state: DoubleRatchet.RatchetState) { st = state }
            override fun getState(sessionId: String): DoubleRatchet.RatchetState? = st
            override fun deleteState(sessionId: String) { st = null }
        }
        val trial = DoubleRatchet(scratch)
        val root = X25519.computeSharedSecret(myPriv, peerX25519Pub)
        trial.initializeReceiver(peerId, root, X25519.KeyPair(myPriv, myPub))
        val plaintext = runCatching { trial.decrypt(peerId, enc) }.getOrNull() ?: return null
        val fresh = scratch.st ?: return null
        ratchetStorage.saveState(peerId, fresh)
        runCatching { Log.w(TAG, ">>> ratchet: peer ${peerId.take(8)} restarted its v3 session (re-login/reset) — adopted the new session instead of dropping") }
        return plaintext
    }

    private val rendezvousSalt = Labels.RENDEZVOUS

    private fun rendezvousId(peerX25519Pub: ByteArray, fromId: String, toId: String): String? {
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return null
        val shared = X25519.computeSharedSecret(myPriv, peerX25519Pub)
        val info = "rdv|$fromId|$toId".encodeToByteArray()
        return AesGcm.deriveKeyHKDF(shared, rendezvousSalt, info).toHex()
    }

    fun rendezvousSendId(peerId: String, peerX25519Pub: ByteArray): String? {
        val myId = secureKeyStorage.getUserId() ?: return null
        return rendezvousId(peerX25519Pub, myId, peerId)
    }

    fun rendezvousRecvId(peerId: String, peerX25519Pub: ByteArray): String? {
        val myId = secureKeyStorage.getUserId() ?: return null
        return rendezvousId(peerX25519Pub, peerId, myId)
    }

    fun rendezvousSelfBackupId(peerId: String): String? {
        val myId = secureKeyStorage.getUserId() ?: return null
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return null
        val myPub = secureKeyStorage.getX25519PublicKey() ?: X25519.getPublicKey(myPriv)
        val shared = X25519.computeSharedSecret(myPriv, myPub)
        val info = "rdv-backup|$myId|$peerId".encodeToByteArray()
        return AesGcm.deriveKeyHKDF(shared, rendezvousSalt, info).toHex()
    }

    fun selfInboxId(userId: String, x25519Pub: ByteArray): String {
        return RustCore.sha256(
            Labels.GROUP_INBOX + x25519Pub + userId.encodeToByteArray()
        ).toHex()
    }

    fun inboxVerifyPublicKeyHex(): String? =
        InboxReadCapability.verifyPublicKeyHex(secureKeyStorage.getX25519PrivateKey())

    fun inboxReadProof(rid: String, since: Long, nowSec: Long): String? =
        InboxReadCapability.proof(secureKeyStorage.getX25519PrivateKey(), rid, since, nowSec)

    private val rendezvousEpochPeriodSec = 7L * 24 * 3600

    fun rendezvousEpoch(nowSec: Long): Long = nowSec / rendezvousEpochPeriodSec

    private fun rendezvousIdEpoch(peerX25519Pub: ByteArray, fromId: String, toId: String, epoch: Long): String? {
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return null
        val shared = X25519.computeSharedSecret(myPriv, peerX25519Pub)
        val info = "rdv|e$epoch|$fromId|$toId".encodeToByteArray()
        return AesGcm.deriveKeyHKDF(shared, rendezvousSalt, info).toHex()
    }

    fun rendezvousSendIdEpoch(peerId: String, peerX25519Pub: ByteArray, nowSec: Long): String? {
        val myId = secureKeyStorage.getUserId() ?: return null
        return rendezvousIdEpoch(peerX25519Pub, myId, peerId, rendezvousEpoch(nowSec))
    }

    fun rendezvousRecvIdsEpochs(peerId: String, peerX25519Pub: ByteArray, nowSec: Long): List<String> {
        val myId = secureKeyStorage.getUserId() ?: return emptyList()
        val e = rendezvousEpoch(nowSec)
        return listOfNotNull(
            rendezvousIdEpoch(peerX25519Pub, peerId, myId, e),
            rendezvousIdEpoch(peerX25519Pub, peerId, myId, e - 1)
        ).distinct()
    }

    @Serializable
    data class SealedSenderPackage(
        @SerialName("version") val version: String = "v1",
        @SerialName("ephemeralPublicKey") val ephemeralPublicKey: String,
        @SerialName("encryptedInner") val encryptedInner: String,
        @SerialName("authTag") val authTag: String,
        @SerialName("iv") val iv: String,

        @SerialName("kyberCiphertext") val kyberCiphertext: String? = null
    )

    @Serializable
    data class InnerPackage(
        @SerialName("senderId") val senderId: String,
        @SerialName("senderPublicKey") val senderPublicKey: String,
        @SerialName("senderX25519PublicKey") val senderX25519PublicKey: String,
        @SerialName("ratchetMessage") val ratchetMessage: EncryptedPayload,
        @SerialName("timestamp") val timestamp: Long,
        @SerialName("sealedVersion") val sealedVersion: String = "v1",

        @SerialName("senderDisplayName") val senderDisplayName: String? = null,

        @SerialName("senderKyberPublicKey") val senderKyberPublicKey: String? = null,
        @SerialName("senderDilithiumPublicKey") val senderDilithiumPublicKey: String? = null
    )

    @Serializable
    data class EncryptedPayload(
        @SerialName("encryptedData") val encryptedData: String,
        @SerialName("iv") val iv: String,
        @SerialName("signature") val signature: String,

        @SerialName("ciphertext") val ciphertext: String = "",
        @SerialName("messageCounter") val messageCounter: Int = 0,

        @SerialName("version") val version: String? = null,
        @SerialName("ratchetHeader") val ratchetHeader: RatchetHeader? = null,
        @SerialName("eph") val ephemeralPublicKey: String? = null,
        @SerialName("ct") val ct: String? = null,
        @SerialName("v") val v: Int? = null,

        @SerialName("dilithiumSignature") val dilithiumSignature: String? = null,
        @SerialName("kyberCiphertext") val kyberCiphertext: String? = null
    )

    @Serializable

    data class RatchetHeader(
        @SerialName("dh") val dh: String,
        @SerialName("pn") val pn: Int,
        @SerialName("n") val n: Int
    )

    @Serializable

    data class MessagePayload(
        @SerialName("v") val version: Int = 2,
        @SerialName("t") val type: String,
        @SerialName("c") val content: String,
        @SerialName("ts") val timestamp: Long,
        @SerialName("n") val nonce: String,
        @SerialName("fid") val fileId: String? = null,
        @SerialName("fn") val fileName: String? = null,
        @SerialName("fs") val fileSize: Long? = null,
        @SerialName("mt") val mimeType: String? = null,
        @SerialName("rid") val replyId: String? = null,
        @SerialName("rc") val replyContent: String? = null,
        @SerialName("rn") val replySenderName: String? = null
    )

    data class EncryptionResult(
        val encryptedData: String,
        val iv: String,
        val signature: String,
        val ephemeralPublicKey: String
    )

    data class SealedSenderResult(
        val senderId: String,
        val senderSecp256k1PublicKey: String,
        val senderX25519PublicKey: String,
        val encryptedPayload: EncryptedPayload,
        val senderDisplayName: String? = null,

        val senderDilithiumPublicKey: String? = null
    )

    fun encryptMessage(
        content: String,
        recipientId: String,
        recipientPublicKey: ByteArray,
        recipientX25519PublicKey: ByteArray,
        type: String = "text",
        fileId: String? = null,
        fileName: String? = null,
        fileSize: Long? = null,
        mimeType: String? = null,
        sequenceNumber: Int,
        replyId: String? = null,
        replyContent: String? = null,
        replySenderName: String? = null
    ): EncryptionResult {
        val senderSecp256k1PrivateKey = secureKeyStorage.getSecp256k1PrivateKey()
            ?: throw IllegalStateException("Sender secp256k1 private key not found")

        val payload = MessagePayload(
            type = type,
            content = addPadding(content),
            timestamp = Clock.System.now().toEpochMilliseconds(),
            nonce = generateNonce(),
            fileId = fileId,
            fileName = fileName,
            fileSize = fileSize,
            mimeType = mimeType,
            replyId = replyId,
            replyContent = replyContent,
            replySenderName = replySenderName
        )
        val payloadJson = json.encodeToString(payload)

        val ephemeralKeyPair = X25519.generateKeyPair()
        val sharedSecret = X25519.computeSharedSecret(
            ephemeralKeyPair.privateKey,
            recipientX25519PublicKey
        )
        val aesKey = AesGcm.deriveKey(sharedSecret)

        val encrypted = AesGcm.encrypt(payloadJson.encodeToByteArray(), aesKey)

        val signature = Secp256k1.sign(encrypted.ciphertext, senderSecp256k1PrivateKey)

        return EncryptionResult(
            encryptedData = encrypted.ciphertext.toHex(),
            iv = encrypted.iv.toHex(),
            signature = signature.toHexString(),
            ephemeralPublicKey = ephemeralKeyPair.publicKey.toHex()
        )
    }

    fun encryptMessageAsPayload(
        content: String,
        recipientId: String,
        recipientPublicKey: ByteArray,
        recipientX25519PublicKey: ByteArray,
        type: String = "text",
        fileId: String? = null,
        fileName: String? = null,
        fileSize: Long? = null,
        mimeType: String? = null,
        sequenceNumber: Int,
        replyId: String? = null,
        replyContent: String? = null,
        replySenderName: String? = null
    ): EncryptedPayload {
        val result = encryptMessage(
            content, recipientId, recipientPublicKey, recipientX25519PublicKey,
            type, fileId, fileName, fileSize, mimeType, sequenceNumber,
            replyId, replyContent, replySenderName
        )

        return EncryptedPayload(
            encryptedData = result.encryptedData,
            iv = result.iv,
            signature = result.signature,
            ciphertext = result.encryptedData,
            messageCounter = sequenceNumber,
            version = null,
            ratchetHeader = null,

            ephemeralPublicKey = result.ephemeralPublicKey,
            ct = null,
            v = null
        )
    }

    fun encryptMessageHybridPQ(
        content: String,
        recipientId: String,
        recipientHybridPublicKey: HybridKeyExchange.HybridPublicKey,
        type: String = "text",
        fileId: String? = null,
        fileName: String? = null,
        fileSize: Long? = null,
        mimeType: String? = null,
        sequenceNumber: Int,
        replyId: String? = null,
        replyContent: String? = null,
        replySenderName: String? = null
    ): EncryptedPayload {
        Log.d(TAG, "Encrypting message with Hybrid PQ scheme (v2)")

        val senderHybridExchangeKeyPair = secureKeyStorage.getHybridExchangeKeyPair()
            ?: throw IllegalStateException("Sender hybrid exchange key pair not found")
        val senderHybridSignatureKeyPair = secureKeyStorage.getHybridSignatureKeyPair()
            ?: throw IllegalStateException("Sender hybrid signature key pair not found")

        val payload = MessagePayload(
            type = type,
            content = addPadding(content),
            timestamp = Clock.System.now().toEpochMilliseconds(),
            nonce = generateNonce(),
            fileId = fileId,
            fileName = fileName,
            fileSize = fileSize,
            mimeType = mimeType,
            replyId = replyId,
            replyContent = replyContent,
            replySenderName = replySenderName
        )
        val payloadJson = json.encodeToString(payload)

        val encapsulation = HybridKeyExchange.encapsulate(
            senderHybridExchangeKeyPair.privateKey,
            recipientHybridPublicKey
        )

        val aesKey = encapsulation.sharedSecret.getAesKey()

        val encrypted = AesGcm.encrypt(payloadJson.encodeToByteArray(), aesKey)

        val hybridSignature = HybridSignature.sign(encrypted.ciphertext, senderHybridSignatureKeyPair.privateKey)

        Log.d(TAG, "Message encrypted with hybrid PQ scheme. Signature size: ${hybridSignature.totalSize()} bytes")

        return EncryptedPayload(
            encryptedData = encrypted.ciphertext.toHex(),
            iv = encrypted.iv.toHex(),
            signature = hybridSignature.secp256k1Hex(),
            ciphertext = encrypted.ciphertext.toHex(),
            messageCounter = sequenceNumber,
            version = "hybrid-pq-v2",
            ratchetHeader = null,
            ephemeralPublicKey = null,
            ct = null,
            v = 2,

            dilithiumSignature = hybridSignature.dilithiumHex(),
            kyberCiphertext = encapsulation.kyberCiphertextHex()
        )
    }

    fun decryptMessageHybridPQ(
        encryptedPayload: EncryptedPayload,
        senderHybridPublicKey: HybridSignature.HybridPublicKey,
        senderHybridExchangePublicKey: HybridKeyExchange.HybridPublicKey
    ): MessagePayload {
        Log.d(TAG, "Decrypting message with Hybrid PQ scheme (v2)")

        val recipientHybridExchangeKeyPair = secureKeyStorage.getHybridExchangeKeyPair()
            ?: throw IllegalStateException("Recipient hybrid exchange key pair not found")

        val ciphertextHex = encryptedPayload.encryptedData.ifEmpty {
            encryptedPayload.ciphertext.ifEmpty { encryptedPayload.ct ?: "" }
        }
        val ciphertext = ciphertextHex.hexToBytes()
        val iv = encryptedPayload.iv.hexToBytes()

        val kyberCiphertextHex = encryptedPayload.kyberCiphertext
            ?: throw IllegalStateException("Kyber ciphertext not found in hybrid PQ message")
        val kyberCiphertext = kyberCiphertextHex.hexToBytes()

        val classicalSignatureHex = encryptedPayload.signature
        val dilithiumSignatureHex = encryptedPayload.dilithiumSignature
            ?: throw IllegalStateException("Dilithium signature not found in hybrid PQ message")

        val hybridSignature = HybridSignature.HybridSig.fromComponents(
            secp256k1Hex = classicalSignatureHex,
            dilithiumHex = dilithiumSignatureHex
        )

        if (!HybridSignature.verify(ciphertext, hybridSignature, senderHybridPublicKey)) {
            throw SecurityException("Invalid hybrid PQ signature - verification failed")
        }

        Log.d(TAG, "Hybrid signature verified successfully")

        val sharedSecret = HybridKeyExchange.decapsulate(
            recipientHybridExchangeKeyPair.privateKey,
            senderHybridExchangePublicKey,
            kyberCiphertext
        )

        val aesKey = sharedSecret.getAesKey()

        val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
        val decryptedBytes = AesGcm.decrypt(encryptedData, aesKey)
        val payloadJson = decryptedBytes.decodeToString()

        val payload = json.decodeFromString<MessagePayload>(payloadJson)
        return payload.copy(content = removePadding(payload.content))
    }

    fun shouldUseHybridPQ(): Boolean {
        return secureKeyStorage.isHybridCryptoEnabled()
    }

    fun encryptMessageAuto(
        content: String,
        recipientId: String,
        recipientPublicKey: ByteArray,
        recipientX25519PublicKey: ByteArray,
        recipientKyberPublicKey: ByteArray? = null,
        type: String = "text",
        fileId: String? = null,
        fileName: String? = null,
        fileSize: Long? = null,
        mimeType: String? = null,
        sequenceNumber: Int,
        replyId: String? = null,
        replyContent: String? = null,
        replySenderName: String? = null,
        recipientSupportsRatchet: Boolean = false
    ): EncryptedPayload {
        if (recipientSupportsRatchet && secureKeyStorage.isRatchetEnabled()) {
            encryptMessageRatchet(
                content, recipientId, recipientX25519PublicKey, type,
                fileId, fileName, fileSize, mimeType, replyId, replyContent, replySenderName
            )?.let { return it }
        }

        if (shouldUseHybridPQ() && recipientKyberPublicKey != null) {
            try {
                val recipientHybridPublicKey = HybridKeyExchange.HybridPublicKey(
                    x25519 = recipientX25519PublicKey,
                    kyber = recipientKyberPublicKey
                )
                return encryptMessageHybridPQ(
                    content, recipientId, recipientHybridPublicKey,
                    type, fileId, fileName, fileSize, mimeType, sequenceNumber,
                    replyId, replyContent, replySenderName
                )
            } catch (e: Exception) {
                Log.e(TAG, "Hybrid PQ encryption failed for a PQ-capable recipient — refusing to downgrade", e)
                throw e
            }
        }

        return encryptMessageAsPayload(
            content, recipientId, recipientPublicKey, recipientX25519PublicKey,
            type, fileId, fileName, fileSize, mimeType, sequenceNumber,
            replyId, replyContent, replySenderName
        )
    }

    fun decryptMessage(
        encryptedPayload: EncryptedPayload,
        senderId: String,
        senderPublicKey: ByteArray
    ): MessagePayload {
        val recipientX25519PrivateKey = secureKeyStorage.getX25519PrivateKey()
            ?: throw IllegalStateException("Recipient X25519 private key not found")

        val ciphertextHex = encryptedPayload.encryptedData.ifEmpty {
            encryptedPayload.ciphertext.ifEmpty { encryptedPayload.ct ?: "" }
        }
        val ivHex = encryptedPayload.iv
        val ciphertext = ciphertextHex.hexToBytes()
        val iv = ivHex.hexToBytes()

        val isRatchetFormat = encryptedPayload.version == "ratchet-v1" && encryptedPayload.ratchetHeader != null

        if (isRatchetFormat) {
            val header = encryptedPayload.ratchetHeader!!
            val headerJson = json.encodeToString(header)
            val dataToVerify = (headerJson + ciphertextHex + ivHex).encodeToByteArray()
            val signature = Secp256k1.Signature.fromHexString(encryptedPayload.signature)
            if (!Secp256k1.verify(dataToVerify, signature, senderPublicKey)) {
                throw SecurityException("Invalid ratchet message signature")
            }

            val dhPublicKey = header.dh.decodeKeyAuto()
            val sharedSecret = X25519.computeSharedSecret(recipientX25519PrivateKey, dhPublicKey)
            val aesKey = AesGcm.deriveKey(sharedSecret)
            val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
            val decryptedBytes = AesGcm.decrypt(encryptedData, aesKey)
            val payloadJson = decryptedBytes.decodeToString()
            val payload = json.decodeFromString<MessagePayload>(payloadJson)
            return payload.copy(content = removePadding(payload.content))
        } else {
            val signature = Secp256k1.Signature.fromHexString(encryptedPayload.signature)
            if (!Secp256k1.verify(ciphertext, signature, senderPublicKey)) {
                throw SecurityException("Invalid legacy message signature")
            }

            val senderX25519PublicKeyStr = encryptedPayload.ephemeralPublicKey
                ?: throw IllegalStateException("No sender X25519 public key found in legacy message")
            val senderX25519PublicKey = senderX25519PublicKeyStr.decodeKeyAuto()
            val sharedSecret = X25519.computeSharedSecret(recipientX25519PrivateKey, senderX25519PublicKey)
            val aesKey = AesGcm.deriveKey(sharedSecret)
            val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
            val decryptedBytes = AesGcm.decrypt(encryptedData, aesKey)
            val payloadJson = decryptedBytes.decodeToString()
            val payload = json.decodeFromString<MessagePayload>(payloadJson)
            return payload.copy(content = removePadding(payload.content))
        }
    }

    fun decryptMessageFromSealedSender(sealedResult: SealedSenderResult): MessagePayload {
        val encryptedPayload = sealedResult.encryptedPayload

        if (encryptedPayload.version == "hybrid-pq-v2") {
            return decryptMessageFromSealedSenderHybridPQ(sealedResult)
        }

        if (encryptedPayload.version == "ratchet-v3") {
            return decryptMessageRatchet(
                encryptedPayload,
                sealedResult.senderId,
                sealedResult.senderX25519PublicKey.decodeKeyAuto()
            )
        }

        val recipientX25519PrivateKey = secureKeyStorage.getX25519PrivateKey()
            ?: throw IllegalStateException("Recipient X25519 private key not found")

        val senderSecp256k1PublicKey = sealedResult.senderSecp256k1PublicKey.hexToBytes()

        val senderX25519PublicKey = sealedResult.senderX25519PublicKey.decodeKeyAuto()

        val ciphertextHex = encryptedPayload.encryptedData.ifEmpty {
            encryptedPayload.ciphertext.ifEmpty { encryptedPayload.ct ?: "" }
        }
        val ivHex = encryptedPayload.iv
        val ciphertext = ciphertextHex.hexToBytes()
        val iv = ivHex.hexToBytes()

        val isRatchetFormat = encryptedPayload.version == "ratchet-v1" && encryptedPayload.ratchetHeader != null

        if (isRatchetFormat) {
            val header = encryptedPayload.ratchetHeader!!
            val headerJson = json.encodeToString(header)
            val dataToVerify = (headerJson + ciphertextHex + ivHex).encodeToByteArray()
            val signature = Secp256k1.Signature.fromHexString(encryptedPayload.signature)

            if (!Secp256k1.verify(dataToVerify, signature, senderSecp256k1PublicKey)) {
                throw SecurityException("Invalid ratchet message signature")
            }

            val dhPublicKey = header.dh.decodeKeyAuto()
            val sharedSecret = X25519.computeSharedSecret(recipientX25519PrivateKey, dhPublicKey)
            val aesKey = AesGcm.deriveKey(sharedSecret)

            val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
            val decryptedBytes = AesGcm.decrypt(encryptedData, aesKey)
            val payloadJson = decryptedBytes.decodeToString()
            val payload = json.decodeFromString<MessagePayload>(payloadJson)
            return payload.copy(content = removePadding(payload.content))
        } else {
            val signature = Secp256k1.Signature.fromHexString(encryptedPayload.signature)

            if (!Secp256k1.verify(ciphertext, signature, senderSecp256k1PublicKey)) {
                throw SecurityException("Invalid legacy message signature")
            }

            val dhPublicKey = encryptedPayload.ephemeralPublicKey
                ?.takeIf { it.isNotBlank() }?.decodeKeyAuto() ?: senderX25519PublicKey
            val sharedSecret = X25519.computeSharedSecret(recipientX25519PrivateKey, dhPublicKey)
            val aesKey = AesGcm.deriveKey(sharedSecret)

            val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
            val decryptedBytes = AesGcm.decrypt(encryptedData, aesKey)
            val payloadJson = decryptedBytes.decodeToString()
            val payload = json.decodeFromString<MessagePayload>(payloadJson)
            return payload.copy(content = removePadding(payload.content))
        }
    }

    private fun decryptMessageFromSealedSenderHybridPQ(sealedResult: SealedSenderResult): MessagePayload {
        Log.d(TAG, "Decrypting Hybrid PQ message from sealed sender")

        val encryptedPayload = sealedResult.encryptedPayload

        val recipientHybridExchangeKeyPair = secureKeyStorage.getHybridExchangeKeyPair()
            ?: throw IllegalStateException("Recipient hybrid exchange key pair not found for PQ decryption")

        val ciphertextHex = encryptedPayload.encryptedData.ifEmpty {
            encryptedPayload.ciphertext.ifEmpty { encryptedPayload.ct ?: "" }
        }
        val ciphertext = ciphertextHex.hexToBytes()
        val iv = encryptedPayload.iv.hexToBytes()

        val kyberCiphertextHex = encryptedPayload.kyberCiphertext
            ?: throw IllegalStateException("Kyber ciphertext not found in hybrid PQ sealed message")
        val kyberCiphertext = kyberCiphertextHex.hexToBytes()

        val senderSecp256k1PublicKey = sealedResult.senderSecp256k1PublicKey.hexToBytes()

        val dilithiumSignatureHex = encryptedPayload.dilithiumSignature
            ?: throw IllegalStateException("Dilithium signature not found in hybrid PQ message")

        val classicalSignature = Secp256k1.Signature.fromHexString(encryptedPayload.signature)
        if (!Secp256k1.verify(ciphertext, classicalSignature, senderSecp256k1PublicKey)) {
            throw SecurityException("Invalid classical (Secp256k1) signature in hybrid PQ message")
        }

        val senderDilithiumPubHex = sealedResult.senderDilithiumPublicKey
        if (!senderDilithiumPubHex.isNullOrBlank()) {
            val dPub = Dilithium3.DilithiumPublicKey.fromHex(senderDilithiumPubHex)
            val dSig = Dilithium3.DilithiumSignature.fromHex(dilithiumSignatureHex)
            if (!Dilithium3.verify(ciphertext, dSig, dPub)) {
                throw SecurityException("Invalid post-quantum (Dilithium3) signature in hybrid PQ message")
            }
            Log.d(TAG, "Both classical + post-quantum (Dilithium3) signatures verified")
        } else {
            Log.d(TAG, "Classical signature verified; no sender Dilithium key present (classical-only)")
        }

        val senderX25519PublicKey = sealedResult.senderX25519PublicKey.decodeKeyAuto()

        val x25519SharedSecret = X25519.computeSharedSecret(
            recipientHybridExchangeKeyPair.privateKey.x25519,
            senderX25519PublicKey
        )

        val kyberSharedSecret = Kyber1024.decapsulate(
            kyberCiphertext,
            recipientHybridExchangeKeyPair.privateKey.kyber
        )

        val combinedSecret = combineHybridSecrets(x25519SharedSecret, kyberSharedSecret)
        val aesKey = combinedSecret.copyOfRange(0, 32)

        val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
        val decryptedBytes = AesGcm.decrypt(encryptedData, aesKey)
        val payloadJson = decryptedBytes.decodeToString()

        val payload = json.decodeFromString<MessagePayload>(payloadJson)
        Log.d(TAG, "Hybrid PQ message decrypted successfully")
        return payload.copy(content = removePadding(payload.content))
    }

    private fun combineHybridSecrets(x25519Secret: ByteArray, kyberSecret: ByteArray): ByteArray {
        val inputKeyMaterial = x25519Secret + kyberSecret

        return RustCore.hkdfSha256(
            inputKeyMaterial, Labels.HYBRID, "key-derivation".encodeToByteArray(), 64u
        )
    }

    fun decryptMessageRaw(
        encryptedData: String,
        iv: String,
        signature: String,
        ephemeralPublicKey: String,
        senderPublicKey: ByteArray
    ): MessagePayload {
        val recipientX25519PrivateKey = secureKeyStorage.getX25519PrivateKey()
            ?: throw IllegalStateException("Recipient X25519 private key not found")

        val ciphertext = encryptedData.hexToBytes()
        val ivBytes = iv.hexToBytes()
        val ephPubKey = ephemeralPublicKey.hexToBytes()

        val sig = Secp256k1.Signature.fromHexString(signature)
        if (!Secp256k1.verify(ciphertext, sig, senderPublicKey)) {
            throw SecurityException("Invalid message signature")
        }

        val sharedSecret = X25519.computeSharedSecret(recipientX25519PrivateKey, ephPubKey)
        val aesKey = AesGcm.deriveKey(sharedSecret)

        val encrypted = AesGcm.EncryptedData(ciphertext, ivBytes)
        val decryptedBytes = AesGcm.decrypt(encrypted, aesKey)
        val payloadJson = decryptedBytes.decodeToString()

        val payload = json.decodeFromString<MessagePayload>(payloadJson)
        return payload.copy(content = removePadding(payload.content))
    }

    fun createSealedSender(
        encryptedPayload: EncryptedPayload,
        senderId: String,
        recipientX25519PublicKey: ByteArray
    ): SealedSenderPackage {
        val senderSecp256k1PublicKey = secureKeyStorage.getSecp256k1PublicKey()
            ?: throw IllegalStateException("Sender secp256k1 public key not found")
        val senderX25519PublicKey = secureKeyStorage.getX25519PublicKey()
            ?: throw IllegalStateException("Sender X25519 public key not found")

        val sealKeyPair = X25519.generateKeyPair()

        val senderDisplayName = secureKeyStorage.getNickname()

        val innerPackage = InnerPackage(
            senderId = senderId,
            senderPublicKey = senderSecp256k1PublicKey.toHex(),
            senderX25519PublicKey = senderX25519PublicKey.toBase64(),
            ratchetMessage = encryptedPayload,
            timestamp = Clock.System.now().toEpochMilliseconds(),
            sealedVersion = "v1",
            senderDisplayName = senderDisplayName
        )
        val innerJson = json.encodeToString(innerPackage)

        val sharedSecret = X25519.computeSharedSecret(sealKeyPair.privateKey, recipientX25519PublicKey)

        val aesKey = deriveKeyHKDF(sharedSecret, "sealed-sender-salt-v1", "sealed-sender-v1")

        val iv = secureRandomBytes(12)

        val encryptedWithTag = AesGcm.encryptWithTag(innerJson.encodeToByteArray(), aesKey, iv)

        return SealedSenderPackage(
            version = "v1",
            ephemeralPublicKey = sealKeyPair.publicKey.toHex(),
            encryptedInner = encryptedWithTag.ciphertext.toHex(),
            authTag = encryptedWithTag.authTag.toHex(),
            iv = iv.toHex()
        )
    }

    fun createSealedSenderHybridPQ(
        encryptedPayload: EncryptedPayload,
        senderId: String,
        recipientHybridPublicKey: HybridKeyExchange.HybridPublicKey
    ): SealedSenderPackage {
        Log.d(TAG, "Creating Hybrid PQ sealed sender package (v2)")

        val senderHybridExchangeKeyPair = secureKeyStorage.getHybridExchangeKeyPair()
            ?: throw IllegalStateException("Sender hybrid exchange key pair not found")
        val senderHybridSignatureKeyPair = secureKeyStorage.getHybridSignatureKeyPair()
            ?: throw IllegalStateException("Sender hybrid signature key pair not found")

        val ephemeralKeyPair = X25519.generateKeyPair()

        val innerPackage = InnerPackage(
            senderId = senderId,
            senderPublicKey = senderHybridSignatureKeyPair.publicKey.secp256k1Hex(),
            senderX25519PublicKey = senderHybridExchangeKeyPair.publicKey.x25519.toBase64(),
            ratchetMessage = encryptedPayload,
            timestamp = Clock.System.now().toEpochMilliseconds(),
            sealedVersion = VERSION_HYBRID_PQ,

            senderKyberPublicKey = senderHybridExchangeKeyPair.publicKey.kyberHex(),
            senderDilithiumPublicKey = senderHybridSignatureKeyPair.publicKey.dilithiumHex()
        )
        val innerJson = json.encodeToString(innerPackage)

        val x25519SharedSecret = X25519.computeSharedSecret(
            ephemeralKeyPair.privateKey,
            recipientHybridPublicKey.x25519
        )

        val kyberEncapsulation = Kyber1024.encapsulate(recipientHybridPublicKey.kyber)

        val combinedSecret = combineHybridSecrets(x25519SharedSecret, kyberEncapsulation.sharedSecret)
        val aesKey = combinedSecret.copyOfRange(0, 32)

        val iv = secureRandomBytes(12)

        val encryptedWithTag = AesGcm.encryptWithTag(innerJson.encodeToByteArray(), aesKey, iv)

        Log.d(TAG, "Created v2 sealed sender with Kyber ciphertext: ${kyberEncapsulation.ciphertext.size} bytes")

        return SealedSenderPackage(
            version = VERSION_HYBRID_PQ,
            ephemeralPublicKey = ephemeralKeyPair.publicKey.toHex(),
            encryptedInner = encryptedWithTag.ciphertext.toHex(),
            authTag = encryptedWithTag.authTag.toHex(),
            iv = iv.toHex(),
            kyberCiphertext = kyberEncapsulation.ciphertext.toHex()
        )
    }

    fun createSealedSenderAuto(
        encryptedPayload: EncryptedPayload,
        senderId: String,
        recipientX25519PublicKey: ByteArray,
        recipientKyberPublicKey: ByteArray? = null
    ): SealedSenderPackage {
        if (shouldUseHybridPQ() && recipientKyberPublicKey != null) {
            try {
                val recipientHybridPublicKey = HybridKeyExchange.HybridPublicKey(
                    x25519 = recipientX25519PublicKey,
                    kyber = recipientKyberPublicKey
                )
                return createSealedSenderHybridPQ(encryptedPayload, senderId, recipientHybridPublicKey)
            } catch (e: Exception) {
                Log.e(TAG, "v2 sealed sender failed for a PQ-capable recipient — refusing to downgrade", e)
                throw e
            }
        }

        return createSealedSender(encryptedPayload, senderId, recipientX25519PublicKey)
    }

    fun openSealedSender(sealedPackage: SealedSenderPackage): Pair<String, EncryptedPayload> {
        val result = openSealedSenderFull(sealedPackage)
        return Pair(result.senderId, result.encryptedPayload)
    }

    fun openSealedSenderFull(sealedPackage: SealedSenderPackage): SealedSenderResult {
        if (sealedPackage.version == VERSION_HYBRID_PQ && sealedPackage.kyberCiphertext != null) {
            return openSealedSenderFullHybridPQ(sealedPackage)
        }

        val recipientX25519PrivateKey = secureKeyStorage.getX25519PrivateKey()
            ?: throw IllegalStateException("Recipient X25519 private key not found")

        val ephemeralPublicKey = sealedPackage.ephemeralPublicKey.hexToBytes()
        val encryptedInner = sealedPackage.encryptedInner.hexToBytes()
        val authTag = sealedPackage.authTag.hexToBytes()
        val iv = sealedPackage.iv.hexToBytes()

        val sharedSecret = X25519.computeSharedSecret(recipientX25519PrivateKey, ephemeralPublicKey)

        val aesKey = deriveKeyHKDF(sharedSecret, "sealed-sender-salt-v1", "sealed-sender-v1")

        val decryptedBytes = AesGcm.decryptWithTag(encryptedInner, authTag, iv, aesKey)
        val innerJson = decryptedBytes.decodeToString()

        val innerPackage = json.decodeFromString<InnerPackage>(innerJson)

        return SealedSenderResult(
            senderId = innerPackage.senderId,
            senderSecp256k1PublicKey = innerPackage.senderPublicKey,
            senderX25519PublicKey = innerPackage.senderX25519PublicKey,
            encryptedPayload = innerPackage.ratchetMessage,
            senderDisplayName = innerPackage.senderDisplayName,
            senderDilithiumPublicKey = innerPackage.senderDilithiumPublicKey
        )
    }

    private fun openSealedSenderFullHybridPQ(sealedPackage: SealedSenderPackage): SealedSenderResult {
        Log.d(TAG, "Opening Hybrid PQ sealed sender package (v2)")

        val recipientHybridExchangeKeyPair = secureKeyStorage.getHybridExchangeKeyPair()
            ?: throw IllegalStateException("Recipient hybrid exchange key pair not found for v2 sealed sender")

        val ephemeralPublicKey = sealedPackage.ephemeralPublicKey.hexToBytes()
        val encryptedInner = sealedPackage.encryptedInner.hexToBytes()
        val authTag = sealedPackage.authTag.hexToBytes()
        val iv = sealedPackage.iv.hexToBytes()
        val kyberCiphertext = sealedPackage.kyberCiphertext!!.hexToBytes()

        val x25519SharedSecret = X25519.computeSharedSecret(
            recipientHybridExchangeKeyPair.privateKey.x25519,
            ephemeralPublicKey
        )

        val kyberSharedSecret = Kyber1024.decapsulate(
            kyberCiphertext,
            recipientHybridExchangeKeyPair.privateKey.kyber
        )

        val combinedSecret = combineHybridSecrets(x25519SharedSecret, kyberSharedSecret)
        val aesKey = combinedSecret.copyOfRange(0, 32)

        val decryptedBytes = AesGcm.decryptWithTag(encryptedInner, authTag, iv, aesKey)
        val innerJson = decryptedBytes.decodeToString()

        val innerPackage = json.decodeFromString<InnerPackage>(innerJson)

        Log.d(TAG, "Opened v2 sealed sender from: ${innerPackage.senderId.take(8)}...")

        return SealedSenderResult(
            senderId = innerPackage.senderId,
            senderSecp256k1PublicKey = innerPackage.senderPublicKey,
            senderX25519PublicKey = innerPackage.senderX25519PublicKey,
            encryptedPayload = innerPackage.ratchetMessage,
            senderDisplayName = innerPackage.senderDisplayName,
            senderDilithiumPublicKey = innerPackage.senderDilithiumPublicKey
        )
    }

    fun openSealedSenderHex(sealedPackage: SealedSenderPackage): Pair<String, EncryptedPayload> {
        return openSealedSender(sealedPackage)
    }

    fun openSealedSenderAuto(sealedPackage: SealedSenderPackage): Pair<String, EncryptedPayload> {
        val result = openSealedSenderAutoFull(sealedPackage)
        return Pair(result.senderId, result.encryptedPayload)
    }

    fun openSealedSenderAutoFull(sealedPackage: SealedSenderPackage): SealedSenderResult {
        return try {
            openSealedSenderFull(sealedPackage)
        } catch (e: Exception) {
            try {
                openSealedSenderBase64Full(sealedPackage)
            } catch (e2: Exception) {
                throw e
            }
        }
    }

    private fun openSealedSenderBase64(sealedPackage: SealedSenderPackage): Pair<String, EncryptedPayload> {
        val result = openSealedSenderBase64Full(sealedPackage)
        return Pair(result.senderId, result.encryptedPayload)
    }

    private fun openSealedSenderBase64Full(sealedPackage: SealedSenderPackage): SealedSenderResult {
        val recipientX25519PrivateKey = secureKeyStorage.getX25519PrivateKey()
            ?: throw IllegalStateException("Recipient X25519 private key not found")

        val ephemeralPublicKey = B64.decode(sealedPackage.ephemeralPublicKey)
        val encryptedInner = B64.decode(sealedPackage.encryptedInner)
        val authTag = B64.decode(sealedPackage.authTag)
        val iv = B64.decode(sealedPackage.iv)

        val sharedSecret = X25519.computeSharedSecret(recipientX25519PrivateKey, ephemeralPublicKey)
        val aesKey = deriveKeyHKDF(sharedSecret, "sealed-sender-salt-v1", "sealed-sender-v1")

        val decryptedBytes = AesGcm.decryptWithTag(encryptedInner, authTag, iv, aesKey)
        val innerJson = decryptedBytes.decodeToString()

        val innerPackage = json.decodeFromString<InnerPackage>(innerJson)
        return SealedSenderResult(
            senderId = innerPackage.senderId,
            senderSecp256k1PublicKey = innerPackage.senderPublicKey,
            senderX25519PublicKey = innerPackage.senderX25519PublicKey,
            encryptedPayload = innerPackage.ratchetMessage,
            senderDilithiumPublicKey = innerPackage.senderDilithiumPublicKey
        )
    }

    fun openLegacySealedSender(jsonString: String): Pair<String, EncryptedPayload>? {
        return try {
            val legacy = json.decodeFromString<LegacySealedPackage>(jsonString)
            if (legacy.ct != null && legacy.eph != null && legacy.iv != null) {
                openLegacyFormat(legacy)
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }

    @Serializable

    private data class LegacySealedPackage(
        @SerialName("v") val v: Int? = null,
        @SerialName("ct") val ct: String? = null,
        @SerialName("eph") val eph: String? = null,
        @SerialName("iv") val iv: String? = null
    )

    private fun openLegacyFormat(legacy: LegacySealedPackage): Pair<String, EncryptedPayload> {
        val recipientX25519PrivateKey = secureKeyStorage.getX25519PrivateKey()
            ?: throw IllegalStateException("Recipient X25519 private key not found")

        val ephemeralPublicKey = legacy.eph!!.hexToBytes()
        val ciphertext = legacy.ct!!.hexToBytes()
        val iv = legacy.iv!!.hexToBytes()

        val sharedSecret = X25519.computeSharedSecret(recipientX25519PrivateKey, ephemeralPublicKey)
        val aesKey = AesGcm.deriveKey(sharedSecret, "sealed-sender".encodeToByteArray())

        val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
        val decryptedBytes = AesGcm.decrypt(encryptedData, aesKey)
        val innerJson = decryptedBytes.decodeToString()

        val innerPackage = json.parseToJsonElement(innerJson).jsonObject
        val senderId = innerPackage["senderId"]!!.jsonPrimitive.content

        (innerPackage["payload"] as? JsonObject)?.let { payloadObj ->
            return Pair(senderId, json.decodeFromJsonElement<EncryptedPayload>(payloadObj))
        }

        (innerPackage["ratchetMessage"] as? JsonObject)?.let { ratchetObj ->
            return Pair(senderId, json.decodeFromJsonElement<EncryptedPayload>(ratchetObj))
        }

        throw IllegalStateException("Could not parse inner package")
    }

    private fun deriveKeyHKDF(sharedSecret: ByteArray, salt: String, info: String): ByteArray =

        RustCore.hkdfSha256(
            sharedSecret, salt.encodeToByteArray(), info.encodeToByteArray(), 32u
        )

    private fun addPadding(content: String): String {
        val paddingLength = 256 - (content.length % 256)
        val padding = (1..paddingLength).map { ' ' }.joinToString("")
        return content + padding
    }

    private fun removePadding(content: String): String {
        return content.trimEnd(' ')
    }

    private fun generateNonce(): String = secureRandomBytes(16).toHex()

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    private fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun ByteArray.toBase64(): String = B64.encode(this)
    private fun String.fromBase64(): ByteArray = B64.decode(this)

    private fun String.decodeKeyAuto(): ByteArray {
        return try {
            if (this.length == 64 && this.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                this.hexToBytes()
            } else {
                this.fromBase64()
            }
        } catch (e: Exception) {
            try {
                if (this.length == 64) {
                    this.hexToBytes()
                } else {
                    this.fromBase64()
                }
            } catch (e2: Exception) {
                throw IllegalArgumentException("Cannot decode key: not valid HEX or BASE64. Value: ${this.take(20)}...")
            }
        }
    }

    private fun String.isHexKey(): Boolean {
        return this.length == 64 && this.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
    }
}
