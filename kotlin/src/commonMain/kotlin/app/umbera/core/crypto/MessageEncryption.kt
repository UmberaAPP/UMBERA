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
import app.umbera.core.util.BuildFlags
import app.umbera.core.util.Log
import app.umbera.core.util.withLock
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

class MessageEncryption(
    private val secureKeyStorage: SecureKeyStoreCommon,
    persistentRatchetStorage: DoubleRatchet.RatchetStorage
) {
    private val ratchetStorage = DeferredRatchetStorage(persistentRatchetStorage)
    fun <T> deferringInbound(block: () -> T): Pair<T, Long?> = ratchetOpLock.withLock {
        ratchetStorage.deferNow = true
        try {
            val r = block()
            r to ratchetStorage.takeLastToken()
        } finally {
            ratchetStorage.deferNow = false
            ratchetStorage.takeLastToken()
        }
    }
    fun commitInboundRatchet(peerId: String, token: Long) = ratchetOpLock.withLock { ratchetStorage.commit(peerId, token) }
    companion object {
        private const val TAG = "MessageEncryption"
        const val VERSION_LEGACY = "v1"
        const val VERSION_HYBRID_PQ = "v2"

        const val WIRE_CAP_V4 = 1
        const val WIRE_CAP_PQ_RATCHET = 2
        const val WIRE_CAP_CHUNKS = 4
        const val WIRE_CAP_DEVICES = 8
        const val WIRE_CAP_GROUP_PQSIG = 16
        const val WIRE_CAP_SEAL_V3 = 32
        const val WIRE_CAP_SAFETY_V2 = 64

        const val WIRE_CAP_RID_EPOCH = 128
        const val WIRE_CAP_CALLSIG_V2 = 256
        const val WIRE_CAPS = WIRE_CAP_V4 or WIRE_CAP_CHUNKS or WIRE_CAP_DEVICES
        fun isRatchetVersion(v: String?): Boolean = v == "ratchet-v3" || v == "ratchet-v4"

        fun selfInboxIdOf(userId: String, x25519Pub: ByteArray): String =
            RustCore.sha256(Labels.GROUP_INBOX + x25519Pub + userId.encodeToByteArray())
                .joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    }
    private val json = WireJson.json
    private val doubleRatchet = DoubleRatchet(ratchetStorage, identityKem = { identityKemPair() })
    private fun identityKemPair(): Pair<ByteArray, ByteArray>? {
        val pub = secureKeyStorage.getKyberPublicKey() ?: return null
        val seed = secureKeyStorage.getKyberPrivateKey() ?: return null
        return pub to seed
    }
    fun wireCaps(): Int = localWireCaps()
    private fun localWireCaps(): Int =
        WIRE_CAPS or (if (identityKemPair() != null) WIRE_CAP_PQ_RATCHET else 0) or
            (if (SecurityRollout.sealV3Accept && identityKemPair() != null) WIRE_CAP_SEAL_V3 else 0) or
            (if (SafetyNumber.announcesV2(secureKeyStorage)) WIRE_CAP_SAFETY_V2 else 0) or
            (if (ridEpochsLocal() && identityKemPair() != null) WIRE_CAP_RID_EPOCH else 0) or
            (if (SecurityRollout.callSigV2 && SecurityRollout.sealV3Accept && identityKemPair() != null) WIRE_CAP_CALLSIG_V2 else 0)
    private fun ridEpochsLocal(): Boolean = SecurityRollout.ridRotation && SecurityRollout.ridV2 && SecurityRollout.sealV3Accept

    private val ratchetOpLock = app.umbera.core.util.SyncLock()

    private fun ensureRatchetSessionLocked(peerId: String, peerX25519Pub: ByteArray, peerKyberPub: ByteArray? = null): Boolean {
        val pqPeerKem = peerKyberPub?.takeIf {
            it.size == Kyber1024.PUBLIC_KEY_SIZE && identityKemPair() != null &&
                secureKeyStorage.peerHasWireCap(peerId, WIRE_CAP_PQ_RATCHET)
        }
        if (BuildFlags.DEBUG) Log.w(TAG, ">>> ratchet ensure peer=${peerId.take(8)} kyber=${peerKyberPub != null} myKem=${identityKemPair() != null} peerPqCap=${secureKeyStorage.peerHasWireCap(peerId, WIRE_CAP_PQ_RATCHET)} state=${ratchetStorage.getState(peerId) != null} pq=${doubleRatchet.isPqEnabled(peerId)}")
        if (ratchetStorage.getState(peerId) != null) {
            if (pqPeerKem != null && !doubleRatchet.isPqEnabled(peerId)) doubleRatchet.enablePq(peerId, pqPeerKem)
            if (!secureKeyStorage.peerHasWireCap(peerId, WIRE_CAP_PQ_RATCHET) && doubleRatchet.isPqEnabled(peerId)) {
                doubleRatchet.disablePq(peerId)
            }
            return true
        }
        val myId = secureKeyStorage.getUserId() ?: return false
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return false
        val myPub = secureKeyStorage.getX25519PublicKey() ?: X25519.getPublicKey(myPriv)
        val root = X25519.computeSharedSecret(myPriv, peerX25519Pub)
        if (myId < peerId) {
            doubleRatchet.initializeSender(peerId, root, peerX25519Pub, remoteIdentityKem = pqPeerKem)
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
        replySenderName: String? = null,
        recipientKyberPublicKey: ByteArray? = null,
        clientId: String? = null,
    ): EncryptedPayload? {
        return ratchetOpLock.withLock {
            encryptMessageRatchetLocked(
                content, recipientId, recipientX25519PublicKey, type, fileId, fileName,
                fileSize, mimeType, replyId, replyContent, replySenderName, recipientKyberPublicKey, clientId
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
        replySenderName: String?,
        recipientKyberPublicKey: ByteArray?,
        clientId: String?,
    ): EncryptedPayload? {
        if (!ensureRatchetSessionLocked(recipientId, recipientX25519PublicKey, recipientKyberPublicKey)) return null
        val state = ratchetStorage.getState(recipientId) ?: return null
        if (state.sendingChainKey == null) return null
        val nonce = secureRandomBytes(16)
        val payload = MessagePayload(
            caps = localWireCaps(),
            sealAck = sealAckFor(recipientId),
            ridDir = ridDirFor(recipientId), ridAck = ridAckFor(recipientId),
            type = type,
            content = addPadding(content),
            timestamp = Clock.System.now().toEpochMilliseconds(),
            nonce = nonce.toHex(),
            fileId = fileId, fileName = fileName, fileSize = fileSize, mimeType = mimeType,
            replyId = replyId, replyContent = replyContent, replySenderName = replySenderName,
            clientId = clientId,
        )
        val enc = doubleRatchet.encrypt(recipientId, json.encodeToString(payload).encodeToByteArray())
        if (BuildFlags.DEBUG) Log.w(TAG, ">>> ratchet send pq=${enc.header.isPq} kemCt=${enc.header.kemCt != null} kemPub=${enc.header.kemPub != null}")
        return EncryptedPayload(
            encryptedData = enc.ciphertext.ciphertext.toHex(),
            iv = enc.ciphertext.iv.toHex(),
            signature = "",
            version = if (enc.header.isPq) "ratchet-v4" else "ratchet-v3",
            ratchetHeader = RatchetHeader(
                dh = enc.header.dhPublicKey.toHex(),
                pn = enc.header.previousChainLength,
                n = enc.header.messageNumber,
                kp = enc.header.kemPub?.let { B64.encode(it) },
                kc = enc.header.kemCt?.let { B64.encode(it) },
                kt = enc.header.kemTarget?.let { B64.encode(it) },
            )
        )
    }
    fun resetRatchetSession(peerId: String) {
        ratchetOpLock.withLock { runCatching { ratchetStorage.deleteState(peerId) } }
    }
    fun sealedSenderKeyBytes(result: SealedSenderResult): Pair<ByteArray, ByteArray>? = runCatching {
        result.senderSecp256k1PublicKey.hexToBytes() to result.senderX25519PublicKey.decodeKeyAuto()
    }.getOrNull()
    fun hasRatchetSession(peerId: String): Boolean = ratchetStorage.getState(peerId) != null
    fun decryptMessageRatchet(payload: EncryptedPayload, peerId: String, peerX25519PublicKey: ByteArray): MessagePayload =
        ratchetOpLock.withLock { decryptMessageRatchetLocked(payload, peerId, peerX25519PublicKey) }
    private fun decryptMessageRatchetLocked(payload: EncryptedPayload, peerId: String, peerX25519PublicKey: ByteArray): MessagePayload {
        val priorState = ratchetStorage.getState(peerId)
        ensureRatchetSessionLocked(peerId, peerX25519PublicKey)
        val h = payload.ratchetHeader ?: throw IllegalStateException("ratchet payload missing header")
        val ctHex = payload.encryptedData.ifEmpty { payload.ciphertext }
        val enc = DoubleRatchet.EncryptedMessage(
            header = DoubleRatchet.MessageHeader(
                dhPublicKey = h.dh.hexToBytes(),
                previousChainLength = h.pn,
                messageNumber = h.n,
                kemPub = h.kp?.let { B64.decode(it) },
                kemCt = h.kc?.let { B64.decode(it) },
                kemTarget = h.kt?.let { B64.decode(it) },
            ),
            ciphertext = AesGcm.EncryptedData(ctHex.hexToBytes(), payload.iv.hexToBytes())
        )
        val plaintext = try {
            ratchetStorage.inboundDecrypt { doubleRatchet.decrypt(peerId, enc) }
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
        val trial = DoubleRatchet(scratch, identityKem = { identityKemPair() })
        val root = X25519.computeSharedSecret(myPriv, peerX25519Pub)
        trial.initializeReceiver(peerId, root, X25519.KeyPair(myPriv, myPub))
        val plaintext = runCatching { trial.decrypt(peerId, enc) }.getOrNull() ?: return null
        val fresh = scratch.st ?: return null
        ratchetStorage.inboundDecrypt { ratchetStorage.saveState(peerId, fresh) }
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
    fun selfInboxId(userId: String, x25519Pub: ByteArray): String = selfInboxIdOf(userId, x25519Pub)
    fun inboxVerifyPublicKeyHex(): String? =
        InboxReadCapability.verifyPublicKeyHex(secureKeyStorage.getX25519PrivateKey())
    fun inboxReadProof(rid: String, since: Long, nowSec: Long): String? {
        InboxReadCapabilityV2.ensureWired()
        val ever = InboxReadCapabilityV2.everBound()
        if (SecurityRollout.inboxReadV2 || ever) {
            if (InboxReadCapabilityV2.isBound(InboxReadCapabilityV2.epochOf(nowSec))) {
                val priv = secureKeyStorage.getX25519PrivateKey()
                if (priv != null) runCatching { return InboxReadCapabilityV2.proof(priv, rid, since, nowSec) }
            }
            if (ever) return null
        }
        return InboxReadCapability.proof(secureKeyStorage.getX25519PrivateKey(), rid, since, nowSec)
    }

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
        @SerialName("kyberCiphertext") val kyberCiphertext: String? = null,
        @SerialName("sh") val sealHint: String? = null
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
        @SerialName("n") val n: Int,
        @SerialName("kp") val kp: String? = null,
        @SerialName("kc") val kc: String? = null,
        @SerialName("kt") val kt: String? = null,
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
        @SerialName("rn") val replySenderName: String? = null,
        @SerialName("cap") val caps: Int? = null,
        @SerialName("cid") val clientId: String? = null,

        @SerialName("sa") val sealAck: String? = null,
        @SerialName("rd") val ridDir: String? = null,
        @SerialName("ra") val ridAck: String? = null,
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
        val senderDilithiumPublicKey: String? = null,
        internal val sealPairSecret: ByteArray? = null,
        internal val sealDirSecret: ByteArray? = null,
        val sealedVersion: String? = null,
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
        replySenderName: String? = null,
        clientId: String? = null,
    ): EncryptionResult {
        val senderSecp256k1PrivateKey = secureKeyStorage.getSecp256k1PrivateKey()
            ?: throw IllegalStateException("Sender secp256k1 private key not found")

        val payload = MessagePayload(
            caps = localWireCaps(),
            sealAck = sealAckFor(recipientId),
            ridDir = ridDirFor(recipientId), ridAck = ridAckFor(recipientId),
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
            replySenderName = replySenderName,
            clientId = clientId,
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
        replySenderName: String? = null,
        clientId: String? = null,
    ): EncryptedPayload {
        val result = encryptMessage(
            content, recipientId, recipientPublicKey, recipientX25519PublicKey,
            type, fileId, fileName, fileSize, mimeType, sequenceNumber,
            replyId, replyContent, replySenderName, clientId
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
        replySenderName: String? = null,
        clientId: String? = null,
        staticV3: Boolean = false,
    ): EncryptedPayload {
        Log.d(TAG, "Encrypting message with Hybrid PQ scheme (${if (staticV3) "v3" else "v2"})")
        val senderHybridExchangeKeyPair = secureKeyStorage.getHybridExchangeKeyPair()
            ?: throw IllegalStateException("Sender hybrid exchange key pair not found")
        val senderHybridSignatureKeyPair = secureKeyStorage.getHybridSignatureKeyPair()
            ?: throw IllegalStateException("Sender hybrid signature key pair not found")
        val payload = MessagePayload(
            caps = localWireCaps(),
            sealAck = sealAckFor(recipientId),
            ridDir = ridDirFor(recipientId), ridAck = ridAckFor(recipientId),
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
            replySenderName = replySenderName,
            clientId = clientId,
        )
        val payloadJson = json.encodeToString(payload)
        val encapsulation = if (staticV3) HybridKeyExchange.encapsulateV3(
            senderHybridExchangeKeyPair.privateKey, senderHybridExchangeKeyPair.publicKey.x25519, recipientHybridPublicKey
        ) else HybridKeyExchange.encapsulate(
            senderHybridExchangeKeyPair.privateKey,
            recipientHybridPublicKey
        )
        val aesKey = encapsulation.sharedSecret.getAesKey()
        val encrypted = AesGcm.encrypt(payloadJson.encodeToByteArray(), aesKey, if (staticV3) SealV3.AAD_STATIC else null)
        val hybridSignature = HybridSignature.sign(encrypted.ciphertext, senderHybridSignatureKeyPair.privateKey)
        Log.d(TAG, "Message encrypted with hybrid PQ scheme. Signature size: ${hybridSignature.totalSize()} bytes")
        return EncryptedPayload(
            encryptedData = encrypted.ciphertext.toHex(),
            iv = encrypted.iv.toHex(),
            signature = hybridSignature.secp256k1Hex(),
            ciphertext = encrypted.ciphertext.toHex(),
            messageCounter = sequenceNumber,
            version = if (staticV3) SealV3.PAYLOAD_STATIC_V3 else "hybrid-pq-v2",
            ratchetHeader = null,
            ephemeralPublicKey = null,
            ct = null,
            v = if (staticV3) 3 else 2,
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
        recipientSupportsRatchet: Boolean = false,
        clientId: String? = null,
    ): EncryptedPayload {
        if (recipientSupportsRatchet && secureKeyStorage.isRatchetEnabled()) {
            encryptMessageRatchet(
                content, recipientId, recipientX25519PublicKey, type,
                fileId, fileName, fileSize, mimeType, replyId, replyContent, replySenderName,
                recipientKyberPublicKey = recipientKyberPublicKey,
                clientId = clientId,
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
                    replyId, replyContent, replySenderName, clientId,
                    staticV3 = SecurityRollout.sealV3Send && secureKeyStorage.peerSealV3Pinned(recipientId),
                )
            } catch (e: Exception) {

                Log.e(TAG, "Hybrid PQ encryption failed for a PQ-capable recipient — refusing to downgrade", e)
                throw e
            }
        }
        return encryptMessageAsPayload(
            content, recipientId, recipientPublicKey, recipientX25519PublicKey,
            type, fileId, fileName, fileSize, mimeType, sequenceNumber,
            replyId, replyContent, replySenderName, clientId
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
        val payload = decryptMessageFromSealedSenderInner(sealedResult)

        runCatching { sealAfterDecrypt(sealedResult, payload) }
        return payload
    }
    private fun decryptMessageFromSealedSenderInner(sealedResult: SealedSenderResult): MessagePayload {
        val encryptedPayload = sealedResult.encryptedPayload
        if (BuildFlags.DEBUG) Log.w(TAG, ">>> open payload version=${encryptedPayload.version} pq=${encryptedPayload.ratchetHeader?.kc != null}")
        if (encryptedPayload.version == "hybrid-pq-v2" || encryptedPayload.version == SealV3.PAYLOAD_STATIC_V3) {
            return decryptMessageFromSealedSenderHybridPQ(sealedResult)
        }
        if (isRatchetVersion(encryptedPayload.version)) {
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
        val staticV3 = encryptedPayload.version == SealV3.PAYLOAD_STATIC_V3

        if (staticV3 && senderDilithiumPubHex.isNullOrBlank()) throw SecurityException("hybrid-pq-v3 without sender ML-DSA key")
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
        val aesKey = if (staticV3) {
            HybridKeyExchange.decapsulateV3(recipientHybridExchangeKeyPair, senderX25519PublicKey, kyberCiphertext).getAesKey()
        } else {
            val x25519SharedSecret = X25519.computeSharedSecret(
                recipientHybridExchangeKeyPair.privateKey.x25519,
                senderX25519PublicKey
            )
            val kyberSharedSecret = Kyber1024.decapsulate(
                kyberCiphertext,
                recipientHybridExchangeKeyPair.privateKey.kyber
            )
            val combinedSecret = combineHybridSecrets(x25519SharedSecret, kyberSharedSecret)
            combinedSecret.copyOfRange(0, 32)
        }
        val encryptedData = AesGcm.EncryptedData(ciphertext, iv)
        val decryptedBytes = AesGcm.decrypt(encryptedData, aesKey, if (staticV3) SealV3.AAD_STATIC else null)
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
        recipientKyberPublicKey: ByteArray? = null,
        recipientId: String? = null,
    ): SealedSenderPackage {
        if (recipientId != null && SecurityRollout.sealV3Send && recipientKyberPublicKey != null && shouldUseHybridPQ() &&
            secureKeyStorage.peerSealV3Pinned(recipientId)
        ) {
            return createSealedSenderV3(encryptedPayload, senderId, recipientId, recipientX25519PublicKey, recipientKyberPublicKey)
        }
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

    fun canSendCallSigV2(peerId: String, peerKyber: ByteArray?): Boolean =
        SecurityRollout.callSigV2 && SecurityRollout.sealV3Send && peerKyber != null && shouldUseHybridPQ() &&
            secureKeyStorage.peerSealV3Pinned(peerId) && secureKeyStorage.peerCallSigV2(peerId)

    fun sealCallSignalV2(
        peerId: String, peerX25519: ByteArray, peerKyber: ByteArray, senderId: String,
        t: String, cid: String, vid: Boolean, data: String?, ts: Long,
    ): SealedSenderPackage {
        val priv = secureKeyStorage.getSecp256k1PrivateKey() ?: throw IllegalStateException("Sender secp256k1 private key not found")
        val body = CallSigV2.Body(
            t = t, cid = cid, vid = vid, ts = ts, d = data,
            caps = localWireCaps(), sealAck = sealAckFor(peerId), ridDir = ridDirFor(peerId), ridAck = ridAckFor(peerId),
        )
        val blob = CallSigV2.pack(json.encodeToString(body))
        val sig = Secp256k1.sign(CallSigV2.signedBytes(senderId, peerId, blob), priv)
        val payload = EncryptedPayload(encryptedData = blob.toBase64(), iv = "", signature = sig.toHexString(), version = CallSigV2.PAYLOAD)
        return createSealedSenderV3(payload, senderId, peerId, peerX25519, peerKyber)
    }
    fun openCallSignalV2(r: SealedSenderResult): CallSigV2.Body? {
        val p = r.encryptedPayload
        if (p.version != CallSigV2.PAYLOAD) return null
        if (r.sealedVersion != SealV3.VERSION && r.sealedVersion != SealV3.VERSION_SHORT)
            throw SecurityException("callsig-v2 outside seal v3 (${r.sealedVersion})")
        val me = secureKeyStorage.getUserId() ?: throw IllegalStateException("no own user id")
        val blob = B64.decode(p.encryptedData)
        val sig = Secp256k1.Signature.fromHexString(p.signature)
        if (!Secp256k1.verify(CallSigV2.signedBytes(r.senderId, me, blob), sig, r.senderSecp256k1PublicKey.hexToBytes()))
            throw SecurityException("callsig-v2: bad signature")
        val body = json.decodeFromString<CallSigV2.Body>(CallSigV2.unpack(blob))
        runCatching {
            sealAfterDecrypt(r, MessagePayload(
                type = "signaling", content = "", timestamp = body.ts, nonce = "",
                caps = body.caps, sealAck = body.sealAck, ridDir = body.ridDir, ridAck = body.ridAck,
            ))
        }
        return body
    }

    private val rid2Salt = "umbera-rendezvous-v2".encodeToByteArray()
    private fun rid2(peerX25519Pub: ByteArray, dir: ByteArray, fromId: String, toId: String): String? {
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return null
        return RendezvousV2.rid(X25519.computeSharedSecret(myPriv, peerX25519Pub), dir, fromId, toId)
    }
    private fun rid2Tx(peerId: String): RendezvousV2.Tx? =
        secureKeyStorage.getRid2Tx(peerId)?.let { runCatching { json.decodeFromString<RendezvousV2.Tx>(it) }.getOrNull() }
    private fun rid2Rx(peerId: String): List<RendezvousV2.Rx> =
        secureKeyStorage.getRid2Rx(peerId)?.let { runCatching { json.decodeFromString<List<RendezvousV2.Rx>>(it) }.getOrNull() } ?: emptyList()
    fun rendezvousSendIdCurrent(peerId: String, peerX25519Pub: ByteArray, nowMs: Long = nowMs()): String? {
        if (SecurityRollout.ridV2) {
            val t = rid2Tx(peerId)
            val myId = secureKeyStorage.getUserId()
            if (t != null && t.confirmedMs > 0 && myId != null) {

                val r = if (t.epochs == 1) rid2e(peerX25519Pub, B64.decode(t.dir), myId, peerId, RendezvousV2.epochOf(nowMs))
                else rid2(peerX25519Pub, B64.decode(t.dir), myId, peerId)
                r?.let { return it }
            }
        }
        return rendezvousSendId(peerId, peerX25519Pub)
    }
    private fun rid2e(peerX25519Pub: ByteArray, dir: ByteArray, fromId: String, toId: String, epoch: Long): String? {
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return null
        return RendezvousV2.ridEpoch(X25519.computeSharedSecret(myPriv, peerX25519Pub), dir, fromId, toId, epoch)
    }
    data class RecvRid(val rid: String, val epoch: Long?, val cadence: RendezvousV2.Cadence, val chainId: String?)
    fun rendezvousRecvPlan(peerId: String, peerX25519Pub: ByteArray, nowMs: Long = nowMs(), forPurge: Boolean = false): List<RecvRid> {
        val v1 = rendezvousRecvId(peerId, peerX25519Pub)
        val every = RendezvousV2.Cadence.EVERY_PASS
        if (!SecurityRollout.ridV2) return listOfNotNull(v1?.let { RecvRid(it, null, every, null) })
        val rx = rid2Rx(peerId)
        val myId = secureKeyStorage.getUserId() ?: return listOfNotNull(v1?.let { RecvRid(it, null, every, null) })
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return listOfNotNull(v1?.let { RecvRid(it, null, every, null) })
        val ss = X25519.computeSharedSecret(myPriv, peerX25519Pub)
        val out = ArrayList<RecvRid>()
        val peerEpochs = secureKeyStorage.peerHasWireCap(peerId, WIRE_CAP_RID_EPOCH) && SecurityRollout.ridRotation
        for (r in rx) {
            val dir = B64.decode(r.dir)
            if (r.epochs == 1) {
                val plan = if (forPurge) {
                    val e = RendezvousV2.epochOf(nowMs)
                    ((e - RendezvousV2.maxBackEpochs())..(e + 1)).map { it to every }
                } else RendezvousV2.plan(nowMs, r.drainedTo)
                for ((ep, cad) in plan) out.add(RecvRid(RendezvousV2.ridEpoch(ss, dir, peerId, myId, ep), ep, cad, r.id))
            }
            val staticLive = r.epochs != 1 || !peerEpochs || forPurge ||
                nowMs - maxOf(r.epochsMs, r.staticLastMs) < RendezvousV2.staticGraceMs()
            if (staticLive) out.add(RecvRid(RendezvousV2.rid(ss, dir, peerId, myId), null, every, r.id))
        }
        val since = maxOf(rx.maxOfOrNull { it.pinnedMs } ?: 0L, secureKeyStorage.getRid2V1Last(peerId))
        val keepV1 = rx.isEmpty() || forPurge || nowMs - since < RendezvousV2.RID_V1_GRACE_MS
        if (keepV1 && v1 != null) out.add(RecvRid(v1, null, every, null))
        return out.distinctBy { it.rid }
    }
    fun rendezvousRecvIds(peerId: String, peerX25519Pub: ByteArray, nowMs: Long = nowMs(), forPurge: Boolean = false): List<String> =
        rendezvousRecvPlan(peerId, peerX25519Pub, nowMs, forPurge).map { it.rid }
    fun noteRendezvousEpochsDrained(peerId: String, chainId: String, nowMs: Long = nowMs()) {
        val rx = rid2Rx(peerId)
        val e = RendezvousV2.epochOf(nowMs)
        if (rx.none { it.id == chainId && it.epochs == 1 && (it.drainedTo ?: Long.MIN_VALUE) < e }) return
        secureKeyStorage.setRid2Rx(peerId, json.encodeToString(rx.map { if (it.id == chainId && it.epochs == 1) it.copy(drainedTo = e) else it }))
    }
    fun noteRendezvousReceipt(peerId: String, rid: String, peerX25519Pub: ByteArray) {
        if (!SecurityRollout.ridV2) return
        if (rid == rendezvousRecvId(peerId, peerX25519Pub)) { secureKeyStorage.setRid2V1Last(peerId, nowMs()); return }
        val rx = rid2Rx(peerId)
        if (rx.none { it.epochs == 1 }) return
        val myId = secureKeyStorage.getUserId() ?: return
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return
        val ss = X25519.computeSharedSecret(myPriv, peerX25519Pub)
        val hit = rx.firstOrNull { it.epochs == 1 && RendezvousV2.rid(ss, B64.decode(it.dir), peerId, myId) == rid } ?: return
        val now = nowMs()
        secureKeyStorage.setRid2Rx(peerId, json.encodeToString(rx.map { if (it.id == hit.id) it.copy(staticLastMs = now) else it }))
    }
    private fun ridDirFor(recipientId: String): String? {
        if (!SecurityRollout.ridV2) return null
        val t = rid2Tx(recipientId) ?: return null
        val offer = ridEpochsLocal() && secureKeyStorage.peerHasWireCap(recipientId, WIRE_CAP_RID_EPOCH)
        return when {
            t.confirmedMs == 0L -> RendezvousV2.mark(t.id, offer)
            t.epochs == 0 && offer -> RendezvousV2.mark(t.id, true)
            else -> null
        }
    }
    private fun ridAckFor(recipientId: String): String? {
        if (!SecurityRollout.ridV2) return null
        val r = rid2Rx(recipientId).maxByOrNull { it.pinnedMs } ?: return null
        return RendezvousV2.mark(r.id, r.epochs == 1 && SecurityRollout.ridRotation)
    }
    private fun ridAfterDecrypt(sender: String, payload: MessagePayload) {
        if (!SecurityRollout.ridV2) return
        val now = nowMs()
        payload.ridDir?.let { raw ->
            val (id, wantEpochs) = RendezvousV2.parse(raw)
            val epochs = wantEpochs && SecurityRollout.ridRotation
            val rx = rid2Rx(sender)
            val cur = rx.firstOrNull { it.id == id }
            if (cur == null) {
                val dir = sealLock.withLock { sealRx(sender, now)?.chains?.firstOrNull { it.id == id }?.dir }
                if (dir != null) secureKeyStorage.setRid2Rx(sender, json.encodeToString((listOf(
                    RendezvousV2.Rx(id, dir, now, epochs = if (epochs) 1 else 0, epochsMs = 0,
                        drainedTo = if (epochs) RendezvousV2.epochOf(now) - 1 else null)) + rx).take(2)))
            } else if (epochs && cur.epochs == 0) {
                secureKeyStorage.setRid2Rx(sender, json.encodeToString(rx.map {
                    if (it.id == id) it.copy(epochs = 1, epochsMs = now, drainedTo = RendezvousV2.epochOf(now) - 1) else it
                }))
            }
        }
        val t = rid2Tx(sender) ?: return
        val (ack, ackEpochs) = payload.ridAck?.let { RendezvousV2.parse(it) } ?: (null to false)
        if (ack == t.id) {
            val e = if (ackEpochs && ridEpochsLocal()) 1 else 0
            when {
                t.confirmedMs == 0L ->
                    secureKeyStorage.setRid2Tx(sender, json.encodeToString(t.copy(confirmedMs = now, ackTs = payload.timestamp, epochs = e)))
                t.epochs == 0 && e == 1 && payload.timestamp > t.ackTs ->
                    secureKeyStorage.setRid2Tx(sender, json.encodeToString(t.copy(epochs = 1, ackTs = payload.timestamp)))
                t.epochs == 1 && !ackEpochs && payload.timestamp > t.ackTs ->
                    secureKeyStorage.setRid2Tx(sender, json.encodeToString(t.copy(epochs = 0, ackTs = payload.timestamp)))
            }
        } else if (t.confirmedMs > 0 && payload.timestamp > t.ackTs && (payload.caps ?: 0) and WIRE_CAP_SEAL_V3 != 0 && ack == null) {
            notePairDropped(sender, t.confirmedMs)
            secureKeyStorage.removeRid2Tx(sender)
        }
    }
    fun pairStateSinceMs(peerId: String): Long? {
        val seal = sealLock.withLock {
            secureKeyStorage.getSealTx(peerId)?.let { runCatching { json.decodeFromString<SealV3.TxState>(it) }.getOrNull() }?.active?.createdMs
        }
        val rid = rid2Tx(peerId)?.confirmedMs?.takeIf { it > 0 }
        val dropped = secureKeyStorage.getPairDroppedSince(peerId).takeIf { it > 0 }
        secureKeyStorage.removePairDroppedSince(peerId)
        return listOfNotNull(seal, rid, dropped).minOrNull()
    }
    private fun notePairDropped(peerId: String, sinceMs: Long) {
        if (sinceMs <= 0) return
        val cur = secureKeyStorage.getPairDroppedSince(peerId)
        if (cur == 0L || sinceMs < cur) secureKeyStorage.setPairDroppedSince(peerId, sinceMs)
    }
    fun onPeerLostPairState(peerId: String, nowMs: Long = nowMs()) {
        sealLock.withLock { secureKeyStorage.removeSealTx(peerId) }
        secureKeyStorage.removeRid2Tx(peerId)
        secureKeyStorage.setRid2V1Last(peerId, nowMs)
    }
    fun rendezvousSelfBackupIdV2(peerId: String): String? {
        val myId = secureKeyStorage.getUserId() ?: return null
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return null
        val seed = secureKeyStorage.getKyberPrivateKey() ?: return null
        val myPub = secureKeyStorage.getX25519PublicKey() ?: X25519.getPublicKey(myPriv)
        val shared = X25519.computeSharedSecret(myPriv, myPub)
        val pq = RustCore.hkdfSha256(seed, rid2Salt, "rdv-backup-v2/key".encodeToByteArray(), 32u)
        return RustCore.hkdfSha256(shared + pq, rid2Salt, "rdv-backup-v2|$myId|$peerId".encodeToByteArray(), 32u).toHex()
    }
    private fun selfBackupIkm(): ByteArray? {
        val myPriv = secureKeyStorage.getX25519PrivateKey() ?: return null
        val seed = secureKeyStorage.getKyberPrivateKey() ?: return null
        val myPub = secureKeyStorage.getX25519PublicKey() ?: X25519.getPublicKey(myPriv)
        val shared = X25519.computeSharedSecret(myPriv, myPub)
        return shared + RustCore.hkdfSha256(seed, rid2Salt, "rdv-backup-v2/key".encodeToByteArray(), 32u)
    }
    fun rendezvousSelfBackupIdCurrent(peerId: String, nowMs: Long = nowMs()): String? {
        if (SecurityRollout.ridV2 && rid2Tx(peerId)?.let { it.confirmedMs > 0 && it.epochs == 1 } == true) {
            val myId = secureKeyStorage.getUserId()
            val ikm = selfBackupIkm()
            if (myId != null && ikm != null) return RendezvousV2.selfBackupEpoch(ikm, myId, peerId, RendezvousV2.epochOf(nowMs))
        }
        return (if (SecurityRollout.ridV2) rendezvousSelfBackupIdV2(peerId) else null) ?: rendezvousSelfBackupId(peerId)
    }
    fun rendezvousSelfBackupIds(peerId: String, nowMs: Long = nowMs(), forPurge: Boolean = false): List<String> {
        val base = listOfNotNull(rendezvousSelfBackupIdV2(peerId).takeIf { SecurityRollout.ridV2 }, rendezvousSelfBackupId(peerId))
        if (!SecurityRollout.ridV2 || !SecurityRollout.ridRotation) return base.distinct()
        val myId = secureKeyStorage.getUserId() ?: return base.distinct()
        val ikm = selfBackupIkm() ?: return base.distinct()
        val e = RendezvousV2.epochOf(nowMs)
        val lo = if (forPurge) e - RendezvousV2.maxBackEpochs()
        else maxOf(e - RendezvousV2.maxBackEpochs(), (secureKeyStorage.getRid2SelfBackupDrained(peerId) ?: Long.MIN_VALUE) + 1)
        val epochs = (lo..e).map { RendezvousV2.selfBackupEpoch(ikm, myId, peerId, it) }
        return (epochs + base).distinct()
    }
    fun noteSelfBackupEpochsDrained(peerId: String, nowMs: Long = nowMs()) {
        if (!SecurityRollout.ridV2 || !SecurityRollout.ridRotation) return
        val e = RendezvousV2.epochOf(nowMs)
        if ((secureKeyStorage.getRid2SelfBackupDrained(peerId) ?: Long.MIN_VALUE) < e) secureKeyStorage.setRid2SelfBackupDrained(peerId, e)
    }

    private val sealLock = app.umbera.core.util.SyncLock()
    private fun nowMs(): Long = Clock.System.now().toEpochMilliseconds()
    private fun innerV3(encryptedPayload: EncryptedPayload, senderId: String, version: String): String {
        val sig = secureKeyStorage.getHybridSignatureKeyPair() ?: throw IllegalStateException("Sender hybrid signature key pair not found")
        val ex = secureKeyStorage.getHybridExchangeKeyPair() ?: throw IllegalStateException("Sender hybrid exchange key pair not found")
        return json.encodeToString(InnerPackage(
            senderId = senderId,
            senderPublicKey = sig.publicKey.secp256k1Hex(),
            senderX25519PublicKey = ex.publicKey.x25519.toBase64(),
            ratchetMessage = encryptedPayload,
            timestamp = nowMs(),
            sealedVersion = version,
            senderDilithiumPublicKey = if (encryptedPayload.version == "hybrid-pq-v2" || encryptedPayload.version == SealV3.PAYLOAD_STATIC_V3)
                sig.publicKey.dilithiumHex() else null,
        ))
    }
    fun createSealedSenderV3(
        encryptedPayload: EncryptedPayload, senderId: String, recipientId: String,
        rcptX: ByteArray, rcptEk: ByteArray,
    ): SealedSenderPackage = sealLock.withLock {
        val tag = SealV3.rcptTag(rcptX, rcptEk)
        val now = nowMs()
        val st = secureKeyStorage.getSealTx(recipientId)?.let { runCatching { json.decodeFromString<SealV3.TxState>(it) }.getOrNull() } ?: SealV3.TxState()
        val a = st.active
        val live = a != null && a.rcpt == tag && a.n < SealV3.SHORT_PER_FULL && now - a.createdMs in 0 until SealV3.PAIR_MAX_AGE_MS
        if (live && st.sinceIn < SealV3.RECV_WINDOW) {
            val ck = B64.decode(a!!.ck)
            val mk = SealV3.chainMk(ck)

            secureKeyStorage.setSealTx(recipientId, json.encodeToString(st.copy(
                active = a.copy(ck = B64.encode(SealV3.chainNext(ck)), n = a.n + 1), sinceIn = st.sinceIn + 1)))
            return@withLock sealShort(innerV3(encryptedPayload, senderId, SealV3.VERSION_SHORT), mk, rcptX, rcptEk)
        }
        val (pkg, pair, dir) = sealFull(innerV3(encryptedPayload, senderId, SealV3.VERSION), rcptX, rcptEk)
        val pend = (listOf(SealV3.TxPending(SealV3.pairId(pair), B64.encode(pair), now, tag, B64.encode(dir))) + st.pending.filter { it.rcpt == tag }).take(3)
        secureKeyStorage.setSealTx(recipientId, json.encodeToString(
            SealV3.TxState(pending = pend, active = if (live) a else null, sinceIn = if (live) st.sinceIn else 0)))
        pkg
    }
    private fun sealFull(innerJson: String, rcptX: ByteArray, rcptEk: ByteArray): Triple<SealedSenderPackage, ByteArray, ByteArray> {
        val eph = X25519.generateKeyPair()
        val ssX = X25519.computeSharedSecret(eph.privateKey, rcptX)
        val kem = Kyber1024.encapsulate(rcptEk)
        val th = SealV3.transcriptFull(eph.publicKey, kem.ciphertext, rcptX, rcptEk)
        val key = SealV3.fullOkm(ssX, kem.sharedSecret, th).copyOfRange(0, 32)
        val pair = SealV3.pairSecret(ssX, kem.sharedSecret, th)
        val dir = SealV3.dirSecret(ssX, kem.sharedSecret, th)
        val iv = secureRandomBytes(12)
        val e = AesGcm.encryptWithTag(innerJson.encodeToByteArray(), key, iv, SealV3.AAD_FULL)
        return Triple(SealedSenderPackage(
            version = SealV3.VERSION, ephemeralPublicKey = eph.publicKey.toBase64(), encryptedInner = e.ciphertext.toBase64(),
            authTag = e.authTag.toBase64(), iv = iv.toBase64(), kyberCiphertext = kem.ciphertext.toBase64(),
        ), pair, dir)
    }
    private fun sealShort(innerJson: String, mk: ByteArray, rcptX: ByteArray, rcptEk: ByteArray): SealedSenderPackage {
        val eph = X25519.generateKeyPair()
        val ssX = X25519.computeSharedSecret(eph.privateKey, rcptX)
        val hint = SealV3.hint(mk)
        val key = SealV3.shortKey(ssX, mk, SealV3.transcriptShort(eph.publicKey, rcptX, rcptEk, hint))
        val iv = secureRandomBytes(12)
        val e = AesGcm.encryptWithTag(innerJson.encodeToByteArray(), key, iv, SealV3.AAD_SHORT)
        return SealedSenderPackage(
            version = SealV3.VERSION_SHORT, ephemeralPublicKey = eph.publicKey.toBase64(), encryptedInner = e.ciphertext.toBase64(),
            authTag = e.authTag.toBase64(), iv = iv.toBase64(), sealHint = hint.toBase64(),
        )
    }
    private fun b64Exact(s: String?, n: Int, what: String): ByteArray {
        val b = runCatching { B64.decode(s ?: "") }.getOrNull() ?: throw IllegalArgumentException("seal v3: $what")
        require(b.size == n) { "seal v3: $what ${b.size}" }
        return b
    }
    private fun innerResult(innerJson: String, version: String, pair: ByteArray?, dir: ByteArray? = null): SealedSenderResult {
        val inner = json.decodeFromString<InnerPackage>(innerJson)
        require(inner.sealedVersion == version) { "seal v3: inner version ${inner.sealedVersion}" }
        return SealedSenderResult(
            senderId = inner.senderId, senderSecp256k1PublicKey = inner.senderPublicKey,
            senderX25519PublicKey = inner.senderX25519PublicKey, encryptedPayload = inner.ratchetMessage,
            senderDisplayName = inner.senderDisplayName, senderDilithiumPublicKey = inner.senderDilithiumPublicKey,
            sealPairSecret = pair, sealDirSecret = dir, sealedVersion = version,
        )
    }
    private fun openSealedSenderV3(p: SealedSenderPackage): SealedSenderResult {
        val kp = secureKeyStorage.getHybridExchangeKeyPair() ?: throw IllegalStateException("Recipient hybrid exchange key pair not found for v3")
        val eph = b64Exact(p.ephemeralPublicKey, 32, "eph")
        val ct = b64Exact(p.kyberCiphertext, Kyber1024.CIPHERTEXT_SIZE, "ct")
        val iv = b64Exact(p.iv, 12, "iv")
        val tagB = b64Exact(p.authTag, 16, "tag")
        val inner = B64.decode(p.encryptedInner)
        val ssX = X25519.computeSharedSecret(kp.privateKey.x25519, eph)
        val ssKem = Kyber1024.decapsulate(ct, kp.privateKey.kyber)
        val th = SealV3.transcriptFull(eph, ct, kp.publicKey.x25519, kp.publicKey.kyber)
        val key = SealV3.fullOkm(ssX, ssKem, th).copyOfRange(0, 32)
        val plain = AesGcm.decryptWithTag(inner, tagB, iv, key, SealV3.AAD_FULL)
        return innerResult(plain.decodeToString(), SealV3.VERSION, SealV3.pairSecret(ssX, ssKem, th), SealV3.dirSecret(ssX, ssKem, th))
    }
    private fun openSealedSenderV3Short(p: SealedSenderPackage): SealedSenderResult {
        val kp = secureKeyStorage.getHybridExchangeKeyPair() ?: throw IllegalStateException("Recipient hybrid exchange key pair not found for v3s")
        val eph = b64Exact(p.ephemeralPublicKey, 32, "eph")
        val hint = b64Exact(p.sealHint, SealV3.HINT_LEN, "hint")
        val iv = b64Exact(p.iv, 12, "iv")
        val tagB = b64Exact(p.authTag, 16, "tag")
        val inner = B64.decode(p.encryptedInner)
        val hintHex = SealV3.hex(hint)
        return sealLock.withLock {
            val now = nowMs()
            for (peer in secureKeyStorage.sealRxPeers()) {
                val st = sealRx(peer, now) ?: continue
                for (c in st.chains) {
                    val (n, mk) = SealV3.rxFind(c, hintHex) ?: continue
                    val ssX = X25519.computeSharedSecret(kp.privateKey.x25519, eph)
                    val key = SealV3.shortKey(ssX, mk, SealV3.transcriptShort(eph, kp.publicKey.x25519, kp.publicKey.kyber, hint))
                    val plain = runCatching { AesGcm.decryptWithTag(inner, tagB, iv, key, SealV3.AAD_SHORT) }.getOrNull() ?: continue
                    val r = innerResult(plain.decodeToString(), SealV3.VERSION_SHORT, null)
                    require(r.senderId == peer) { "seal v3s: chain owner mismatch" }
                    val upd = st.copy(chains = st.chains.map { if (it.id == c.id) SealV3.rxAccept(it, n, now) else it })
                    secureKeyStorage.setSealRx(peer, json.encodeToString(upd))
                    return@withLock r
                }
            }
            throw SecurityException("seal v3s: no pair secret")
        }
    }
    private fun sealRx(peer: String, now: Long): SealV3.RxState? {
        val raw = secureKeyStorage.getSealRx(peer) ?: return null
        val st = runCatching { json.decodeFromString<SealV3.RxState>(raw) }.getOrNull() ?: return null
        val live = st.chains.filter { now - it.usedMs < SealV3.RECV_MAX_AGE_MS }
        if (live.size != st.chains.size) {
            if (live.isEmpty()) secureKeyStorage.removeSealRx(peer) else secureKeyStorage.setSealRx(peer, json.encodeToString(SealV3.RxState(live)))
        }
        return if (live.isEmpty()) null else SealV3.RxState(live)
    }
    private fun sealAckFor(recipientId: String): String? {
        if (!SecurityRollout.sealV3Accept) return null
        return runCatching { sealLock.withLock { sealRx(recipientId, nowMs())?.chains?.maxByOrNull { it.createdMs }?.id } }.getOrNull()
    }
    private fun sealAfterDecrypt(r: SealedSenderResult, payload: MessagePayload) {
        val sender = r.senderId

        val keys = sealedSenderKeyBytes(r) ?: return
        if (secureKeyStorage.pinnedPeerKeyMatches(sender, keys.first, keys.second) != true) return
        runCatching { ridAfterDecrypt(sender, payload) }
        val pair = r.sealPairSecret
        if (pair != null && SecurityRollout.sealV3Accept) {
            sealLock.withLock {
                val now = nowMs()
                val cur = sealRx(sender, now) ?: SealV3.RxState()
                val id = SealV3.pairId(pair)
                if (cur.chains.none { it.id == id }) {
                    val chains = (cur.chains + SealV3.rxNew(pair, now, r.sealDirSecret)).sortedByDescending { it.createdMs }.take(SealV3.RECV_KEEP)
                    secureKeyStorage.setSealRx(sender, json.encodeToString(SealV3.RxState(chains)))
                }
            }
        }
        val ack = payload.sealAck
        sealLock.withLock {
            val st = secureKeyStorage.getSealTx(sender)?.let { runCatching { json.decodeFromString<SealV3.TxState>(it) }.getOrNull() } ?: return@withLock
            if (ack == null) {

                if (st.active != null && (payload.caps ?: 0) and WIRE_CAP_SEAL_V3 != 0 && payload.timestamp >= st.ackTs) {
                    notePairDropped(sender, st.active.createdMs)
                    secureKeyStorage.setSealTx(sender, json.encodeToString(st.copy(active = null)))
                }
                return@withLock
            }
            if (st.active?.id == ack) {
                val at = maxOf(st.ackTs, payload.timestamp)
                if (st.sinceIn != 0 || at != st.ackTs) secureKeyStorage.setSealTx(sender, json.encodeToString(st.copy(sinceIn = 0, ackTs = at)))
                return@withLock
            }
            val hit = st.pending.firstOrNull { it.id == ack } ?: return@withLock
            secureKeyStorage.setSealTx(sender, json.encodeToString(SealV3.TxState(
                pending = st.pending.filter { it.createdMs > hit.createdMs },
                active = SealV3.TxChain(hit.id, hit.secret, 0, hit.createdMs, hit.rcpt),
                ackTs = maxOf(st.ackTs, payload.timestamp),
            )))
            if (SecurityRollout.ridV2 && hit.dir != null && secureKeyStorage.getRid2Tx(sender) == null)
                secureKeyStorage.setRid2Tx(sender, json.encodeToString(RendezvousV2.Tx(hit.id, hit.dir, 0)))
        }
    }
    fun openSealedSender(sealedPackage: SealedSenderPackage): Pair<String, EncryptedPayload> {
        val result = openSealedSenderFull(sealedPackage)
        return Pair(result.senderId, result.encryptedPayload)
    }

    fun openSealedSenderFull(sealedPackage: SealedSenderPackage): SealedSenderResult {
        if (sealedPackage.version == SealV3.VERSION) return openSealedSenderV3(sealedPackage)
        if (sealedPackage.version == SealV3.VERSION_SHORT) return openSealedSenderV3Short(sealedPackage)
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
        if (sealedPackage.version == SealV3.VERSION || sealedPackage.version == SealV3.VERSION_SHORT) return openSealedSenderFull(sealedPackage)
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
internal class DeferredRatchetStorage(private val disk: DoubleRatchet.RatchetStorage) : DoubleRatchet.RatchetStorage {
    var deferNow = false
    private class Entry(val token: Long, val state: DoubleRatchet.RatchetState, var done: Boolean)
    private val queue = HashMap<String, ArrayDeque<Entry>>()
    private var inbound = false
    private var nextToken = 1L
    private var lastToken: Long? = null
    fun <T> inboundDecrypt(block: () -> T): T {
        inbound = true
        try { return block() } finally { inbound = false }
    }

    fun takeLastToken(): Long? = lastToken.also { lastToken = null }
    override fun saveState(sessionId: String, state: DoubleRatchet.RatchetState) {
        val deferred = deferNow && inbound
        if (!deferred && queue[sessionId] == null) { disk.saveState(sessionId, state); return }
        val q = queue.getOrPut(sessionId) { ArrayDeque() }
        val token = nextToken++
        q.addLast(Entry(token, state, done = !deferred))
        if (deferred) lastToken = token
        flush(sessionId)
    }
    override fun getState(sessionId: String): DoubleRatchet.RatchetState? =
        queue[sessionId]?.lastOrNull()?.state ?: disk.getState(sessionId)
    override fun deleteState(sessionId: String) {
        queue.remove(sessionId)
        disk.deleteState(sessionId)
    }
    fun commit(sessionId: String, token: Long) {
        queue[sessionId]?.firstOrNull { it.token == token }?.done = true
        flush(sessionId)
    }
    private fun flush(sessionId: String) {
        val q = queue[sessionId] ?: return
        var persist: DoubleRatchet.RatchetState? = null
        while (q.isNotEmpty() && q.first().done) persist = q.removeFirst().state
        if (persist != null) {
            disk.saveState(sessionId, persist)
        }
        if (q.isEmpty()) queue.remove(sessionId)
    }
}
