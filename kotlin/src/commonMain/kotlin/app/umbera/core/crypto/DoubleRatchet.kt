package app.umbera.core.crypto

// Double Ratchet session for 1:1 conversations.

import kotlinx.datetime.Clock
import kotlinx.serialization.Serializable

import app.umbera.core.util.SyncLock
import app.umbera.core.util.withLock

class DoubleRatchet(
    private val storage: RatchetStorage,
    private val nowMs: () -> Long = { Clock.System.now().toEpochMilliseconds() }
) {
    companion object {
        private const val MAX_SKIP = 1000
        private const val INFO_ROOT = "root"
        private const val INFO_CHAIN = "chain"
        private const val INFO_MESSAGE = "message"

        internal const val MAX_SKIPPED_TOTAL = 2000
        internal const val SKIPPED_KEY_TTL_MS = 30L * 24 * 60 * 60 * 1000

        internal fun enforceSkippedKeyBounds(state: RatchetState, nowMs: Long): RatchetState {
            if (state.skippedMessageKeys.isEmpty()) {
                return if (state.skippedKeyOrder.isEmpty() && state.skippedKeyAddedAt.isEmpty()) state
                else state.copy(skippedKeyOrder = emptyList(), skippedKeyAddedAt = emptyMap())
            }
            val keys = state.skippedMessageKeys.toMutableMap()
            val stamps = state.skippedKeyAddedAt.toMutableMap()

            val recorded = state.skippedKeyOrder.filter { it in keys }
            val recordedSet = recorded.toSet()
            val legacy = keys.keys.filter { it !in recordedSet }
            for (k in legacy) if (k !in stamps) stamps[k] = nowMs
            val order = ArrayDeque<String>(legacy.size + recorded.size)
            order.addAll(legacy)
            order.addAll(recorded)

            val expired = order.filter { (stamps[it] ?: nowMs) + SKIPPED_KEY_TTL_MS <= nowMs }
            if (expired.isNotEmpty()) {
                val gone = expired.toSet()
                for (k in gone) { keys.remove(k); stamps.remove(k) }
                order.removeAll(gone)
            }

            while (keys.size > MAX_SKIPPED_TOTAL) {
                val victim = order.removeFirst()
                keys.remove(victim)
                stamps.remove(victim)
            }

            stamps.keys.retainAll(keys.keys)
            return state.copy(
                skippedMessageKeys = keys,
                skippedKeyOrder = order.toList(),
                skippedKeyAddedAt = stamps
            )
        }

        internal fun isPossibleSessionRestart(
            state: RatchetState,
            header: MessageHeader,
            peerIsInitiator: Boolean
        ): Boolean {
            if (!peerIsInitiator) return false
            if (header.previousChainLength != 0) return false
            val remote = state.remoteDhPublicKey
            if (remote != null && remote.contentEquals(header.dhPublicKey)) return false
            if (state.skippedMessageKeys.isNotEmpty()) {
                val sb = StringBuilder(header.dhPublicKey.size * 2 + 1)
                for (b in header.dhPublicKey) sb.append(((b.toInt() and 0xFF) + 0x100).toString(16).substring(1))
                sb.append(':')
                val prefix = sb.toString()
                if (state.skippedMessageKeys.keys.any { it.startsWith(prefix) }) return false
            }
            return true
        }
    }

    private val sessionLocks = HashMap<String, SyncLock>()
    private val sessionLocksGuard = SyncLock()

    @Serializable

    data class RatchetState(
        val dhKeyPair: X25519.KeyPair,
        val remoteDhPublicKey: ByteArray?,
        val rootKey: ByteArray,
        val sendingChainKey: ByteArray?,
        val receivingChainKey: ByteArray?,
        val sendingMessageNumber: Int = 0,
        val receivingMessageNumber: Int = 0,
        val previousSendingChainLength: Int = 0,

        val skippedMessageKeys: Map<String, ByteArray> = emptyMap(),

        val skippedKeyOrder: List<String> = emptyList(),
        val skippedKeyAddedAt: Map<String, Long> = emptyMap()
    )

    data class MessageHeader(
        val dhPublicKey: ByteArray,
        val previousChainLength: Int,
        val messageNumber: Int
    ) {
        fun toByteArray(): ByteArray {
            val out = ByteArray(32 + 4 + 4)
            dhPublicKey.copyInto(out, 0)
            writeIntBe(out, 32, previousChainLength)
            writeIntBe(out, 36, messageNumber)
            return out
        }

        companion object {
            fun fromByteArray(data: ByteArray): MessageHeader {
                require(data.size >= 40) { "ratchet header must be 40 bytes, got ${data.size}" }
                val dhPublicKey = data.copyOfRange(0, 32)
                val previousChainLength = readIntBe(data, 32)
                val messageNumber = readIntBe(data, 36)
                return MessageHeader(dhPublicKey, previousChainLength, messageNumber)
            }

            private fun readIntBe(b: ByteArray, off: Int): Int =
                ((b[off].toInt() and 0xFF) shl 24) or
                    ((b[off + 1].toInt() and 0xFF) shl 16) or
                    ((b[off + 2].toInt() and 0xFF) shl 8) or
                    (b[off + 3].toInt() and 0xFF)

            private fun writeIntBe(b: ByteArray, off: Int, v: Int) {
                b[off] = (v ushr 24).toByte()
                b[off + 1] = (v ushr 16).toByte()
                b[off + 2] = (v ushr 8).toByte()
                b[off + 3] = v.toByte()
            }
        }
    }

    data class EncryptedMessage(
        val header: MessageHeader,
        val ciphertext: AesGcm.EncryptedData
    )

    fun initializeSender(
        sessionId: String,
        sharedSecret: ByteArray,
        remotePublicKey: ByteArray
    ): RatchetState {
        val dhKeyPair = X25519.generateKeyPair()
        val dhOutput = X25519.computeSharedSecret(dhKeyPair.privateKey, remotePublicKey)

        val (rootKey, sendingChainKey) = kdfRootKey(sharedSecret, dhOutput)

        val state = RatchetState(
            dhKeyPair = dhKeyPair,
            remoteDhPublicKey = remotePublicKey,
            rootKey = rootKey,
            sendingChainKey = sendingChainKey,
            receivingChainKey = null
        )

        storage.saveState(sessionId, state)
        return state
    }

    fun initializeReceiver(
        sessionId: String,
        sharedSecret: ByteArray,
        dhKeyPair: X25519.KeyPair
    ): RatchetState {
        val state = RatchetState(
            dhKeyPair = dhKeyPair,
            remoteDhPublicKey = null,
            rootKey = sharedSecret,
            sendingChainKey = null,
            receivingChainKey = null
        )

        storage.saveState(sessionId, state)
        return state
    }

    private fun getLock(sessionId: String): SyncLock =
        sessionLocksGuard.withLock { sessionLocks.getOrPut(sessionId) { SyncLock() } }

    private fun skipKey(dhPublicKey: ByteArray, messageNumber: Int): String {
        val sb = StringBuilder(dhPublicKey.size * 2 + 8)
        for (b in dhPublicKey) sb.append(((b.toInt() and 0xFF) + 0x100).toString(16).substring(1))
        sb.append(':').append(messageNumber)
        return sb.toString()
    }

    fun encrypt(sessionId: String, plaintext: ByteArray): EncryptedMessage {
        return getLock(sessionId).withLock {
            var state = storage.getState(sessionId)
                ?: throw IllegalStateException("No ratchet state for session $sessionId")

            val (chainKey, messageKey) = kdfChainKey(state.sendingChainKey!!)

            val header = MessageHeader(
                dhPublicKey = state.dhKeyPair.publicKey,
                previousChainLength = state.previousSendingChainLength,
                messageNumber = state.sendingMessageNumber
            )

            val ciphertext = AesGcm.encrypt(plaintext, messageKey, header.toByteArray())

            state = state.copy(
                sendingChainKey = chainKey,
                sendingMessageNumber = state.sendingMessageNumber + 1
            )
            storage.saveState(sessionId, state)

            EncryptedMessage(header, ciphertext)
        }
    }

    fun decrypt(sessionId: String, message: EncryptedMessage): ByteArray {
        return getLock(sessionId).withLock {
            var state = storage.getState(sessionId)
                ?: throw IllegalStateException("No ratchet state for session $sessionId")

            val lookupKey = skipKey(message.header.dhPublicKey, message.header.messageNumber)
            val skippedKey = state.skippedMessageKeys[lookupKey]
            if (skippedKey != null) {
                val plaintext = AesGcm.decrypt(message.ciphertext, skippedKey, message.header.toByteArray())
                val newSkipped = state.skippedMessageKeys.toMutableMap()
                newSkipped.remove(lookupKey)

                state = state.copy(
                    skippedMessageKeys = newSkipped,
                    skippedKeyOrder = state.skippedKeyOrder - lookupKey,
                    skippedKeyAddedAt = state.skippedKeyAddedAt - lookupKey
                )
                storage.saveState(sessionId, state)
                return@withLock plaintext
            }

            if (state.remoteDhPublicKey == null ||
                !message.header.dhPublicKey.contentEquals(state.remoteDhPublicKey)) {
                state = performDhRatchet(state, message.header)
            }

            state = skipMessageKeys(state, message.header.messageNumber)

            val (chainKey, messageKey) = kdfChainKey(state.receivingChainKey!!)
            val plaintext = AesGcm.decrypt(message.ciphertext, messageKey, message.header.toByteArray())

            state = state.copy(
                receivingChainKey = chainKey,
                receivingMessageNumber = state.receivingMessageNumber + 1
            )

            state = enforceSkippedKeyBounds(state, nowMs())
            storage.saveState(sessionId, state)

            plaintext
        }
    }

    private fun performDhRatchet(state: RatchetState, header: MessageHeader): RatchetState {
        var newState = state
        if (state.receivingChainKey != null) {
            newState = skipMessageKeys(newState, header.previousChainLength)
        }

        val dhOutput = X25519.computeSharedSecret(state.dhKeyPair.privateKey, header.dhPublicKey)
        val (rootKey1, receivingChainKey) = kdfRootKey(state.rootKey, dhOutput)

        val newDhKeyPair = X25519.generateKeyPair()
        val dhOutput2 = X25519.computeSharedSecret(newDhKeyPair.privateKey, header.dhPublicKey)
        val (rootKey2, sendingChainKey) = kdfRootKey(rootKey1, dhOutput2)

        return newState.copy(
            dhKeyPair = newDhKeyPair,
            remoteDhPublicKey = header.dhPublicKey,
            rootKey = rootKey2,
            sendingChainKey = sendingChainKey,
            receivingChainKey = receivingChainKey,
            sendingMessageNumber = 0,
            receivingMessageNumber = 0,
            previousSendingChainLength = state.sendingMessageNumber
        )
    }

    private fun skipMessageKeys(state: RatchetState, until: Int): RatchetState {
        if (state.receivingChainKey == null) return state
        if (state.remoteDhPublicKey == null) return state
        if (until - state.receivingMessageNumber > MAX_SKIP) {
            throw IllegalStateException("Too many skipped messages")
        }

        var chainKey: ByteArray = state.receivingChainKey
        val skipped = state.skippedMessageKeys.toMutableMap()

        val order = state.skippedKeyOrder.toMutableList()
        val stamps = state.skippedKeyAddedAt.toMutableMap()
        val now = nowMs()
        val remoteDhKey = state.remoteDhPublicKey

        for (i in state.receivingMessageNumber until until) {
            val (newChainKey, messageKey) = kdfChainKey(chainKey)
            val key = skipKey(remoteDhKey, i)
            skipped[key] = messageKey
            if (key !in stamps) {
                order.add(key)
                stamps[key] = now
            }
            chainKey = newChainKey
        }

        return enforceSkippedKeyBounds(
            state.copy(
                receivingChainKey = chainKey,
                receivingMessageNumber = until,
                skippedMessageKeys = skipped,
                skippedKeyOrder = order,
                skippedKeyAddedAt = stamps
            ),
            now
        )
    }

    private fun kdfRootKey(rootKey: ByteArray, dhOutput: ByteArray): Pair<ByteArray, ByteArray> {
        val output = RustCore.hkdfSha256(dhOutput, rootKey, INFO_ROOT.encodeToByteArray(), 64u)

        return Pair(
            output.copyOfRange(0, 32),
            output.copyOfRange(32, 64)
        )
    }

    private fun kdfChainKey(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
        val output = RustCore.hkdfSha256(chainKey, ByteArray(0), INFO_CHAIN.encodeToByteArray(), 64u)

        return Pair(
            output.copyOfRange(0, 32),
            output.copyOfRange(32, 64)
        )
    }

    interface RatchetStorage {
        fun saveState(sessionId: String, state: RatchetState)
        fun getState(sessionId: String): RatchetState?
        fun deleteState(sessionId: String)
    }
}
