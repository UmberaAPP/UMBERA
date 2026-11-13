package app.umbera.core.crypto

import kotlinx.datetime.Clock
import kotlinx.serialization.Serializable

import app.umbera.core.util.SyncLock
import app.umbera.core.util.withLock

/**
 * Double Ratchet Algorithm implementation for forward secrecy.
 * Based on the Signal Protocol specification.
 *
 * @param nowMs wall-clock source, injectable so the audit C-2 TTL logic is
 *   testable without waiting 30 days. Production uses the system clock.
 */
class DoubleRatchet(
    private val storage: RatchetStorage,
    private val nowMs: () -> Long = { Clock.System.now().toEpochMilliseconds() },
    /**
     * PQ ratchet (v4): my long-term ML-KEM-1024 key (public, 64 B seed); the peer
     * encapsulates to it on session start / upgrade to v4. null means no key (v4 unavailable).
     */
    private val identityKem: () -> Pair<ByteArray, ByteArray>? = { null },
) {
    companion object {
        private const val MAX_SKIP = 1000
        private const val INFO_ROOT = "root"
        private const val INFO_ROOT_PQ = "root+mlkem1024"

        // PQ ratchet: how often to offer the peer a fresh ML-KEM key: not on
        // every turn (key+ciphertext ≈ 3 KB), but once per this many new chains or once a day.
        // A KEM secret mixed in once protects the entire subsequent root against "harvest now,
        // decrypt later"; periodic refresh provides post-compromise recovery.
        internal const val PQ_EVERY_CHAINS = 20
        internal const val PQ_EVERY_MS = 24L * 60 * 60 * 1000

        /** 8-byte ML-KEM key id: tells the receiver which secret opens the ciphertext. */
        fun kemKeyId(pub: ByteArray): ByteArray = RustCore.sha256(pub).copyOfRange(0, 8)
        private const val INFO_CHAIN = "chain"
        private const val INFO_MESSAGE = "message"

        // audit C-2 FIX: MAX_SKIP only bounds ONE DH-ratchet step, but the
        // skippedMessageKeys map is copied state-to-state and PERSISTED, and its
        // only removal was a lookup hit — so a hostile-but-legitimate peer could
        // rotate its DH key while "skipping" up to MAX_SKIP-1 messages each step
        // and grow the victim's on-disk state without bound (disk/memory DoS).
        // Worse, every retained key erodes forward secrecy: the message it was
        // derived for stays decryptable for as long as the key lives. So the
        // WHOLE map gets a global cap (Signal uses 2000) with FIFO eviction of
        // the oldest entries, plus a wall-clock TTL — a key whose message hasn't
        // arrived in weeks belongs to a message that never will.
        internal const val MAX_SKIPPED_TOTAL = 2000
        internal const val SKIPPED_KEY_TTL_MS = 30L * 24 * 60 * 60 * 1000 // 30 days

        /**
         * audit C-2: apply the global bounds to a state's skipped-key map.
         * Pure function (companion) so the eviction/TTL logic is unit-testable
         * without the native crypto core.
         *
         * Legacy states (persisted before the order/timestamp bookkeeping
         * existed) have entries in the map that appear in neither
         * [RatchetState.skippedKeyOrder] nor [RatchetState.skippedKeyAddedAt].
         * Their age is unknown, so they are ranked OLDEST (evicted first under
         * cap pressure) but their TTL clock starts NOW — evicting a user's
         * pending out-of-order backlog the moment they upgrade would be worse
         * than granting old entries one grace period.
         */
        internal fun enforceSkippedKeyBounds(state: RatchetState, nowMs: Long): RatchetState {
            if (state.skippedMessageKeys.isEmpty()) {
                return if (state.skippedKeyOrder.isEmpty() && state.skippedKeyAddedAt.isEmpty()) state
                else state.copy(skippedKeyOrder = emptyList(), skippedKeyAddedAt = emptyMap())
            }
            val keys = state.skippedMessageKeys.toMutableMap()
            val stamps = state.skippedKeyAddedAt.toMutableMap()
            // Canonical FIFO order: legacy (unknown-age) entries first, then the
            // recorded insertion order; drop bookkeeping for already-consumed keys.
            val recorded = state.skippedKeyOrder.filter { it in keys }
            val recordedSet = recorded.toSet()
            val legacy = keys.keys.filter { it !in recordedSet }
            for (k in legacy) if (k !in stamps) stamps[k] = nowMs
            val order = ArrayDeque<String>(legacy.size + recorded.size)
            order.addAll(legacy)
            order.addAll(recorded)
            // 1. TTL: drop keys older than the window (forward-secrecy hygiene).
            val expired = order.filter { (stamps[it] ?: nowMs) + SKIPPED_KEY_TTL_MS <= nowMs }
            if (expired.isNotEmpty()) {
                val gone = expired.toSet()
                for (k in gone) { keys.remove(k); stamps.remove(k) }
                order.removeAll(gone)
            }
            // 2. Global cap: FIFO-evict the oldest. Newest keys always survive,
            // so fresh out-of-order messages keep decrypting.
            while (keys.size > MAX_SKIPPED_TOTAL) {
                val victim = order.removeFirst()
                keys.remove(victim)
                stamps.remove(victim)
            }
            // Keep the stamp map in lockstep with the key map (a hit-path removal
            // elsewhere might have left an orphan behind).
            stamps.keys.retainAll(keys.keys)
            return state.copy(
                skippedMessageKeys = keys,
                skippedKeyOrder = order.toList(),
                skippedKeyAddedAt = stamps
            )
        }
        /**
         * SESSION-RESTART DETECTION (lost-first-message fix, 25.09.2026).
         *
         * The v3 bootstrap has no explicit "new session" marker: the INITIATOR
         * (smaller userId) starts a session with [initializeSender] from the static
         * ECDH root and a fresh random DH key, and the RESPONDER derives the same first
         * chain from the same root. When the initiator re-logs in on a fresh device
         * (or resets after TYPEX_RRESET), it starts a NEW session while the responder
         * still holds the OLD one (or one polluted by replayed history). The old code
         * then ran a DH-ratchet step from the OLD root, the decrypt failed, and K2
         * DROPPED the message — exactly "the first message after re-login is lost,
         * the following ones arrive" (the reset made message #2 bootstrap cleanly).
         *
         * This pure predicate says whether a header that failed against [state] MAY be
         * the start of a fresh initiator session, i.e. is worth a trial decrypt against
         * a static-root bootstrap. It is deliberately narrow:
         *  - only when the PEER is the initiator (only an initiator's first chain is
         *    derivable from the static root);
         *  - the peer's fresh session has previousChainLength == 0 (its sending chain
         *    has never been rotated);
         *  - the DH key must be NEW: equal to our current remote key or to a chain we
         *    still hold skipped keys for means it is the SAME session (a duplicate or
         *    a genuinely out-of-window message), never a restart — adopting a fresh
         *    state then would throw away a healthy live session.
         * AES-GCM on the trial decrypt is what actually authenticates the restart.
         */
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

    // MDL-003 FIX: Per-session locks to prevent race conditions
    // Without this, concurrent encrypt/decrypt on the same session can corrupt ratchet state
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
        // audit C-05 FIX: keyed by "<dhPublicKeyHex>:<messageNumber>". Previously
        // this was Map<Pair<ByteArray,Int>,..> — ByteArray uses REFERENCE equality,
        // so every skipped-key lookup missed (out-of-order messages failed) and the
        // Pair<ByteArray,..> key didn't survive Gson persistence. A stable string
        // key fixes both.
        val skippedMessageKeys: Map<String, ByteArray> = emptyMap(),
        // audit C-2 FIX: bookkeeping for the global skipped-key bounds — the
        // insertion ORDER (FIFO eviction) and insertion TIME (TTL) must survive
        // persistence, or every restart would reset the eviction queue and the
        // TTL clock. Both default to empty so a state persisted BEFORE this fix
        // still deserializes (kotlinx fills a missing field from its default —
        // the existing ratchet keeps working); such legacy entries are handled
        // by [enforceSkippedKeyBounds] as oldest-with-a-grace-TTL.
        val skippedKeyOrder: List<String> = emptyList(),
        val skippedKeyAddedAt: Map<String, Long> = emptyMap(),
        // ---- PQ ratchet (v4). All fields have defaults: v3 state deserializes as
        // before and works as before while pqEnabled=false.
        /** The session mixes ML-KEM-1024 into the root (both sides on the new version). */
        val pqEnabled: Boolean = false,
        /** Fresh ML-KEM key I offer to the peer (put into every header). */
        val myKemPub: ByteArray? = null,
        val myKemSeed: ByteArray? = null,
        /** Peer's ML-KEM key: I encapsulate to it when creating my next chain. */
        val remoteKemPub: ByteArray? = null,
        /** Ciphertext and key id for my CURRENT chain, carried in each of its messages. */
        val sendKemCt: ByteArray? = null,
        val sendKemTarget: ByteArray? = null,
        /** My new chains since the last key offer / time of the last PQ step. */
        val chainsSincePq: Int = 0,
        val lastPqMs: Long = 0,
    )

    data class MessageHeader(
        val dhPublicKey: ByteArray,
        val previousChainLength: Int,
        val messageNumber: Int,
        // v4: my offered ML-KEM key / the chain ciphertext and the id of the key it was
        // made to. All null: a v3 header, byte-for-byte unchanged.
        val kemPub: ByteArray? = null,
        val kemCt: ByteArray? = null,
        val kemTarget: ByteArray? = null,
    ) {
        val isPq: Boolean get() = kemPub != null || kemCt != null

        fun toByteArray(): ByteArray {
            // 32-byte DH key + two big-endian Int32s — the old ByteBuffer layout.
            val out = ByteArray(32 + 4 + 4)
            dhPublicKey.copyInto(out, 0)
            writeIntBe(out, 32, previousChainLength)
            writeIntBe(out, 36, messageNumber)
            if (!isPq) return out
            // v4: KEM fields are bound to AES-GCM (AAD) via a hash, so they cannot be swapped unnoticed.
            val bind = byteArrayOf(0x34) +
                lenPrefixed(kemPub) + lenPrefixed(kemTarget) + lenPrefixed(kemCt)
            return out + RustCore.sha256(bind)
        }

        private fun lenPrefixed(b: ByteArray?): ByteArray {
            val n = b?.size ?: 0
            val head = byteArrayOf((n ushr 8).toByte(), n.toByte())
            return if (b == null) head else head + b
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

    /**
     * Initialize the ratchet for the sender (who initiates the conversation)
     */
    fun initializeSender(
        sessionId: String,
        sharedSecret: ByteArray,
        remotePublicKey: ByteArray,
        /** Peer's long-term ML-KEM key: the session starts as v4 (null → v3). */
        remoteIdentityKem: ByteArray? = null,
    ): RatchetState {
        val dhKeyPair = X25519.generateKeyPair()
        val dhOutput = X25519.computeSharedSecret(dhKeyPair.privateKey, remotePublicKey)

        val base = RatchetState(
            dhKeyPair = dhKeyPair,
            remoteDhPublicKey = remotePublicKey,
            rootKey = sharedSecret,
            sendingChainKey = null,
            receivingChainKey = null,
            pqEnabled = remoteIdentityKem != null,
            remoteKemPub = remoteIdentityKem,
        )
        val state = newSendingChain(base, dhOutput, sharedSecret)

        storage.saveState(sessionId, state)
        return state
    }

    /**
     * Initialize the ratchet for the receiver
     */
    fun initializeReceiver(
        sessionId: String,
        sharedSecret: ByteArray,
        dhKeyPair: X25519.KeyPair
    ): RatchetState {
        // v4 turns on by itself once the first header with KEM fields arrives (performDhRatchet).
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

    // MDL-003 FIX: Get or create a lock for a specific session
    private fun getLock(sessionId: String): SyncLock =
        sessionLocksGuard.withLock { sessionLocks.getOrPut(sessionId) { SyncLock() } }

    // audit C-05 FIX: content-based key for the skipped-message-keys map.
    private fun skipKey(dhPublicKey: ByteArray, messageNumber: Int): String {
        val sb = StringBuilder(dhPublicKey.size * 2 + 8)
        for (b in dhPublicKey) sb.append(((b.toInt() and 0xFF) + 0x100).toString(16).substring(1))
        sb.append(':').append(messageNumber)
        return sb.toString()
    }

    /**
     * Encrypt a message
     * MDL-003 FIX: Synchronized per-session to prevent race conditions
     */
    fun encrypt(sessionId: String, plaintext: ByteArray): EncryptedMessage {
        return getLock(sessionId).withLock {
            var state = storage.getState(sessionId)
                ?: throw IllegalStateException("No ratchet state for session $sessionId")

            // Generate message key from sending chain
            val (chainKey, messageKey) = kdfChainKey(state.sendingChainKey!!)

            val header = MessageHeader(
                dhPublicKey = state.dhKeyPair.publicKey,
                previousChainLength = state.previousSendingChainLength,
                messageNumber = state.sendingMessageNumber,
                kemPub = if (state.pqEnabled) state.myKemPub else null,
                kemCt = if (state.pqEnabled) state.sendKemCt else null,
                kemTarget = if (state.pqEnabled) state.sendKemTarget else null,
            )

            // Encrypt with message key
            val ciphertext = AesGcm.encrypt(plaintext, messageKey, header.toByteArray())

            // Update state
            state = state.copy(
                sendingChainKey = chainKey,
                sendingMessageNumber = state.sendingMessageNumber + 1
            )
            storage.saveState(sessionId, state)

            EncryptedMessage(header, ciphertext)
        }
    }

    /**
     * Decrypt a message
     * MDL-003 FIX: Synchronized per-session to prevent race conditions
     */
    fun decrypt(sessionId: String, message: EncryptedMessage): ByteArray {
        return getLock(sessionId).withLock {
            var state = storage.getState(sessionId)
                ?: throw IllegalStateException("No ratchet state for session $sessionId")

            // Check for skipped message keys
            val lookupKey = skipKey(message.header.dhPublicKey, message.header.messageNumber)
            val skippedKey = state.skippedMessageKeys[lookupKey]
            if (skippedKey != null) {
                val plaintext = AesGcm.decrypt(message.ciphertext, skippedKey, message.header.toByteArray())
                val newSkipped = state.skippedMessageKeys.toMutableMap()
                newSkipped.remove(lookupKey)
                // audit C-2: keep the FIFO/TTL bookkeeping in lockstep with the map.
                state = state.copy(
                    skippedMessageKeys = newSkipped,
                    skippedKeyOrder = state.skippedKeyOrder - lookupKey,
                    skippedKeyAddedAt = state.skippedKeyAddedAt - lookupKey
                )
                storage.saveState(sessionId, state)
                return@withLock plaintext
            }

            // Perform DH ratchet if needed
            if (state.remoteDhPublicKey == null ||
                !message.header.dhPublicKey.contentEquals(state.remoteDhPublicKey)) {
                state = performDhRatchet(state, message.header)
            }

            // Skip messages if needed
            state = skipMessageKeys(state, message.header.messageNumber)

            // Decrypt
            val (chainKey, messageKey) = kdfChainKey(state.receivingChainKey!!)
            val plaintext = AesGcm.decrypt(message.ciphertext, messageKey, message.header.toByteArray())

            // Update state
            state = state.copy(
                receivingChainKey = chainKey,
                receivingMessageNumber = state.receivingMessageNumber + 1
            )
            // audit C-2: sweep the TTL on every inbound message too — a session
            // that never skips again must still shed keys that have aged out
            // (otherwise the TTL would only ever fire on the skip path).
            state = enforceSkippedKeyBounds(state, nowMs())
            storage.saveState(sessionId, state)

            plaintext
        }
    }

    private fun performDhRatchet(state: RatchetState, header: MessageHeader): RatchetState {
        // Skip any remaining messages from the previous sending chain
        var newState = state
        if (state.receivingChainKey != null) {
            newState = skipMessageKeys(newState, header.previousChainLength)
        }

        // Calculate new receiving chain. v4: if the peer's chain carries an ML-KEM ciphertext,
        // its secret is mixed into the root (the peer did the same when creating it).
        val dhOutput = X25519.computeSharedSecret(state.dhKeyPair.privateKey, header.dhPublicKey)
        val kemIn = header.kemCt?.let { ct -> decapsulateFor(state, ct, header.kemTarget) }
        val (rootKey1, receivingChainKey) =
            if (kemIn != null) kdfRootKeyPq(state.rootKey, dhOutput, kemIn) else kdfRootKey(state.rootKey, dhOutput)

        // The key I offered has been used by the peer: stop offering it.
        val usedMine = kemIn != null && header.kemTarget != null && state.myKemPub != null &&
            header.kemTarget.contentEquals(kemKeyId(state.myKemPub))
        val afterRecv = newState.copy(
            remoteDhPublicKey = header.dhPublicKey,
            rootKey = rootKey1,
            receivingChainKey = receivingChainKey,
            receivingMessageNumber = 0,
            previousSendingChainLength = state.sendingMessageNumber,
            // Header with KEM fields = the peer is on v4: the session switches to v4 by itself.
            pqEnabled = state.pqEnabled || header.isPq,
            myKemPub = if (usedMine) null else state.myKemPub,
            myKemSeed = if (usedMine) null else state.myKemSeed,
            // Fresh peer key: I encapsulate to it in my next chain.
            remoteKemPub = header.kemPub ?: state.remoteKemPub,
        )

        // Generate new DH key pair and calculate sending chain
        val newDhKeyPair = X25519.generateKeyPair()
        val dhOutput2 = X25519.computeSharedSecret(newDhKeyPair.privateKey, header.dhPublicKey)
        return newSendingChain(afterRecv.copy(dhKeyPair = newDhKeyPair), dhOutput2, rootKey1)
    }

    /**
     * Create my new sending chain from root [rootKey]. v4: if I have the peer's ML-KEM key,
     * encapsulate to it and mix in the secret (the ciphertext goes in every message
     * of this chain); when due, offer the peer my fresh key.
     */
    private fun newSendingChain(state: RatchetState, dhOutput: ByteArray, rootKey: ByteArray): RatchetState {
        val now = nowMs()
        val remoteKem = if (state.pqEnabled) state.remoteKemPub else null
        val enc = remoteKem?.let { Kyber1024.encapsulate(it) }
        val (rootKey2, sendingChainKey) =
            if (enc != null) kdfRootKeyPq(rootKey, dhOutput, enc.sharedSecret) else kdfRootKey(rootKey, dhOutput)
        val chains = state.chainsSincePq + 1
        val due = state.pqEnabled && state.myKemPub == null &&
            (state.lastPqMs == 0L || chains >= PQ_EVERY_CHAINS || now - state.lastPqMs >= PQ_EVERY_MS)
        val fresh = if (due) Kyber1024.generateKeyPair() else null
        return state.copy(
            rootKey = rootKey2,
            sendingChainKey = sendingChainKey,
            sendingMessageNumber = 0,
            sendKemCt = enc?.ciphertext,
            sendKemTarget = remoteKem?.let { kemKeyId(it) },
            remoteKemPub = if (enc != null) null else state.remoteKemPub,
            myKemPub = fresh?.publicKey?.encoded ?: state.myKemPub,
            myKemSeed = fresh?.privateKey?.encoded ?: state.myKemSeed,
            chainsSincePq = if (fresh != null) 0 else chains,
            lastPqMs = if (fresh != null || enc != null) now else state.lastPqMs,
        )
    }

    /** Open an ML-KEM ciphertext with my key of id [target]: the offered fresh one or the long-term one. */
    private fun decapsulateFor(state: RatchetState, ct: ByteArray, target: ByteArray?): ByteArray {
        val mine = state.myKemPub
        if (target != null && mine != null && state.myKemSeed != null && target.contentEquals(kemKeyId(mine))) {
            return Kyber1024.decapsulate(ct, state.myKemSeed)
        }
        val identity = identityKem() ?: throw IllegalStateException("ratchet v4: no ML-KEM key to open the chain")
        if (target != null && !target.contentEquals(kemKeyId(identity.first))) {
            throw IllegalStateException("ratchet v4: chain is encapsulated to an unknown ML-KEM key")
        }
        return Kyber1024.decapsulate(ct, identity.second)
    }

    /**
     * Upgrade an existing session to v4 (the peer has updated). My next
     * chain encapsulates to their long-term ML-KEM key [remoteIdentityKem]. Breaks nothing:
     * until the chain changes, messages flow as before.
     */
    fun enablePq(sessionId: String, remoteIdentityKem: ByteArray) {
        getLock(sessionId).withLock {
            val st = storage.getState(sessionId) ?: return@withLock
            if (st.pqEnabled) return@withLock
            storage.saveState(sessionId, st.copy(pqEnabled = true, remoteKemPub = st.remoteKemPub ?: remoteIdentityKem))
        }
    }

    /**
     * The peer no longer understands v4 (older version): continue without ML-KEM fields.
     * A root already mixed with ML-KEM stays; subsequent chains are plain X25519 steps (v3).
     */
    fun disablePq(sessionId: String) {
        getLock(sessionId).withLock {
            val st = storage.getState(sessionId) ?: return@withLock
            if (!st.pqEnabled) return@withLock
            storage.saveState(sessionId, st.copy(
                pqEnabled = false, myKemPub = null, myKemSeed = null, remoteKemPub = null,
                sendKemCt = null, sendKemTarget = null,
            ))
        }
    }

    /** Is v4 enabled for this session? */
    fun isPqEnabled(sessionId: String): Boolean = storage.getState(sessionId)?.pqEnabled == true

    private fun skipMessageKeys(state: RatchetState, until: Int): RatchetState {
        if (state.receivingChainKey == null) return state
        if (state.remoteDhPublicKey == null) return state
        if (until - state.receivingMessageNumber > MAX_SKIP) {
            throw IllegalStateException("Too many skipped messages")
        }

        var chainKey: ByteArray = state.receivingChainKey
        val skipped = state.skippedMessageKeys.toMutableMap()
        // audit C-2: record insertion order + time for every new key so the
        // global FIFO cap and the TTL can do their job across restarts.
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

        // audit C-2: enforce the GLOBAL bounds (cap 2000 FIFO + TTL) — MAX_SKIP
        // above only limited this single step, not the accumulated map.
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
        // HKDF in the Rust core; ikm=dhOutput, salt=rootKey — byte-identical to
        // the previous BC call (locked by the double_ratchet golden).
        val output = RustCore.hkdfSha256(dhOutput, rootKey, INFO_ROOT.encodeToByteArray(), 64u)

        return Pair(
            output.copyOfRange(0, 32),  // New root key
            output.copyOfRange(32, 64)  // Chain key
        )
    }

    /** v4: HKDF(ikm = DH ‖ ML-KEM secret, salt = root) with a separate label; hybrid: the root
     *  stays secret unless BOTH (X25519 and ML-KEM-1024) are broken. */
    private fun kdfRootKeyPq(rootKey: ByteArray, dhOutput: ByteArray, kemSecret: ByteArray): Pair<ByteArray, ByteArray> {
        val output = RustCore.hkdfSha256(dhOutput + kemSecret, rootKey, INFO_ROOT_PQ.encodeToByteArray(), 64u)
        return Pair(output.copyOfRange(0, 32), output.copyOfRange(32, 64))
    }

    private fun kdfChainKey(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
        // Empty salt == BC's null salt == RFC 5869 HashLen zeros (HMAC pads the
        // key with zeros either way) — byte-identical, golden-locked.
        val output = RustCore.hkdfSha256(chainKey, ByteArray(0), INFO_CHAIN.encodeToByteArray(), 64u)

        return Pair(
            output.copyOfRange(0, 32),  // New chain key
            output.copyOfRange(32, 64)  // Message key
        )
    }

    interface RatchetStorage {
        fun saveState(sessionId: String, state: RatchetState)
        fun getState(sessionId: String): RatchetState?
        fun deleteState(sessionId: String)
    }
}
