package app.umbera.core.crypto.mls

import app.umbera.core.crypto.MlsCommitBundle
import app.umbera.core.crypto.MlsEngine
import app.umbera.core.crypto.MlsIncoming
import app.umbera.core.crypto.MlsMemberInfo
import app.umbera.core.crypto.MlsSuites
import app.umbera.core.crypto.RustCore
import app.umbera.core.data.repository.GroupRejoinPolicy
import app.umbera.core.util.B64
import app.umbera.core.util.WireJson
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import app.umbera.core.crypto.SecureKeyStoreCommon
import app.umbera.core.crypto.secureRandomBytes
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Device-side manager for the native MLS (RFC 9420) group crypto. Owns ONE MLS client
 * PER GROUP, each with its own random per-group identity (`memberId`) so the same person
 * is NOT linkable across groups. Every mutating operation re-serializes the client state
 * into [SecureKeyStoreCommon] (encrypted, client-only — never the server).
 *
 * All group key agreement happens here; the bytes it returns are handed to the anonymous
 * pairwise-rendezvous fan-out (transport), and bytes received are fed back in.
 *
 * KMP: moved to :shared unchanged over the platform-neutral [MlsEngine] facade
 * (Android delegates to the same UniFFI bindings as before — byte-identical).
 */
class MlsManager(
    private val secureKeyStorage: SecureKeyStoreCommon
) {
    private val mutex = Mutex()
    private val cache = HashMap<String, MlsEngine>()
    /** Own sent packets per group since the last bookkeeping write ([GroupRekeyPolicy]). */
    private val sentSince = HashMap<String, Int>()

    // Logging out wipes the on-disk state. Otherwise the in-memory copy would keep decrypting
    // groups the person no longer has, for as long as the process lives.
    private val accountReset = app.umbera.core.data.AccountScopedState.register { mutex.withLock { cache.clear(); sentSince.clear() } }

    /**
     * [keyPackage] — legacy suite (taken by an admin on an old version), [keyPackageXw] — X-Wing
     * (same leaf, taken by the admin of an X-Wing group). null — the core did not issue an X-Wing package.
     */
    data class JoinTicket(val memberId: ByteArray, val keyPackage: ByteArray, val keyPackageXw: ByteArray? = null)

    private fun hex(b: ByteArray): String = b.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    private fun groupKey(gid: ByteArray) = "g_${hex(gid)}"
    private fun pendingKey(memberId: ByteArray) = "p_${hex(memberId)}"

    private fun randomMemberId(): ByteArray = secureRandomBytes(32)

    /** Load a cached/persisted client for a state key, or null if none exists. */
    private fun load(stateKey: String): MlsEngine? {
        cache[stateKey]?.let { return it }
        val blob = secureKeyStorage.getMlsState(stateKey) ?: return null
        return MlsEngine.fromState(blob).also { cache[stateKey] = it }
    }

    private fun persist(stateKey: String, client: MlsEngine) {
        secureKeyStorage.setMlsState(stateKey, client.exportState())
        cache[stateKey] = client
    }

    /**
     * Create a brand-new group with a fresh per-group identity. Returns our memberId.
     * New groups use X-Wing (X25519 + ML-KEM-768). If the first invitee to arrive runs an old
     * version, the group is recreated with the legacy suite ([recreateAlone] — while only we are in it) or
     * moved via [regroup].
     */
    suspend fun createGroup(gid: ByteArray, suite: UShort = MlsSuites.XWING): ByteArray = mutex.withLock {
        val memberId = randomMemberId()
        val client = MlsEngine(memberId)
        client.createGroupFor(gid, suite)
        persist(groupKey(gid), client)
        memberId
    }

    /**
     * Begin joining a group we were invited to: make a fresh per-group identity + a
     * KeyPackage to hand to the admin. The pending client is kept until the Welcome
     * arrives (we don't yet know the gid).
     */
    suspend fun prepareJoin(): JoinTicket = mutex.withLock {
        val memberId = randomMemberId()
        val client = MlsEngine(memberId)
        val kp = client.generateKeyPackage()
        val kpXw = runCatching { client.generateKeyPackageFor(MlsSuites.XWING) }.getOrNull()
        persist(pendingKey(memberId), client)
        JoinTicket(memberId, kp, kpXw)
    }

    /** Linked devices: own desktop's request to join group [gid] next to the phone's leaf [primaryMemberId]. */
    data class SiblingTicket(val memberId: ByteArray, val keyPackage: ByteArray, val deviceSig: ByteArray, val keyPackageXw: ByteArray? = null)

    /**
     * Desktop: a fresh leaf with a random memberId (groups are not linkable to each other), a KeyPackage and
     * a link signature "phone leaf ↔ this leaf" made with the new leaf's key.
     * The pending client is kept, as in [prepareJoin], until the Welcome from the phone.
     */
    suspend fun prepareSiblingJoin(gid: ByteArray, primaryMemberId: ByteArray): SiblingTicket = mutex.withLock {
        val memberId = randomMemberId()
        val client = MlsEngine(memberId)
        val kp = client.generateKeyPackage()
        val kpXw = runCatching { client.generateKeyPackageFor(MlsSuites.XWING) }.getOrNull()
        val sig = client.siblingSign(gid, primaryMemberId, memberId)
        persist(pendingKey(memberId), client)
        SiblingTicket(memberId, kp, sig, kpXw)
    }

    /** Phone: link signature with own leaf in group [gid]. */
    suspend fun siblingSign(gid: ByteArray, primaryMemberId: ByteArray, deviceMemberId: ByteArray): ByteArray = mutex.withLock {
        (load(groupKey(gid)) ?: error("no MLS group")).siblingSign(gid, primaryMemberId, deviceMemberId)
    }

    /** Verify a link between two leaves against the keys of the group's current tree. */
    suspend fun siblingVerify(gid: ByteArray, primaryMemberId: ByteArray, deviceMemberId: ByteArray, primarySig: ByteArray, deviceSig: ByteArray): Boolean = mutex.withLock {
        val client = load(groupKey(gid)) ?: return@withLock false
        runCatching { client.siblingVerify(gid, primaryMemberId, deviceMemberId, primarySig, deviceSig) }.getOrDefault(false)
    }

    /** How many leaves the group may have now (100 — all on the new core, otherwise 20). */
    suspend fun leafLimit(gid: ByteArray): Int = mutex.withLock {
        (load(groupKey(gid)) ?: error("no MLS group")).leafLimit(gid).toInt()
    }

    /** Whether our leaf carries the new-core marker (if not, run [updateKeys] once and send the Commit). */
    suspend fun ownLeafMarked(gid: ByteArray): Boolean = mutex.withLock {
        (load(groupKey(gid)) ?: error("no MLS group")).ownLeafMarked(gid)
    }

    /** Finish joining once the admin's Welcome arrives. Returns the joined group id. */
    suspend fun completeJoin(memberId: ByteArray, welcome: ByteArray, expectedGid: ByteArray? = null): ByteArray = mutex.withLock {
        val pk = pendingKey(memberId)
        val client = load(pk) ?: error("no pending MLS join for this memberId")
        val gid = client.processWelcome(welcome)
        // A Welcome for a different group, or on top of a group we are already in, is
        // rejected BEFORE the state is written (otherwise a foreign Welcome overwrote our group).
        if (expectedGid != null && !gid.contentEquals(expectedGid)) error("Welcome is for another group")
        // "Already in the group" is decided by the caller (GroupRepositoryImpl.handleInvite): it wipes the old
        // state only on an invite from that group's admin.
        if (cache.containsKey(groupKey(gid)) || secureKeyStorage.getMlsState(groupKey(gid)) != null) error("already in this group")
        persist(groupKey(gid), client)
        cache.remove(pk)
        secureKeyStorage.removeMlsState(pk)
        gid
    }

    /** Add members by their KeyPackages → Commit (existing) + Welcome (new). [op]: see [CommitMark.op]. */
    suspend fun addMembers(gid: ByteArray, keyPackages: List<ByteArray>, op: String? = null, nowMs: Long = 0L): MlsCommitBundle = mutex.withLock {
        val client = load(groupKey(gid)) ?: error("no MLS group")
        val before = client.exportState()
        val epoch = client.epoch(gid).toLong()
        val bundle = client.addMembers(gid, keyPackages)
        pushMark(gid, CommitMark(epoch, sha(bundle.commit), B64.encode(before), nowMs, op), nowMs)
        persist(groupKey(gid), client)
        bundle
    }

    /** Remove members by leaf index → Commit to fan out. */
    suspend fun removeMembers(gid: ByteArray, leafIndices: List<UInt>, op: String? = null, nowMs: Long = 0L): ByteArray = mutex.withLock {
        val client = load(groupKey(gid)) ?: error("no MLS group")
        val before = client.exportState()
        val epoch = client.epoch(gid).toLong()
        val commit = client.removeMembers(gid, leafIndices)
        pushMark(gid, CommitMark(epoch, sha(commit), B64.encode(before), nowMs, op), nowMs)
        persist(groupKey(gid), client)
        commit
    }

    /**
     * The person's previous device leaves, the new one joins: two Commits in a row. [beforePersist] receives them
     * before the state is written to disk and must store them for resending: a crash between the write and
     * the broadcast would otherwise leave the admin on an epoch nobody else has.
     * The new leaf must carry [expectedMemberId], otherwise everything is rolled back.
     */
    suspend fun replaceMember(
        gid: ByteArray, leafIndex: UInt, keyPackage: ByteArray, expectedMemberId: ByteArray,
        op: String, nowMs: Long,
        beforePersist: (removeCommit: ByteArray, add: MlsCommitBundle, epochAfter: Long) -> Unit,
    ) = mutex.withLock {
        val key = groupKey(gid)
        val client = load(key) ?: error("no MLS group")
        val before = client.exportState()
        val e0 = client.epoch(gid).toLong()
        try {
            val c1 = client.removeMembers(gid, listOf(leafIndex))
            val mid = client.exportState()
            val bundle = client.addMembers(gid, listOf(keyPackage))
            check(client.members(gid).any { it.identity.contentEquals(expectedMemberId) }) { "KeyPackage identity mismatch" }
            beforePersist(c1, bundle, client.epoch(gid).toLong())
            pushMark(gid, CommitMark(e0, sha(c1), B64.encode(before), nowMs, null), nowMs)
            pushMark(gid, CommitMark(e0 + 1, sha(bundle.commit), B64.encode(mid), nowMs, op), nowMs)
            persist(key, client)
        } catch (t: Throwable) {
            // The previous state is on disk, no longer in memory.
            cache[key] = MlsEngine.fromState(before)
            throw t
        }
    }

    /**
     * Update of own leaf (Commit with UpdatePath, post-compromise security) → Commit to broadcast.
     * The state is saved before the Commit ([CommitMark], as for add/remove) — otherwise a Commit
     * that lost a race (another member updated at the same epoch) could not be replayed, and the device
     * would be left alone on its own branch. [op] — what to restore on losing (GroupRepositoryImpl: "rekey").
     * Schedule bookkeeping ([GroupRekeyPolicy]) starts over.
     */
    suspend fun updateKeys(gid: ByteArray, op: String? = null, nowMs: Long = 0L): ByteArray = mutex.withLock {
        val client = load(groupKey(gid)) ?: error("no MLS group")
        val before = client.exportState()
        val epoch = client.epoch(gid).toLong()
        val commit = client.updateKeys(gid)
        if (nowMs > 0L) {
            pushMark(gid, CommitMark(epoch, sha(commit), B64.encode(before), nowMs, op), nowMs)
            saveRekey(gid, GroupRekeyPolicy.afterUpdate(nowMs, ::jitterRandom))
        }
        persist(groupKey(gid), client)
        commit
    }

    /** Encrypt an application payload for the group (ratchet advances → state persisted). */
    suspend fun encrypt(gid: ByteArray, plaintext: ByteArray): ByteArray = mutex.withLock {
        val client = load(groupKey(gid)) ?: error("no MLS group")
        val ct = client.encrypt(gid, plaintext)
        persist(groupKey(gid), client)
        countOwnSend(gid)
        ct
    }

    // ── own-leaf update schedule (GroupRekeyPolicy) ─────────────────────────────
    private fun rekeyKey(gid: ByteArray) = "pu_${hex(gid)}"
    private fun jitterRandom(bound: Long): Long = if (bound <= 0L) 0L else kotlin.random.Random.nextLong(bound)

    private fun readRekey(gid: ByteArray): GroupRekeyPolicy.State? =
        secureKeyStorage.getMlsState(rekeyKey(gid))?.let { b ->
            runCatching { WireJson.json.decodeFromString<GroupRekeyPolicy.State>(b.decodeToString()) }.getOrNull()
        }

    private fun saveRekey(gid: ByteArray, s: GroupRekeyPolicy.State) {
        sentSince.remove(hex(gid))
        secureKeyStorage.setMlsState(rekeyKey(gid), WireJson.json.encodeToString(s).encodeToByteArray())
    }

    /** Own packets are counted in memory and written to disk every [SENT_FLUSH] (a write per message is wasteful). */
    private fun countOwnSend(gid: ByteArray) {
        val h = hex(gid)
        val n = (sentSince[h] ?: 0) + 1
        if (n < SENT_FLUSH) { sentSince[h] = n; return }
        val s = readRekey(gid) ?: run { sentSince[h] = n; return }
        saveRekey(gid, s.copy(sentSince = s.sentSince + n))
    }

    /** Leaf bookkeeping with packets not yet flushed from memory. No record — one is created with [GroupRekeyPolicy.initial]. */
    suspend fun rekeyState(gid: ByteArray, nowMs: Long): GroupRekeyPolicy.State = mutex.withLock {
        val s = readRekey(gid) ?: GroupRekeyPolicy.initial(nowMs, ::jitterRandom).also { saveRekey(gid, it) }
        s.copy(sentSince = s.sentSince + (sentSince[hex(gid)] ?: 0))
    }

    /** Our update Commit lost a race: schedule a retry soon. */
    suspend fun rekeyLostRace(gid: ByteArray, nowMs: Long) = mutex.withLock {
        val s = readRekey(gid) ?: GroupRekeyPolicy.initial(nowMs, ::jitterRandom)
        saveRekey(gid, GroupRekeyPolicy.afterLostRace(s, nowMs, ::jitterRandom))
    }

    /** Feed an inbound MLS message: decrypts application payloads / applies Commits. */
    suspend fun processIncoming(gid: ByteArray, message: ByteArray): MlsIncoming = mutex.withLock {
        val client = load(groupKey(gid)) ?: error("no MLS group")
        val result = client.processIncoming(gid, message)
        persist(groupKey(gid), client)
        result
    }

    /** Result of [processIncomingTracked]. [lostOps]: our membership changes that lost a race. */
    class Tracked(
        val incoming: MlsIncoming,
        val rolledBack: Boolean = false,
        val lostOps: List<String> = emptyList(),
        /**
         * Atomicity (OpenMLS 0.9 rejects replays): for an application message the group
         * state is written to disk only by this call — AFTER the message is stored in the database. A crash before it
         * leaves the previous state on disk, so the packet is reread and decrypted again (the duplicate in the database is dropped
         * by message id). null — the state is already written.
         */
        val commit: (suspend () -> Unit)? = null,
    )

    /**
     * Regular processing plus handling of late packets. The server does not order groups, so two
     * admins can Commit at the same epoch. Before each Commit we keep the state
     * ([CommitMark]). A packet that does not fit the current epoch is tried against these states:
     * a message decrypts there and is not lost; a Commit means a race: the smaller hash wins for everyone,
     * the losing branch is discarded. A member on an old version does not resolve races: it stays on the first branch.
     */
    suspend fun processIncomingTracked(
        gid: ByteArray, message: ByteArray, nowMs: Long,
        // Commit/Proposal only from these leaves (the envelope's ML-DSA signer). null — as before.
        handshakeSenders: List<ByteArray>? = null,
    ): Tracked = mutex.withLock {
        val key = groupKey(gid)
        val client = load(key) ?: error("no MLS group")
        val before = client.exportState()
        val epoch = client.epoch(gid).toLong()
        val result = client.feed(gid, message, handshakeSenders)
        when (result) {
            is MlsIncoming.CommitApplied -> {
                pushMark(gid, CommitMark(epoch, sha(message), B64.encode(before), nowMs), nowMs)
                persist(key, client)
                Tracked(result)
            }
            is MlsIncoming.Ignored -> resolveLate(gid, message, nowMs, handshakeSenders) ?: fromRetired(gid, message, nowMs) ?: Tracked(result)
            is MlsIncoming.Application -> {
                // In memory — the new state (subsequent packets build on it); on disk — after the write.
                cache[key] = client
                Tracked(result, commit = { mutex.withLock { cache[key]?.let { persist(key, it) } } })
            }
            else -> { persist(key, client); Tracked(result) }
        }
    }

    /** Without a list — the legacy call byte for byte; with a list — the core does not merge another leaf's Commit. */
    private fun MlsEngine.feed(gid: ByteArray, message: ByteArray, handshakeSenders: List<ByteArray>?): MlsIncoming =
        if (handshakeSenders == null) processIncoming(gid, message)
        else processIncomingWithSender(gid, message, handshakeSenders).incoming

    private fun resolveLate(gid: ByteArray, message: ByteArray, nowMs: Long, handshakeSenders: List<ByteArray>? = null): Tracked? {
        val marks = loadMarks(gid, nowMs)
        for (i in marks.indices.reversed()) {
            val m = marks[i]
            val trial = runCatching { MlsEngine.fromState(B64.decode(m.s)) }.getOrNull() ?: continue
            val r = runCatching { trial.feed(gid, message, handshakeSenders) }.getOrNull()
            when (r) {
                is MlsIncoming.Application -> { trial.close(); return Tracked(r) }
                is MlsIncoming.CommitApplied -> {
                    val h = sha(message)
                    if (!GroupRejoinPolicy.commitWins(h, m.h)) { trial.close(); return Tracked(MlsIncoming.Ignored) }
                    val lost = marks.subList(i, marks.size).mapNotNull { it.op }
                    saveMarks(gid, marks.subList(0, i) + m.copy(h = h, op = null, t = nowMs))
                    persist(groupKey(gid), trial)
                    return Tracked(r, rolledBack = true, lostOps = lost)
                }
                else -> trial.close()
            }
        }
        return null
    }

    // ── Moving a group to another suite (X-Wing ↔ legacy) ─────────────────────────
    // A group's suite cannot change in MLS, so the group is recreated with the same gid and the same memberIds: the initiator
    // (admin) builds a new group from pre-published key packages of all leaves and sends the Welcome
    // as a message of the PREVIOUS group. Chat history lives in the app database and is untouched. The previous state
    // stays "retired" for [RETIRED_TTL_MS]: it decrypts late messages of the previous group.
    // Old versions do not take part: moving to X-Wing happens only when ALL leaves carry the X-Wing core marker.

    private fun regroupKey(gid: ByteArray, suite: UShort) = "rg_${hex(gid)}_$suite"
    private fun retiredKey(gid: ByteArray) = "go_${hex(gid)}"
    private fun retiredMetaKey(gid: ByteArray) = "gom_${hex(gid)}"

    @Serializable
    private data class RetiredMeta(val t: Long, val fromEpoch: Long, val h: String)

    /** Group suite. */
    suspend fun groupSuite(gid: ByteArray): UShort = mutex.withLock {
        (load(groupKey(gid)) ?: error("no MLS group")).groupCiphersuite(gid)
    }

    /** All leaves run a core with X-Wing (so the group can be moved to X-Wing and back). */
    suspend fun allSupportXwing(gid: ByteArray): Boolean = mutex.withLock {
        val c = load(groupKey(gid)) ?: return@withLock false
        runCatching { c.membersSupport(gid, MlsSuites.XWING) }.getOrDefault(false)
    }

    /** Suite the group can be moved to. */
    fun otherSuite(suite: UShort): UShort = if (suite == MlsSuites.XWING) MlsSuites.LEGACY else MlsSuites.XWING

    /**
     * Our leaf's key package for a future move to [suite]: a pending client with the same memberId is kept until
     * the move happens. Each call issues a fresh package (the previous pending one is replaced).
     */
    suspend fun regroupKeyPackage(gid: ByteArray, suite: UShort): ByteArray = mutex.withLock {
        val c = (load(groupKey(gid)) ?: error("no MLS group")).spawnSameIdentity()
        val kp = c.generateKeyPackageFor(suite)
        secureKeyStorage.setMlsState(regroupKey(gid, suite), c.exportState())
        c.close()
        kp
    }

    /** Move result at the initiator: a previous-group message with the Welcome (to broadcast) and the epoch moved from. */
    class RegroupResult(val oldGroupMessage: ByteArray, val fromEpoch: Long, val hash: String)

    /**
     * Initiator: a new group in suite [suite] from [keyPackages] (one per leaf except ours; package memberIds
     * must match the membership of the previous group — otherwise rejected, nothing changes).
     */
    suspend fun regroup(
        gid: ByteArray, suite: UShort, keyPackages: List<ByteArray>, nowMs: Long,
        plaintextFor: (welcome: ByteArray, fromEpoch: Long) -> ByteArray,
    ): RegroupResult = mutex.withLock {
        val key = groupKey(gid)
        val old = load(key) ?: error("no MLS group")
        val oldIds = old.members(gid).map { hex(it.identity) }.toSet()
        val fromEpoch = old.epoch(gid).toLong()
        val fresh = old.spawnSameIdentity()
        fresh.createGroupFor(gid, suite)
        val welcome = if (keyPackages.isEmpty()) ByteArray(0) else fresh.addMembers(gid, keyPackages).welcome
        val newIds = fresh.members(gid).map { hex(it.identity) }.toSet()
        if (newIds != oldIds) { fresh.close(); error("regroup: roster mismatch (${newIds.size} vs ${oldIds.size})") }
        val h = sha(welcome + fromEpoch.toString().encodeToByteArray())
        // The Welcome goes out as a message of the PREVIOUS group: members are still in it.
        val msg = old.encrypt(gid, plaintextFor(welcome, fromEpoch))
        retire(gid, old, fromEpoch, h, nowMs)
        persist(key, fresh)
        RegroupResult(msg, fromEpoch, h)
    }

    /**
     * Member: accept a move Welcome. true — the group is moved (or already moved by this same Welcome).
     * With two simultaneous moves from one epoch the smaller hash wins — the same for everyone.
     */
    suspend fun acceptRegroup(gid: ByteArray, suite: UShort, welcome: ByteArray, fromEpoch: Long, nowMs: Long): Boolean = mutex.withLock {
        val key = groupKey(gid)
        val h = sha(welcome + fromEpoch.toString().encodeToByteArray())
        val meta = retiredMeta(gid, nowMs)
        // Base — the previous group: the current one if no move has happened yet, or a "retired" one at the same epoch (two moves racing).
        var base: MlsEngine = when {
            meta == null -> load(key) ?: return@withLock false
            meta.fromEpoch == fromEpoch -> {
                if (h == meta.h) return@withLock true
                if (h > meta.h) return@withLock false
                MlsEngine.fromState(secureKeyStorage.getMlsState(retiredKey(gid)) ?: return@withLock false)
            }
            else -> load(key) ?: return@withLock false
        }
        if (meta == null || meta.fromEpoch != fromEpoch) {
            if (base.groupCiphersuite(gid) == suite) return@withLock false
            if (base.epoch(gid).toLong() != fromEpoch) {
                // A Commit (our regular leaf update or someone else's) crossed with the move —
                // we are already at a later epoch. The move was built from [fromEpoch]: the base is the saved state of that epoch
                // (the mark before the Commit); the Commit after it goes away with the previous group.
                val m = loadMarks(gid, nowMs).lastOrNull { it.e == fromEpoch } ?: return@withLock false
                base = runCatching { MlsEngine.fromState(B64.decode(m.s)) }.getOrNull() ?: return@withLock false
                if (base.epoch(gid).toLong() != fromEpoch || base.groupCiphersuite(gid) == suite) return@withLock false
            }
        }
        val pending = secureKeyStorage.getMlsState(regroupKey(gid, suite)) ?: return@withLock false
        val fresh = MlsEngine.fromState(pending)
        val joined = runCatching { fresh.processWelcome(welcome) }.getOrNull()
        if (joined == null || !joined.contentEquals(gid) || fresh.groupCiphersuite(gid) != suite) { fresh.close(); return@withLock false }
        val oldIds = base.members(gid).map { hex(it.identity) }.toSet()
        if (fresh.members(gid).map { hex(it.identity) }.toSet() != oldIds) { fresh.close(); return@withLock false }
        retire(gid, base, fromEpoch, h, nowMs)
        persist(key, fresh)
        true
    }

    private fun retire(gid: ByteArray, old: MlsEngine, fromEpoch: Long, h: String, nowMs: Long) {
        secureKeyStorage.setMlsState(retiredKey(gid), old.exportState())
        secureKeyStorage.setMlsState(retiredMetaKey(gid), WireJson.json.encodeToString(RetiredMeta(nowMs, fromEpoch, h)).encodeToByteArray())
        // Commit race marks belong to the previous group.
        secureKeyStorage.removeMlsState(marksKey(gid))
    }

    private fun retiredMeta(gid: ByteArray, nowMs: Long): RetiredMeta? {
        val m = secureKeyStorage.getMlsState(retiredMetaKey(gid))?.let {
            runCatching { WireJson.json.decodeFromString<RetiredMeta>(it.decodeToString()) }.getOrNull()
        } ?: return null
        if (nowMs - m.t > RETIRED_TTL_MS) {
            secureKeyStorage.removeMlsState(retiredKey(gid))
            secureKeyStorage.removeMlsState(retiredMetaKey(gid))
            return null
        }
        return m
    }

    /** A late message of the previous group (before the move): decryption only, Commits of the previous group are not applied. */
    private fun fromRetired(gid: ByteArray, message: ByteArray, nowMs: Long): Tracked? {
        retiredMeta(gid, nowMs) ?: return null
        val blob = secureKeyStorage.getMlsState(retiredKey(gid)) ?: return null
        val old = runCatching { MlsEngine.fromState(blob) }.getOrNull() ?: return null
        val r = runCatching { old.processIncoming(gid, message) }.getOrNull()
        if (r is MlsIncoming.Application) {
            secureKeyStorage.setMlsState(retiredKey(gid), old.exportState())
            old.close()
            return Tracked(r)
        }
        old.close()
        return null
    }

    /** While only we are in the group (and no own desktops): recreate it in place with suite [suite], without a move. */
    suspend fun recreateAlone(gid: ByteArray, suite: UShort): Boolean = mutex.withLock {
        val key = groupKey(gid)
        val c = load(key) ?: return@withLock false
        if (c.members(gid).size != 1) return@withLock false
        val fresh = c.spawnSameIdentity()
        fresh.createGroupFor(gid, suite)
        secureKeyStorage.removeMlsState(marksKey(gid))
        persist(key, fresh)
        true
    }

    /** State before a Commit. [op]: our action (GroupRepositoryImpl JSON) to restore on losing a race. */
    @Serializable
    private data class CommitMark(val e: Long, val h: String, val s: String, val t: Long, val op: String? = null)

    private fun marksKey(gid: ByteArray) = "cm_${hex(gid)}"
    private fun sha(b: ByteArray) = hex(RustCore.sha256(b))

    private fun loadMarks(gid: ByteArray, nowMs: Long): List<CommitMark> =
        secureKeyStorage.getMlsState(marksKey(gid))?.let { blob ->
            runCatching { WireJson.json.decodeFromString<List<CommitMark>>(blob.decodeToString()) }.getOrNull()
        }.orEmpty().filter { nowMs - it.t < MARK_TTL_MS }

    private fun saveMarks(gid: ByteArray, marks: List<CommitMark>) =
        secureKeyStorage.setMlsState(marksKey(gid), WireJson.json.encodeToString(marks).encodeToByteArray())

    private fun pushMark(gid: ByteArray, m: CommitMark, nowMs: Long) =
        saveMarks(gid, (loadMarks(gid, nowMs) + m).takeLast(MAX_MARKS))

    /** A ticket no longer needed: the person accepted the invite again. */
    suspend fun dropPendingJoin(memberId: ByteArray) = mutex.withLock {
        cache.remove(pendingKey(memberId))
        secureKeyStorage.removeMlsState(pendingKey(memberId))
    }

    /** Per-epoch exported secret (e.g. a conference media key). Rotates on rekey. */
    suspend fun exportSecret(gid: ByteArray, label: String, length: UInt): ByteArray = mutex.withLock {
        val client = load(groupKey(gid)) ?: error("no MLS group")
        client.exportSecret(gid, label, length)
    }

    suspend fun epoch(gid: ByteArray): Long = mutex.withLock {
        (load(groupKey(gid)) ?: error("no MLS group")).epoch(gid).toLong()
    }

    suspend fun members(gid: ByteArray): List<MlsMemberInfo> = mutex.withLock {
        (load(groupKey(gid)) ?: error("no MLS group")).members(gid)
    }

    /** True if we hold MLS state for this group. */
    fun hasGroup(gid: ByteArray): Boolean =
        cache.containsKey(groupKey(gid)) || secureKeyStorage.getMlsState(groupKey(gid)) != null

    /** Forget a group's crypto state (on leave / wipe). */
    suspend fun forget(gid: ByteArray) = mutex.withLock {
        cache.remove(groupKey(gid))
        secureKeyStorage.removeMlsState(groupKey(gid))
        secureKeyStorage.removeMlsState(marksKey(gid))
        secureKeyStorage.removeMlsState(retiredKey(gid))
        secureKeyStorage.removeMlsState(retiredMetaKey(gid))
        secureKeyStorage.removeMlsState(regroupKey(gid, MlsSuites.XWING))
        secureKeyStorage.removeMlsState(regroupKey(gid, MlsSuites.LEGACY))
        secureKeyStorage.removeMlsState(rekeyKey(gid))
        sentSince.remove(hex(gid))
    }

    private companion object {
        const val SENT_FLUSH = 10
        const val MAX_MARKS = 8
        /** Old epoch secrets are kept briefly: the same cost as max_past_epochs in MLS. */
        const val MARK_TTL_MS = 3L * 24 * 60 * 60 * 1000
        /** The previous group after a suite move is kept as long: late messages still decrypt. */
        const val RETIRED_TTL_MS = 3L * 24 * 60 * 60 * 1000
    }
}
