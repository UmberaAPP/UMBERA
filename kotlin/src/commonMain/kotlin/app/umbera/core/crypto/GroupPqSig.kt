package app.umbera.core.crypto

/**
 * Second, post-quantum authenticity layer for groups.
 *
 *  - Commit / Proposal / Welcome / control frames (wireKind="control"): full ML-DSA-65 signature over the
 *    MLS frame (which already carries Ed25519). The ML-DSA key is NOT put in the envelope: the receiver uses the sender's
 *    pinned key (directory + transparency log).
 *  - Application messages: a per-epoch sender hash chain (32 B `h_{i-1}` in the envelope) and a `pqcp` checkpoint
 *    signature every [CHECKPOINT_EVERY] messages or after [CHECKPOINT_IDLE_MS] of silence.
 *
 * Pure logic, no network or storage: everything external (keys, time) is passed in as parameters.
 * Enabled only by [SecurityRollout.groupPqSig]; when disabled it is never called.
 */
object GroupPqSig {
    const val VERSION = 1
    const val CHECKPOINT_EVERY = 20
    const val CHECKPOINT_IDLE_MS = 30_000L
    const val HASH_LEN = 32
    /** Context of the device hybrid signature (Ed25519 + ML-DSA-65 from the desktop seed, DeviceLinkCore.deviceSign): a separate label,
     *  so a group signature cannot pass as a device-envelope signature and vice versa. */
    const val DEVICE_CONTEXT = "umbera-grp-pqsig-v1/dev"

    private val COMMIT_LABEL = "umbera-grp-pqsig-v1".encodeToByteArray()
    private val CHAIN_LABEL = "umbera-grp-chain-v1".encodeToByteArray()
    private val GENESIS_LABEL = "umbera-grp-chain-genesis-v1".encodeToByteArray()

    private fun sha(b: ByteArray): ByteArray = RustCore.sha256(b)

    /** Length-prefixed concatenation: field boundaries are unambiguous (bytes cannot "leak" from gid into kind etc.). */
    private class W {
        private val parts = ArrayList<ByteArray>()
        fun raw(b: ByteArray) = apply { parts += b }
        fun lv(b: ByteArray) = apply { parts += u32(b.size); parts += b }
        fun lv(s: String) = lv(s.encodeToByteArray())
        fun u64(v: Long) = apply { parts += ByteArray(8) { i -> (v ushr (56 - 8 * i)).toByte() } }
        fun u32v(v: Int) = apply { parts += u32(v) }
        fun bytes(): ByteArray {
            val out = ByteArray(parts.sumOf { it.size }); var o = 0
            for (p in parts) { p.copyInto(out, o); o += p.size }
            return out
        }
    }
    private fun u32(v: Int) = ByteArray(4) { i -> (v ushr (24 - 8 * i)).toByte() }
    private fun optHash(b: ByteArray?): ByteArray = if (b == null) ByteArray(0) else sha(b)

    // ── 1. Full signature of Commit / Proposal / Welcome / control frames ─────────────────────────────

    /**
     * What is signed. `mls` is exactly the MLS frame bytes (they contain the Ed25519 signature and the epoch, so the layers are bound);
     * `roster`/`sibs` are what fan-out keys and device bindings are taken from (a substituted roster is rejected).
     */
    fun commitTranscript(gid: String, kind: String, mls: ByteArray, welcome: ByteArray?, roster: String?, sibs: String?): ByteArray =
        W().raw(COMMIT_LABEL).u32v(VERSION).lv(gid).lv(kind).lv(sha(mls))
            .lv(optHash(welcome)).lv(optHash(roster?.encodeToByteArray())).lv(optHash(sibs?.encodeToByteArray())).bytes()

    fun signCommit(transcript: ByteArray, mlDsaSecret: ByteArray): ByteArray = Dilithium3.sign(transcript, mlDsaSecret).bytes

    /** Never throws: corrupted key/signature → false. */
    fun verifyCommit(transcript: ByteArray, sig: ByteArray, mlDsaPublic: ByteArray): Boolean =
        runCatching { Dilithium3.verify(transcript, sig, mlDsaPublic) }.getOrDefault(false)

    // ── 2. Hash chain of application messages ──────────────────────────────────────────────────────

    /** h_0: bound to the group, epoch and leaf, so a chain cannot be moved to another group/epoch/leaf. */
    fun genesis(gid: String, epoch: Long, leaf: String): ByteArray = sha(W().raw(GENESIS_LABEL).lv(gid).u64(epoch).lv(leaf).bytes())

    /** h_i = SHA-256(label ‖ h_{i-1} ‖ id_i ‖ H(frame_i)). */
    fun step(prev: ByteArray, msgId: String, frame: ByteArray): ByteArray =
        sha(W().raw(CHAIN_LABEL).lv(prev).lv(msgId).lv(sha(frame)).bytes())

    /** What the checkpoint signature covers. */
    fun checkpointMessage(gid: String, epoch: Long, leaf: String, index: Int, h: ByteArray): ByteArray =
        W().raw(CHAIN_LABEL).raw("/cp".encodeToByteArray()).lv(gid).u64(epoch).lv(leaf).u32v(index).lv(h).bytes()

    /** Checkpoint signature: "my first [index] messages in this epoch yield [h]". */
    class Checkpoint(val epoch: Long, val index: Int, val h: ByteArray, val sig: ByteArray) {
        /** Binary form for the `pqcp` field: version(1) ‖ epoch(8) ‖ i(4) ‖ h(32) ‖ signature. */
        fun encode(): ByteArray = W().raw(byteArrayOf(VERSION.toByte())).u64(epoch).u32v(index).raw(h).raw(sig).bytes()
        companion object {
            fun decode(b: ByteArray): Checkpoint? {
                if (b.size < 1 + 8 + 4 + HASH_LEN + 1 || b[0].toInt() != VERSION) return null
                var e = 0L; for (k in 1..8) e = (e shl 8) or (b[k].toLong() and 0xFF)
                var i = 0; for (k in 9..12) i = (i shl 8) or (b[k].toInt() and 0xFF)
                if (i <= 0) return null
                return Checkpoint(e, i, b.copyOfRange(13, 13 + HASH_LEN), b.copyOfRange(13 + HASH_LEN, b.size))
            }
        }
    }

    /** Sender: own chain in the current epoch. New epoch → [reset] (the chain starts from a new h_0). */
    class SenderChain(private val gid: String, private val leaf: String, epoch: Long, private val nowMs: Long) {
        var epoch: Long = epoch; private set
        var index: Int = 0; private set
        var head: ByteArray = genesis(gid, epoch, leaf); private set
        private var lastCpIndex = 0
        private var lastSendMs = nowMs
        // Sparse groups: a message after silence carries the signature itself (see [checkpointDueOnSend]).
        private var quietStart = false

        // lastSendMs is left alone: "silence" is the time since my last message; an epoch change does not interrupt it.
        fun reset(newEpoch: Long, @Suppress("UNUSED_PARAMETER") now: Long) { epoch = newEpoch; index = 0; head = genesis(gid, newEpoch, leaf); lastCpIndex = 0 }

        fun leafIs(l: String): Boolean = leaf.equals(l, ignoreCase = true)

        /** There are own messages in this epoch not yet covered by a checkpoint signature. */
        fun hasUnconfirmed(): Boolean = index > lastCpIndex

        /**
         * Move to a new epoch (own or someone else's Commit). Old-epoch messages not yet covered by a checkpoint get
         * one NOW (signed in the old epoch); otherwise [reset] dropped them and receivers kept them "not
         * PQ-confirmed" forever (warning in the chat; affected messages sent < 30 s before a group key change).
         * Returns the checkpoint to fan out BEFORE the first message of the new epoch (or null), then calls [reset].
         */
        fun advance(newEpoch: Long, now: Long, signer: (ByteArray) -> ByteArray): Checkpoint? {
            val cp = if (hasUnconfirmed()) checkpointWith(signer) else null
            reset(newEpoch, now)
            return cp
        }

        /** Next message: return `h_{i-1}` (put into the envelope, 32 B) and advance the head. */
        fun next(msgId: String, frame: ByteArray, now: Long): ByteArray {
            val prev = head
            quietStart = index == lastCpIndex && now - lastSendMs >= CHECKPOINT_IDLE_MS
            head = step(prev, msgId, frame); index++; lastSendMs = now
            return prev
        }

        /** Whether a checkpoint signature is due: 20 own unconfirmed messages or 30 s of silence after unconfirmed ones. */
        fun checkpointDue(now: Long): Boolean =
            index > lastCpIndex && (index - lastCpIndex >= CHECKPOINT_EVERY || now - lastSendMs >= CHECKPOINT_IDLE_MS)

        /**
         * Whether to put the checkpoint signature INTO the same frame just produced by [next]. Every [CHECKPOINT_EVERY], as
         * before; plus the first message after [CHECKPOINT_IDLE_MS] of silence (everything before it is confirmed). In a sparse group
         * (messages less often than once per 30 s) every message used to drag a STANDALONE signature frame 30 s later (one
         * envelope per member); now the signature rides in the message itself, with no standalone frame. The wire format is
         * unchanged: newer versions already accept `pqcp` in an application frame (every 20th), older 2.0.x ignore the field.
         */
        fun checkpointDueOnSend(now: Long): Boolean = index > lastCpIndex && (quietStart || checkpointDue(now))

        fun checkpoint(mlDsaSecret: ByteArray): Checkpoint = checkpointWith { Dilithium3.sign(it, mlDsaSecret).bytes }

        /** Any signer: the account key (phone) or the device hybrid signature (desktop, [DEVICE_CONTEXT]). */
        fun checkpointWith(signer: (ByteArray) -> ByteArray): Checkpoint {
            val sig = signer(checkpointMessage(gid, epoch, leaf, index, head))
            lastCpIndex = index
            return Checkpoint(epoch, index, head.copyOf(), sig)
        }

        /**
         * State for persistence (≈ 110 B per group), saved after every [next] and checkpoint.
         * Previously the chain lived only in memory: Android/iOS kill the process all the time while an epoch lasts up to 7 days,
         * so after a restart the chain started again from h_0, and the very first message produced a "fork" for every receiver
         * (red warning for an honest member and VIOLATED until the next epoch).
         */
        fun save(): String = "1|${leaf.lowercase()}|$epoch|$index|${head.toHex()}|$lastCpIndex"

        companion object {
            /** Restore a saved chain; foreign leaf (member rejoined the group) or corrupted record → null (start from h_0). */
            fun restore(gid: String, leaf: String, saved: String?, now: Long): SenderChain? {
                val p = saved?.split('|') ?: return null
                if (p.size != 6 || p[0] != "1" || p[1] != leaf.lowercase()) return null
                val epoch = p[2].toLongOrNull() ?: return null
                val index = p[3].toIntOrNull()?.takeIf { it >= 0 } ?: return null
                val head = p[4].fromHexOrNull()?.takeIf { it.size == HASH_LEN } ?: return null
                val cp = p[5].toIntOrNull()?.takeIf { it in 0..index } ?: return null
                // Chain restored after a restart: the process was killed, so assume silence before it.
                return SenderChain(gid, leaf, epoch, now - CHECKPOINT_IDLE_MS).also { c ->
                    c.index = index; c.head = head; c.lastCpIndex = cp
                    if (index == 0 && !head.contentEquals(genesis(gid, epoch, leaf))) return null
                }
            }
        }
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    private fun String.fromHexOrNull(): ByteArray? {
        if (length % 2 != 0) return null
        return runCatching { ByteArray(length / 2) { i -> substring(2 * i, 2 * i + 2).toInt(16).toByte() } }.getOrNull()
    }

    enum class Status { UNCONFIRMED, CONFIRMED, VIOLATED }

    /**
     * Receiver: the chain of ONE sender in ONE epoch. Arrival order is arbitrary (messages are linked by
     * `h_{i-1}`, not by index). Display is not delayed; the status is just "not PQ-confirmed" until the checkpoint.
     *  - substituted frame → its h matches neither the next message's link nor the checkpoint → VIOLATED;
     *  - two different messages on the same `h_{i-1}` (fork) → VIOLATED;
     *  - checkpoint with an invalid signature → VIOLATED (chain state).
     *  A violation is irreversible until the next epoch.
     */
    class ReceiverChain(private val gid: String, private val leaf: String, val epoch: Long, private val verifier: (msg: ByteArray, sig: ByteArray) -> Boolean) {
        constructor(gid: String, leaf: String, epoch: Long, senderMlDsaPublic: ByteArray) :
            this(gid, leaf, epoch, { m: ByteArray, sg: ByteArray -> verifyCommit(m, sg, senderMlDsaPublic) })
        private class Node(val id: String, val prev: Key, val h: Key)
        private class Key(val b: ByteArray) {
            override fun equals(other: Any?) = other is Key && other.b.contentEquals(b)
            override fun hashCode() = b.contentHashCode()
        }
        private val g = Key(genesis(gid, epoch, leaf))
        private val byPrev = HashMap<Key, Node>()
        private val byH = HashMap<Key, Node>()
        private val byId = HashMap<String, Node>()
        private val confirmed = HashSet<String>()
        private val pending = ArrayList<Checkpoint>()
        var violated: Boolean = false; private set
        var violationReason: String? = null; private set

        private fun violate(why: String) { if (!violated) { violated = true; violationReason = why } }
        /** External violation (e.g. the leaf does not belong to the signer): the leaf chain is no longer confirmed. */
        fun markViolated(why: String) = violate(why)

        fun status(msgId: String): Status = when {
            violated -> Status.VIOLATED
            msgId in confirmed -> Status.CONFIRMED
            else -> Status.UNCONFIRMED
        }

        /** Application message received: `prevH` from the envelope, frame is exactly the MLS frame bytes. */
        fun accept(msgId: String, prevH: ByteArray, frame: ByteArray): Status {
            if (prevH.size != HASH_LEN) { violate("bad-h"); return status(msgId) }
            if (byId.containsKey(msgId)) return status(msgId) // replay of the same message: no change
            val node = Node(msgId, Key(prevH), Key(step(prevH, msgId, frame)))
            val other = byPrev[node.prev]
            if (other != null) { violate("fork"); return status(msgId) }
            byPrev[node.prev] = node; byH[node.h] = node; byId[msgId] = node
            tryPending()
            return status(msgId)
        }

        /** Sender checkpoint received. */
        fun acceptCheckpoint(cp: Checkpoint): Boolean {
            if (cp.epoch != epoch) return false // foreign epoch: not our chain
            if (!runCatching { verifier(checkpointMessage(gid, epoch, leaf, cp.index, cp.h), cp.sig) }.getOrDefault(false)) {
                violate("bad-checkpoint-sig"); return false
            }
            pending += cp; tryPending()
            return !violated
        }

        /**
         * Check pending checkpoints. Confirmation goes FROM THE CHECKPOINT BACKWARDS, not from h_0. h_i is a hash chain:
         * a path of links computed here from the received frames that ends exactly at the signed `cp.h` proves
         * that every frame on it is the one the sender folded into the chain. So a receiver restarted mid-epoch
         * (without the start of the chain) still confirms everything it received after the restart.
         *
         * Violation (VIOLATED):
         *  - the path back from `cp.h` is longer than the checkpoint index, or reaches h_0 in other than `cp.index` steps (forged index);
         *  - the path back breaks at position p while we hold all frames 1..p-1 forward from h_0, so our frame at position
         *    p-1 is not the signed one (substituted frame or fork). A break with no frames ahead just means "still in flight" or
         *    "before the restart": unconfirmed, but not a violation.
         */
        private fun tryPending() {
            if (violated || pending.isEmpty()) return
            var forward = -1 // how many links follow contiguously from h_0 (computed once, on demand)
            fun forwardLen(): Int {
                if (forward >= 0) return forward
                var n = 0; var cur = g
                while (true) { val x = byPrev[cur] ?: break; n++; cur = x.h; if (n > byId.size) break }
                forward = n; return n
            }
            val it = pending.iterator()
            while (it.hasNext()) {
                val cp = it.next()
                var n = byH[Key(cp.h)] ?: run {
                    // No frame with this head. If all cp.index frames from h_0 are already contiguous, our last one is not
                    // the signed one (substitution); otherwise it is still in flight.
                    if (forwardLen() >= cp.index) { violate("chain-mismatch"); return }
                    null
                } ?: continue
                val back = ArrayList<Node>()
                while (true) {
                    back += n
                    if (n.prev == g || back.size > cp.index) break
                    n = byH[n.prev] ?: break
                }
                val fromGenesis = back.last().prev == g
                if (back.size > cp.index || (fromGenesis && back.size != cp.index)) { violate("chain-mismatch"); return }
                if (!fromGenesis) {
                    val start = cp.index - back.size + 1 // position of the earliest link on the path
                    if (forwardLen() >= start - 1) { violate("chain-mismatch"); return }
                }
                for (b in back) confirmed += b.id
                if (fromGenesis) it.remove() // otherwise wait for the missing early ones: once they arrive, confirm them too
            }
        }

        /** Messages that never linked into the chain (inserted with a foreign `h_{i-1}`): suspicious after a checkpoint. */
        fun unlinked(): Set<String> {
            val linked = HashSet<String>(); var cur = g
            while (true) { val n = byPrev[cur] ?: break; if (!linked.add(n.id)) break; cur = n.h }
            return byId.keys - linked
        }
    }

    /** Which leaf chain accepts a frame or checkpoint of epoch [epoch]. */
    sealed interface Pick {
        class Use(val chain: ReceiverChain) : Pick
        /** New epoch for the leaf: create a chain and move the current one to "previous". */
        data object Create : Pick
        /** Epoch older than the previous one (or no previous one): not accepted into a chain. */
        data object Drop : Pick
    }

    /**
     * Besides the current chain we keep the PREVIOUS epoch's chain. The old epoch's checkpoint goes as a standalone frame
     * and may arrive after the first message of the new epoch (a neighbouring message overtook it in fan-out, network, polling order);
     * previously "old epoch after new" was dropped and messages before the Commit stayed "unconfirmed".
     */
    fun pick(cur: ReceiverChain?, prev: ReceiverChain?, epoch: Long): Pick = when {
        cur == null || cur.epoch < epoch -> Pick.Create
        cur.epoch == epoch -> Pick.Use(cur)
        prev != null && prev.epoch == epoch -> Pick.Use(prev)
        else -> Pick.Drop
    }

    /**
     * The receiver keeps per-leaf chains: the current epoch and one previous ([pick]). A new sender epoch → the current one
     * becomes previous, and the new one starts from that epoch's h_0.
     */
    class ReceiverBook(private val gid: String, private val keyOf: (leaf: String) -> ByteArray?) {
        private val chains = HashMap<String, ReceiverChain>()
        private val prevChains = HashMap<String, ReceiverChain>()
        fun chain(leaf: String, epoch: Long): ReceiverChain? {
            val cur = chains[leaf]
            return when (val p = pick(cur, prevChains[leaf], epoch)) {
                is Pick.Use -> p.chain
                Pick.Drop -> null
                Pick.Create -> {
                    val pk = keyOf(leaf) ?: return null
                    ReceiverChain(gid, leaf, epoch, pk).also { n ->
                        if (cur != null) prevChains[leaf] = cur else prevChains.remove(leaf)
                        chains[leaf] = n
                    }
                }
            }
        }
    }

    /** Binding of leaves "phone [pm] ↔ desktop [dm]" (signed by both leaves in the MLS layer); [dev] is the device id, if known. */
    class LeafLink(val pm: String, val dm: String, val dev: String?)

    /**
     * MLS leaf (leaf credentials verified by OpenMLS) ↔ signer. Otherwise a member with their own valid PQ key
     * could sign frames of someone else's leaf (or pass their desktop off as the phone).
     *  - signed by the account (`pqk == null`): the leaf is NOT a desktop leaf and belongs to the signer's account;
     *  - signed by device `pqk`: the leaf is the desktop from a binding, the binding's phone belongs to the signer's account,
     *    the leaf itself (if its owner is known) is theirs too, and the binding's device id (if known) equals `pqk`.
     */
    fun leafMatchesSigner(leaf: String, signerUserId: String, pqk: String?, ownerOfLeaf: (String) -> String?, links: List<LeafLink>): Boolean =
        leafVerdict(leaf, signerUserId, pqk, ownerOfLeaf, links) == LeafVerdict.MATCH

    /** Leaf vs signer: match, contradict, or we have no data (binding / userId not received). */
    enum class LeafVerdict { MATCH, UNKNOWN, CONTRADICTS }

    /**
     * Same rules as [leafMatchesSigner], but "no data" is separate from "contradicts". No data: a phone leaf
     * without `realUserId` on our side (can be null), a desktop leaf without a binding (member upgraded from an older version and
     * missed the bindings). Contradicts: data exists and says "not theirs": different owner, a known desktop leaf under the
     * account key, a known phone under a device key, a binding to another device.
     */
    fun leafVerdict(leaf: String, signerUserId: String, pqk: String?, ownerOfLeaf: (String) -> String?, links: List<LeafLink>): LeafVerdict {
        val l = leaf.lowercase()
        val link = links.firstOrNull { it.dm.equals(l, ignoreCase = true) }
        val own = ownerOfLeaf(l)
        if (pqk == null) return when {
            link != null -> LeafVerdict.CONTRADICTS
            own == null -> LeafVerdict.UNKNOWN
            own == signerUserId -> LeafVerdict.MATCH
            else -> LeafVerdict.CONTRADICTS
        }
        if (own != null && own != signerUserId) return LeafVerdict.CONTRADICTS
        if (link == null) {
            // A known phone (it has a binding as pm) under a device key: not their leaf.
            if (links.any { it.pm.equals(l, ignoreCase = true) }) return LeafVerdict.CONTRADICTS
            return LeafVerdict.UNKNOWN
        }
        if (link.dev != null && link.dev != pqk) return LeafVerdict.CONTRADICTS
        val phoneOwner = ownerOfLeaf(link.pm.lowercase()) ?: return LeafVerdict.UNKNOWN
        return if (phoneOwner == signerUserId) LeafVerdict.MATCH else LeafVerdict.CONTRADICTS
    }

    /**
     * Leaves (memberId hex) from which the core accepts a Commit/Proposal of a SIGNED frame: all except those that by our data
     * do NOT belong to the signer ([leafVerdict] = CONTRADICTS). Previously only the signer's confirmed leaves were allowed,
     * and with incomplete data (no binding, no userId) a legitimate Commit (leaf update every 7 days, leave,
     * add) was rejected: the receiver stayed in the old epoch and could decrypt nothing further (silent split).
     */
    fun commitSendersSigned(leaves: List<String>, signerUserId: String, pqk: String?, ownerOfLeaf: (String) -> String?, links: List<LeafLink>): List<String> =
        leaves.filter { leafVerdict(it, signerUserId, pqk, ownerOfLeaf, links) != LeafVerdict.CONTRADICTS }

    /**
     * Leaves from which the core accepts a Commit/Proposal of an UNSIGNED frame: null if nobody in the group announced a signature
     * (as before, no restriction); otherwise all except those that announced WIRE_CAP_GROUP_PQSIG (sticky upgrade).
     */
    fun commitSendersUnsigned(leaves: List<String>, pinnedGpq: (String) -> Boolean): List<String>? {
        val (gpq, plain) = leaves.partition(pinnedGpq)
        return if (gpq.isEmpty()) null else plain
    }

    /** Per-message overhead bytes in the JSON envelope (`"h":"<base64 32 B>"` and a comma). */
    fun envelopeChainOverheadJson(): Int = ",\"h\":\"\"".length + b64Len(HASH_LEN)
    /** Bytes of the `pqcp` field in the JSON envelope. */
    fun envelopeCheckpointOverheadJson(sigLen: Int): Int = ",\"pqcp\":\"\"".length + b64Len(1 + 8 + 4 + HASH_LEN + sigLen)
    fun b64Len(n: Int): Int = (n + 2) / 3 * 4
}
