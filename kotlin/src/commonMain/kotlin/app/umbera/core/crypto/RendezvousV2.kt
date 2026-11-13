package app.umbera.core.crypto

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * 1:1 mailbox addresses v2. Computation — MessageEncryption.rid2 /
 * rendezvousSendIdCurrent / rendezvousRecvIds; this file holds the transition state and timings.
 *
 * Address rotation by epoch (behind [SecurityRollout.ridRotation], bit [MessageEncryption.WIRE_CAP_RID_EPOCH]):
 * `rid2e(A→B, e) = HKDF(X25519(A,B) ‖ D_AB, salt "umbera-rendezvous-v2", info "rdv-e|A|B|<e>", 32)` — the same
 * direction secret D (from the full v3 envelope, ML-KEM + X25519), 0 extra bytes per message. The epoch is global:
 * `e = floor(unix_sec / [periodSec])` — all addresses of all pairs change in the same second (rotating a single pair at
 * its own time would reveal "this address became that one" from stream continuity alone).
 */
object RendezvousV2 {
    /** How long to keep polling the previous address after v2 is pinned and after the last message on the previous one. */
    const val RID_V1_GRACE_MS = 14L * 24 * 3600_000L

    /** The server keeps envelopes for 30 days (expires_at = NOW() + 30 days). */
    const val SERVER_RETENTION_SEC = 30L * 24 * 3600

    /**
     * Epoch length, seconds. One week. Shortened in test runs
     * (LIVE_RID_EPOCH_SEC); unchanged in release builds.
     */
    @kotlin.concurrent.Volatile
    var periodSec: Long = 7L * 24 * 3600

    private val SALT = "umbera-rendezvous-v2".encodeToByteArray()

    private fun hex(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    /** rid2(from→to) = HKDF(X25519(from,to) ‖ D_from→to, salt "umbera-rendezvous-v2", info "rdv|from|to", 32), hex. */
    fun rid(ssX25519: ByteArray, dir: ByteArray, fromId: String, toId: String): String =
        hex(RustCore.hkdfSha256(ssX25519 + dir, SALT, "rdv|$fromId|$toId".encodeToByteArray(), 32u))

    /** Address for epoch [epoch]: same input as [rid], different label (addresses of different epochs are unlinkable without D — HKDF). */
    fun ridEpoch(ssX25519: ByteArray, dir: ByteArray, fromId: String, toId: String, epoch: Long): String =
        hex(RustCore.hkdfSha256(ssX25519 + dir, SALT, "rdv-e|$fromId|$toId|$epoch".encodeToByteArray(), 32u))

    /** Copy of own messages sent to [peerId] in epoch [epoch] — in step with the address to them (own seed, not the pair secret). */
    fun selfBackupEpoch(selfIkm: ByteArray, myId: String, peerId: String, epoch: Long): String =
        hex(RustCore.hkdfSha256(selfIkm, SALT, "rdv-backup-e|$myId|$peerId|$epoch".encodeToByteArray(), 32u))

    fun epochOf(nowMs: Long): Long {
        val sec = nowMs / 1000
        val q = sec / periodSec
        return if (sec % periodSec != 0L && sec < 0) q - 1 else q
    }
    fun epochStartMs(epoch: Long): Long = epoch * periodSec * 1000

    /** How many epochs back are worth reading at all: server retention + 1, at most 6 (also with shortened epochs). */
    fun maxBackEpochs(): Long = minOf(6L, (SERVER_RETENTION_SEC + periodSec - 1) / periodSec + 1)

    /** After an epoch change the previous one is polled on every pass for this long (sender clock behind, queue, delay). */
    fun prevFastMs(): Long = minOf(2L * 3600_000, periodSec * 1000 / 4)

    /** The next epoch is polled on every pass for this long before the boundary (sender clock ahead). */
    fun nextFastMs(): Long = minOf(15L * 60_000, periodSec * 1000 / 8)

    /** Outside the fast windows neighbouring epochs are polled once per this interval (clock skew either way — nothing lost). */
    fun slowSweepMs(): Long = minOf(30L * 60_000, periodSec * 1000 / 4)

    /** The previous static rid2 after the chain moved to epochs / after the last message on it. */
    fun staticGraceMs(): Long = minOf(48L * 3600_000, periodSec * 1000 * 2)

    /** How often to poll an epoch address. */
    enum class Cadence { EVERY_PASS, SLOW }

    /**
     * Epoch polling plan for one receiving chain. [drainedTo] — which epoch was current when everything was fully drained
     * (null — unknown: read from e−1); epochs before it are closed, it itself is not (it may have been written to later). Current — every pass; skipped (offline) — every pass until drained
     * completely; e−1 — every pass for [prevFastMs] after the boundary, slowly afterwards; e+1 — every pass for [nextFastMs] before the
     * boundary, slowly otherwise. The socket subscription (no requests or PoW) covers all epochs in the plan.
     */
    fun plan(nowMs: Long, drainedTo: Long?): List<Pair<Long, Cadence>> {
        val e = epochOf(nowMs)
        // drainedTo — the epoch that was current at the last full drain: it may have been written to afterwards, so read it too.
        val lo = maxOf(e - maxBackEpochs(), minOf(drainedTo ?: (e - 1), e - 1))
        val out = ArrayList<Pair<Long, Cadence>>()
        for (x in lo..e - 1) {
            val fast = x < e - 1 || (drainedTo ?: Long.MIN_VALUE) < x || nowMs - epochStartMs(e) < prevFastMs()
            out.add(x to if (fast) Cadence.EVERY_PASS else Cadence.SLOW)
        }
        out.add(e to Cadence.EVERY_PASS)
        out.add((e + 1) to if (epochStartMs(e + 1) - nowMs < nextFastMs()) Cadence.EVERY_PASS else Cadence.SLOW)
        return out
    }

    /**
     * Which plan addresses to poll on this pass: "every pass" — always, "slow" — at most once per [slowSweepMs] per
     * address (process memory; after a restart the first pass also polls the slow ones — the safe side).
     */
    class Sweep {
        private val last = app.umbera.core.util.SyncMap<String, Long>()
        fun due(rid: String, cadence: Cadence, nowMs: Long): Boolean {
            if (cadence == Cadence.EVERY_PASS) return true
            val l = last[rid]
            if (l != null && nowMs - l < slowSweepMs()) return false
            last[rid] = nowMs
            if (last.keys.size > 4096) last.clear()
            return true
        }
    }

    /** `rd`/`ra` value with the "with epochs" mark: id + "+" (1 byte, only in transition and confirmation messages). */
    const val EPOCH_MARK = '+'
    fun mark(id: String, epochs: Boolean) = if (epochs) id + EPOCH_MARK else id
    fun parse(v: String): Pair<String, Boolean> = if (v.endsWith(EPOCH_MARK)) v.dropLast(1) to true else v to false

    /**
     * Me → peer: direction secret [dir] (base64) with id [id]; [confirmedMs] > 0 — they confirmed polling rid2;
     * [ackTs] — timestamp of THEIR confirming message (by their clock: compared only with their own messages, no clock skew).
     * [epochs] = 1 — they confirmed polling epoch addresses (`ra` with "+"), we write to the current epoch's address.
     */
    @Serializable
    data class Tx(
        @SerialName("i") val id: String, @SerialName("d") val dir: String, @SerialName("c") val confirmedMs: Long,
        @SerialName("a") val ackTs: Long = 0,
        @SerialName("e") val epochs: Int = 0,
    )

    /**
     * Peer → me: the v2 address they announced (`rd`), and when I started polling it. [epochs] = 1 — by epochs
     * (since [epochsMs]); [drainedTo] — the epoch that was current at the last full drain (see [plan]); [staticLastMs] — the last message on the static rid2.
     */
    @Serializable
    data class Rx(
        @SerialName("i") val id: String, @SerialName("d") val dir: String, @SerialName("t") val pinnedMs: Long,
        @SerialName("e") val epochs: Int = 0,
        @SerialName("em") val epochsMs: Long = 0,
        @SerialName("l") val drainedTo: Long? = null,
        @SerialName("sl") val staticLastMs: Long = 0,
    )
}
