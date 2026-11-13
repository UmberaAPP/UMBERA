package app.umbera.core.devices

import app.umbera.core.crypto.RendezvousV2
import app.umbera.core.crypto.RustCore
import app.umbera.core.crypto.X25519
import app.umbera.core.util.B64
import app.umbera.core.util.SyncLock
import app.umbera.core.util.withLock
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Device address epochs (gated by [app.umbera.core.crypto.SecurityRollout.deviceRidRotation]) —
 * see the protocol description, "Device address epochs".
 *
 * Previously the device-pair address was constant: `HKDF(X25519(from,to), "umbera-dv1/rid", "rdv|from|to")`. It was written in the same
 * second as the message to the peer's phone and, via write timestamps in the database, bridged adjacent 1:1 address epochs (mailbox
 * address rotation, ridRotation) for users with a linked computer. Now the device-pair address rotates in the same globally shared
 * second as the 1:1 addresses: `e = floor(unix / RendezvousV2.periodSec)`.
 *
 * The address secret is chosen by the RECIPIENT and derived from its ML-KEM seed (like the self-copy in ridRotation):
 *   `R(to ← from) = HKDF(recipient's ML-KEM seed, salt "umbera-dv1/rx", info "dv-rx|<from>|<to>", 32)`,
 *   `rid_e(from → to) = HKDF(X25519(from,to) ‖ R, salt "umbera-dv1/rid-e", info "rdv-e|<from>|<to>|<e>", 32)` (hex, 32 B).
 * The recipient hands R to the sender ONCE in the `rk` field inside the device envelope (outer layer X25519 + ML-KEM-1024,
 * body signed by the device): a quantum adversary cannot compute epoch addresses from the directory's public keys. Per message:
 * 0 extra bytes. R is deterministic: after reinstall/restore the recipient immediately listens on the same addresses with no exchange
 * (the sender keeps writing — no messages lost; ratchet desync is repaired by the existing "reset + retry").
 *
 * Negotiation is the offer itself: an old device ignores the `rk` field (ignoreUnknownKeys) and writes to the constant address,
 * which the recipient ALWAYS listens on. Without R at the sender (or with the switch off) — the constant address, byte for byte.
 */
class DeviceRidEpochs(
    private val kv: DeviceKv,
    private val nowMs: () -> Long,
    private val enabled: () -> Boolean,
) {
    companion object {
        private val SALT_RX = "umbera-dv1/rx".encodeToByteArray()
        private val SALT_E = "umbera-dv1/rid-e".encodeToByteArray()
        private const val K_TX = "dvet:"
        private const val K_RX = "dver:"

        private fun hex(b: ByteArray) = b.joinToString("") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }

        /** Address secret that recipient [to] hands to sender [from]: derived from the recipient's ML-KEM seed. */
        fun rxSecret(mlkemSeed: ByteArray, from: DeviceAddr, to: DeviceAddr): ByteArray =
            RustCore.hkdfSha256(mlkemSeed, SALT_RX, "dv-rx|${from.key}|${to.key}".encodeToByteArray(), 32u)

        /** Address of epoch [epoch] for the pair from → to (input: the pair's shared X25519 and the recipient's secret). */
        fun ridEpoch(ssX25519: ByteArray, r: ByteArray, from: DeviceAddr, to: DeviceAddr, epoch: Long): String =
            hex(RustCore.hkdfSha256(ssX25519 + r, SALT_E, "rdv-e|${from.key}|${to.key}|$epoch".encodeToByteArray(), 32u))

        /** Re-offer to a sender still writing to the constant address: daily, after three — weekly (capped by the epoch period). */
        fun reofferGapMs(offers: Int): Long {
            val p = RendezvousV2.periodSec * 1000
            return if (offers < 3) minOf(24L * 3600_000, p) else minOf(7L * 24 * 3600_000, 4 * p)
        }

        /** An offer without a piggyback envelope (service "rk") — at a random point in the window, to avoid bursts. */
        fun offerSpreadMs(): Long = minOf(10L * 60_000, RendezvousV2.periodSec * 1000 / 8).coerceAtLeast(1)

        const val SYS_OFFER = "rk"
    }

    /** Sender: the recipient's secret [r] (base64) and when it arrived. */
    @Serializable
    internal data class Tx(@SerialName("r") val r: String, @SerialName("t") val t: Long)

    /**
     * Recipient (one record per sending device): we listen on epoch addresses from [firstMs]. [offeredMs]/[offers] — when and
     * how many times R was handed out; [drainedTo] — the epoch that was current at the last full drain (as in ridRotation);
     * [epochSeenMs]/[staticSeenMs] — last envelopes on the epoch address / on the constant one; [reoffer] — after our
     * offer the sender still writes to the constant address (lost R or an old build) — offer again after [reofferGapMs].
     */
    @Serializable
    internal data class Rx(
        @SerialName("f") val firstMs: Long,
        @SerialName("o") val offeredMs: Long = 0,
        @SerialName("n") val offers: Int = 0,
        @SerialName("l") val drainedTo: Long? = null,
        @SerialName("ep") val epochSeenMs: Long = 0,
        @SerialName("st") val staticSeenMs: Long = 0,
        @SerialName("ro") val reoffer: Boolean = false,
    )

    private val json = kotlinx.serialization.json.Json { ignoreUnknownKeys = true; encodeDefaults = false }
    private val lock = SyncLock()

    private fun loadTx(to: DeviceAddr): Tx? = kv.get(K_TX + to.key)?.let { runCatching { json.decodeFromString(Tx.serializer(), it) }.getOrNull() }
    internal fun rx(from: DeviceAddr): Rx? = kv.get(K_RX + from.key)?.let { runCatching { json.decodeFromString(Rx.serializer(), it) }.getOrNull() }
    private fun storeRx(from: DeviceAddr, r: Rx) = kv.put(K_RX + from.key, json.encodeToString(Rx.serializer(), r))

    /** Whether we hold this recipient's address secret (for metrics and tests). */
    fun hasTx(to: DeviceAddr): Boolean = loadTx(to) != null

    // ── sender ──

    /** Where to write an envelope for [to]: the current epoch address if the recipient handed out R and the switch is on, else the constant one. */
    fun sendRid(me: LocalDevice, to: RemoteDevice, at: Long = nowMs()): String {
        val tx = if (enabled()) loadTx(to.addr) else null
        val r = tx?.let { runCatching { B64.decode(it.r) }.getOrNull() }?.takeIf { it.size == 32 }
            ?: return DeviceEnvelope.rid(me, to, me.addr, to.addr)
        return ridEpoch(X25519.computeSharedSecret(me.x25519Private, to.x25519), r, me.addr, to.addr, RendezvousV2.epochOf(at))
    }

    /** An `rk` offer arrived from [from] (body signed by it, verified): store it. */
    fun onOffer(from: DeviceAddr, rk: String) = lock.withLock {
        val r = runCatching { B64.decode(rk) }.getOrNull()?.takeIf { it.size == 32 } ?: return@withLock
        val cur = loadTx(from)
        if (cur?.r == B64.encode(r)) return@withLock
        kv.put(K_TX + from.key, json.encodeToString(Tx.serializer(), Tx(B64.encode(r), nowMs())))
    }

    // ── recipient ──

    /**
     * Recipient record for [from]; with the switch on it is created on first sight (epoch listening starts from it). Without a record —
     * only the constant address (as before). A new record reads back the whole retention period (after a restore the sender
     * may have written to epochs while we were away).
     */
    internal fun rxOrCreate(from: DeviceAddr, at: Long = nowMs()): Rx? = lock.withLock {
        rx(from) ?: if (!enabled()) null else Rx(firstMs = at, drainedTo = RendezvousV2.epochOf(at) - RendezvousV2.maxBackEpochs()).also { storeRx(from, it) }
    }

    /** Whether to hand R to sender [from] with this envelope. */
    fun shouldOffer(from: DeviceAddr, at: Long = nowMs()): Boolean {
        if (!enabled()) return false
        val r = rx(from) ?: return false
        return r.offeredMs == 0L || (r.reoffer && at - r.offeredMs >= reofferGapMs(r.offers))
    }

    fun offerFor(me: LocalDevice, from: DeviceAddr): String = B64.encode(rxSecret(me.mlkemSeed, from, me.addr))

    fun noteOffered(from: DeviceAddr, at: Long = nowMs()) = lock.withLock {
        val r = rx(from) ?: return@withLock
        storeRx(from, r.copy(offeredMs = at, offers = r.offers + 1, reoffer = false))
    }

    /** An envelope from [from] arrived on the constant address ([onStatic]) or on an epoch address; [sealedTs] — its timestamp. */
    fun noteArrival(from: DeviceAddr, onStatic: Boolean, sealedTs: Long, at: Long = nowMs()) = lock.withLock {
        val r = rx(from) ?: return@withLock
        val next = if (onStatic) {
            // Sealed after our offer (+ a minute of clock slack) — the sender does not know R: offer again.
            val stale = r.offeredMs > 0 && sealedTs > r.offeredMs + 60_000
            r.copy(staticSeenMs = at, reoffer = r.reoffer || stale)
        } else r.copy(epochSeenMs = at, reoffer = false)
        // Persist only if something changed noticeably (not on every envelope).
        if (next.reoffer != r.reoffer || (onStatic && at - r.staticSeenMs > 60_000) || (!onStatic && at - r.epochSeenMs > 60_000)) storeRx(from, next)
    }

    fun noteDrained(from: DeviceAddr, at: Long = nowMs()) = lock.withLock {
        val r = rx(from) ?: return@withLock
        val e = RendezvousV2.epochOf(at)
        if (r.drainedTo != e) storeRx(from, r.copy(drainedTo = e))
    }

    fun forget(addr: DeviceAddr) = lock.withLock {
        kv.remove(K_TX + addr.key); kv.remove(K_RX + addr.key)
    }

    /** One address in the receive plan for a device: [epoch] null means the constant address. */
    class Recv(val rid: String, val device: RemoteDevice, val epoch: Long?, val cadence: RendezvousV2.Cadence)

    /**
     * Receive plan for [from]: the constant address — always (subscription; polled every pass while the sender uses it, and once per
     * slowSweepMs once it has written only to epochs for 48 h); epochs — per the ridRotation plan (e−1/e/e+1, missed offline ones up to 6),
     * and for a sender that has not written to an epoch within 48 h (old build) — slowly (the request-free subscription remains).
     */
    fun plan(me: LocalDevice, from: RemoteDevice, at: Long = nowMs()): List<Recv> {
        val static = DeviceEnvelope.rid(me, from, from.addr, me.addr)
        val r = rxOrCreate(from.addr, at)
        val grace = RendezvousV2.staticGraceMs()
        val staticSlow = r != null && r.epochSeenMs > 0 && at - r.staticSeenMs > grace && at - r.firstMs > grace
        val out = ArrayList<Recv>()
        out += Recv(static, from, null, if (staticSlow) RendezvousV2.Cadence.SLOW else RendezvousV2.Cadence.EVERY_PASS)
        if (r == null) return out
        val idle = r.epochSeenMs == 0L && at - r.firstMs > grace
        val ss = X25519.computeSharedSecret(me.x25519Private, from.x25519)
        val sec = rxSecret(me.mlkemSeed, from.addr, me.addr)
        for ((e, cad) in RendezvousV2.plan(at, r.drainedTo)) {
            out += Recv(ridEpoch(ss, sec, from.addr, me.addr, e), from, e, if (idle) RendezvousV2.Cadence.SLOW else cad)
        }
        return out
    }
}
