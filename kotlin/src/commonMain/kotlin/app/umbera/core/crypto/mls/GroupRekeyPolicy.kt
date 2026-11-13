package app.umbera.core.crypto.mls

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Periodic update of one's own MLS leaf for post-compromise recovery (post-compromise security).
 *
 *
 * Each device (phone and linked desktop each have their own leaf) makes a Commit with UpdatePath by itself
 * ([MlsManager.updateKeys]):
 *  - every [INTERVAL_MS] with a random offset ±[JITTER_MS] (the deadline is chosen once, in advance, so group
 *    members update at different times, without a burst);
 *  - or after [MSG_LIMIT] own packets in the group (but not more often than [MIN_GAP_MS]);
 *  - or right after a long device idle period (the app did not run for longer than [IDLE_GAP_MS]) if more than
 *    [IDLE_GAP_MS] has passed since the last update.
 * The first deadline for a group with no updates yet (app upgraded in place) is random within the interval,
 * so phones upgraded on the same day do not send Commits all at once.
 *
 * Only the "is it due" decision lives here: pure logic, tested without the core (GroupRekeyPolicyTest). When it is possible
 * (mailbox caught up, group is quiet, one group per pass) is decided by GroupRepositoryImpl.
 */
object GroupRekeyPolicy {
    const val INTERVAL_MS = 7L * 24 * 60 * 60 * 1000
    const val JITTER_MS = 12L * 60 * 60 * 1000
    const val MSG_LIMIT = 100
    /** At most once per hour per group, even in a very busy conversation. */
    const val MIN_GAP_MS = 60L * 60 * 1000
    /** "Long idle": the device did not run for three days. */
    const val IDLE_GAP_MS = 3L * 24 * 60 * 60 * 1000
    /** After launch: drain the mailbox first (otherwise the Commit targets a stale epoch and loses the race). */
    const val STARTUP_GRACE_MS = 90_000L
    /** A Commit was just applied in the group (someone else's update, membership change): wait, don't collide. */
    const val QUIET_MS = 3L * 60 * 1000
    /** Our Commit lost a race: retry in 2–15 min. */
    const val LOST_RETRY_MIN_MS = 2L * 60 * 1000
    const val LOST_RETRY_SPAN_MS = 13L * 60 * 1000

    /**
     * For test runs ONLY: shortened interval. Set by a test launch (desktop: -Dumbera.test.rekeyIntervalMs
     * together with umbera.test.masterKeyFile; Android: a file in the app folder of a debug build; iOS: an environment variable
     * in the simulator). Never set in release builds.
     */
    @kotlin.concurrent.Volatile
    var testIntervalMs: Long? = rekeyTestOverride()?.takeIf { it >= 10_000L }

    fun interval(): Long = testIntervalMs ?: INTERVAL_MS
    fun jitter(): Long = testIntervalMs?.let { it / 10 } ?: JITTER_MS
    fun minGap(): Long = testIntervalMs?.let { it / 2 } ?: MIN_GAP_MS
    fun idleGap(): Long = testIntervalMs?.let { it * 2 } ?: IDLE_GAP_MS
    fun quiet(): Long = testIntervalMs?.let { minOf(QUIET_MS, it / 4) } ?: QUIET_MS
    fun startupGrace(): Long = testIntervalMs?.let { minOf(STARTUP_GRACE_MS, it / 4) } ?: STARTUP_GRACE_MS

    /** Per-group leaf record. [t] is the last own update (or join), [n] own packets since then, [d] the deadline. */
    @Serializable
    data class State(
        @SerialName("t") val lastUpdateMs: Long,
        @SerialName("n") val sentSince: Int = 0,
        @SerialName("d") val dueAtMs: Long,
    )

    enum class Reason { TIME, MESSAGES, IDLE }

    /** [rnd] is uniform in [0, bound). */
    fun nextDue(nowMs: Long, rnd: (Long) -> Long): Long {
        val j = jitter()
        return nowMs + interval() - j + rnd(2 * j + 1)
    }

    /** Group without a record (upgraded in place, joined on an older build): random deadline within the interval. */
    fun initial(nowMs: Long, rnd: (Long) -> Long): State =
        State(lastUpdateMs = nowMs, sentSince = 0, dueAtMs = nowMs + rnd(interval()) + 1)

    fun afterUpdate(nowMs: Long, rnd: (Long) -> Long): State = State(nowMs, 0, nextDue(nowMs, rnd))

    /** Own Commit lost a race: update again soon (a deadline rather than immediately, the winner may still be sending). */
    fun afterLostRace(s: State, nowMs: Long, rnd: (Long) -> Long): State {
        val scale = testIntervalMs?.let { t -> { v: Long -> minOf(v, t / 4) } } ?: { v: Long -> v }
        // lastUpdate is moved back, otherwise MIN_GAP would block the retry.
        return s.copy(lastUpdateMs = nowMs - minGap(), dueAtMs = nowMs + scale(LOST_RETRY_MIN_MS) + rnd(scale(LOST_RETRY_SPAN_MS) + 1))
    }

    /**
     * Whether the leaf is due for an update. [idleResume]: the device just resumed after being idle longer than [IDLE_GAP_MS]
     * (first pass after launch).
     */
    fun due(s: State, nowMs: Long, idleResume: Boolean): Reason? {
        val since = nowMs - s.lastUpdateMs
        if (since < minGap()) return null
        if (nowMs >= s.dueAtMs) return Reason.TIME
        if (s.sentSince >= MSG_LIMIT) return Reason.MESSAGES
        if (idleResume && since >= idleGap()) return Reason.IDLE
        return null
    }
}

/** Shortened interval for testing, only in a platform test launch (desktop: test properties; iOS: simulator). */
internal expect fun rekeyTestOverride(): Long?
