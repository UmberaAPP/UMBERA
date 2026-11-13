package app.umbera.core.crypto

import app.umbera.core.crypto.mls.GroupRekeyPolicy
import app.umbera.core.crypto.mls.MlsManager
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Periodic update of one's own leaf at the MlsManager level, the way GroupRepositoryImpl calls it:
 * update with a state mark (a race of two updates converges for everyone; the loser sees its "rekey" and
 * updates again), a late message from the previous epoch still opens, schedule bookkeeping (deadline, 100 own
 * packets), a suite migration crossing one's own update is accepted. X-Wing groups and the previous suite.
 */
class MlsRekeyTest {

    private class MemKvStore : SecureKvStore {
        val map = HashMap<String, Any>()
        override fun getString(key: String): String? = map[key] as? String
        override fun putString(key: String, value: String) { map[key] = value }
        override fun getBoolean(key: String, default: Boolean): Boolean = map[key] as? Boolean ?: default
        override fun putBoolean(key: String, value: Boolean) { map[key] = value }
        override fun getInt(key: String, default: Int): Int = map[key] as? Int ?: default
        override fun putInt(key: String, value: Int) { map[key] = value }
        override fun getLong(key: String, default: Long): Long = map[key] as? Long ?: default
        override fun putLong(key: String, value: Long) { map[key] = value }
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String): Set<String>? = map[key] as? Set<String>
        override fun putStringSet(key: String, value: Set<String>) { map[key] = value }
        override fun contains(key: String): Boolean = map.containsKey(key)
        override fun remove(key: String) { map.remove(key) }
        override fun allKeys(): Set<String> = map.keys.toSet()
        override fun clear() { map.clear() }
    }

    private fun manager() = MlsManager(SecureKeyStoreCommon(MemKvStore(), { false }))
    private val now = 1_800_000_000_000L

    private suspend fun app(m: MlsManager, gid: ByteArray, msg: ByteArray): ByteArray {
        val r = m.processIncomingTracked(gid, msg, now)
        val a = assertIs<MlsIncoming.Application>(r.incoming)
        r.commit?.invoke()
        return a.plaintext
    }

    private suspend fun group(suite: UShort): Pair<ByteArray, List<MlsManager>> {
        val gid = secureRandomBytes(32)
        val a = manager(); val b = manager(); val c = manager()
        a.createGroup(gid, suite)
        val tb = b.prepareJoin(); val tc = c.prepareJoin()
        fun pick(t: MlsManager.JoinTicket) = if (suite == MlsSuites.XWING) assertNotNull(t.keyPackageXw) else t.keyPackage
        val add = a.addMembers(gid, listOf(pick(tb), pick(tc)))
        b.completeJoin(tb.memberId, add.welcome, gid); c.completeJoin(tc.memberId, add.welcome, gid)
        assertEquals(suite, b.groupSuite(gid))
        return gid to listOf(a, b, c)
    }

    private suspend fun allTalk(gid: ByteArray, ms: List<MlsManager>, tag: String) {
        for ((i, s) in ms.withIndex()) {
            val text = "$tag/$i".encodeToByteArray()
            val ct = s.encrypt(gid, text)
            for ((j, r) in ms.withIndex()) if (j != i) assertContentEquals(text, app(r, gid, ct), "$tag: $j reads $i")
        }
        assertEquals(1, ms.map { it.exportSecret(gid, "conf", 32u).toList() }.toSet().size, "$tag: one epoch secret")
    }

    private suspend fun raceConverges(suite: UShort) {
        val (gid, ms) = group(suite)
        val (a, b, c) = ms
        val e0 = a.epoch(gid)
        val ub = b.updateKeys(gid, "rekey-b", now)
        val uc = c.updateKeys(gid, "rekey-c", now)
        // A's message from the previous epoch that reaches B and C after their updates.
        val late = a.encrypt(gid, "late".encodeToByteArray())
        val r1 = a.processIncomingTracked(gid, ub, now); assertIs<MlsIncoming.CommitApplied>(r1.incoming)
        val r2 = a.processIncomingTracked(gid, uc, now)
        val rb = b.processIncomingTracked(gid, uc, now)
        val rc = c.processIncomingTracked(gid, ub, now)
        // The same Commit wins for everyone: either A and C roll back to C's Commit, or B and C to B's Commit.
        val cWins = r2.rolledBack
        if (cWins) {
            assertIs<MlsIncoming.CommitApplied>(rb.incoming); assertTrue(rb.rolledBack)
            assertEquals(listOf("rekey-b"), rb.lostOps)
            assertIs<MlsIncoming.Ignored>(rc.incoming)
        } else {
            assertIs<MlsIncoming.Ignored>(r2.incoming); assertIs<MlsIncoming.Ignored>(rb.incoming)
            assertIs<MlsIncoming.CommitApplied>(rc.incoming); assertTrue(rc.rolledBack)
            assertEquals(listOf("rekey-c"), rc.lostOps)
        }
        assertEquals(setOf(e0 + 1), ms.map { it.epoch(gid) }.toSet())
        // The late message from the previous epoch opens for both (mark before their own Commit).
        assertContentEquals("late".encodeToByteArray(), app(b, gid, late))
        assertContentEquals("late".encodeToByteArray(), app(c, gid, late))
        allTalk(gid, ms, "after race")
        // The loser replays its update (GroupRepositoryImpl.recoverLostOps → rekeyLostRace → deadline).
        val loser = if (cWins) b else c
        val redo = loser.updateKeys(gid, "rekey-again", now + 1)
        for (m in ms) if (m !== loser) assertIs<MlsIncoming.CommitApplied>(m.processIncomingTracked(gid, redo, now + 1).incoming)
        assertEquals(setOf(e0 + 2), ms.map { it.epoch(gid) }.toSet())
        allTalk(gid, ms, "after redo")
        for (m in ms) assertEquals(suite, m.groupSuite(gid))
    }

    @Test
    fun concurrentUpdatesConvergeAndLoserRedoes_xwing() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        raceConverges(MlsSuites.XWING)
    }

    @Test
    fun concurrentUpdatesConvergeAndLoserRedoes_legacy() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        raceConverges(MlsSuites.LEGACY)
    }

    @Test
    fun threeUpdatesInARowKeepEveryoneInSync() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        for (suite in listOf(MlsSuites.XWING, MlsSuites.LEGACY)) {
            val (gid, ms) = group(suite)
            for ((round, who) in listOf(1, 2, 0).withIndex()) {
                val commit = ms[who].updateKeys(gid, "rekey", now + round)
                for ((i, m) in ms.withIndex()) if (i != who) assertIs<MlsIncoming.CommitApplied>(m.processIncomingTracked(gid, commit, now + round).incoming)
                allTalk(gid, ms, "round $round")
            }
        }
    }

    @Test
    fun scheduleCountsOwnPacketsAndResetsOnUpdate() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        val (gid, ms) = group(MlsSuites.XWING)
        val a = ms[0]
        val s0 = a.rekeyState(gid, now)
        // The first deadline is random within the interval (devices upgraded together do not Commit together).
        assertTrue(s0.dueAtMs > now && s0.dueAtMs <= now + GroupRekeyPolicy.INTERVAL_MS + 1)
        assertEquals(0, s0.sentSince)
        repeat(GroupRekeyPolicy.MSG_LIMIT) { a.encrypt(gid, "m$it".encodeToByteArray()) }
        val s1 = a.rekeyState(gid, now)
        assertEquals(GroupRekeyPolicy.MSG_LIMIT, s1.sentSince)
        // Right after joining: not more often than MIN_GAP; after an hour: due by count.
        assertNull(GroupRekeyPolicy.due(s1, now + 1, idleResume = false))
        assertEquals(GroupRekeyPolicy.Reason.MESSAGES, GroupRekeyPolicy.due(s1, now + GroupRekeyPolicy.MIN_GAP_MS, idleResume = false))
        a.updateKeys(gid, "rekey", now + GroupRekeyPolicy.MIN_GAP_MS)
        val s2 = a.rekeyState(gid, now + GroupRekeyPolicy.MIN_GAP_MS)
        assertEquals(0, s2.sentSince)
        val t2 = now + GroupRekeyPolicy.MIN_GAP_MS
        assertTrue(s2.dueAtMs in (t2 + GroupRekeyPolicy.INTERVAL_MS - GroupRekeyPolicy.JITTER_MS)..(t2 + GroupRekeyPolicy.INTERVAL_MS + GroupRekeyPolicy.JITTER_MS))
        // Lost race: retry in minutes, not in a week.
        a.rekeyLostRace(gid, t2 + 10)
        val s3 = a.rekeyState(gid, t2 + 10)
        assertTrue(s3.dueAtMs - (t2 + 10) <= GroupRekeyPolicy.LOST_RETRY_MIN_MS + GroupRekeyPolicy.LOST_RETRY_SPAN_MS)
        assertEquals(GroupRekeyPolicy.Reason.TIME, GroupRekeyPolicy.due(s3, s3.dueAtMs, idleResume = false))
        // Forgotten group: no record.
        a.forget(gid)
    }

    /** X-Wing migration crossed my update: accept the migration from the epoch before my Commit. */
    @Test
    fun regroupCrossingOwnUpdateIsAccepted() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        val (gid, ms) = group(MlsSuites.LEGACY)
        val (a, b, c) = ms
        val kpB = b.regroupKeyPackage(gid, MlsSuites.XWING)
        val kpC = c.regroupKeyPackage(gid, MlsSuites.XWING)
        // B updated its leaf, its Commit is still in flight; meanwhile A (admin) migrates the group.
        val ub = b.updateKeys(gid, "rekey", now)
        fun wrap(w: ByteArray, e: Long) = e.toString().encodeToByteArray() + "|".encodeToByteArray() + w
        val res = a.regroup(gid, MlsSuites.XWING, listOf(kpB, kpC), now, ::wrap)
        fun welcomeOf(p: ByteArray) = p.copyOfRange(p.indexOf('|'.code.toByte()) + 1, p.size)
        // B's Commit reaches A and C after the migration: not applied to the new group and breaks nothing.
        assertIs<MlsIncoming.Ignored>(a.processIncomingTracked(gid, ub, now).incoming)
        assertIs<MlsIncoming.CommitApplied>(c.processIncomingTracked(gid, ub, now).incoming)
        // B and C accept the migration (both are already past fromEpoch).
        for (m in listOf(b, c)) {
            val p = app(m, gid, res.oldGroupMessage)
            assertTrue(m.acceptRegroup(gid, MlsSuites.XWING, welcomeOf(p), res.fromEpoch, now), "regroup accepted past own/peer update")
            assertEquals(MlsSuites.XWING, m.groupSuite(gid))
        }
        allTalk(gid, ms, "after regroup")
    }
}
