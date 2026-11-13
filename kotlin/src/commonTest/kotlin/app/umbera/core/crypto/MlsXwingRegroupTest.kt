package app.umbera.core.crypto

import app.umbera.core.crypto.mls.MlsManager
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * X-Wing at the MlsManager level, the way GroupRepositoryImpl calls it: new X-Wing groups, two
 * key packages in the reply to an invitation, migrating a previous-suite group to X-Wing without losing history
 * (a late message of the previous group still decrypts), reverse migration for a member on an older version,
 * a race of two migrations (one wins for everyone), in-place recreation while we are the only member.
 */
class MlsXwingRegroupTest {

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

    private suspend fun app(m: MlsManager, gid: ByteArray, msg: ByteArray): ByteArray {
        val r = m.processIncomingTracked(gid, msg, 1_000L)
        val a = assertIs<MlsIncoming.Application>(r.incoming)
        r.commit?.invoke()
        return a.plaintext
    }

    @Test
    fun newGroupsAreXwingAndJoinWithTheXwingPackage() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        val gid = secureRandomBytes(32)
        val a = manager(); val b = manager()
        a.createGroup(gid)
        assertEquals(MlsSuites.XWING, a.groupSuite(gid))
        val t = b.prepareJoin()
        val xw = assertNotNull(t.keyPackageXw)
        assertEquals(MlsSuites.XWING, MlsKeyPackages.info(xw).ciphersuite)
        assertEquals(MlsSuites.LEGACY, MlsKeyPackages.info(t.keyPackage).ciphersuite)
        assertContentEquals(t.memberId, MlsKeyPackages.info(xw).identity)
        val bundle = a.addMembers(gid, listOf(xw))
        assertContentEquals(gid, b.completeJoin(t.memberId, bundle.welcome, gid))
        assertEquals(MlsSuites.XWING, b.groupSuite(gid))
        assertContentEquals("pq".encodeToByteArray(), app(b, gid, a.encrypt(gid, "pq".encodeToByteArray())))
    }

    @Test
    fun legacyGroupUpgradesToXwingWithoutLosingLateMessages() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        val gid = secureRandomBytes(32)
        val a = manager(); val b = manager(); val c = manager()
        val aId = a.createGroup(gid, MlsSuites.LEGACY)
        val tb = b.prepareJoin(); val tc = c.prepareJoin()
        val add = a.addMembers(gid, listOf(tb.keyPackage, tc.keyPackage))
        b.completeJoin(tb.memberId, add.welcome, gid); c.completeJoin(tc.memberId, add.welcome, gid)
        assertTrue(a.allSupportXwing(gid))
        // Message of the previous group that reaches A after the migration.
        val late = c.encrypt(gid, "late".encodeToByteArray())
        val kpB = b.regroupKeyPackage(gid, MlsSuites.XWING)
        val kpC = c.regroupKeyPackage(gid, MlsSuites.XWING)
        val res = a.regroup(gid, MlsSuites.XWING, listOf(kpB, kpC), 1_000L) { w, e -> "W".encodeToByteArray() + e.toString().encodeToByteArray() + "|".encodeToByteArray() + w }
        assertEquals(MlsSuites.XWING, a.groupSuite(gid))
        // B and C receive the previous group's message with the Welcome and switch over.
        for (m in listOf(b, c)) {
            val p = app(m, gid, res.oldGroupMessage)
            val bar = p.indexOf('|'.code.toByte())
            val welcome = p.copyOfRange(bar + 1, p.size)
            assertTrue(m.acceptRegroup(gid, MlsSuites.XWING, welcome, res.fromEpoch, 1_000L))
            // Replaying the same Welcome: no change.
            assertTrue(m.acceptRegroup(gid, MlsSuites.XWING, welcome, res.fromEpoch, 1_000L))
            assertEquals(MlsSuites.XWING, m.groupSuite(gid))
        }
        assertContentEquals("late".encodeToByteArray(), app(a, gid, late))
        assertContentEquals("x".encodeToByteArray(), app(c, gid, b.encrypt(gid, "x".encodeToByteArray())))
        assertContentEquals("y".encodeToByteArray(), app(a, gid, c.encrypt(gid, "y".encodeToByteArray())))
        // Everyone has the same call secret.
        val s = listOf(a, b, c).map { it.exportSecret(gid, "conf", 32u).toList() }.toSet()
        assertEquals(1, s.size)
        assertContentEquals(aId, a.members(gid).first { it.identity.contentEquals(aId) }.identity)
    }

    @Test
    fun concurrentRegroupsConvergeOnTheSmallerHash() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        val gid = secureRandomBytes(32)
        val a = manager(); val b = manager(); val c = manager()
        a.createGroup(gid, MlsSuites.LEGACY)
        val tb = b.prepareJoin(); val tc = c.prepareJoin()
        val add = a.addMembers(gid, listOf(tb.keyPackage, tc.keyPackage))
        b.completeJoin(tb.memberId, add.welcome, gid); c.completeJoin(tc.memberId, add.welcome, gid)
        val kpA = a.regroupKeyPackage(gid, MlsSuites.XWING)
        val kpB = b.regroupKeyPackage(gid, MlsSuites.XWING)
        val kpC = c.regroupKeyPackage(gid, MlsSuites.XWING)
        fun wrap(w: ByteArray, e: Long) = e.toString().encodeToByteArray() + "|".encodeToByteArray() + w
        val ra = a.regroup(gid, MlsSuites.XWING, listOf(kpB, kpC), 1_000L, ::wrap)
        val rb = b.regroup(gid, MlsSuites.XWING, listOf(kpA, kpC), 1_000L, ::wrap)
        fun welcomeOf(p: ByteArray) = p.copyOfRange(p.indexOf('|'.code.toByte()) + 1, p.size)
        // Everyone receives the other's migration; previous-group messages are opened by the "retired" group.
        val pa = app(b, gid, ra.oldGroupMessage); val pb = app(a, gid, rb.oldGroupMessage)
        val pa2 = app(c, gid, ra.oldGroupMessage); val pb2 = app(c, gid, rb.oldGroupMessage)
        b.acceptRegroup(gid, MlsSuites.XWING, welcomeOf(pa), ra.fromEpoch, 1_000L)
        a.acceptRegroup(gid, MlsSuites.XWING, welcomeOf(pb), rb.fromEpoch, 1_000L)
        c.acceptRegroup(gid, MlsSuites.XWING, welcomeOf(pa2), ra.fromEpoch, 1_000L)
        c.acceptRegroup(gid, MlsSuites.XWING, welcomeOf(pb2), rb.fromEpoch, 1_000L)
        // All three are in one group: messages flow in every direction.
        assertContentEquals("1".encodeToByteArray(), app(b, gid, a.encrypt(gid, "1".encodeToByteArray())))
        assertContentEquals("2".encodeToByteArray(), app(c, gid, a.encrypt(gid, "2".encodeToByteArray())))
        assertContentEquals("3".encodeToByteArray(), app(a, gid, c.encrypt(gid, "3".encodeToByteArray())))
        assertEquals(1, listOf(a, b, c).map { it.exportSecret(gid, "conf", 32u).toList() }.toSet().size)
    }

    @Test
    fun aloneGroupRecreatesForAnOldInviteeAndRegroupNeedsEveryLeaf() = runTest {
        if (!rustCoreTestsEnabled()) return@runTest
        val gid = secureRandomBytes(32)
        val a = manager(); val b = manager()
        a.createGroup(gid)
        assertTrue(a.recreateAlone(gid, MlsSuites.LEGACY))
        assertEquals(MlsSuites.LEGACY, a.groupSuite(gid))
        val tb = b.prepareJoin()
        b.completeJoin(tb.memberId, a.addMembers(gid, listOf(tb.keyPackage)).welcome, gid)
        assertFalse(a.recreateAlone(gid, MlsSuites.XWING))
        // Without B's package the migration cannot be built (membership mismatch), the group stays as it was.
        val failed = runCatching { a.regroup(gid, MlsSuites.XWING, emptyList(), 1_000L) { w, _ -> w } }
        assertTrue(failed.isFailure)
        assertEquals(MlsSuites.LEGACY, a.groupSuite(gid))
        assertContentEquals("ok".encodeToByteArray(), app(b, gid, a.encrypt(gid, "ok".encodeToByteArray())))
    }

    @Test
    fun callFrameKeysAgree() {
        if (!rustCoreTestsEnabled()) return
        val kp = CallPq.keypair()
        val r = CallPq.respond("cid-1", kp.public)
        val i = CallPq.finish("cid-1", kp.secret, kp.public, r.answer)
        assertContentEquals(i.send, r.keys.recv)
        assertContentEquals(i.recv, r.keys.send)
        assertContentEquals(i.check, r.keys.check)
        assertEquals(32, i.send.size)
    }
}
