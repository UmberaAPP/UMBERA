package app.umbera.core.crypto

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Safety-number version by peer capability. v2 only when the pair has pinned the peer's
 * WIRE_CAP_SAFETY_V2 bit (the peer itself computes v2); otherwise v1 byte for byte, as in 2.0.3 / 2.0.1. The bit is pinned
 * upwards; its disappearance is a downgrade ("key changed" window). A QR of the other version raises no false alarm.
 */
class SafetyNumberNegotiationTest {
    private class Kv : SecureKvStore {
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

    private fun b(n: Int, seed: Int) = ByteArray(n) { (it * 31 + seed).toByte() }
    private fun hex(x: ByteArray) = x.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    /** Account: public keys (secp256k1, X25519, ML-DSA-65, ML-KEM-1024). */
    private class Acc(val id: String, val secp: ByteArray, val x: ByteArray, val dsa: ByteArray, val kem: ByteArray)

    private fun acc(id: String, seed: Int) = Acc(id, b(33, seed), b(32, seed + 1), b(Dilithium3.PUBLIC_KEY_SIZE, seed + 2), b(Kyber1024.PUBLIC_KEY_SIZE, seed + 3))

    private fun device(me: Acc, peers: List<Acc>): SecureKeyStoreCommon {
        val ks = SecureKeyStoreCommon(Kv(), { false })
        ks.saveUserId(me.id)
        ks.saveSecp256k1PublicKey(me.secp); ks.saveX25519PublicKey(me.x)
        ks.saveDilithiumPublicKey(me.dsa); ks.saveKyberPublicKey(me.kem)
        for (p in peers) { ks.savePeerDilithium(p.id, p.dsa); ks.savePeerKyber(p.id, p.kem) }
        return ks
    }

    private fun screen(ks: SecureKeyStoreCommon, peer: Acc, v2: Boolean = SecurityRollout.safetyNumberV2) =
        SafetyNumber.forScreen(ks, peer.id, hex(peer.secp), app.umbera.core.util.B64.encode(peer.x), v2)!!

    /** The 2.0.3 / 2.0.1 formula (VerifyIdentityViewModel before v2) — the v1 reference, byte for byte. */
    private fun legacyV1(ks: SecureKeyStoreCommon, peer: Acc) =
        SafetyNumber.combined(SafetyNumber.mine(ks)!!, SafetyNumber.identity(hex(peer.secp), app.umbera.core.util.B64.encode(peer.x))!!)

    private val alice = acc("alice", 1)
    private val bob = acc("bob", 70)
    private val bit = MessageEncryption.WIRE_CAP_SAFETY_V2
    private val base = MessageEncryption.WIRE_CAPS

    @AfterTest fun restore() { SecurityRollout.setAll(true) }

    @Test fun withoutPeerBitBothSeeV1ByteForByte() {
        val a = device(alice, listOf(bob)); val bb = device(bob, listOf(alice))
        val sa = screen(a, bob); val sb = screen(bb, alice)
        assertEquals(SafetyNumber.V1, sa.version); assertEquals(sa.pair, sb.pair)
        assertEquals(legacyV1(a, bob), sa.pair.number)
        assertEquals(sa.pair.number, sa.qr) // QR v1 is the bare number, as always
        assertTrue(SafetyNumber.announcesV2(a))
    }

    @Test fun bothBitsGiveSameV2() {
        val a = device(alice, listOf(bob)); val bb = device(bob, listOf(alice))
        assertEquals(PeerCapsVerdict.OK, a.checkAndPinPeerWireCaps(bob.id, base or bit, 1000))
        assertEquals(PeerCapsVerdict.OK, bb.checkAndPinPeerWireCaps(alice.id, base or bit, 1000))
        val sa = screen(a, bob); val sb = screen(bb, alice)
        assertEquals(SafetyNumber.V2, sa.version); assertEquals(sa.pair, sb.pair)
        assertNotEquals(legacyV1(a, bob), sa.pair.number)
        assertTrue(sa.qr.startsWith("usn2:"))
    }

    @Test fun calmUpgradeNoticeAfterV1WasShown() {
        val a = device(alice, listOf(bob))
        assertEquals(SafetyNumber.Change.NONE, screen(a, bob).change) // v1 shown and remembered
        a.checkAndPinPeerWireCaps(bob.id, base or bit, 1000)
        val up = screen(a, bob)
        assertEquals(SafetyNumber.V2, up.version)
        assertEquals(SafetyNumber.Change.UPDATED_TO_V2, up.change)
        SafetyNumber.acknowledge(a, bob.id, up)
        assertEquals(SafetyNumber.Change.NONE, screen(a, bob).change)
    }

    @Test fun newVsOldStaysV1() {
        // "old" (protocol 2.0.3): switch off — does not advertise the bit, computes v1
        val a = device(alice, listOf(bob))
        a.checkAndPinPeerWireCaps(bob.id, base, 1000) // his messages lack the bit
        val sa = screen(a, bob)
        val old = device(bob, listOf(alice))
        val sOld = screen(old, alice, v2 = false)
        assertFalse(SecurityRollout.run { setAll(false); SafetyNumber.announcesV2(old) })
        SecurityRollout.setAll(true)
        assertEquals(SafetyNumber.V1, sa.version); assertEquals(sa.pair, sOld.pair)
        assertEquals(legacyV1(old, alice), sOld.pair.number)
    }

    @Test fun peerWithoutPqKeysStaysV1EvenWithBit() {
        val a = SecureKeyStoreCommon(Kv(), { false }).apply {
            saveUserId(alice.id); saveSecp256k1PublicKey(alice.secp); saveX25519PublicKey(alice.x)
            saveDilithiumPublicKey(alice.dsa); saveKyberPublicKey(alice.kem)
        } // no peer ML-DSA/ML-KEM keys
        a.checkAndPinPeerWireCaps(bob.id, base or bit, 1000)
        assertEquals(SafetyNumber.V1, screen(a, bob).version)
    }

    @Test fun oneSidedBitIsResolvedByScanWithoutAlarm() {
        val a = device(alice, listOf(bob)); val bb = device(bob, listOf(alice))
        a.checkAndPinPeerWireCaps(bob.id, base or bit, 1000) // Bob's bit reached Alice, hers has not reached Bob yet
        val sa = screen(a, bob); val sb = screen(bb, alice)
        assertEquals(SafetyNumber.V2, sa.version); assertEquals(SafetyNumber.V1, sb.version)
        // Alice scans Bob's v1 QR: the legacy part matches — neither a confirmation nor an alarm
        assertEquals(SafetyNumber.Scan.PEER_ON_V1, SafetyNumber.checkScan(a, bob.id, sb.qr, sa))
        // Bob scans Alice's v2 QR: matches his v2 over the same keys — proof, Bob switches to v2
        assertEquals(SafetyNumber.Scan.MATCH_V2, SafetyNumber.checkScan(bb, alice.id, sa.qr, sb))
        assertTrue(bb.peerSafetyV2(alice.id))
        assertEquals(sa.pair, screen(bb, alice).pair)
        // someone else's QR — mismatch
        val evil = acc("bob", 99)
        val se = screen(device(evil, listOf(alice)).also { it.checkAndPinPeerWireCaps(alice.id, base or bit, 1) }, alice)
        assertEquals(SafetyNumber.Scan.MISMATCH, SafetyNumber.checkScan(a, bob.id, se.qr, screen(a, bob)))
        assertEquals(SafetyNumber.Scan.MISMATCH, SafetyNumber.checkScan(a, bob.id, "usn2:zz", sa))
    }

    @Test fun swappedPqKeyIsMismatchNotUpgrade() {
        // the server substituted Bob's ML-KEM at Alice: v1 the same, v2 different
        val a = device(alice, listOf(bob)); val bb = device(bob, listOf(alice))
        a.savePeerKyber(bob.id, b(Kyber1024.PUBLIC_KEY_SIZE, 5))
        a.checkAndPinPeerWireCaps(bob.id, base or bit, 1000); bb.checkAndPinPeerWireCaps(alice.id, base or bit, 1000)
        val sa = screen(a, bob); val sb = screen(bb, alice)
        assertEquals(SafetyNumber.V2, sa.version); assertNotEquals(sa.pair, sb.pair)
        assertEquals(SafetyNumber.Scan.MISMATCH, SafetyNumber.checkScan(bb, alice.id, sa.qr, sb))
    }

    @Test fun bitIsPinnedAndItsLossIsDowngrade() {
        val a = device(alice, listOf(bob))
        a.checkAndPinPeerWireCaps(bob.id, base or bit, 1000)
        assertTrue(a.getPinnedPeerCryptoCaps(bob.id)!!.wire and bit != 0)
        assertEquals(PeerCapsVerdict.STALE, a.checkAndPinPeerWireCaps(bob.id, base, 500)) // stale message from the queue — does not count
        assertFalse(a.isPeerKeyChanged(bob.id))
        assertEquals(PeerCapsVerdict.DOWNGRADE, a.checkAndPinPeerWireCaps(bob.id, base, 2000))
        assertTrue(a.isPeerKeyChanged(bob.id))
        assertEquals(SafetyNumber.V2, screen(a, bob).version) // the code is not silently downgraded
    }

    @Test fun switchOffMeansV1AndNoAnnounce() {
        val a = device(alice, listOf(bob))
        a.checkAndPinPeerWireCaps(bob.id, base or bit, 1000)
        SecurityRollout.setAll(false)
        assertFalse(SafetyNumber.announcesV2(a))
        assertEquals(SafetyNumber.V1, screen(a, bob).version)
    }

    @Test fun linkedComputerShowsSameCodeAsPhone() {
        val phone = device(alice, listOf(bob))
        val pc = SecureKeyStoreCommon(Kv(), { false }).apply {
            saveUserId(alice.id)
            saveLinkedDevice("dev1", b(32, 3), alice.secp, alice.dsa, alice.x, alice.kem, "addr")
            savePeerDilithium(bob.id, bob.dsa); savePeerKyber(bob.id, bob.kem)
        }
        assertEquals(screen(phone, bob).pair, screen(pc, bob).pair) // v1 identical
        assertTrue(SafetyNumber.announcesV2(pc))
        phone.checkAndPinPeerWireCaps(bob.id, base or bit, 1000)
        pc.markPeerSafetyV2(bob.id) // the computer sees the bit in the device envelope
        assertEquals(SafetyNumber.V2, screen(pc, bob).version)
        assertEquals(screen(phone, bob).pair, screen(pc, bob).pair)
    }
}
