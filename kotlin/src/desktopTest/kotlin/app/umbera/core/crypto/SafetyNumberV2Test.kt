package app.umbera.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/** Safety number v2 with PQ keys, v1→v2 transition without a false alarm. */
class SafetyNumberV2Test {
    private fun b(n: Int, seed: Int) = ByteArray(n) { (it * 31 + seed).toByte() }
    private fun keys(seed: Int, pq: Boolean = true) =
        SafetyNumber.Keys(b(33, seed), b(32, seed + 1), if (pq) b(1952, seed + 2) else null, if (pq) b(1568, seed + 3) else null)

    private val alice = keys(1)
    private val bob = keys(50)

    @Test fun sameNumberOnBothSides() {
        val ab = SafetyNumber.forPair(alice, bob, v2Enabled = true)
        val ba = SafetyNumber.forPair(bob, alice, v2Enabled = true)
        assertEquals(SafetyNumber.V2, ab.version)
        assertEquals(ab, ba)
        assertEquals(64, ab.number.length) // same length as v1
    }

    @Test fun v2CoversPqKeys() {
        val base = SafetyNumber.forPair(alice, bob, true).number
        val swappedKem = SafetyNumber.Keys(bob.secp256k1, bob.x25519, bob.mlDsaPk, b(1568, 99))
        val swappedDsa = SafetyNumber.Keys(bob.secp256k1, bob.x25519, b(1952, 99), bob.mlKemPk)
        assertNotEquals(base, SafetyNumber.forPair(alice, swappedKem, true).number)
        assertNotEquals(base, SafetyNumber.forPair(alice, swappedDsa, true).number)
    }

    @Test fun lengthPrefixPreventsSplicing() {
        // the same bytes in sequence, but the key boundary is shifted: the fingerprint must differ
        val a = SafetyNumber.identityV2(b(33, 1), b(32, 2), b(4, 3), b(4, 4))
        val all = b(33, 1) + b(32, 2) + b(4, 3) + b(4, 4)
        val c = SafetyNumber.identityV2(all.copyOfRange(0, 34), all.copyOfRange(34, 65), all.copyOfRange(65, 69), all.copyOfRange(69, 73))
        assertNotEquals(a, c)
    }

    @Test fun fallsBackToV1WithoutPqOrWhenDisabled() {
        val v1 = SafetyNumber.combined(SafetyNumber.identity(alice.secp256k1, alice.x25519), SafetyNumber.identity(bob.secp256k1, bob.x25519))
        val noPq = SafetyNumber.forPair(alice, keys(50, pq = false), true)
        assertEquals(SafetyNumber.V1, noPq.version)
        assertEquals(v1, noPq.number)
        val off = SafetyNumber.forPair(alice, bob, v2Enabled = false)
        assertEquals(SafetyNumber.PairNumber(v1, SafetyNumber.V1), off)
        // the switch is on, but the pair's version is chosen by negotiation (SafetyNumberNegotiationTest)
        assertEquals(true, SecurityRollout.safetyNumberV2)
    }

    @Test fun upgradeIsCalmButKeySwapAlarms() {
        val oldV1 = SafetyNumber.forPair(alice, bob, false)
        val nowV2 = SafetyNumber.forPair(alice, bob, true)
        assertEquals(SafetyNumber.Change.UPDATED_TO_V2, SafetyNumber.classify(oldV1, nowV2, oldV1.number))
        assertEquals(SafetyNumber.Change.NONE, SafetyNumber.classify(nowV2, nowV2, oldV1.number))
        assertEquals(SafetyNumber.Change.NONE, SafetyNumber.classify(null, nowV2, oldV1.number))
        // X25519 changed at the same time: that is a key change, not an "upgrade"
        val evil = SafetyNumber.Keys(bob.secp256k1, b(32, 77), bob.mlDsaPk, bob.mlKemPk)
        val evilV1 = SafetyNumber.forPair(alice, evil, false).number
        val evilV2 = SafetyNumber.forPair(alice, evil, true)
        assertEquals(SafetyNumber.Change.KEY_CHANGED, SafetyNumber.classify(oldV1, evilV2, evilV1))
        // PQ key change while already on v2: alarm
        val pqSwap = SafetyNumber.forPair(alice, SafetyNumber.Keys(bob.secp256k1, bob.x25519, bob.mlDsaPk, b(1568, 5)), true)
        assertEquals(SafetyNumber.Change.KEY_CHANGED, SafetyNumber.classify(nowV2, pqSwap, oldV1.number))
        // downgrade v2→v1 (PQ keys "gone"): alarm, not silence
        assertEquals(SafetyNumber.Change.KEY_CHANGED, SafetyNumber.classify(nowV2, oldV1, oldV1.number))
    }

    @Test fun peerKeysDecodeDirectoryEncodings() {
        val hex = { x: ByteArray -> x.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') } }
        val k = SafetyNumber.peerKeys(hex(bob.secp256k1), app.umbera.core.util.B64.encode(bob.x25519), hex(bob.mlKemPk!!), hex(bob.mlDsaPk!!))!!
        assertEquals(SafetyNumber.forPair(alice, bob, true), SafetyNumber.forPair(alice, k, true))
        val noPq = SafetyNumber.peerKeys(hex(bob.secp256k1), app.umbera.core.util.B64.encode(bob.x25519), "", null)!!
        assertEquals(false, noPq.hasPq)
    }
}
