package app.umbera.core.crypto

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Hybrid STH: Ed25519 + ML-DSA-65. The vector is produced by the Go server
 * (the server's STH test, Ed25519 seed 0x11×32, ML-DSA seed 0x22×32,
 * deterministic signing; regenerate with KT_PQ_VECTOR_OUT=…). Go crypto/mldsa signs,
 * the Rust core (ml-dsa crate) verifies here — a cross-implementation check.
 */
class KeyTransparencyPqSthTest {

    private val edPub = "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
    private val edSig = "17653d18ecfe5eca7ff956f03a87a2d10f4bd405316d365c6320da44d5ba23a1cde13763a43b6b55fb446cf9f5093965fe221fdb3241f2be07835f460b86bc00"
    private val pqSig = "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"
    private val pqPub = "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"

    private fun sth(
        treeSize: Int = 5, root: String = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", ts: Long = 1731264000000L,
        edPublicKey: String = edPub, pqSignature: String? = pqSig, pqPublicKey: String? = pqPub,
    ) = KeyTransparencyVerifier.Sth(treeSize, root, ts, edSig, edPublicKey, pqSignature, pqPublicKey)

    @AfterTest fun reset() { SecurityRollout.ktPqSth = false }

    @Test fun messageMatchesGo() {
        assertEquals(
            "KT-STH-PQ-v1|5|cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd|1731264000000|$edPub",
            KeyTransparencyVerifier.sthPqMessage(sth()).decodeToString(),
        )
    }

    @Test fun switchOffBehavesAsBefore() {
        if (!rustCoreTestsEnabled()) return
        SecurityRollout.ktPqSth = false
        assertTrue(KeyTransparencyVerifier.sthAuthentic(sth(), edPub, null))
        // garbage PQ half is ignored while off (old behaviour: Ed25519 only)
        assertTrue(KeyTransparencyVerifier.sthAuthentic(sth(pqSignature = "AAAA"), edPub, pqPub))
        assertTrue(KeyTransparencyVerifier.sthAuthentic(sth(pqSignature = null, pqPublicKey = null), edPub, pqPub))
    }

    @Test fun hybridVerifiesAndPins() {
        if (!rustCoreTestsEnabled()) return
        SecurityRollout.ktPqSth = true
        assertTrue(KeyTransparencyVerifier.sthAuthentic(sth(), null, null), "first contact: both halves good")
        assertTrue(KeyTransparencyVerifier.sthAuthentic(sth(), edPub, pqPub), "pinned keys match")
        // old server (no PQ half) and nothing PQ pinned yet → accepted (old server keeps working)
        assertTrue(KeyTransparencyVerifier.sthAuthentic(sth(pqSignature = null, pqPublicKey = null), edPub, null))
    }

    @Test fun hybridRejectsTamperSwapAndStrip() {
        if (!rustCoreTestsEnabled()) return
        SecurityRollout.ktPqSth = true
        // a bad PQ signature fails even though Ed25519 is good
        val flipped = pqSig.substring(0, 10) + (if (pqSig[10] == 'A') 'B' else 'A') + pqSig.substring(11)
        assertFalse(KeyTransparencyVerifier.sthAuthentic(sth(pqSignature = flipped), edPub, pqPub))
        // ML-DSA key differs from the pinned one
        assertFalse(KeyTransparencyVerifier.sthAuthentic(sth(), edPub, "AAAA" + pqPub.substring(4)))
        // downgrade: PQ key pinned, server strips the PQ half
        assertFalse(KeyTransparencyVerifier.sthAuthentic(sth(pqSignature = null, pqPublicKey = null), edPub, pqPub))
        // Ed25519 half tampered (tree size) → fails regardless of PQ
        assertFalse(KeyTransparencyVerifier.sthAuthentic(sth(treeSize = 6), edPub, pqPub))
        // Ed25519 pin mismatch
        assertFalse(KeyTransparencyVerifier.sthAuthentic(sth(), "00".repeat(32), pqPub))
    }
}
