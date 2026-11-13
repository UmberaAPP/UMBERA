package app.umbera.core.crypto

import app.umbera.core.util.WireJson
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import app.umbera.core.crypto.GroupPqSig.Status

/** Hash chain + checkpoint signature + ML-DSA on Commit (real Rust core, same as on iOS). */
class GroupPqSigTest {
    private val gid = "a1b2c3d4"
    private val leaf = "leaf-07"
    private val kp = Dilithium3.generateKeyPair()
    private val sk = kp.privateKey.encoded
    private val pk = kp.publicKey.encoded

    private fun frame(i: Int) = ByteArray(300) { (it * 31 + i).toByte() }

    private data class Sent(val id: String, val prev: ByteArray, val frame: ByteArray)

    private fun sendN(chain: GroupPqSig.SenderChain, n: Int, from: Int = 0): List<Sent> =
        (from until from + n).map { i -> val f = frame(i); Sent("m$i", chain.next("m$i", f, 1000L + i), f) }

    @Test fun chainConfirmsInOrder() {
        val s = GroupPqSig.SenderChain(gid, leaf, epoch = 5, nowMs = 0)
        val msgs = sendN(s, 20)
        assertTrue(s.checkpointDue(2000))
        val cp = GroupPqSig.Checkpoint.decode(s.checkpoint(sk).encode())!!
        val r = GroupPqSig.ReceiverChain(gid, leaf, 5, pk)
        msgs.forEach { assertEquals(Status.UNCONFIRMED, r.accept(it.id, it.prev, it.frame)) }
        assertTrue(r.acceptCheckpoint(cp))
        msgs.forEach { assertEquals(Status.CONFIRMED, r.status(it.id)) }
        assertFalse(s.checkpointDue(2000))
    }

    @Test fun reorderAndGapThenConfirm() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val msgs = sendN(s, 7)
        val cp = s.checkpoint(sk)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        // Checkpoint arrives before the messages, messages out of order, one still in flight.
        assertTrue(r.acceptCheckpoint(cp))
        listOf(6, 2, 0, 4, 1, 5).forEach { r.accept(msgs[it].id, msgs[it].prev, msgs[it].frame) }
        // Walking back from the checkpoint to the gap (m3 in flight): already confirmed; before the gap: not yet.
        (0..3).forEach { assertEquals(Status.UNCONFIRMED, r.status(msgs[it].id)) }
        (4..6).forEach { assertEquals(Status.CONFIRMED, r.status(msgs[it].id)) }
        r.accept(msgs[3].id, msgs[3].prev, msgs[3].frame)
        msgs.forEach { assertEquals(Status.CONFIRMED, r.status(it.id)) }
        // Replaying an already accepted message changes nothing.
        assertEquals(Status.CONFIRMED, r.accept(msgs[3].id, msgs[3].prev, msgs[3].frame))
    }

    @Test fun substitutedMiddleFrameIsViolated() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val msgs = sendN(s, 5)
        val cp = s.checkpoint(sk)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        msgs.forEachIndexed { i, m ->
            val f = if (i == 2) m.frame.copyOf().also { it[10] = (it[10] + 1).toByte() } else m.frame
            r.accept(m.id, m.prev, f)
        }
        // The path back from the checkpoint breaks at m3 (its h_{i-1} is the real m2), while walking forward from h_0 the
        // receiver has m0, m1 and the substituted m2, so the signed m2 is not ours. Previously this was only "unconfirmed".
        assertFalse(r.acceptCheckpoint(cp))
        assertEquals("chain-mismatch", r.violationReason)
        msgs.forEach { assertEquals(Status.VIOLATED, r.status(it.id)) }
    }

    /** Substitution while earlier frames are still in flight: the substituted one is not confirmed; once the earlier ones arrive, it is a violation. */
    @Test fun substitutedFrameWithGapNeverConfirmsThenViolates() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val msgs = sendN(s, 6)
        val cp = s.checkpoint(sk)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        val bad = msgs[3].frame.copyOf().also { it[0] = (it[0] + 1).toByte() }
        r.accept(msgs[3].id, msgs[3].prev, bad)
        r.accept(msgs[4].id, msgs[4].prev, msgs[4].frame)
        r.accept(msgs[5].id, msgs[5].prev, msgs[5].frame)
        assertTrue(r.acceptCheckpoint(cp))
        assertEquals(Status.CONFIRMED, r.status("m5"))
        assertEquals(Status.CONFIRMED, r.status("m4")) // m4 is honest: its link leads to the signed head
        assertEquals(Status.UNCONFIRMED, r.status("m3")) // substituted: the path from the checkpoint does not reach it
        listOf(0, 1, 2).forEach { r.accept(msgs[it].id, msgs[it].prev, msgs[it].frame) }
        assertEquals(Status.VIOLATED, r.status("m3"))
        assertEquals("chain-mismatch", r.violationReason)
    }

    @Test fun substitutedLastFrameMismatchIsViolated() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val msgs = sendN(s, 4)
        val cp = s.checkpoint(sk)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        msgs.forEachIndexed { i, m -> r.accept(m.id, m.prev, if (i == 3) frame(999) else m.frame) }
        assertFalse(r.acceptCheckpoint(cp))
        assertEquals(Status.VIOLATED, r.status("m0"))
        assertEquals("chain-mismatch", r.violationReason)
    }

    @Test fun forkIsViolated() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val msgs = sendN(s, 2)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        r.accept(msgs[0].id, msgs[0].prev, msgs[0].frame)
        assertEquals(Status.VIOLATED, r.accept("evil", msgs[0].prev, frame(77)))
        assertEquals("fork", r.violationReason)
    }

    @Test fun foreignCheckpointSignatureIsViolated() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val msgs = sendN(s, 3)
        val other = Dilithium3.generateKeyPair().privateKey.encoded
        val cp = s.checkpoint(other)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        msgs.forEach { r.accept(it.id, it.prev, it.frame) }
        assertFalse(r.acceptCheckpoint(cp))
        assertEquals(Status.VIOLATED, r.status("m1"))
    }

    @Test fun chainNotTransferableToOtherGroupLeafOrEpoch() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val msgs = sendN(s, 3)
        val cp = s.checkpoint(sk)
        for (r in listOf(GroupPqSig.ReceiverChain("other", leaf, 1, pk), GroupPqSig.ReceiverChain(gid, "leaf-08", 1, pk))) {
            msgs.forEach { r.accept(it.id, it.prev, it.frame) }
            assertFalse(r.acceptCheckpoint(cp))
            assertEquals(Status.VIOLATED, r.status("m0"))
        }
        // Foreign epoch: the checkpoint does not belong to this chain.
        val r2 = GroupPqSig.ReceiverChain(gid, leaf, 2, pk)
        assertFalse(r2.acceptCheckpoint(cp))
    }

    @Test fun newEpochResetsChain() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        sendN(s, 5)
        val g1 = s.head.copyOf()
        s.reset(2, 5000)
        assertEquals(0, s.index)
        assertTrue(s.head.contentEquals(GroupPqSig.genesis(gid, 2, leaf)))
        assertFalse(s.head.contentEquals(g1))
        val msgs = sendN(s, 3, from = 100)
        val book = GroupPqSig.ReceiverBook(gid) { pk }
        val r = book.chain(leaf, 2)!!
        msgs.forEach { r.accept(it.id, it.prev, it.frame) }
        assertTrue(r.acceptCheckpoint(s.checkpoint(sk)))
        msgs.forEach { assertEquals(Status.CONFIRMED, r.status(it.id)) }
        // Epoch 1 is neither current nor previous (this leaf never opened epoch 1): rejected.
        assertNull(book.chain(leaf, 1))
    }

    /** As in GroupRepositoryImpl.pqChainApp: the checkpoint rides in the envelope of the 20th message (after next); the receiver
     *  accepts the frame, then the checkpoint from the same envelope; the 25th is already the next batch, "unconfirmed" until its own. */
    @Test fun piggybackCheckpointOnTwentieth() {
        val s = GroupPqSig.SenderChain(gid, leaf, 3, 0)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 3, pk)
        var cps = 0
        for (i in 0 until 25) {
            val f = frame(i); val id = "f$i"
            val prev = s.next(id, f, 1000L + i)
            val cp = if (s.checkpointDue(1000L + i)) s.checkpoint(sk).encode() else null
            r.accept(id, prev, f)
            cp?.let { cps++; assertTrue(r.acceptCheckpoint(GroupPqSig.Checkpoint.decode(it)!!)) }
        }
        assertEquals(1, cps)
        (0 until 20).forEach { assertEquals(Status.CONFIRMED, r.status("f$it")) }
        (20 until 25).forEach { assertEquals(Status.UNCONFIRMED, r.status("f$it")) }
        assertTrue(s.checkpointDue(1024L + GroupPqSig.CHECKPOINT_IDLE_MS)) // 30 s of silence → standalone checkpoint
        assertTrue(r.acceptCheckpoint(s.checkpoint(sk)))
        (20 until 25).forEach { assertEquals(Status.CONFIRMED, r.status("f$it")) }
    }

    /** Desktop: checkpoint signed with the device hybrid (Ed25519 + ML-DSA-65 from the seed, its own group context). Verified with the
     *  device keys; a device-envelope signature (context umbera-dv1/sig) does not pass as a group signature, nor does a foreign device. */
    @Test fun deviceSignedCheckpoint() {
        val seed = DeviceLinkCore.deviceSeedGenerate()
        val keys = DeviceLinkCore.devicePublicKeys(seed)
        val verify = { m: ByteArray, sg: ByteArray -> DeviceLinkCore.deviceVerify(keys, GroupPqSig.DEVICE_CONTEXT, m, sg) }
        val s = GroupPqSig.SenderChain(gid, "pc-leaf", 4, 0)
        val msgs = (0 until 3).map { i -> val f = frame(i); Sent("d$i", s.next("d$i", f, 10L + i), f) }
        val good = s.checkpointWith { DeviceLinkCore.deviceSign(seed, GroupPqSig.DEVICE_CONTEXT, it) }
        val r = GroupPqSig.ReceiverChain(gid, "pc-leaf", 4, verify)
        msgs.forEach { r.accept(it.id, it.prev, it.frame) }
        assertTrue(r.acceptCheckpoint(good))
        msgs.forEach { assertEquals(Status.CONFIRMED, r.status(it.id)) }
        // Checkpoint signed in the device-envelope context: rejected.
        val s2 = GroupPqSig.SenderChain(gid, "pc-leaf", 4, 0)
        val m2 = (0 until 2).map { i -> val f = frame(i); Sent("e$i", s2.next("e$i", f, 10L + i), f) }
        val wrongCtx = s2.checkpointWith { DeviceLinkCore.deviceSign(seed, "umbera-dv1/sig", it) }
        val r2 = GroupPqSig.ReceiverChain(gid, "pc-leaf", 4, verify)
        m2.forEach { r2.accept(it.id, it.prev, it.frame) }
        assertFalse(r2.acceptCheckpoint(wrongCtx))
        // Foreign device.
        val other = DeviceLinkCore.deviceSeedGenerate()
        val s3 = GroupPqSig.SenderChain(gid, "pc-leaf", 4, 0)
        val m3 = (0 until 2).map { i -> val f = frame(i); Sent("g$i", s3.next("g$i", f, 10L + i), f) }
        val r3 = GroupPqSig.ReceiverChain(gid, "pc-leaf", 4, verify)
        m3.forEach { r3.accept(it.id, it.prev, it.frame) }
        assertFalse(r3.acceptCheckpoint(s3.checkpointWith { DeviceLinkCore.deviceSign(other, GroupPqSig.DEVICE_CONTEXT, it) }))
        assertEquals(Status.VIOLATED, r3.status("g0"))
        // Commit signed by a device.
        val t = GroupPqSig.commitTranscript(gid, "mls", frame(9), null, null, "[sibs]")
        val sig = DeviceLinkCore.deviceSign(seed, GroupPqSig.DEVICE_CONTEXT, t)
        assertTrue(verify(t, sig))
        assertFalse(verify(GroupPqSig.commitTranscript(gid, "mls", frame(9), null, null, "[sibs2]"), sig))
    }

    /** Which leaves the core accepts for a Commit: signed (only the signer's leaves) and unsigned
     *  (all except those that announced a signature; if nobody announced, no restriction, as before). */
    @Test fun commitSenderLists() {
        val owners = mapOf("alice-phone" to "alice", "bob-phone" to "bob", "alice-pc" to "alice", "carol-phone" to "carol")
        val links = listOf(GroupPqSig.LeafLink("alice-phone", "alice-pc", "dev-a1"))
        val tree = listOf("alice-phone", "alice-pc", "bob-phone", "carol-phone")
        val own = { l: String -> owners[l] }
        assertEquals(listOf("alice-phone"), GroupPqSig.commitSendersSigned(tree, "alice", null, own, links))
        assertEquals(listOf("alice-pc"), GroupPqSig.commitSendersSigned(tree, "alice", "dev-a1", own, links))
        assertEquals(emptyList(), GroupPqSig.commitSendersSigned(tree, "alice", "dev-a9", own, links))
        assertEquals(emptyList(), GroupPqSig.commitSendersSigned(tree, "mallory", null, own, links))
        // Unsigned: nobody announced → null (as before); Bob announced → his unsigned Commit is rejected.
        assertEquals(null, GroupPqSig.commitSendersUnsigned(tree) { false })
        assertEquals(listOf("alice-phone", "alice-pc", "carol-phone"), GroupPqSig.commitSendersUnsigned(tree) { it == "bob-phone" })
        assertEquals(emptyList(), GroupPqSig.commitSendersUnsigned(tree) { true })
    }

    /** A member with their OWN valid key impersonates someone else's leaf (or their desktop leaf as the phone): rejected. */
    @Test fun leafMustBelongToSigner() {
        val owners = mapOf("alice-phone" to "alice", "bob-phone" to "bob", "alice-pc" to "alice")
        val links = listOf(GroupPqSig.LeafLink("alice-phone", "alice-pc", "dev-a1"))
        val own = { l: String -> owners[l] }
        // Correct: phone signed by the account, desktop by its own device.
        assertTrue(GroupPqSig.leafMatchesSigner("alice-phone", "alice", null, own, links))
        assertTrue(GroupPqSig.leafMatchesSigner("ALICE-PC", "alice", "dev-a1", own, links))
        // Bob signs a frame of Alice's leaf with his own key.
        assertFalse(GroupPqSig.leafMatchesSigner("alice-phone", "bob", null, own, links))
        assertFalse(GroupPqSig.leafMatchesSigner("alice-pc", "bob", "dev-a1", own, links))
        // Desktop leaf signed with the account key (instead of the device key), and phone leaf signed by the device.
        assertFalse(GroupPqSig.leafMatchesSigner("alice-pc", "alice", null, own, links))
        assertFalse(GroupPqSig.leafMatchesSigner("alice-phone", "alice", "dev-a1", own, links))
        // Another device of the same account for this leaf; unknown leaf.
        assertFalse(GroupPqSig.leafMatchesSigner("alice-pc", "alice", "dev-a2", own, links))
        assertFalse(GroupPqSig.leafMatchesSigner("stranger", "alice", null, own, links))
        // After a mismatch the leaf chain is "violated", and a valid checkpoint does not clear it.
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val m = (0 until 2).map { i -> val f = frame(i); Sent("x$i", s.next("x$i", f, i.toLong()), f) }
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        m.forEach { r.accept(it.id, it.prev, it.frame) }
        r.markViolated("leaf-signer-mismatch")
        assertFalse(r.acceptCheckpoint(s.checkpoint(sk)))
        assertEquals(Status.VIOLATED, r.status("x0"))
    }

    @Test fun idleCheckpoint() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        assertFalse(s.checkpointDue(100_000)) // nothing to confirm
        s.next("a", frame(1), 1000)
        assertFalse(s.checkpointDue(1000 + 29_999))
        assertTrue(s.checkpointDue(1000 + 30_000))
    }

    // Optimization: in a quiet group the signature rides in the message itself after silence; no standalone frame needed.
    @Test fun sparseMessageCarriesItsOwnCheckpoint() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        var t = 0L
        repeat(5) { i ->
            t += 120_000 // less often than once per 30 s
            val f = frame(i)
            val prev = s.next("s$i", f, t)
            assertTrue(s.checkpointDueOnSend(t), "message $i after silence carries the signature")
            val cp = s.checkpoint(sk)
            r.accept("s$i", prev, f)
            assertTrue(r.acceptCheckpoint(cp))
            assertEquals(Status.CONFIRMED, r.status("s$i"))
            assertFalse(s.checkpointDue(t + 30_000), "no standalone frame needed after 30 s")
        }
    }

    @Test fun burstAfterQuietSignsFirstThenTail() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        s.next("b0", frame(0), 100_000)
        assertTrue(s.checkpointDueOnSend(100_000)); s.checkpoint(sk)
        s.next("b1", frame(1), 105_000)
        assertFalse(s.checkpointDueOnSend(105_000), "inside a batch: no signature")
        s.next("b2", frame(2), 110_000)
        assertFalse(s.checkpointDueOnSend(110_000))
        assertTrue(s.checkpointDue(140_000), "batch tail: standalone checkpoint after silence, as before")
    }

    @Test fun firstMessageAfterRestoreIsSignedInline() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        s.next("r0", frame(0), 1000); s.checkpoint(sk)
        val restored = GroupPqSig.SenderChain.restore(gid, leaf, s.save(), 2000)!!
        restored.next("r1", frame(1), 2001)
        assertTrue(restored.checkpointDueOnSend(2001))
    }

    @Test fun commitSignature() {
        val mls = frame(5)
        val t = GroupPqSig.commitTranscript(gid, "mls", mls, null, "[roster]", null)
        val sig = GroupPqSig.signCommit(t, sk)
        assertTrue(GroupPqSig.verifyCommit(t, sig, pk))
        val bad = mls.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFalse(GroupPqSig.verifyCommit(GroupPqSig.commitTranscript(gid, "mls", bad, null, "[roster]", null), sig, pk))
        assertFalse(GroupPqSig.verifyCommit(GroupPqSig.commitTranscript(gid, "mls", mls, null, "[roster2]", null), sig, pk))
        assertFalse(GroupPqSig.verifyCommit(GroupPqSig.commitTranscript(gid, "mls", mls, null, "[roster]", "[sibs]"), sig, pk))
        assertFalse(GroupPqSig.verifyCommit(GroupPqSig.commitTranscript("other", "mls", mls, null, "[roster]", null), sig, pk))
        assertFalse(GroupPqSig.verifyCommit(t, sig, Dilithium3.generateKeyPair().publicKey.encoded))
        assertFalse(GroupPqSig.verifyCommit(t, ByteArray(10), pk)) // corrupted signature: false, not an exception
    }

    @Test fun byteOverhead() {
        val sigLen = GroupPqSig.signCommit(byteArrayOf(1), sk).size
        val perMsgRaw = GroupPqSig.HASH_LEN
        val perMsgJson = GroupPqSig.envelopeChainOverheadJson()
        val cpJson = GroupPqSig.envelopeCheckpointOverheadJson(sigLen)
        val avgJson = perMsgJson + cpJson.toDouble() / GroupPqSig.CHECKPOINT_EVERY
        val commitJson = ",\"pqs\":\"\",\"pqv\":1".length + GroupPqSig.b64Len(sigLen)
        val oldPerEnvelope = ",\"pqs\":\"\",\"pqk\":\"a\",\"pqv\":1".length + GroupPqSig.b64Len(sigLen)
        println("Overhead: ML-DSA-65 signature $sigLen B; message +$perMsgRaw B (in JSON +$perMsgJson B); " +
            "pqcp checkpoint in JSON +$cpJson B once per ${GroupPqSig.CHECKPOINT_EVERY}; average ≈ +${avgJson.toInt()} B/message; " +
            "Commit/Proposal +$commitJson B; would be (signature on every envelope) +$oldPerEnvelope B/message")
        assertEquals(3309, sigLen)
        assertEquals(32, perMsgRaw)
        assertTrue(avgJson < 400, "average overhead $avgJson")
    }

    /**
     * Messages sent < 30 s before a group key change used to stay "not PQ-confirmed"
     * forever: reset() dropped the old epoch's chain without a checkpoint. advance() returns the old epoch's checkpoint.
     */
    @Test fun epochChangeFlushesPendingCheckpoint() {
        val s = GroupPqSig.SenderChain(gid, leaf, epoch = 2, nowMs = 0)
        val old = sendN(s, 9)
        val r2 = GroupPqSig.ReceiverChain(gid, leaf, 2, pk)
        old.forEach { assertEquals(Status.UNCONFIRMED, r2.accept(it.id, it.prev, it.frame)) }
        // Epoch change after 5 s (before 30 s of silence): checkpoint signed in the OLD epoch, covering all 9.
        assertFalse(s.checkpointDue(5_000))
        val cp = s.advance(4, 5_000) { Dilithium3.sign(it, sk).bytes }!!
        assertEquals(2L, cp.epoch); assertEquals(9, cp.index)
        assertTrue(r2.acceptCheckpoint(GroupPqSig.Checkpoint.decode(cp.encode())!!))
        old.forEach { assertEquals(Status.CONFIRMED, r2.status(it.id)) }
        // The new epoch has its own chain from zero, confirmed by its own checkpoint.
        assertEquals(4L, s.epoch); assertEquals(0, s.index); assertFalse(s.hasUnconfirmed())
        val fresh = sendN(s, 3, from = 100)
        val r4 = GroupPqSig.ReceiverChain(gid, leaf, 4, pk)
        fresh.forEach { r4.accept(it.id, it.prev, it.frame) }
        assertTrue(r4.acceptCheckpoint(s.checkpoint(sk)))
        fresh.forEach { assertEquals(Status.CONFIRMED, r4.status(it.id)) }
        // Everything is already confirmed: no extra signature on the next epoch change.
        assertNull(s.advance(5, 9_000) { error("no signature expected") })
    }

    // ── Sender and receiver restart in the middle of an epoch ──────────────

    /** (a) Sender restarted in the same epoch: the chain is restored from storage, no fork, no warning. */
    @Test fun senderRestartSameEpochContinuesChain() {
        val r = GroupPqSig.ReceiverChain(gid, leaf, 9, pk)
        val s1 = GroupPqSig.SenderChain(gid, leaf, 9, 0)
        repeat(3) { i -> val f = frame(i); r.accept("a$i", s1.next("a$i", f, i.toLong()), f) }
        assertTrue(r.acceptCheckpoint(s1.checkpoint(sk)))
        val saved = s1.save()
        val s2 = GroupPqSig.SenderChain.restore(gid, leaf, saved, 100)!! // process killed and restarted
        val f = frame(50)
        assertEquals(Status.UNCONFIRMED, r.accept("b0", s2.next("b0", f, 100), f))
        assertFalse(r.violated)
        assertEquals(Status.CONFIRMED, r.status("a0"))
        assertTrue(r.acceptCheckpoint(s2.checkpoint(sk)))
        assertEquals(Status.CONFIRMED, r.status("b0"))
    }

    /** Saved but not sent (process died between next and fan-out): the gap is not a violation, later messages are confirmed. */
    @Test fun senderCrashAfterSaveLeavesGapNotFork() {
        val r = GroupPqSig.ReceiverChain(gid, leaf, 9, pk)
        val s1 = GroupPqSig.SenderChain(gid, leaf, 9, 0)
        repeat(2) { i -> val f = frame(i); r.accept("a$i", s1.next("a$i", f, i.toLong()), f) }
        s1.next("lost", frame(7), 3) // folded into the chain and saved, but never sent
        val s2 = GroupPqSig.SenderChain.restore(gid, leaf, s1.save(), 10)!!
        val f = frame(8)
        r.accept("b0", s2.next("b0", f, 10), f)
        assertTrue(r.acceptCheckpoint(s2.checkpoint(sk)))
        assertFalse(r.violated)
        assertEquals(Status.CONFIRMED, r.status("b0"))
    }

    /** Without persistence (old behaviour) a restart still produces a fork, and we catch it. */
    @Test fun senderRestartWithoutStateIsFork() {
        val r = GroupPqSig.ReceiverChain(gid, leaf, 9, pk)
        val s1 = GroupPqSig.SenderChain(gid, leaf, 9, 0)
        repeat(3) { i -> val f = frame(i); r.accept("a$i", s1.next("a$i", f, i.toLong()), f) }
        val s2 = GroupPqSig.SenderChain(gid, leaf, 9, 100)
        val f = frame(50)
        assertEquals(Status.VIOLATED, r.accept("b0", s2.next("b0", f, 100), f)); assertEquals("fork", r.violationReason)
    }

    /** Saved state: foreign leaf / corrupted record is not restored; old epoch yields a checkpoint on change. */
    @Test fun restoreGuards() {
        val s = GroupPqSig.SenderChain(gid, leaf, 3, 0)
        val old = sendN(s, 4)
        val saved = s.save()
        assertNull(GroupPqSig.SenderChain.restore(gid, "leaf-08", saved, 0))
        assertNull(GroupPqSig.SenderChain.restore(gid, leaf, null, 0))
        assertNull(GroupPqSig.SenderChain.restore(gid, leaf, saved.replaceAfterLast('|', "99"), 0)) // lastCp > index
        assertNull(GroupPqSig.SenderChain.restore(gid, leaf, "1|$leaf|3|0|" + "00".repeat(32) + "|0", 0)) // index 0, head is not h_0
        val back = GroupPqSig.SenderChain.restore(gid, leaf, saved, 0)!!
        assertEquals(3L, back.epoch); assertEquals(4, back.index); assertTrue(back.head.contentEquals(s.head))
        // While the process was down, the group rekeyed: messages before the restart are covered by the old epoch's checkpoint.
        val r = GroupPqSig.ReceiverChain(gid, leaf, 3, pk)
        old.forEach { r.accept(it.id, it.prev, it.frame) }
        val cp = back.advance(4, 50) { Dilithium3.sign(it, sk).bytes }!!
        assertTrue(r.acceptCheckpoint(cp))
        old.forEach { assertEquals(Status.CONFIRMED, r.status(it.id)) }
    }

    /** (b) Receiver restarted mid-epoch: the start of the chain is missing, but everything received afterwards is confirmed. */
    @Test fun receiverRestartMidEpochConfirms() {
        val s = GroupPqSig.SenderChain(gid, leaf, 9, 0)
        repeat(5) { i -> s.next("a$i", frame(i), i.toLong()) }
        val r = GroupPqSig.ReceiverChain(gid, leaf, 9, pk) // receiver restart
        val ids = (5 until 10).map { i -> val f = frame(i); r.accept("a$i", s.next("a$i", f, i.toLong()), f); "a$i" }
        assertTrue(r.acceptCheckpoint(s.checkpoint(sk)))
        ids.forEach { assertEquals(Status.CONFIRMED, r.status(it)) }
        // The next batch of the same epoch too.
        val more = (10 until 13).map { i -> val f = frame(i); r.accept("a$i", s.next("a$i", f, i.toLong()), f); "a$i" }
        assertTrue(r.acceptCheckpoint(s.checkpoint(sk)))
        more.forEach { assertEquals(Status.CONFIRMED, r.status(it)) }
    }

    /** Substitution after a receiver restart: the substituted message and everything before it is unconfirmed, everything after is confirmed. */
    @Test fun receiverRestartSubstitutionNeverConfirmed() {
        val s = GroupPqSig.SenderChain(gid, leaf, 9, 0)
        repeat(5) { i -> s.next("a$i", frame(i), i.toLong()) }
        val r = GroupPqSig.ReceiverChain(gid, leaf, 9, pk)
        (5 until 10).forEach { i ->
            val f = frame(i); val prev = s.next("a$i", f, i.toLong())
            r.accept("a$i", prev, if (i == 7) frame(700) else f)
        }
        r.acceptCheckpoint(s.checkpoint(sk))
        listOf("a5", "a6", "a7").forEach { assertTrue(r.status(it) != Status.CONFIRMED, it) }
        listOf("a8", "a9").forEach { assertEquals(Status.CONFIRMED, r.status(it), it) }
    }

    /** Forged index: the path from the head is longer than the signature claims: violation (the checkpoint is signed, but not this one). */
    @Test fun checkpointIndexMustMatchPathLength() {
        val s = GroupPqSig.SenderChain(gid, leaf, 1, 0)
        val msgs = sendN(s, 4)
        val r = GroupPqSig.ReceiverChain(gid, leaf, 1, pk)
        msgs.forEach { r.accept(it.id, it.prev, it.frame) }
        // Honest signature, but over (index=2, h=h_4): the path from h_4 to h_0 is 4 links ≠ 2.
        val sig = Dilithium3.sign(GroupPqSig.checkpointMessage(gid, 1, leaf, 2, s.head), sk).bytes
        assertFalse(r.acceptCheckpoint(GroupPqSig.Checkpoint(1, 2, s.head.copyOf(), sig)))
        assertEquals("chain-mismatch", r.violationReason)
    }

    /**
     * The old epoch's checkpoint arrived AFTER the first message of the new epoch (a neighbouring message overtook
     * it during fan-out). Previously the leaf chain had already moved to the new epoch and dropped the checkpoint, so messages before the Commit
     * stayed "unconfirmed" forever. Now the previous epoch's chain accepts it.
     */
    @Test fun staleCheckpointAfterNewEpochMessageStillConfirms() {
        val s = GroupPqSig.SenderChain(gid, leaf, epoch = 6, nowMs = 0)
        val old = sendN(s, 4)
        val book = GroupPqSig.ReceiverBook(gid) { pk }
        old.forEach { book.chain(leaf, 6)!!.accept(it.id, it.prev, it.frame) }
        val stale = s.advance(7, 1_000) { Dilithium3.sign(it, sk).bytes }!!
        val first = sendN(s, 1, from = 50).single()
        // Race: first a message of epoch 7, then the checkpoint of epoch 6.
        book.chain(leaf, 7)!!.accept(first.id, first.prev, first.frame)
        val prevChain = book.chain(leaf, 6)
        assertTrue(prevChain != null && prevChain.epoch == 6L)
        assertTrue(prevChain.acceptCheckpoint(GroupPqSig.Checkpoint.decode(stale.encode())!!))
        old.forEach { assertEquals(Status.CONFIRMED, prevChain.status(it.id)) }
        // Two epochs back: no longer accepted.
        val third = s.advance(8, 2_000) { Dilithium3.sign(it, sk).bytes }
        assertTrue(third != null)
        book.chain(leaf, 8)
        assertNull(book.chain(leaf, 6))
        assertTrue(book.chain(leaf, 7) != null)
    }

    /**
     * A legitimate Commit with incomplete leaf data (no phone userId, no desktop binding: the member
     * upgraded from an older version) used to yield an empty list → CommitRejected → receiver stuck in the old epoch forever.
     * Now only leaves whose data contradicts the signer are rejected.
     */
    @Test fun commitWithIncompleteLeafDataIsNotRejected() {

        // Alice's phone without a userId on our side, Alice's desktop without a binding; Bob is known.
        val owners = mapOf("bob-phone" to "bob", "alice-pc" to "alice")
        val own = { l: String -> owners[l] }
        val tree = listOf("alice-phone", "alice-pc", "bob-phone")
        assertEquals(listOf("alice-phone"), GroupPqSig.commitSendersSigned(tree, "alice", null, own, emptyList())
            .filter { it != "alice-pc" }) // alice-pc has no binding for the account key: also "no data"
        assertEquals(GroupPqSig.LeafVerdict.UNKNOWN, GroupPqSig.leafVerdict("alice-phone", "alice", null, own, emptyList()))
        assertEquals(GroupPqSig.LeafVerdict.CONTRADICTS, GroupPqSig.leafVerdict("bob-phone", "alice", null, own, emptyList()))
        // Desktop without a binding, signed by the device: no data, allowed; someone else's (Bob's) leaf: not allowed.
        assertEquals(GroupPqSig.LeafVerdict.UNKNOWN, GroupPqSig.leafVerdict("alice-pc", "alice", "dev-a1", own, emptyList()))
        assertEquals(listOf("alice-phone", "alice-pc"), GroupPqSig.commitSendersSigned(tree, "alice", "dev-a1", own, emptyList()))
        assertFalse("bob-phone" in GroupPqSig.commitSendersSigned(tree, "alice", "dev-a1", own, emptyList()))
        // Binding exists, but we have no userId for the bound phone: no data, not a substitution.
        val links = listOf(GroupPqSig.LeafLink("alice-phone", "alice-pc", "dev-a1"))
        assertEquals(GroupPqSig.LeafVerdict.UNKNOWN, GroupPqSig.leafVerdict("alice-pc", "alice", "dev-a1", own, links))
        // A contradiction is still rejected: binding to another device, known phone under a device key.
        assertEquals(GroupPqSig.LeafVerdict.CONTRADICTS, GroupPqSig.leafVerdict("alice-pc", "alice", "dev-a2", own, links))
        assertEquals(GroupPqSig.LeafVerdict.CONTRADICTS, GroupPqSig.leafVerdict("alice-phone", "alice", "dev-a1", own, links))
        assertEquals(GroupPqSig.LeafVerdict.CONTRADICTS, GroupPqSig.leafVerdict("alice-pc", "alice", null, own, links))
        // For the application chain "no data" is not "matched": no PQ confirmation without binding to the signer.
        assertFalse(GroupPqSig.leafMatchesSigner("alice-phone", "alice", null, own, emptyList()))
    }
}

/**
 * Measures whether PQ causes stalls: sizes and timings on the real
 * Rust core: ML-KEM-1024, ML-DSA-65, 1:1 envelope v2 / v3 / v3s, group chain and checkpoint signature.
 * Prints a table as "PQ-REPORT …" lines (collected by the report) and checks that the new scheme meets its targets:
 *  - the average 1:1 envelope on the new path (1 full v3 + 49 short v3s) is smaller than v2;
 *  - group overhead per message under steady traffic (h + checkpoint every 20) ≤ 205 B raw (target ≈ +200) / ≤ 280 B JSON;
 *  - ML-DSA sign/verify and ML-KEM encapsulation take single-digit milliseconds, not hundreds.
 */
class PqOverheadReportTest {

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

    private class MemRatchetStorage : DoubleRatchet.RatchetStorage {
        val states = HashMap<String, DoubleRatchet.RatchetState>()
        override fun saveState(sessionId: String, state: DoubleRatchet.RatchetState) { states[sessionId] = state }
        override fun getState(sessionId: String): DoubleRatchet.RatchetState? = states[sessionId]
        override fun deleteState(sessionId: String) { states.remove(sessionId) }
    }

    private class User(val id: String) {
        val ks = SecureKeyStoreCommon(MemKvStore(), { false })
        val enc: MessageEncryption
        init {
            ks.saveUserId(id)
            ks.saveHybridSignatureKeyPair(HybridSignature.generateKeyPair())
            ks.saveHybridExchangeKeyPair(HybridKeyExchange.generateKeyPair())
            enc = MessageEncryption(ks, MemRatchetStorage())
        }
        val secp get() = ks.getSecp256k1PublicKey()!!
        val x get() = ks.getX25519PublicKey()!!
        val ek get() = ks.getKyberPublicKey()!!
    }

    private fun pair(newPath: Boolean): Pair<User, User> {
        val a = User("alice"); val b = User("bob")
        a.ks.checkAndPinPeerKey("bob", b.secp, b.x); b.ks.checkAndPinPeerKey("alice", a.secp, a.x)
        if (newPath) {
            a.ks.checkAndPinPeerWireCaps("bob", MessageEncryption.WIRE_CAP_SEAL_V3, 1)
            b.ks.checkAndPinPeerWireCaps("alice", MessageEncryption.WIRE_CAP_SEAL_V3, 1)
        }
        return a to b
    }

    private fun send(from: User, to: User, text: String): MessageEncryption.SealedSenderPackage {
        val p = from.enc.encryptMessageAsPayload(text, to.id, to.secp, to.x, sequenceNumber = 1)
        return from.enc.createSealedSenderAuto(p, from.id, to.x, to.ek, recipientId = to.id)
    }

    private fun recv(to: User, pkg: MessageEncryption.SealedSenderPackage) =
        to.enc.decryptMessageFromSealedSender(to.enc.openSealedSenderAutoFull(pkg))

    private fun len(p: MessageEncryption.SealedSenderPackage) =
        WireJson.json.encodeToString(MessageEncryption.SealedSenderPackage.serializer(), p).length

    @AfterTest fun restore() { SecurityRollout.sealV3Accept = false; SecurityRollout.sealV3Send = false }

    private fun med(v: List<Long>): Double = v.sorted()[v.size / 2] / 1e6
    private fun p95(v: List<Long>): Double = v.sorted()[(v.size * 95 / 100).coerceAtMost(v.size - 1)] / 1e6
    private inline fun timed(n: Int, warm: Int = 20, f: (Int) -> Unit): List<Long> {
        repeat(warm) { f(-1 - it) }
        return List(n) { i -> val t = System.nanoTime(); f(i); System.nanoTime() - t }
    }
    private fun row(what: String, bytes: Any, ms: String) = println("PQ-REPORT | $what | $bytes | $ms")
    private fun f(d: Double) = "%.3f".format(d)

    @Test fun primitives() {
        if (!rustCoreTestsEnabled()) return
        val kem = Kyber1024.generateKeyPair()
        var enc: Kyber1024.Encapsulation? = null
        val tEnc = timed(200) { enc = Kyber1024.encapsulate(kem.publicKey.encoded) }
        val ct = enc!!.ciphertext
        val tDec = timed(200) { Kyber1024.decapsulate(ct, kem.privateKey.encoded) }
        val tKg = timed(50, 5) { Kyber1024.generateKeyPair() }
        assertEquals(Kyber1024.CIPHERTEXT_SIZE, ct.size)
        row("ML-KEM-1024 capsule (ciphertext)", ct.size, "encaps ${f(med(tEnc))} / p95 ${f(p95(tEnc))}")
        row("ML-KEM-1024 decapsulation", "—", "decaps ${f(med(tDec))} / p95 ${f(p95(tDec))}")
        row("ML-KEM-1024 key (public)", kem.publicKey.encoded.size, "keygen ${f(med(tKg))}")

        val dsa = Dilithium3.generateKeyPair()
        val msg = ByteArray(160) { it.toByte() }
        var sig = ByteArray(0)
        val tSign = timed(200) { sig = Dilithium3.sign(msg, dsa.privateKey.encoded).bytes }
        val tVer = timed(200) { check(Dilithium3.verify(msg, sig, dsa.publicKey.encoded)) }
        assertEquals(Dilithium3.SIGNATURE_SIZE, sig.size)
        row("ML-DSA-65 signature", sig.size, "sign ${f(med(tSign))} / p95 ${f(p95(tSign))}")
        row("ML-DSA-65 verification", "—", "verify ${f(med(tVer))} / p95 ${f(p95(tVer))}")
        row("ML-DSA-65 key (public)", dsa.publicKey.encoded.size, "—")
        assertTrue(med(tSign) < 50 && med(tVer) < 20 && med(tEnc) < 20 && med(tDec) < 20,
            "PQ primitives too slow: sign=${med(tSign)} verify=${med(tVer)} enc=${med(tEnc)} dec=${med(tDec)} ms")
    }

    @Test fun envelopes1to1() {
        if (!rustCoreTestsEnabled()) return
        val text = "x".repeat(40)
        // v2 (previous path, as of 2.0.3): 50 messages, size and seal / open time.
        val (a2, b2) = pair(newPath = false)
        val v2Len = ArrayList<Int>(); val v2Seal = ArrayList<Long>(); val v2Open = ArrayList<Long>()
        repeat(60) { i ->
            val t0 = System.nanoTime(); val p = send(a2, b2, "$text$i"); val t1 = System.nanoTime()
            check(recv(b2, p).content.endsWith("$i")); val t2 = System.nanoTime()
            check(p.version != SealV3.VERSION && p.version != SealV3.VERSION_SHORT) { "v2 path sent ${p.version}" }
            if (i >= 10) { v2Len += len(p); v2Seal += t1 - t0; v2Open += t2 - t1 }
        }
        // New path: first a full v3, after the reply (sa) short v3s, a full one every 50.
        SecurityRollout.sealV3Accept = true; SecurityRollout.sealV3Send = true
        val (a, b) = pair(newPath = true)
        val first = send(a, b, text); recv(b, first); recv(a, send(b, a, "ack"))
        val full = ArrayList<Int>(); val short = ArrayList<Int>()
        val fullSeal = ArrayList<Long>(); val fullOpen = ArrayList<Long>(); val sSeal = ArrayList<Long>(); val sOpen = ArrayList<Long>()
        full += len(first)
        repeat(160) { i ->
            val t0 = System.nanoTime(); val p = send(a, b, "$text$i"); val t1 = System.nanoTime()
            check(recv(b, p).content.endsWith("$i")); val t2 = System.nanoTime()
            if (i % 25 == 0) recv(a, send(b, a, "ack$i"))
            if (i < 10) return@repeat
            when (p.version) {
                SealV3.VERSION -> { full += len(p); fullSeal += t1 - t0; fullOpen += t2 - t1 }
                SealV3.VERSION_SHORT -> { short += len(p); sSeal += t1 - t0; sOpen += t2 - t1 }
                else -> error("new path sent ${p.version}")
            }
        }
        val v2m = v2Len.sorted()[v2Len.size / 2]; val fm = full.sorted()[full.size / 2]; val sm = short.sorted()[short.size / 2]
        val avg = (fm + SealV3.SHORT_PER_FULL * sm) / (SealV3.SHORT_PER_FULL + 1)
        row("1:1 envelope v2 (as of 2.0.3), 40 chars", v2m, "seal ${f(med(v2Seal))} / open ${f(med(v2Open))}")
        row("1:1 envelope v3 full (ML-KEM capsule)", "$fm (n=${full.size})", if (fullSeal.isEmpty()) "—" else "seal ${f(med(fullSeal))} / open ${f(med(fullOpen))}")
        row("1:1 envelope v3s short", "$sm (n=${short.size})", "seal ${f(med(sSeal))} / open ${f(med(sOpen))}")
        row("1:1 envelope, new path, average over 50", avg, "difference vs v2: ${avg - v2m} B (${(avg - v2m) * 100 / v2m} %)")
        assertTrue(short.isNotEmpty() && avg < v2m, "new path not smaller: v2=$v2m v3=$fm v3s=$sm avg=$avg")
    }

    @Test fun groupChainAndBatchSignature() {
        if (!rustCoreTestsEnabled()) return
        val kp = Dilithium3.generateKeyPair()
        val sk = kp.privateKey.encoded; val pk = kp.publicKey.encoded
        val chain = GroupPqSig.SenderChain("g1", "leaf-1", epoch = 3, nowMs = 0)
        val rx = GroupPqSig.ReceiverChain("g1", "leaf-1", 3, pk)
        val stepT = ArrayList<Long>(); val cpSign = ArrayList<Long>(); val cpVer = ArrayList<Long>()
        var cpBytes = 0
        for (round in 0 until 30) {
            repeat(GroupPqSig.CHECKPOINT_EVERY) { i ->
                val id = "m$round-$i"; val frame = ByteArray(400) { (it + i).toByte() }
                val t = System.nanoTime(); val prev = chain.next(id, frame, 1000L * round + i); stepT += System.nanoTime() - t
                rx.accept(id, prev, frame)
            }
            check(chain.checkpointDue(1000L * round + 30))
            val t0 = System.nanoTime(); val cp = chain.checkpoint(sk); val t1 = System.nanoTime()
            val enc = cp.encode(); cpBytes = enc.size
            check(rx.acceptCheckpoint(GroupPqSig.Checkpoint.decode(enc)!!)); val t2 = System.nanoTime()
            cpSign += t1 - t0; cpVer += t2 - t1
        }
        val chainJson = GroupPqSig.envelopeChainOverheadJson()
        val cpJson = GroupPqSig.envelopeCheckpointOverheadJson(Dilithium3.SIGNATURE_SIZE)
        val perMsg = chainJson + cpJson / GroupPqSig.CHECKPOINT_EVERY
        val perMsgRaw = GroupPqSig.HASH_LEN + cpBytes / GroupPqSig.CHECKPOINT_EVERY
        val commitSig = ",\"pqs\":\"\"".length + GroupPqSig.b64Len(Dilithium3.SIGNATURE_SIZE)
        row("Group: chain link h per message", "${GroupPqSig.HASH_LEN} raw / $chainJson JSON", "step ${f(med(stepT))}")
        row("Group: pqcp checkpoint every 20 (batched)", "$cpBytes raw / $cpJson JSON", "sign ${f(med(cpSign))} / verify+link 20 ${f(med(cpVer))}")
        row("Group: per-message overhead at ≥20 steady traffic (target ≈ +200)", "$perMsgRaw raw / $perMsg JSON", "signature per message ${f(med(cpSign) / GroupPqSig.CHECKPOINT_EVERY)}")
        // Sparse traffic: after 30 s of silence the checkpoint goes as a STANDALONE frame (wireKind=control), batch of k messages.
        for (k in listOf(1, 3, 5, 10)) row("Group: batch of $k, then 30 s of silence", "${GroupPqSig.HASH_LEN + cpBytes / k} raw / ${chainJson + cpJson / k} JSON per message", "+ 1 standalone checkpoint frame per receiver")
        row("Group: Commit/Welcome signature (each)", "${Dilithium3.SIGNATURE_SIZE} raw / $commitSig JSON", "sign ≈ as ML-DSA above")
        row("Group: if every message were signed", commitSig, "${commitSig / perMsg}x larger")
        assertTrue(perMsgRaw <= 205 && perMsg <= 280, "group per-message PQ overhead raw=$perMsgRaw json=$perMsg B")
    }
}
