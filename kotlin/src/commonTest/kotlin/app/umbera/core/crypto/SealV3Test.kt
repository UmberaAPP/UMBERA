package app.umbera.core.crypto

import app.umbera.core.util.B64
import app.umbera.core.util.WireJson
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Envelope v3 (transcript binding), short v3s (ML-KEM capsule once every 50), file key v2.
 * KAT reference — Rust `sealv3::tests::kat_matches_kotlin` (same inputs, same bytes).
 */
class SealV3Test {

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

    /** Each side pinned the other's keys (as after TOFU and the log) and saw the s bit in its message. */
    private fun pair(): Pair<User, User> {
        val a = User("alice"); val b = User("bob")
        a.ks.checkAndPinPeerKey("bob", b.secp, b.x); b.ks.checkAndPinPeerKey("alice", a.secp, a.x)
        a.ks.checkAndPinPeerWireCaps("bob", MessageEncryption.WIRE_CAP_SEAL_V3, 1); b.ks.checkAndPinPeerWireCaps("alice", MessageEncryption.WIRE_CAP_SEAL_V3, 1)
        return a to b
    }

    private fun send(from: User, to: User, text: String): MessageEncryption.SealedSenderPackage {
        val p = from.enc.encryptMessageAsPayload(text, to.id, to.secp, to.x, sequenceNumber = 1)
        return from.enc.createSealedSenderAuto(p, from.id, to.x, to.ek, recipientId = to.id)
    }

    private fun recv(to: User, pkg: MessageEncryption.SealedSenderPackage): Pair<MessageEncryption.SealedSenderResult, MessageEncryption.MessagePayload> {
        val r = to.enc.openSealedSenderAutoFull(pkg)
        return r to to.enc.decryptMessageFromSealedSender(r)
    }

    private fun on() { SecurityRollout.sealV3Accept = true; SecurityRollout.sealV3Send = true }
    @AfterTest fun off() { SecurityRollout.sealV3Accept = false; SecurityRollout.sealV3Send = false }

    @Test fun flagsOffIsV2() {
        if (!rustCoreTestsEnabled()) return
        // Switches default to ON: turn them off explicitly (on iPhone this test runs first, before another test's @AfterTest).
        off()
        val (a, b) = pair()
        val pkg = send(a, b, "hi")
        assertEquals("v2", pkg.version)
        assertNull(pkg.sealHint)
        assertEquals("hi", recv(b, pkg).second.content.trimEnd())
        // Without the switch the s bit and the acknowledgement are not advertised: cap as before.
        val p = a.enc.encryptMessageAsPayload("x", "bob", b.secp, b.x, sequenceNumber = 1)
        val inner = b.enc.decryptMessageFromSealedSender(b.enc.openSealedSenderFull(a.enc.createSealedSenderAuto(p, "alice", b.x, b.ek)))
        assertEquals(0, (inner.caps ?: 0) and MessageEncryption.WIRE_CAP_SEAL_V3)
        assertEquals(0, (inner.caps ?: 0) and MessageEncryption.WIRE_CAP_RID_EPOCH)
        assertNull(inner.sealAck)
        assertNull(inner.ridDir); assertNull(inner.ridAck)
    }

    @Test fun fullThenShortChainThenFullAgain() {
        if (!rustCoreTestsEnabled()) return
        on()
        val (a, b) = pair()
        // 1) no acknowledgement yet — full v3, no PQ keys inside.
        val f1 = send(a, b, "first")
        assertEquals(SealV3.VERSION, f1.version)
        val (r1, p1) = recv(b, f1)
        assertEquals("v3", r1.sealedVersion)
        assertNull(r1.senderDilithiumPublicKey)
        assertEquals("first", p1.content.trimEnd())
        assertEquals(SealV3.VERSION, send(a, b, "second, still full").version)
        // 2) Bob replies — acknowledgement `sa` of the new secret; Alice now has a chain.
        val reply = send(b, a, "ok")
        val (_, rp) = recv(a, reply)
        assertNotNull(rp.sealAck)
        // 3) Then 49 short ones, each opens; all hints differ. Bob replies every 16
        //    (with no incoming messages, at most RECV_WINDOW short ones in a row).
        val hints = HashSet<String>()
        for (i in 0 until SealV3.SHORT_PER_FULL) {
            if (i > 0 && i % SealV3.RECV_WINDOW == 0) recv(a, send(b, a, "still here $i"))
            val s = send(a, b, "short $i")
            assertEquals(SealV3.VERSION_SHORT, s.version, "message $i")
            assertNull(s.kyberCiphertext)
            assertTrue(hints.add(s.sealHint!!))
            val (rs, ps) = recv(b, s)
            assertEquals("alice", rs.senderId)
            assertEquals("short $i", ps.content.trimEnd())
        }
        // 4) Chain exhausted — full again.
        assertEquals(SealV3.VERSION, send(a, b, "rotate").version)
    }

    @Test fun shortsSurviveReorderAndDuplicate() {
        if (!rustCoreTestsEnabled()) return
        on()
        val (a, b) = pair()
        recv(b, send(a, b, "f")); recv(a, send(b, a, "ack"))
        val s = (0 until 5).map { send(a, b, "m$it") }
        assertEquals(SealV3.VERSION_SHORT, s[0].version)
        for (i in listOf(3, 0, 4, 1, 2, 2)) assertEquals("m$i", recv(b, s[i]).second.content.trimEnd())
    }

    @Test fun lostReceiverStateFallsBackToFull() {
        if (!rustCoreTestsEnabled()) return
        on()
        val (a, b) = pair()
        recv(b, send(a, b, "f")); recv(a, send(b, a, "ack"))
        assertEquals(SealV3.VERSION_SHORT, send(a, b, "s").version)
        // Bob lost his secrets (reinstall): his message has no `sa` but has the s bit → Alice sends full ones again.
        b.ks.removeSealRx("alice")
        recv(a, send(b, a, "i am back"))
        assertEquals(SealV3.VERSION, send(a, b, "full again").version)
    }

    /** One-way stream: after RECV_WINDOW short ones with no incoming messages, full again; a reply brings short ones back. */
    @Test fun shortsCappedWithoutInbound() {
        if (!rustCoreTestsEnabled()) return
        on()
        val (a, b) = pair()
        recv(b, send(a, b, "f")); recv(a, send(b, a, "ack"))
        repeat(SealV3.RECV_WINDOW) { assertEquals(SealV3.VERSION_SHORT, send(a, b, "s$it").also { p -> recv(b, p) }.version) }
        // Bob is silent: full ones from here on (if he lost his secrets, he can open these).
        repeat(3) { assertEquals(SealV3.VERSION, send(a, b, "full$it").also { p -> recv(b, p) }.version) }
        // Bob wrote (his `sa` is our chain) — short again.
        recv(a, send(b, a, "here"))
        assertEquals(SealV3.VERSION_SHORT, send(a, b, "short again").version)
    }

    /**
     * Bob restored his account (same keys, no pair secrets and no v2 addresses), Alice
     * writes first, Bob only reads. Previously: short v3s that Bob cannot open, to an rid2 he does not poll.
     * After TYPEX_RRESET with "l" (onPeerLostPairState): full v3 to the legacy address, and Alice listens on Bob's legacy address.
     */
    @Test fun recoveredPeerGetsFullV3OnV1AfterReset() {
        if (!rustCoreTestsEnabled()) return
        on(); SecurityRollout.ridV2 = true; SecurityRollout.ridRotation = false
        try {
            val (a, b) = pair()
            val v1ab = a.enc.rendezvousSendId("bob", b.x)!!
            val v1ba = b.enc.rendezvousSendId("alice", a.x)!!
            // Both sides on short messages and rid2.
            recv(b, send(a, b, "f")); recv(a, send(b, a, "ack")); recv(b, send(a, b, "rd")); recv(a, send(b, a, "ra"))
            recv(a, send(b, a, "f2")); recv(b, send(a, b, "ack2")); recv(a, send(b, a, "rd2")); recv(b, send(a, b, "ra2"))
            assertNotEquals(v1ab, a.enc.rendezvousSendIdCurrent("bob", b.x))
            assertEquals(SealV3.VERSION_SHORT, send(a, b, "short").version)
            // Bob's restore: everything derived from capsules is gone.
            for (k in listOf("alice")) { b.ks.removeSealRx(k); b.ks.setRid2Rx(k, "[]"); b.ks.removeSealTx(k); b.ks.removeRid2Tx(k) }
            assertEquals(listOf(v1ab), b.enc.rendezvousRecvIds("alice", a.x)) // Bob listens only on the legacy address
            // Before the reset Alice would send a short message to rid2 — Bob could not open it (without a message from Bob she would not know).
            val lost = send(a, b, "lost before reset")
            assertTrue(runCatching { b.enc.openSealedSenderAutoFull(lost) }.isFailure)
            // TYPEX_RRESET(l) arrived from Bob's mailbox: the message without sa/ra already cleared the state, but its start
            // time is known — Alice uses it to resend what went out short / to rid2.
            val before = a.enc.pairStateSinceMs("bob")
            assertNotNull(before)
            recv(a, send(b, a, "RRESET body"))
            val since = a.enc.pairStateSinceMs("bob")
            assertEquals(before, since)
            assertNull(a.enc.pairStateSinceMs("bob"))   // returned only once
            a.enc.onPeerLostPairState("bob")
            assertEquals(v1ab, a.enc.rendezvousSendIdCurrent("bob", b.x))
            val first = send(a, b, "after reset")
            assertEquals(SealV3.VERSION, first.version)
            assertEquals("after reset", recv(b, first).second.content.trimEnd())
            // Bob writes to the legacy address — Alice still listens on it 15 days after switching to rid2.
            assertEquals(v1ba, b.enc.rendezvousSendIdCurrent("alice", a.x))
            assertTrue(v1ba in a.enc.rendezvousRecvIds("bob", b.x))
        } finally { SecurityRollout.ridV2 = false; SecurityRollout.ridRotation = true }
    }

    @Test fun strangerCannotPlantPairSecret() {
        if (!rustCoreTestsEnabled()) return
        on()
        val (a, b) = pair()
        val mallory = User("mallory")
        // Mallory writes "as Alice" with her own keys: the envelope opens, but no pair secret is stored for Alice.
        val p = mallory.enc.encryptMessageAsPayload("fake", "bob", b.secp, b.x, sequenceNumber = 1)
        mallory.ks.checkAndPinPeerWireCaps("bob", MessageEncryption.WIRE_CAP_SEAL_V3, 1)
        val pkg = mallory.enc.createSealedSenderAuto(p, "alice", b.x, b.ek, recipientId = "bob")
        assertEquals(SealV3.VERSION, pkg.version)
        val r = b.enc.openSealedSenderFull(pkg)
        runCatching { b.enc.decryptMessageFromSealedSender(r) }
        assertNull(b.ks.getSealRx("alice"))
        assertTrue(a.id.isNotEmpty())
    }

    @Test fun tamperAndDowngradeAreRefused() {
        if (!rustCoreTestsEnabled()) return
        on()
        val (a, b) = pair()
        val f = send(a, b, "x")
        fun flip(s: String): String { val v = B64.decode(s); v[v.size / 2] = (v[v.size / 2].toInt() xor 1).toByte(); return B64.encode(v) }
        assertFails { b.enc.openSealedSenderAutoFull(f.copy(version = "v2")) }
        assertFails { b.enc.openSealedSenderAutoFull(f.copy(ephemeralPublicKey = flip(f.ephemeralPublicKey))) }
        assertFails { b.enc.openSealedSenderAutoFull(f.copy(kyberCiphertext = flip(f.kyberCiphertext!!))) }
        assertFails { b.enc.openSealedSenderAutoFull(f.copy(authTag = flip(f.authTag))) }
        assertFails { b.enc.openSealedSenderAutoFull(f.copy(ephemeralPublicKey = B64.encode(ByteArray(32)))) }
        assertFails { b.enc.openSealedSenderAutoFull(f.copy(kyberCiphertext = B64.encode(B64.decode(f.kyberCiphertext!!).copyOf(1567)))) }
        // A v2 envelope marked as v3 — rejected (strict branching on version).
        SecurityRollout.sealV3Send = false
        val v2 = send(a, b, "y")
        SecurityRollout.sealV3Send = true
        assertFails { b.enc.openSealedSenderAutoFull(v2.copy(version = "v3")) }
        // A recipient with the same X25519 but a different ML-KEM — TH differs, cannot open (rcpt_ek is in the transcript).
        val ks2 = SecureKeyStoreCommon(MemKvStore(), { false })
        val kem2 = HybridKeyExchange.generateKeyPair()
        ks2.saveHybridSignatureKeyPair(HybridSignature.generateKeyPair())
        ks2.saveHybridExchangeKeyPair(HybridKeyExchange.HybridKeyPair(
            HybridKeyExchange.HybridPublicKey(b.x, kem2.publicKey.kyber),
            HybridKeyExchange.HybridPrivateKey(b.ks.getX25519PrivateKey()!!, b.ks.getKyberPrivateKey()!!)))
        assertFails { MessageEncryption(ks2, MemRatchetStorage()).openSealedSenderFull(f) }
        // Short: tampered hint / version.
        recv(b, f); recv(a, send(b, a, "ack"))
        val s = send(a, b, "short")
        assertEquals(SealV3.VERSION_SHORT, s.version)
        assertFails { b.enc.openSealedSenderAutoFull(s.copy(sealHint = flip(s.sealHint!!))) }
        assertFails { b.enc.openSealedSenderAutoFull(s.copy(version = "v3")) }
        assertFails { b.enc.openSealedSenderAutoFull(s.copy(encryptedInner = flip(s.encryptedInner))) }
        assertEquals("short", recv(b, s).second.content.trimEnd())
    }

    @Test fun fileWrapV2() {
        if (!rustCoreTestsEnabled()) return
        val b = User("bob")
        val fk = ByteArray(32) { it.toByte() }
        val w2 = HybridFileKeyWrap.wrap(fk, b.x, b.ek, v2 = true)
        assertEquals(2, w2.version)
        val priv = b.ks.getX25519PrivateKey()!!; val kpriv = b.ks.getKyberPrivateKey()!!
        assertTrue(fk.contentEquals(HybridFileKeyWrap.unwrap(w2, priv, kpriv, b.x, b.ek)))
        val w1 = HybridFileKeyWrap.wrap(fk, b.x, b.ek)
        assertNull(w1.version)
        assertTrue(fk.contentEquals(HybridFileKeyWrap.unwrap(w1, priv, kpriv, b.x, b.ek)))
        // v2 without "v" (as an old version would see it) — tag mismatch; v1 posing as v2 — also rejected.
        assertFails { HybridFileKeyWrap.unwrap(w2.copy(version = null), priv, kpriv) }
        assertFails { HybridFileKeyWrap.unwrap(w1.copy(version = 2), priv, kpriv, b.x, b.ek) }
        assertFails { HybridFileKeyWrap.unwrap(w2.copy(version = 3), priv, kpriv, b.x, b.ek) }
        assertFails { HybridFileKeyWrap.unwrap(w2, priv, kpriv, b.x, HybridKeyExchange.generateKeyPair().publicKey.kyber) }
    }

    /** v2 mailbox address from the direction secret — transition rd → ra → write to rid2, legacy window, rollback on loss. */
    @Test fun rendezvousV2Handshake() {
        if (!rustCoreTestsEnabled()) return
        on(); SecurityRollout.ridV2 = true; SecurityRollout.ridRotation = false
        try {
            val (a, b) = pair()
            val v1ab = a.enc.rendezvousSendId("bob", b.x)!!
            assertEquals(v1ab, b.enc.rendezvousRecvId("alice", a.x))
            assertEquals(listOf(v1ab), b.enc.rendezvousRecvIds("alice", a.x))
            recv(b, send(a, b, "f"))                       // full v3: Bob has the direction secret
            recv(a, send(b, a, "ack"))                     // sa → Alice has a chain and rid2 (unconfirmed)
            assertEquals(v1ab, a.enc.rendezvousSendIdCurrent("bob", b.x))
            recv(b, send(a, b, "rd"))                      // rd → Bob polls rid2 and the legacy address
            val ids = b.enc.rendezvousRecvIds("alice", a.x)
            assertEquals(2, ids.size); assertTrue(v1ab in ids)
            val v2ab = ids.first { it != v1ab }
            assertEquals(64, v2ab.length)
            assertEquals(v1ab, a.enc.rendezvousSendIdCurrent("bob", b.x))  // until Bob confirms — legacy
            recv(a, send(b, a, "ra"))                      // ra → Alice writes only to rid2
            assertEquals(v2ab, a.enc.rendezvousSendIdCurrent("bob", b.x))
            // Legacy address window: after 15 days with no messages on it — v2 only.
            val later = 15L * 24 * 3600_000L + kotlinx.datetime.Clock.System.now().toEpochMilliseconds()
            assertEquals(listOf(v2ab), b.enc.rendezvousRecvIds("alice", a.x, later))
            b.enc.noteRendezvousReceipt("alice", v1ab, a.x)
            assertEquals(2, b.enc.rendezvousRecvIds("alice", a.x).size)
            // The reverse direction is separate (Bob's secret → Alice not yet established) — legacy address there.
            assertEquals(b.enc.rendezvousSendId("alice", a.x), b.enc.rendezvousSendIdCurrent("alice", a.x))
            // Bob lost state: a fresh message without ra → Alice falls back to the legacy address (no messages lost).
            b.ks.removeSealRx("alice"); b.ks.setRid2Rx("alice", "[]")
            recv(a, send(b, a, "lost"))
            assertEquals(v1ab, a.enc.rendezvousSendIdCurrent("bob", b.x))
            // Without the switch — exactly the legacy addresses.
            SecurityRollout.ridV2 = false
            assertEquals(listOf(v1ab), b.enc.rendezvousRecvIds("alice", a.x))
            assertEquals(a.enc.rendezvousSelfBackupId("bob"), a.enc.rendezvousSelfBackupIdCurrent("bob"))
            SecurityRollout.ridV2 = true
            val sb2 = a.enc.rendezvousSelfBackupIdCurrent("bob")!!
            assertNotEquals(a.enc.rendezvousSelfBackupId("bob"), sb2)
            assertEquals(listOf(sb2, a.enc.rendezvousSelfBackupId("bob")!!), a.enc.rendezvousSelfBackupIds("bob"))
        } finally { SecurityRollout.ridV2 = false; SecurityRollout.ridRotation = true }
    }

    private val day = 24L * 3600_000L
    private fun nowMs() = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()
    private fun caps(u: User, peer: String) =
        u.ks.notePeerWireCaps(peer, MessageEncryption.WIRE_CAP_SEAL_V3 or MessageEncryption.WIRE_CAP_RID_EPOCH)

    /** Bring a pair to a confirmed v2 address A→B (full v3 → sa → rd → ra). Returns rd and ra as sent on the wire. */
    private fun handshake(a: User, b: User): Pair<String?, String?> {
        recv(b, send(a, b, "f")); recv(a, send(b, a, "ack"))
        val rd = recv(b, send(a, b, "rd")).second.ridDir
        val ra = recv(a, send(b, a, "ra")).second.ridAck
        return rd to ra
    }

    /**
     * Address rotation: both have the bit — switch straight to epochs (`rd=id+` → `ra=id+`), the sender writes to the
     * current epoch's address, the recipient listens on it, its neighbours and the legacy one (window); no static rid2; epoch
     * addresses differ and are 32 B; the self-copy rotates in the same epoch; deletion covers the whole retention period.
     */
    @Test fun rendezvousEpochHandshake() {
        if (!rustCoreTestsEnabled()) return
        on(); SecurityRollout.ridV2 = true; SecurityRollout.ridRotation = true
        try {
            val (a, b) = pair(); caps(a, "bob"); caps(b, "alice")
            val v1ab = a.enc.rendezvousSendId("bob", b.x)!!
            val (rd, ra) = handshake(a, b)
            assertTrue(rd!!.endsWith("+"), rd); assertTrue(ra!!.endsWith("+"), ra)
            assertEquals(17, rd.length)                    // 16 hex id + 1 marker byte
            val now = nowMs()
            val cur = a.enc.rendezvousSendIdCurrent("bob", b.x, now)!!
            assertEquals(64, cur.length); assertNotEquals(v1ab, cur)
            val plan = b.enc.rendezvousRecvPlan("alice", a.x, now)
            val e = RendezvousV2.epochOf(now)
            assertEquals(cur, plan.first { it.epoch == e }.rid)
            assertTrue(plan.any { it.epoch == e - 1 } && plan.any { it.epoch == e + 1 })
            assertTrue(plan.any { it.rid == v1ab && it.epoch == null })      // legacy — 14-day window
            assertEquals(1, plan.count { it.epoch == null })                    // no static rid2: nothing was written to it
            // Next week: a different address, the recipient listens on it; epoch addresses are pairwise distinct.
            val next = a.enc.rendezvousSendIdCurrent("bob", b.x, now + 7 * day)!!
            assertNotEquals(cur, next)
            assertTrue(next in b.enc.rendezvousRecvIds("alice", a.x, now + 7 * day))
            assertTrue(next in b.enc.rendezvousRecvIds("alice", a.x, now))   // subscription to the next one — in advance
            val weeks = (0 until 10).map { a.enc.rendezvousSendIdCurrent("bob", b.x, now + it * 7 * day)!! }
            assertEquals(10, weeks.toSet().size)
            // Self-copy — in the same epoch, rotates with the address.
            val sb = a.enc.rendezvousSelfBackupIdCurrent("bob", now)!!
            assertNotEquals(sb, a.enc.rendezvousSelfBackupIdCurrent("bob", now + 7 * day))
            assertNotEquals(a.enc.rendezvousSelfBackupIdV2("bob"), sb)
            assertTrue(sb in a.enc.rendezvousSelfBackupIds("bob", now))
            // New device (transition state lost): self-copies of all epochs in the retention period are read from its own seed.
            a.ks.removeRid2Tx("bob")
            val fresh = a.enc.rendezvousSelfBackupIds("bob", now)
            assertTrue(sb in fresh)
            assertEquals(RendezvousV2.maxBackEpochs() + 1 + 2, fresh.size.toLong())
            a.enc.noteSelfBackupEpochsDrained("bob", now)
            assertEquals(2, a.enc.rendezvousSelfBackupIds("bob", now).size)   // selected — only the two legacy ones
            // Deleting a conversation: all epochs in the retention period + the neighbouring one.
            val purge = b.enc.rendezvousRecvIds("alice", a.x, now, forPurge = true)
            assertTrue(purge.size.toLong() >= RendezvousV2.maxBackEpochs() + 2)
            // A call/message on an epoch address is recognised as "paired" (the call layer matches against this list).
            assertTrue(cur in b.enc.rendezvousRecvIds("alice", a.x))
        } finally { SecurityRollout.ridV2 = false }
    }

    /** Peer without the bit (build without epochs): `rd`/`ra` without "+", static rid2 — as before address rotation. */
    @Test fun rendezvousEpochNeedsPeerBit() {
        if (!rustCoreTestsEnabled()) return
        on(); SecurityRollout.ridV2 = true; SecurityRollout.ridRotation = true
        try {
            val (a, b) = pair()   // s bit present, epoch bit absent
            val (rd, ra) = handshake(a, b)
            assertTrue(!rd!!.endsWith("+") && !ra!!.endsWith("+"))
            assertEquals(16, rd.length)
            val now = nowMs()
            val cur = a.enc.rendezvousSendIdCurrent("bob", b.x, now)!!
            assertEquals(cur, a.enc.rendezvousSendIdCurrent("bob", b.x, now + 7 * day))  // does not change
            assertTrue(b.enc.rendezvousRecvPlan("alice", a.x, now).all { it.epoch == null })
            assertTrue(cur in b.enc.rendezvousRecvIds("alice", a.x, now))
            assertEquals(a.enc.rendezvousSelfBackupIdV2("bob"), a.enc.rendezvousSelfBackupIdCurrent("bob", now))
        } finally { SecurityRollout.ridV2 = false }
    }

    /** A chain confirmed as static moves to epochs losslessly: the static rid2 is listened on for a 48 h window. */
    @Test fun rendezvousEpochUpgradeAndFallback() {
        if (!rustCoreTestsEnabled()) return
        on(); SecurityRollout.ridV2 = true; SecurityRollout.ridRotation = true
        try {
            val (a, b) = pair()
            handshake(a, b)
            val now = nowMs()
            val static = a.enc.rendezvousSendIdCurrent("bob", b.x, now)!!
            // Both now have the bit (updated) — the next message proposes the transition.
            caps(a, "bob"); caps(b, "alice")
            val rd = recv(b, send(a, b, "upgrade")).second.ridDir
            assertTrue(rd!!.endsWith("+"))
            assertEquals(static, a.enc.rendezvousSendIdCurrent("bob", b.x, now))  // static until confirmed
            val plan = b.enc.rendezvousRecvPlan("alice", a.x, now)
            assertTrue(static in plan.map { it.rid } && plan.any { it.epoch != null })
            assertTrue(recv(a, send(b, a, "ok")).second.ridAck!!.endsWith("+"))
            val ep = a.enc.rendezvousSendIdCurrent("bob", b.x, now)!!
            assertNotEquals(static, ep)
            assertTrue(ep in b.enc.rendezvousRecvIds("alice", a.x, now))
            assertTrue(static in b.enc.rendezvousRecvIds("alice", a.x, now + day))          // static window
            assertTrue(static !in b.enc.rendezvousRecvIds("alice", a.x, now + 3 * day))     // not after the window
            // A message on the static address within the window extends the window (as with the legacy address).
            b.enc.noteRendezvousReceipt("alice", static, a.x)
            assertTrue(static in b.enc.rendezvousRecvIds("alice", a.x, nowMs() + day))
            // The recipient disabled epochs: its acknowledgement without "+" → the sender falls back to static, the recipient listens on it.
            SecurityRollout.ridRotation = false
            assertTrue(static in b.enc.rendezvousRecvIds("alice", a.x, now + 3 * day))
            assertTrue(!recv(a, send(b, a, "stop")).second.ridAck!!.endsWith("+"))
            SecurityRollout.ridRotation = true
            assertEquals(static, a.enc.rendezvousSendIdCurrent("bob", b.x, now))
            // A sender with the switch off keeps the established epoch chain (does not write where nobody listens).
            val (c, d) = pair(); caps(c, "bob"); caps(d, "alice")
            handshake(c, d)
            val epc = c.enc.rendezvousSendIdCurrent("bob", d.x, now)!!
            SecurityRollout.ridRotation = false
            assertEquals(epc, c.enc.rendezvousSendIdCurrent("bob", d.x, now))
            assertTrue(epc in d.enc.rendezvousRecvIds("alice", c.x, now))
        } finally { SecurityRollout.ridV2 = false; SecurityRollout.ridRotation = true }
    }

    /** Recipient reinstall: its fresh message without `ra` → the sender goes to the legacy address (as with rid2 without epochs). */
    @Test fun rendezvousEpochReceiverLostState() {
        if (!rustCoreTestsEnabled()) return
        on(); SecurityRollout.ridV2 = true; SecurityRollout.ridRotation = true
        try {
            val (a, b) = pair(); caps(a, "bob"); caps(b, "alice")
            handshake(a, b)
            val v1ab = a.enc.rendezvousSendId("bob", b.x)!!
            assertNotEquals(v1ab, a.enc.rendezvousSendIdCurrent("bob", b.x))
            b.ks.removeSealRx("alice"); b.ks.setRid2Rx("alice", "[]")
            recv(a, send(b, a, "lost"))
            assertEquals(v1ab, a.enc.rendezvousSendIdCurrent("bob", b.x))
            assertTrue(v1ab in b.enc.rendezvousRecvIds("alice", a.x))
        } finally { SecurityRollout.ridV2 = false }
    }

    /**
     * Polling plan and request count: a pass every 30 s (socket alive), 14 days across two boundaries, then 20 days
     * offline. Static address — 1 request per pass; epochs — how many? Plus a subscription (no requests) to e−1, e, e+1.
     */
    @Test fun epochPlanRequestCount() {
        val P = RendezvousV2.periodSec * 1000
        val t0 = RendezvousV2.epochStartMs(RendezvousV2.epochOf(nowMs())) + P / 2
        val sweep = RendezvousV2.Sweep()
        var drained: Long? = null
        var fetches = 0L; var passes = 0L
        var t = t0
        val step = 30_000L
        while (t < t0 + 14 * day) {
            val plan = RendezvousV2.plan(t, drained)
            for ((ep, cad) in plan) if (sweep.due("r$ep", cad, t)) fetches++
            drained = RendezvousV2.epochOf(t)
            passes++; t += step
        }
        val perPass = fetches.toDouble() / passes
        println("RID EPOCH REQUESTS: passes=$passes fetches=$fetches perPass=${kotlin.math.round(perPass * 10000) / 10000} (static rid2 = 1.0000)")
        assertTrue(perPass < 1.06, "perPass=$perPass")
        // 20 days offline: the first pass drains the missed epochs (no more than the retention period), then as usual.
        val back = RendezvousV2.plan(t + 20 * day, drained).filter { it.second == RendezvousV2.Cadence.EVERY_PASS }
        val eNow = RendezvousV2.epochOf(t + 20 * day)
        assertTrue(back.map { it.first }.containsAll((drained!!..eNow).toList()), back.toString())  // including the one it went offline in
        assertTrue(back.size <= RendezvousV2.maxBackEpochs() + 2)
        println("RID EPOCH CATCH-UP after 20 days offline: ${back.size} fetches once")
        // Very long offline (beyond the retention period) — no more than maxBack+1 epochs.
        val far = RendezvousV2.plan(t + 90 * day, drained)
        assertTrue(far.size.toLong() <= RendezvousV2.maxBackEpochs() + 2)
        // Boundary: right after it — e−1 on every pass; near the next boundary — e+1 on every pass.
        val b = RendezvousV2.epochStartMs(RendezvousV2.epochOf(t0) + 1)
        assertEquals(RendezvousV2.Cadence.EVERY_PASS, RendezvousV2.plan(b + 60_000, RendezvousV2.epochOf(b)).first { it.first == RendezvousV2.epochOf(b) - 1 }.second)
        assertEquals(RendezvousV2.Cadence.SLOW, RendezvousV2.plan(b + 3 * 3600_000, RendezvousV2.epochOf(b)).first { it.first == RendezvousV2.epochOf(b) - 1 }.second)
        assertEquals(RendezvousV2.Cadence.EVERY_PASS, RendezvousV2.plan(b - 60_000, RendezvousV2.epochOf(b) - 1).first { it.first == RendezvousV2.epochOf(b) }.second)
    }

    /**
     * Static path. Without the bit/switch — hybrid-pq-v2 byte for byte as before; with the bit — hybrid-pq-v3
     * (TH binding, version in AAD), opens; version substitution in either direction and a wrong recipient ML-KEM — rejected.
     */
    @Test fun staticPathV3() {
        if (!rustCoreTestsEnabled()) return
        val (a, b) = pair()
        fun pay(): MessageEncryption.EncryptedPayload = a.enc.encryptMessageAuto("static", "bob", b.secp, b.x, b.ek, sequenceNumber = 1)
        val old = pay()
        assertEquals("hybrid-pq-v2", old.version)
        assertEquals("static", recvPayload(a, b, old).content.trimEnd())
        on()
        val p3 = pay()
        assertEquals(SealV3.PAYLOAD_STATIC_V3, p3.version)
        assertEquals("static", recvPayload(a, b, p3).content.trimEnd())
        // Inside a v3 payload the sender's ML-DSA is mandatory (otherwise classical only) — it goes into the inner packet.
        val sealed = a.enc.createSealedSenderAuto(p3, "alice", b.x, b.ek, recipientId = "bob")
        assertNotNull(b.enc.openSealedSenderAutoFull(sealed).senderDilithiumPublicKey)
        // Version substitution: v3 posing as v2 and v2 posing as v3 — cannot open.
        // (fresh payloads, so the rejection comes from the version and not the replay check)
        assertFails { recvPayload(a, b, pay().copy(version = "hybrid-pq-v2")) }
        off(); val old2 = pay(); on()
        assertFails { recvPayload(a, b, old2.copy(version = SealV3.PAYLOAD_STATIC_V3)) }
        // Same X25519, a different recipient ML-KEM (own keys from storage) — TH will not match.
        val c = User("bob"); c.ks.saveHybridExchangeKeyPair(HybridKeyExchange.HybridKeyPair(
            HybridKeyExchange.HybridPublicKey(b.ks.getHybridExchangeKeyPair()!!.publicKey.x25519, HybridKeyExchange.generateKeyPair().publicKey.kyber),
            b.ks.getHybridExchangeKeyPair()!!.privateKey))
        c.ks.checkAndPinPeerKey("alice", a.secp, a.x)
        // Outer v2 envelope to the real key (its c opens), v3 payload — with a substituted ML-KEM in the transcript.
        val outer = a.enc.createSealedSenderAuto(p3, "alice", b.x, b.ek)
        assertEquals("static", b.enc.decryptMessageFromSealedSender(b.enc.openSealedSenderAutoFull(outer)).content.trimEnd())
        val opened = c.enc.openSealedSenderAutoFull(outer)
        assertFails { c.enc.decryptMessageFromSealedSender(opened) }
    }

    private fun recvPayload(from: User, to: User, p: MessageEncryption.EncryptedPayload): MessageEncryption.MessagePayload =
        to.enc.decryptMessageFromSealedSender(to.enc.openSealedSenderAutoFull(from.enc.createSealedSenderAuto(p, from.id, to.x, to.ek, recipientId = to.id)))

    /** Reference: the same inputs and expected bytes as in Rust (core/src/sealv3.rs). */
    @Test fun katMatchesRust() {
        if (!rustCoreTestsEnabled()) return
        val eph = ByteArray(32) { (it + 1).toByte() }
        val ct = ByteArray(Kyber1024.CIPHERTEXT_SIZE) { (it * 7 + 3).toByte() }
        val rx = ByteArray(32) { (0x40 + it).toByte() }
        val rek = ByteArray(Kyber1024.PUBLIC_KEY_SIZE) { (it * 13 + 5).toByte() }
        val ssX = ByteArray(32) { (0x80 + it).toByte() }
        val ssK = ByteArray(32) { (0xC0 + it).toByte() }
        val th = SealV3.transcriptFull(eph, ct, rx, rek)
        assertEquals(KAT_TH, SealV3.hex(th))
        assertEquals(KAT_OKM, SealV3.hex(SealV3.fullOkm(ssX, ssK, th)))
        val pair = SealV3.pairSecret(ssX, ssK, th)
        assertEquals(KAT_PAIR, SealV3.hex(pair))
        assertEquals(KAT_PAIR_ID, SealV3.pairId(pair))
        val mk0 = SealV3.chainMk(pair)
        val ck1 = SealV3.chainNext(pair)
        assertEquals(KAT_MK0, SealV3.hex(mk0))
        assertEquals(KAT_CK1, SealV3.hex(ck1))
        val hint = SealV3.hint(mk0)
        assertEquals(KAT_HINT0, SealV3.hex(hint))
        assertEquals(KAT_SHORT0, SealV3.hex(SealV3.shortKey(ssX, mk0, SealV3.transcriptShort(eph, rx, rek, hint))))
        val thf = SealV3.transcriptFile(eph, ct, rx, rek)
        assertEquals(KAT_FILE, SealV3.hex(SealV3.fileKey(ssX, ssK, thf)))
        val dir = SealV3.dirSecret(ssX, ssK, th)
        assertEquals(KAT_DIR, SealV3.hex(dir))
        assertEquals(KAT_RID2, RendezvousV2.rid(ssX, dir, "alice", "bob"))
        // Address rotation: epoch 2915 address and the self-copy in the same epoch (self-copy input is ss_X ‖ ss_K instead of its own seed).
        assertEquals(KAT_RID2E, RendezvousV2.ridEpoch(ssX, dir, "alice", "bob", 2915))
        assertEquals(KAT_SELF_E, RendezvousV2.selfBackupEpoch(ssX + ssK, "alice", "bob", 2915))
        // Static path hybrid-pq-v3.
        val tst = SealV3.transcriptStatic(eph, ct, rx, rek)
        assertEquals(KAT_STATIC_TH, SealV3.hex(tst))
        assertEquals(KAT_STATIC_OKM, SealV3.hex(SealV3.staticOkm(ssX, ssK, tst)))
        // Different labels: envelope TH ≠ file TH for the same bytes.
        assertNotEquals(SealV3.hex(th), SealV3.hex(thf))
    }

    /** Per-message byte overhead: v2 vs v3 and v3s (printed for the report, order-of-magnitude check). */
    @Test fun envelopeSizes() {
        if (!rustCoreTestsEnabled()) return
        val (a, b) = pair()
        val text = "x".repeat(40)
        val v2 = WireJson.json.encodeToString(MessageEncryption.SealedSenderPackage.serializer(), send(a, b, text)).length
        on()
        val f = send(a, b, text)
        val v3 = WireJson.json.encodeToString(MessageEncryption.SealedSenderPackage.serializer(), f).length
        recv(b, f); recv(a, send(b, a, "ack"))
        val s = send(a, b, text)
        assertEquals(SealV3.VERSION_SHORT, s.version)
        val v3s = WireJson.json.encodeToString(MessageEncryption.SealedSenderPackage.serializer(), s).length
        val avg = (v3 + (SealV3.SHORT_PER_FULL) * v3s) / (SealV3.SHORT_PER_FULL + 1)
        println("SEAL SIZES: v2=$v2 v3=$v3 v3s=$v3s avg50=$avg (bytes JSON, 40-char text)")
        assertTrue(v3 < v2 && v3s < v3, "v2=$v2 v3=$v3 v3s=$v3s")
    }

    private companion object {
        const val KAT_TH = "3a83de5db60910cb810c32de542789131ee091507625fd39d8ff830fff6f0fa9"
        const val KAT_OKM = "80ad60792e211124b3fe2bc7f2e8a463f346c6b1b9c8a53b82ce9ed5cc974e7198d2c97e0b8165fcc3d17590fcf416dd7daee5d5f68846c6dbca604bd88a5f11"
        const val KAT_PAIR = "9d60f5ae438592cef60d9af88b651d8f4cccaca766596c505c197ae3bd3d8489"
        const val KAT_PAIR_ID = "9b52dc7d1d6d6057"
        const val KAT_MK0 = "2c33ca67e0fff3215bd80c45d82559aea88b1c7d9097750eb292966c28ef2486"
        const val KAT_CK1 = "67b591662d045c8ac71b5782704cca815a30f7f9156bc103636a05ef16fb3530"
        const val KAT_HINT0 = "ccef588f95b87a77"
        const val KAT_SHORT0 = "1f73ff6acb06c058f7f2102245c7e7f90eb32ba72d27a181d097d6cb1ea11290"
        const val KAT_STATIC_TH = "901d6a1ccea60c9e620db5a50d6b762b96a2748c5c1cdfdc43078b1f4f343261"
        const val KAT_STATIC_OKM = "dc9a606428f88ba85e55619239af100497dde757e6e5050d2cb587be40ebc097ce0927852cefa82fb5fbd02fbae8b31e2f36bf6668bea9cbddf3c5835e7a259a"
        const val KAT_DIR = "3303811545f9fe75256e6fb7a619a21cf64039e9f41d003eb3f0b0a1a9e70516"
        const val KAT_RID2 = "3c4fde7e0333e6547f80df5a04fb39261e4c2751eba39959b499518af147e73c"
        const val KAT_RID2E = "893a8ce4da5b1b4c1c192b27f33205e4527ad9cd9dfd0b339620c3b683939569"
        const val KAT_SELF_E = "0909952d1c44f39ab1b094b4be914347f5be0ac7eafbcbb27c37a80b5958e9f3"
        const val KAT_FILE = "e7e71302413123da4d536b9feca033c128ed817d85aab00d3853e355fe8972ef"
    }
}
