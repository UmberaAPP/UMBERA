package app.umbera.core.crypto

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * A malicious server/mailbox replays an OLD message
 * from the peer, or a third party writes "on their behalf". The envelope and payload of such a message open (the payload is static,
 * stateless; the one-time number check in processInbound happens after decryptMessageFromSealedSender), so
 * the `sa`/`ra` acknowledgements inside it must not roll back the pair state.
 */
class SealV3Replay1211Test {

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

    private fun recv(to: User, pkg: MessageEncryption.SealedSenderPackage): MessageEncryption.MessagePayload =
        to.enc.decryptMessageFromSealedSender(to.enc.openSealedSenderAutoFull(pkg))

    private fun now() = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()
    /** The next message is strictly later (payload timestamp in ms). */
    private fun tick() { val t = now(); while (now() <= t + 1) { /* wait for the millisecond to change */ } }

    private fun on() { SecurityRollout.sealV3Accept = true; SecurityRollout.sealV3Send = true }
    @AfterTest fun off() {
        SecurityRollout.sealV3Accept = false; SecurityRollout.sealV3Send = false
        SecurityRollout.ridV2 = false; SecurityRollout.ridRotation = true
    }

    /** Replaying Bob's message written BEFORE the acknowledgement (no `sa`, s bit set) does not drop Alice's short chain. */
    @Test fun replayedPreAckLetterDoesNotDropShortChain() {
        if (!rustCoreTestsEnabled()) return
        on()
        val (a, b) = pair()
        val early = send(b, a, "early, before any pair secret")   // the server kept a copy
        assertEquals(null, recv(a, early).sealAck)
        tick()
        recv(b, send(a, b, "full")); tick(); assertNotNull(recv(a, send(b, a, "ack")).sealAck)
        assertEquals(SealV3.VERSION_SHORT, send(a, b, "s1").also { recv(b, it) }.version)
        // The malicious server puts the old message into Alice's mailbox again (new mailbox number): it opens.
        repeat(3) { assertEquals("early, before any pair secret", recv(a, early).content.trimEnd()) }
        assertEquals(SealV3.VERSION_SHORT, send(a, b, "s2").version, "replaying an old message dropped the short chain")
        // A real loss of secrets on Bob's side (a fresh message without sa) still brings back full envelopes.
        tick(); b.ks.removeSealRx("alice")
        recv(a, send(b, a, "i reinstalled"))
        assertEquals(SealV3.VERSION, send(a, b, "full again").version)
    }

    /** A third party "as Bob" with its own keys: the envelope and payload signature (key from the envelope) check out, but
     *  Alice's pair state with Bob (chain, rid2 address) does not change. */
    @Test fun strangerAsPeerCannotDropPairState() {
        if (!rustCoreTestsEnabled()) return
        on(); SecurityRollout.ridV2 = true; SecurityRollout.ridRotation = false
        val (a, b) = pair()
        recv(b, send(a, b, "f")); tick(); recv(a, send(b, a, "ack")); tick()
        recv(b, send(a, b, "rd")); tick(); recv(a, send(b, a, "ra")); tick()
        val v1ab = a.enc.rendezvousSendId("bob", b.x)!!
        val rid2 = a.enc.rendezvousSendIdCurrent("bob", b.x)!!
        assertNotEquals(v1ab, rid2)
        val m = User("mallory")
        m.ks.checkAndPinPeerKey("alice", a.secp, a.x)
        m.ks.checkAndPinPeerWireCaps("alice", MessageEncryption.WIRE_CAP_SEAL_V3, 1)
        val p = m.enc.encryptMessageAsPayload("fake", "alice", a.secp, a.x, sequenceNumber = 1)
        val pkg = m.enc.createSealedSenderAuto(p, "bob", a.x, a.ek, recipientId = "alice")
        val r = a.enc.openSealedSenderAutoFull(pkg)
        assertEquals("bob", r.senderId)
        runCatching { a.enc.decryptMessageFromSealedSender(r) }
        assertEquals(rid2, a.enc.rendezvousSendIdCurrent("bob", b.x), "a third party moved Alice back to the previous address")
        assertEquals(SealV3.VERSION_SHORT, send(a, b, "still short").version, "a third party dropped the short chain")
    }

    /** Replaying an old `ra=id+` after Bob left epochs does not move Alice back to epoch addresses. */
    @Test fun replayedEpochAckDoesNotReenableEpochs() {
        if (!rustCoreTestsEnabled()) return
        on(); SecurityRollout.ridV2 = true; SecurityRollout.ridRotation = true
        val (a, b) = pair()
        val both = MessageEncryption.WIRE_CAP_SEAL_V3 or MessageEncryption.WIRE_CAP_RID_EPOCH
        a.ks.notePeerWireCaps("bob", both); b.ks.notePeerWireCaps("alice", both)
        recv(b, send(a, b, "f")); tick(); recv(a, send(b, a, "ack")); tick()
        recv(b, send(a, b, "rd")); tick()
        val plus = send(b, a, "ra+")                                  // the server kept a copy
        assertTrue(recv(a, plus).ridAck!!.endsWith("+"))
        val t = now()
        val epoch = a.enc.rendezvousSendIdCurrent("bob", b.x, t)!!
        // Bob turned epochs off: a fresh acknowledgement without "+" — Alice goes to the static rid2.
        tick(); SecurityRollout.ridRotation = false
        assertTrue(!recv(a, send(b, a, "stop")).ridAck!!.endsWith("+"))
        SecurityRollout.ridRotation = true
        val static = a.enc.rendezvousSendIdCurrent("bob", b.x, t)!!
        assertNotEquals(epoch, static)
        // Replay of the old "ra=id+".
        recv(a, plus)
        assertEquals(static, a.enc.rendezvousSendIdCurrent("bob", b.x, t), "replaying an old ra+ moved Alice back to epochs")
    }
}
