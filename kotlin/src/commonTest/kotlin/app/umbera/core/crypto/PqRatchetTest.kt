package app.umbera.core.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Post-quantum ratchet (ratchet-v4): ML-KEM-1024 is mixed into the root at
 * session start and periodically. Requires native ML-KEM (Rust core), so like
 * RustCoreGoldenTest it runs on iosSimulatorArm64Test and is skipped on the JVM.
 */
class PqRatchetTest {

    private class MemStorage : DoubleRatchet.RatchetStorage {
        val states = HashMap<String, DoubleRatchet.RatchetState>()
        override fun saveState(sessionId: String, state: DoubleRatchet.RatchetState) { states[sessionId] = state }
        override fun getState(sessionId: String): DoubleRatchet.RatchetState? = states[sessionId]
        override fun deleteState(sessionId: String) { states.remove(sessionId) }
    }

    private class Party(
        val static: X25519.KeyPair,
        val kem: Kyber1024.KyberKeyPair?,
        clock: () -> Long = { 1_000L },
    ) {
        val storage = MemStorage()
        val ratchet = DoubleRatchet(storage, nowMs = clock,
            identityKem = { kem?.let { it.publicKey.encoded to it.privateKey.encoded } })
    }

    private fun party(withKem: Boolean = true, clock: () -> Long = { 1_000L }) =
        Party(X25519.generateKeyPair(), if (withKem) Kyber1024.generateKeyPair() else null, clock)

    /** Alice is the initiator (her first chain derives from the static root), Bob the responder. */
    private fun session(pq: Boolean, alice: Party = party(), bob: Party = party()): Pair<Party, Party> {
        val root = X25519.computeSharedSecret(alice.static.privateKey, bob.static.publicKey)
        alice.ratchet.initializeSender("s", root, bob.static.publicKey,
            remoteIdentityKem = if (pq) bob.kem!!.publicKey.encoded else null)
        bob.ratchet.initializeReceiver("s", root, bob.static)
        return alice to bob
    }

    private fun DoubleRatchet.send(text: String) = encrypt("s", text.encodeToByteArray())
    private fun DoubleRatchet.recv(m: DoubleRatchet.EncryptedMessage) = decrypt("s", m).decodeToString()

    @Test
    fun v3_session_is_unchanged_and_carries_no_kem() {
        if (!rustCoreTestsEnabled()) return
        val (a, b) = session(pq = false)
        val m1 = a.ratchet.send("hi")
        assertFalse(m1.header.isPq)
        assertEquals(40, m1.header.toByteArray().size, "v3 header bytes (AAD) must stay 40")
        assertEquals("hi", b.ratchet.recv(m1))
        val r1 = b.ratchet.send("yo")
        assertFalse(r1.header.isPq)
        assertEquals("yo", a.ratchet.recv(r1))
        assertFalse(a.ratchet.isPqEnabled("s") || b.ratchet.isPqEnabled("s"))
    }

    @Test
    fun pq_session_round_trips_and_mixes_kem_from_the_first_chain() {
        if (!rustCoreTestsEnabled()) return
        val (a, b) = session(pq = true)
        val m1 = a.ratchet.send("first")
        assertNotNull(m1.header.kemCt, "first chain must carry the ML-KEM ciphertext")
        assertNotNull(m1.header.kemPub, "initiator advertises a fresh ML-KEM key")
        assertContentEquals(DoubleRatchet.kemKeyId(b.kem!!.publicKey.encoded), m1.header.kemTarget)
        assertEquals("first", b.ratchet.recv(m1))
        assertTrue(b.ratchet.isPqEnabled("s"), "receiver switches to v4 from the header alone")
        val r1 = b.ratchet.send("reply")
        assertNotNull(r1.header.kemCt, "reply encapsulates to the initiator's fresh key")
        assertEquals("reply", a.ratchet.recv(r1))
        // Long alternating conversation keeps working.
        repeat(30) { i ->
            assertEquals("a$i", b.ratchet.recv(a.ratchet.send("a$i")))
            assertEquals("b$i", a.ratchet.recv(b.ratchet.send("b$i")))
        }
    }

    @Test
    fun out_of_order_messages_of_a_pq_chain_decrypt() {
        if (!rustCoreTestsEnabled()) return
        val (a, b) = session(pq = true)
        val ms = (0 until 5).map { a.ratchet.send("m$it") }
        // The 4th message of the new chain arrives first: it carries the same KEM fields.
        assertEquals("m3", b.ratchet.recv(ms[3]))
        assertEquals("m0", b.ratchet.recv(ms[0]))
        assertEquals("m4", b.ratchet.recv(ms[4]))
        assertEquals("m1", b.ratchet.recv(ms[1]))
        assertEquals("m2", b.ratchet.recv(ms[2]))
        val r = b.ratchet.send("ok")
        assertEquals("ok", a.ratchet.recv(r))
    }

    @Test
    fun x25519_secrets_alone_do_not_open_a_pq_session() {
        if (!rustCoreTestsEnabled()) return
        // "Harvest now, decrypt later": the attacker has EVERY X25519 secret (Bob's static key,
        // so the static root too) but not Bob's ML-KEM key. Without the KEM secret the root
        // derived for the chain is wrong and AES-GCM rejects the message.
        val alice = party(); val bob = party()
        val (a, b) = session(pq = true, alice = alice, bob = bob)
        val m1 = a.ratchet.send("secret")
        val attacker = Party(bob.static, kem = Kyber1024.generateKeyPair())
        val root = X25519.computeSharedSecret(bob.static.privateKey, alice.static.publicKey)
        attacker.ratchet.initializeReceiver("s", root, bob.static)
        assertFails { attacker.ratchet.recv(m1) }
        val noKem = Party(bob.static, kem = null)
        noKem.ratchet.initializeReceiver("s", root, bob.static)
        assertFails { noKem.ratchet.recv(m1) }
        // The real Bob reads it.
        assertEquals("secret", b.ratchet.recv(m1))
    }

    @Test
    fun tampered_kem_fields_are_rejected() {
        if (!rustCoreTestsEnabled()) return
        val (a, b) = session(pq = true)
        val m1 = a.ratchet.send("x")
        val badCt = m1.header.kemCt!!.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val forged = m1.copy(header = m1.header.copy(kemCt = badCt))
        assertFails { b.ratchet.recv(forged) }
    }

    @Test
    fun existing_v3_session_upgrades_in_place() {
        if (!rustCoreTestsEnabled()) return
        val alice = party(); val bob = party()
        val (a, b) = session(pq = false, alice = alice, bob = bob)
        assertEquals("v3", b.ratchet.recv(a.ratchet.send("v3")))
        assertEquals("v3r", a.ratchet.recv(b.ratchet.send("v3r")))
        // Bob learns Alice is on the new version → his NEXT chain encapsulates to her identity key.
        b.ratchet.enablePq("s", alice.kem!!.publicKey.encoded)
        val sameChain = b.ratchet.send("still same chain")
        assertNull(sameChain.header.kemCt, "the running chain is not re-keyed mid-way")
        assertEquals("still same chain", a.ratchet.recv(sameChain))
        assertEquals("ping", b.ratchet.recv(a.ratchet.send("ping")))
        val upgraded = b.ratchet.send("pq now")
        assertNotNull(upgraded.header.kemCt)
        assertContentEquals(DoubleRatchet.kemKeyId(alice.kem.publicKey.encoded), upgraded.header.kemTarget)
        assertEquals("pq now", a.ratchet.recv(upgraded))
        assertTrue(a.ratchet.isPqEnabled("s"))
        repeat(5) { i ->
            assertEquals("a$i", b.ratchet.recv(a.ratchet.send("a$i")))
            assertEquals("b$i", a.ratchet.recv(b.ratchet.send("b$i")))
        }
    }

    @Test
    fun fresh_kem_keys_are_offered_periodically_not_on_every_turn() {
        if (!rustCoreTestsEnabled()) return
        val (a, b) = session(pq = true)
        var offers = 0
        var cts = 0
        repeat(60) { i ->
            val m = a.ratchet.send("a$i"); if (m.header.kemPub != null) offers++; if (m.header.kemCt != null) cts++
            assertEquals("a$i", b.ratchet.recv(m))
            val r = b.ratchet.send("b$i"); if (r.header.kemPub != null) offers++; if (r.header.kemCt != null) cts++
            assertEquals("b$i", a.ratchet.recv(r))
        }
        assertTrue(offers in 3..20, "keys offered periodically (got $offers of 120 turns)")
        assertTrue(cts in 3..20, "KEM ciphertexts follow the offers (got $cts)")
    }

    @Test
    fun ratchet_state_with_pq_fields_survives_serialization() {
        if (!rustCoreTestsEnabled()) return
        val (a, b) = session(pq = true)
        assertEquals("1", b.ratchet.recv(a.ratchet.send("1")))
        val json = app.umbera.core.util.WireJson.json
        val st = b.storage.states["s"]!!
        val back = json.decodeFromString(DoubleRatchet.RatchetState.serializer(), json.encodeToString(DoubleRatchet.RatchetState.serializer(), st))
        b.storage.states["s"] = back
        assertEquals("2", a.ratchet.recv(b.ratchet.send("2")))
        // An old (pre-v4) persisted state without the new fields still loads.
        val legacy = """{"dhKeyPair":${json.encodeToString(X25519.KeyPair.serializer(), X25519.generateKeyPair())},"remoteDhPublicKey":null,"rootKey":[1,2,3],"sendingChainKey":null,"receivingChainKey":null}"""
        val old = json.decodeFromString(DoubleRatchet.RatchetState.serializer(), legacy)
        assertFalse(old.pqEnabled)
        assertNull(old.myKemPub)
    }
}
