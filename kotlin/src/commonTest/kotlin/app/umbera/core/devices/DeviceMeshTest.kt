package app.umbera.core.devices

import app.umbera.core.crypto.DeviceLinkCore
import app.umbera.core.crypto.DeviceRequest
import app.umbera.core.crypto.DeviceTypes
import app.umbera.core.crypto.Dilithium3
import app.umbera.core.crypto.Kyber1024
import app.umbera.core.crypto.RustCore
import app.umbera.core.crypto.X25519
import app.umbera.core.crypto.secureRandomBytes
import app.umbera.core.data.remote.api.AnonDeviceDto
import app.umbera.core.data.remote.api.AnonDevicesDto
import app.umbera.core.data.remote.api.ApiResponse
import app.umbera.core.data.remote.api.DeviceKeyDto
import app.umbera.core.data.remote.api.OwnDeviceDto
import app.umbera.core.data.remote.api.OwnDevicesDto
import app.umbera.core.util.B64
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Linked devices in a conversation: two accounts (a phone + a computer each), real keys and
 * core, the server is an "address → envelopes" map. Checked: per-device encryption, the pair ratchet
 * in both directions, self-copy to one's own device, replays from the server rejected, corruption and a foreign signature,
 * a device injected by the server, atomicity (commit after write), session reset and retry.
 */
class DeviceMeshTest {

    private fun uuid(): String = hex(secureRandomBytes(16)).let { "${it.substring(0, 8)}-${it.substring(8, 12)}-4${it.substring(13, 16)}-a${it.substring(17, 20)}-${it.substring(20)}" }

    private fun hex(b: ByteArray) = b.joinToString("") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }

    private class MemKv : DeviceKv {
        val m = LinkedHashMap<String, String>()
        override fun get(key: String) = m[key]
        override fun put(key: String, value: String) { m[key] = value }
        override fun remove(key: String) { m.remove(key) }
        override fun keys(prefix: String) = m.keys.filter { it.startsWith(prefix) }.toSet()
    }

    /** The "server": envelopes per rendezvous address + device lists. */
    private class Server {
        val boxes = LinkedHashMap<String, MutableList<String>>()
        val linked = LinkedHashMap<String, MutableList<OwnDeviceDto>>()
        var online = true
        fun post(rid: String, sealed: String): Boolean {
            if (!online) return false
            boxes.getOrPut(rid) { mutableListOf() } += sealed
            return true
        }
    }

    private inner class Account(val server: Server) {
        val userId = uuid()
        val x = X25519.generateKeyPair()
        val kem = Kyber1024.generateKeyPair()
        val secpPriv = secureRandomBytes(32)
        val secpPub = RustCore.secp256k1PublicKey(secpPriv)
        val dsa = RustCore.mldsa65GenerateKeypair()
        val address = RustCore.quantAddress(hex(secpPub), hex(dsa.publicKey))
        val keys = AccountKeys(userId, secpPub, dsa.publicKey, x.publicKey, kem.publicKey.encoded, address)

        fun phone() = LocalDevice.primary(userId, x.privateKey, x.publicKey, kem.publicKey.encoded, kem.privateKey.encoded, secpPriv, dsa.privateKey)

        /** Link a computer: the certificate is signed with the account keys, the server stores the keys and signatures. */
        fun linkPc(): Pair<String, ByteArray> {
            val deviceId = uuid()
            val seed = DeviceLinkCore.deviceSeedGenerate()
            val req = DeviceRequest(DeviceTypes.DESKTOP, "PC", DeviceLinkCore.devicePublicKeys(seed))
            val cert = DeviceLinkCore.deviceCertIssue(req, userId, deviceId, secpPriv, dsa.privateKey, ByteArray(0), 1)
            val info = DeviceLinkCore.deviceCertVerify(cert, address)
            server.linked.getOrPut(userId) { mutableListOf() } += OwnDeviceDto(
                deviceId, "linked", keys = info.wireKeys.map { DeviceKeyDto(it.alg, B64.encode(it.key)) },
                primarySig = B64.encode(info.primarySig), pqSig = B64.encode(info.pqSig),
            )
            return deviceId to seed
        }
    }

    /** One device with its own storage and mesh. */
    private inner class Node(val server: Server, val me: LocalDevice, val accounts: Map<String, Account>) {
        val kv = MemKv()
        val source = object : DeviceDirectorySource {
            override suspend fun accountKeys(userId: String) = accounts[userId]?.keys
            override suspend fun anonDevices(userId: String): ApiResponse<AnonDevicesDto> = ApiResponse(
                200,
                AnonDevicesDto(userId, server.linked[userId].orEmpty().map { AnonDeviceDto(it.deviceId, it.keys, it.primarySig ?: "", it.pqSig) }, "v"),
                null,
            )
            override suspend fun ownDevices(): ApiResponse<OwnDevicesDto> =
                ApiResponse(200, OwnDevicesDto(4, listOf(OwnDeviceDto("primary", "primary")) + server.linked[me.addr.userId].orEmpty()), null)
        }
        val mesh = DeviceMesh(kv, source, { me }, { accounts[me.addr.userId]!!.keys }, post = { _, rid, s, _ -> server.post(rid, s) })
        val cursor = HashMap<String, Int>()

        /** Fetch everything new from own addresses (like polling), commit after "write". */
        suspend fun receive(peers: Collection<String>, commit: Boolean = true): List<MeshInbound> {
            val out = mutableListOf<MeshInbound>()
            for ((rid, dev) in mesh.recvRids(peers)) {
                val box = server.boxes[rid].orEmpty()
                var i = cursor[rid] ?: 0
                while (i < box.size) {
                    val got = runCatching { mesh.open(dev, box[i]) }.getOrNull()
                    if (got != null) { out += got; if (commit) got.commit() }
                    i++
                }
                if (commit) cursor[rid] = i
            }
            return out
        }
    }

    private fun payload(text: String) = """{"t":"text","c":"$text","ts":1,"n":"00"}"""

    @Test
    fun everyDeviceOfBothSidesGetsItsOwnEnvelope() = runTest {
        val server = Server()
        val alice = Account(server); val bob = Account(server)
        val accounts = mapOf(alice.userId to alice, bob.userId to bob)
        val (aPcId, aPcSeed) = alice.linkPc()
        val (bPcId, bPcSeed) = bob.linkPc()
        val aPhone = Node(server, alice.phone(), accounts)
        val aPc = Node(server, LocalDevice.linked(alice.userId, aPcId, aPcSeed), accounts)
        val bPhone = Node(server, bob.phone(), accounts)
        val bPc = Node(server, LocalDevice.linked(bob.userId, bPcId, bPcSeed), accounts)
        for (n in listOf(aPhone, aPc, bPhone, bPc)) { n.mesh.own(0); n.mesh.peer(if (n.me.addr.userId == alice.userId) bob.userId else alice.userId, 0) }

        // Alice's desktop writes to Bob: Bob's phone and desktop get "msg", Alice's phone gets the "out" copy.
        val bobSet = aPc.mesh.peer(bob.userId, 0)!!
        assertEquals(1, bobSet.linked.size)
        assertNotNull(bobSet.primary)
        val own = aPc.mesh.own(0)!!
        assertNotNull(own.primary, "the PC knows its phone")
        val targets = bobSet.all.map { MeshTarget(it, DeviceMesh.KIND_MSG) } + MeshTarget(own.primary!!, DeviceMesh.KIND_OUT, conv = bob.userId)
        assertEquals(3, aPc.mesh.deliver(targets, payload("hi from pc"), nick = "alice", wireKind = "message"))

        val atBobPhone = bPhone.receive(listOf(alice.userId))
        assertEquals(listOf("hi from pc"), atBobPhone.map { it.plaintext.substringAfter("\"c\":\"").substringBefore('"') })
        assertEquals(DeviceMesh.KIND_MSG, atBobPhone.single().body.kind)
        assertEquals(aPcId, atBobPhone.single().from.addr.deviceId)
        assertEquals(1, bPc.receive(listOf(alice.userId)).size)
        val copy = aPhone.receive(listOf(bob.userId)).single()
        assertEquals(DeviceMesh.KIND_OUT, copy.body.kind)
        assertEquals(bob.userId, copy.body.conv)

        // A replay of the same envelope from the server is not accepted a second time.
        bPhone.cursor.clear()
        assertTrue(bPhone.receive(listOf(alice.userId)).isEmpty(), "replayed envelope is ignored")

        // Bob's phone replies to Alice's computer and back — the pair ratchet in both directions, many messages.
        val aPcDev = bPhone.mesh.peer(alice.userId, 0)!!.find(aPcId)!!
        repeat(5) { i -> bPhone.mesh.deliver(listOf(MeshTarget(aPcDev, DeviceMesh.KIND_MSG)), payload("b$i"), null, "message") }
        val got = aPc.receive(listOf(bob.userId))
        assertEquals((0 until 5).map { "b$it" }, got.map { it.plaintext.substringAfter("\"c\":\"").substringBefore('"') })
        assertTrue(got.all { it.body.ratchet != null || it.body.direct != null })
        assertTrue(got.any { it.body.ratchet != null }, "after the first exchange the pair runs the ratchet")
        val bPhoneDev = aPc.mesh.peer(bob.userId, 0)!!.primary!!
        repeat(3) { i -> aPc.mesh.deliver(listOf(MeshTarget(bPhoneDev, DeviceMesh.KIND_MSG)), payload("a$i"), null, "message") }
        val back = bPhone.receive(listOf(alice.userId))
        assertEquals(listOf("a0", "a1", "a2"), back.map { it.plaintext.substringAfter("\"c\":\"").substringBefore('"') })
        assertTrue(back.all { it.body.ratchet != null })
        assertTrue(back.first().body.ratchet!!.kc != null || back.first().body.ratchet!!.kp != null, "PQ ratchet (ML-KEM) is on")
    }

    @Test
    fun forgedOrInjectedDevicesAreRejected() = runTest {
        val server = Server()
        val alice = Account(server); val bob = Account(server); val mallory = Account(server)
        val accounts = mapOf(alice.userId to alice, bob.userId to bob, mallory.userId to mallory)
        // The server injects a "computer" for Alice signed by someone else's account.
        val (mId, _) = mallory.linkPc()
        server.linked[alice.userId] = mutableListOf(server.linked[mallory.userId]!!.single().copy(deviceId = mId))
        // And a device without a PQ signature.
        val (aPcId, _) = alice.linkPc()
        val honest = server.linked[alice.userId]!!.last()
        server.linked[alice.userId]!![server.linked[alice.userId]!!.lastIndex] = honest.copy(pqSig = null)
        val bPhone = Node(server, bob.phone(), accounts)
        val set = bPhone.mesh.peer(alice.userId, 0)!!
        assertTrue(set.linked.isEmpty(), "neither the foreign-signed nor the classical-only device is accepted: ${set.linked.map { it.addr.deviceId }}")
        assertNotNull(set.primary)
        assertTrue(aPcId.isNotEmpty())
    }

    @Test
    fun tamperedAndMisattributedEnvelopesFail() = runTest {
        val server = Server()
        val alice = Account(server); val bob = Account(server)
        val accounts = mapOf(alice.userId to alice, bob.userId to bob)
        val (aPcId, aPcSeed) = alice.linkPc()
        val aPc = Node(server, LocalDevice.linked(alice.userId, aPcId, aPcSeed), accounts)
        val bPhone = Node(server, bob.phone(), accounts)
        val bobDev = aPc.mesh.peer(bob.userId, 0)!!.primary!!
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("x"), null, "message")
        val (rid, sealed) = server.boxes.entries.single().let { it.key to it.value.single() }
        val from = bPhone.mesh.peer(alice.userId, 0)!!.find(aPcId)!!
        // Corruption of any byte.
        val raw = B64.decode(sealed.removePrefix(DeviceEnvelope.PREFIX))
        raw[raw.size - 5] = (raw[raw.size - 5].toInt() xor 1).toByte()
        assertFailsWith<DeviceEnvelopeException> { bPhone.mesh.open(from, DeviceEnvelope.PREFIX + B64.encode(raw)) }
        // The same envelope attributed to another device (Alice's phone) — the signature does not match.
        val alicePhoneDev = bPhone.mesh.peer(alice.userId, 0)!!.primary!!
        assertFailsWith<DeviceEnvelopeException> { bPhone.mesh.open(alicePhoneDev, sealed) }
        // Another device cannot open the envelope.
        val (bPcId, bPcSeed) = bob.linkPc()
        val bPc = Node(server, LocalDevice.linked(bob.userId, bPcId, bPcSeed), accounts)
        assertFailsWith<DeviceEnvelopeException> { bPc.mesh.open(from, sealed) }
        // A copy of "mine" from someone else's account is not accepted.
        val bobSet = aPc.mesh.peer(bob.userId, 0)!!
        aPc.mesh.deliver(listOf(MeshTarget(bobSet.primary!!, DeviceMesh.KIND_OUT, conv = "x")), payload("fake own"), null, "message")
        val second = server.boxes[rid]!!.last()
        assertFailsWith<DeviceEnvelopeException> { bPhone.mesh.open(from, second) }
        assertNotNull(bPhone.mesh.open(from, sealed))
    }

    /** "Last activity" of one's own device — a local record only, from accepted envelopes; others' are not recorded. */
    @Test
    fun ownDeviceLastSeenIsLocalOnly() = runTest {
        val server = Server()
        val alice = Account(server); val bob = Account(server)
        val accounts = mapOf(alice.userId to alice, bob.userId to bob)
        val (aPcId, aPcSeed) = alice.linkPc()
        val aPhone = Node(server, alice.phone(), accounts)
        val aPc = Node(server, LocalDevice.linked(alice.userId, aPcId, aPcSeed), accounts)
        val bPhone = Node(server, bob.phone(), accounts)
        for (n in listOf(aPhone, aPc, bPhone)) { n.mesh.own(0); n.mesh.peer(if (n.me.addr.userId == alice.userId) bob.userId else alice.userId, 0) }
        assertNull(aPhone.mesh.ownLastSeen(aPcId), "nothing received yet")
        val postedBefore = server.boxes.values.sumOf { it.size }
        // Copy of one's own message from the desktop to the phone — the phone records the desktop's time.
        val own = aPc.mesh.own(0)!!
        aPc.mesh.deliver(listOf(MeshTarget(own.primary!!, DeviceMesh.KIND_OUT, conv = bob.userId)), payload("copy"), nick = "alice", wireKind = "message")
        aPhone.receive(listOf(bob.userId))
        val seen = assertNotNull(aPhone.mesh.ownLastSeen(aPcId))
        assertTrue(seen > 0 && seen <= kotlinx.datetime.Clock.System.now().toEpochMilliseconds())
        // The server received nothing new (only the copy envelope itself); the record is in the phone's storage.
        assertEquals(postedBefore + 1, server.boxes.values.sumOf { it.size })
        assertTrue(aPhone.kv.keys("dvls:").isNotEmpty())
        // A peer's envelope is not recorded as "own device".
        aPc.mesh.deliver(listOf(MeshTarget(aPc.mesh.peer(bob.userId, 0)!!.primary!!, DeviceMesh.KIND_MSG)), payload("hi"), null, "message")
        assertEquals(1, bPhone.receive(listOf(alice.userId)).size)
        assertNull(bPhone.mesh.ownLastSeen(aPcId), "a peer's device is not an own device")
        assertTrue(bPhone.kv.keys("dvls:").isEmpty())
        // Desktop unlinked — record erased.
        aPhone.mesh.forgetDevice(DeviceAddr(alice.userId, aPcId))
        assertNull(aPhone.mesh.ownLastSeen(aPcId))
    }

    @Test
    fun stateMovesOnlyOnCommitAndSurvivesInterleavedSend() = runTest {
        val server = Server()
        val alice = Account(server); val bob = Account(server)
        val accounts = mapOf(alice.userId to alice, bob.userId to bob)
        val (aPcId, aPcSeed) = alice.linkPc()
        val aPc = Node(server, LocalDevice.linked(alice.userId, aPcId, aPcSeed), accounts)
        val bPhone = Node(server, bob.phone(), accounts)
        val bobDev = aPc.mesh.peer(bob.userId, 0)!!.primary!!
        val pcDev = bPhone.mesh.peer(alice.userId, 0)!!.find(aPcId)!!
        // Advance the ratchet in both directions.
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("1"), null, "message")
        bPhone.receive(listOf(alice.userId))
        bPhone.mesh.deliver(listOf(MeshTarget(pcDev, DeviceMesh.KIND_MSG)), payload("2"), null, "message")
        aPc.receive(listOf(bob.userId))
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("3"), null, "message")
        // With device address epochs "3" already goes to the epoch address (a new mailbox) — take the pair's latest mailbox.
        val rid = server.boxes.keys.last { r -> bPhone.mesh.recvRids(listOf(alice.userId)).containsKey(r) }
        val env = server.boxes[rid]!!.last()
        // "Crash" before write: opened, not saved — opens again with the same state.
        val first = bPhone.mesh.open(pcDev, env)!!
        assertEquals(payload("3"), first.plaintext)
        val again = bPhone.mesh.open(pcDev, env)!!
        assertEquals(payload("3"), again.plaintext, "no commit — the state did not move, the message is not lost")
        // Between decryption and commit the phone sends on its own (advancing its chain) — commit does not clobber it.
        bPhone.mesh.deliver(listOf(MeshTarget(pcDev, DeviceMesh.KIND_MSG)), payload("4"), null, "message")
        again.commit()
        assertNull(bPhone.mesh.open(pcDev, env), "after commit the envelope is a replay")
        bPhone.mesh.deliver(listOf(MeshTarget(pcDev, DeviceMesh.KIND_MSG)), payload("5"), null, "message")
        val atPc = aPc.receive(listOf(bob.userId))
        assertEquals(listOf(payload("4"), payload("5")), atPc.map { it.plaintext })
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("6"), null, "message")
        assertEquals(listOf(payload("6")), bPhone.receive(listOf(alice.userId)).map { it.plaintext }.filter { it == payload("6") })
    }

    @Test
    fun lostSessionIsResetAndMessageResent() = runTest {
        val server = Server()
        val alice = Account(server); val bob = Account(server)
        val accounts = mapOf(alice.userId to alice, bob.userId to bob)
        val (aPcId, aPcSeed) = alice.linkPc()
        val aPc = Node(server, LocalDevice.linked(alice.userId, aPcId, aPcSeed), accounts)
        val bPhone = Node(server, bob.phone(), accounts)
        val bobDev = aPc.mesh.peer(bob.userId, 0)!!.primary!!
        val pcDev = bPhone.mesh.peer(alice.userId, 0)!!.find(aPcId)!!
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("1"), null, "message")
        bPhone.receive(listOf(alice.userId))
        bPhone.mesh.deliver(listOf(MeshTarget(pcDev, DeviceMesh.KIND_MSG)), payload("2"), null, "message")
        aPc.receive(listOf(bob.userId))
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("3"), null, "message")
        bPhone.receive(listOf(alice.userId))
        // Bob's phone lost its session (reinstall with the same account keys).
        bPhone.mesh.sessions.forget(pcDev.addr)
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("lost?"), null, "message")
        val atBob = bPhone.receive(listOf(alice.userId))
        // Either accepted as a restart, or a retry request; the message is not lost.
        val atPc = aPc.receive(listOf(bob.userId))
        val resent = bPhone.receive(listOf(alice.userId))
        val all = (atBob + resent).map { it.plaintext }
        assertTrue(payload("lost?") in all, "message after a lost session arrives: $all; pc got ${atPc.map { it.sys?.type }}")
        // The channel is intact again in both directions.
        bPhone.mesh.deliver(listOf(MeshTarget(pcDev, DeviceMesh.KIND_MSG)), payload("ok"), null, "message")
        assertTrue(aPc.receive(listOf(bob.userId)).any { it.plaintext == payload("ok") })
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("ok2"), null, "message")
        assertTrue(bPhone.receive(listOf(alice.userId)).any { it.plaintext == payload("ok2") })
        // Now the other side loses the session (the other role: initiator/responder) — also lossless.
        aPc.mesh.sessions.forget(bobDev.addr)
        bPhone.mesh.deliver(listOf(MeshTarget(pcDev, DeviceMesh.KIND_MSG)), payload("lost2?"), null, "message")
        val atPc2 = aPc.receive(listOf(bob.userId))
        bPhone.receive(listOf(alice.userId))
        val resent2 = aPc.receive(listOf(bob.userId))
        assertTrue(payload("lost2?") in (atPc2 + resent2).map { it.plaintext }, "second role: ${(atPc2 + resent2).map { it.plaintext }}")
        aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("ok3"), null, "message")
        assertTrue(bPhone.receive(listOf(alice.userId)).any { it.plaintext == payload("ok3") })
        bPhone.mesh.deliver(listOf(MeshTarget(pcDev, DeviceMesh.KIND_MSG)), payload("ok4"), null, "message")
        assertTrue(aPc.receive(listOf(bob.userId)).any { it.plaintext == payload("ok4") })
    }

    @Test
    fun offlineSendsWaitInOutbox() = runTest {
        val server = Server()
        val alice = Account(server); val bob = Account(server)
        val accounts = mapOf(alice.userId to alice, bob.userId to bob)
        val (aPcId, aPcSeed) = alice.linkPc()
        val aPc = Node(server, LocalDevice.linked(alice.userId, aPcId, aPcSeed), accounts)
        val bPhone = Node(server, bob.phone(), accounts)
        val bobDev = aPc.mesh.peer(bob.userId, 0)!!.primary!!
        server.online = false
        assertEquals(0, aPc.mesh.deliver(listOf(MeshTarget(bobDev, DeviceMesh.KIND_MSG)), payload("later"), null, "message"))
        assertEquals(1, aPc.mesh.outboxSize())
        server.online = true
        aPc.mesh.flushOutbox()
        bPhone.mesh.peer(alice.userId, 0)
        assertEquals(0, aPc.mesh.outboxSize())
        assertEquals(listOf(payload("later")), bPhone.receive(listOf(alice.userId)).map { it.plaintext })
    }

    @Test
    fun deviceSetVersionMatchesServerFormat() = runTest {
        val server = Server()
        val alice = Account(server)
        val accounts = mapOf(alice.userId to alice)
        val node = Node(server, alice.phone(), accounts)
        // Empty set — as on the server: SHA-256("umbera-device-set-v1|").
        assertEquals(hex(RustCore.sha256("umbera-device-set-v1|".encodeToByteArray())), node.mesh.directory.setVersion(emptyList()))
        alice.linkPc()
        val own = node.mesh.own(0)!!
        assertEquals(1, own.linked.size)
        assertNull(own.primary, "the phone's own set lists only its computers")
        assertTrue(Dilithium3.PUBLIC_KEY_SIZE > 0)
    }
}
