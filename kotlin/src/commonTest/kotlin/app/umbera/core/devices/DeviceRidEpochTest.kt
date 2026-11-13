package app.umbera.core.devices

import app.umbera.core.crypto.DeviceLinkCore
import app.umbera.core.crypto.DeviceRequest
import app.umbera.core.crypto.DeviceTypes
import app.umbera.core.crypto.Kyber1024
import app.umbera.core.crypto.RendezvousV2
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
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Device address epochs (DeviceRidEpochs): linked desktops and phones rotate device-pair addresses in a shared second,
 * the secret comes from the recipient (from its ML-KEM seed), once, in the `rk` field. The server is an "address → envelopes" map, each node has its own clock.
 * Checked: lossless transition, a distinct address per epoch, an old device (switch off) — constant address byte for
 * byte and no `rk`, recipient offline across several epochs, recipient restore (everything wiped), sender lost the secret
 * (re-offer), a queue across an epoch boundary, send-time spreading, a service offer without piggyback traffic.
 */
class DeviceRidEpochTest {
    private fun uuid(): String = hex(secureRandomBytes(16)).let { "${it.substring(0, 8)}-${it.substring(8, 12)}-4${it.substring(13, 16)}-a${it.substring(17, 20)}-${it.substring(20)}" }
    private fun hex(b: ByteArray) = b.joinToString("") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }

    private var savedPeriod = 0L
    @BeforeTest fun before() { savedPeriod = RendezvousV2.periodSec; RendezvousV2.periodSec = 600 }
    @AfterTest fun after() { RendezvousV2.periodSec = savedPeriod }

    private class Clock(var ms: Long)

    private class MemKv : DeviceKv {
        val m = LinkedHashMap<String, String>()
        override fun get(key: String) = m[key]
        override fun put(key: String, value: String) { m[key] = value }
        override fun remove(key: String) { m.remove(key) }
        override fun keys(prefix: String) = m.keys.filter { it.startsWith(prefix) }.toSet()
    }

    private class Server {
        val boxes = LinkedHashMap<String, MutableList<String>>()
        val linked = LinkedHashMap<String, MutableList<OwnDeviceDto>>()
        val writes = mutableListOf<Pair<String, Long>>()
        var online = true
        fun post(rid: String, sealed: String, at: Long): Boolean {
            if (!online) return false
            boxes.getOrPut(rid) { mutableListOf() } += sealed
            writes += rid to at
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

    private inner class Node(
        val server: Server, val me: LocalDevice, val accounts: Map<String, Account>, val clock: Clock,
        var epochsOn: Boolean = true, var spreadOn: Boolean = false, val kv: MemKv = MemKv(),
    ) {
        val source = object : DeviceDirectorySource {
            override suspend fun accountKeys(userId: String) = accounts[userId]?.keys
            override suspend fun anonDevices(userId: String): ApiResponse<AnonDevicesDto> = ApiResponse(
                200, AnonDevicesDto(userId, server.linked[userId].orEmpty().map { AnonDeviceDto(it.deviceId, it.keys, it.primarySig ?: "", it.pqSig) }, "v"), null,
            )
            override suspend fun ownDevices(): ApiResponse<OwnDevicesDto> =
                ApiResponse(200, OwnDevicesDto(4, listOf(OwnDeviceDto("primary", "primary")) + server.linked[me.addr.userId].orEmpty()), null)
        }
        val mesh = DeviceMesh(kv, source, { me }, { accounts[me.addr.userId]!!.keys },
            post = { _, rid, s, _ -> server.post(rid, s, clock.ms) }, nowMs = { clock.ms }, epochsOn = { epochsOn }, spreadOn = { spreadOn })
        val cursor = HashMap<String, Int>()
        val peers get() = accounts.keys.filter { it != me.addr.userId }

        /** Like a polling pass: plan, poll "every pass" (slow ones too, the test does not economise), mark what was drained. */
        suspend fun receive(): List<MeshInbound> {
            val out = mutableListOf<MeshInbound>()
            val plan = mesh.recvPlan(peers)
            for (r in plan) {
                val box = server.boxes[r.rid].orEmpty()
                var i = cursor[r.rid] ?: 0
                while (i < box.size) {
                    runCatching { mesh.open(r.device, box[i], r.rid) }.getOrNull()?.let { out += it; it.commit() }
                    i++
                }
                cursor[r.rid] = i
            }
            plan.filter { it.epoch != null }.map { it.device.addr }.toSet().forEach { mesh.noteDrained(it) }
            return out
        }
        suspend fun peerDev(user: String, dev: String? = null): RemoteDevice {
            val set = if (user == me.addr.userId) mesh.own(0)!! else mesh.peer(user, 0)!!
            return if (dev == null) set.primary!! else set.find(dev)!!
        }
        suspend fun send(to: RemoteDevice, text: String, kind: String = DeviceMesh.KIND_MSG, spread: Boolean = false) =
            mesh.deliver(listOf(MeshTarget(to, kind, conv = if (kind == DeviceMesh.KIND_OUT) "c" else null)), payload(text), null, "message", spread = spread)
    }

    private fun payload(text: String) = """{"t":"text","c":"$text","ts":1,"n":"00"}"""
    private fun texts(l: List<MeshInbound>) = l.filter { it.body.kind != DeviceMesh.KIND_SYS }.map { it.plaintext.substringAfter("\"c\":\"").substringBefore('"') }

    /** Alice's desktop and Bob's phone (+ Alice's phone), clock at the start of an epoch + 1 min. */
    private suspend fun setup(aliceOn: Boolean = true, bobOn: Boolean = true): Triple<Node, Node, Node> {
        val server = Server()
        val clock = Clock(RendezvousV2.epochStartMs(4_000_000) + 60_000)
        val alice = Account(server); val bob = Account(server)
        val accounts = mapOf(alice.userId to alice, bob.userId to bob)
        val (pcId, pcSeed) = alice.linkPc()
        val aPc = Node(server, LocalDevice.linked(alice.userId, pcId, pcSeed), accounts, clock, epochsOn = aliceOn)
        val aPhone = Node(server, alice.phone(), accounts, clock, epochsOn = aliceOn)
        val bPhone = Node(server, bob.phone(), accounts, clock, epochsOn = bobOn)
        for (n in listOf(aPc, aPhone, bPhone)) { n.mesh.own(0); n.peers.forEach { n.mesh.peer(it, 0) } }
        return Triple(aPc, aPhone, bPhone)
    }

    @Test
    fun katMatchesRust() {
        val ssX = ByteArray(32) { (0x80 + it).toByte() }
        val seed = ByteArray(32) { (0xC0 + it).toByte() }
        val from = DeviceAddr("alice", "primary"); val to = DeviceAddr("bob", "pc1")
        val r = DeviceRidEpochs.rxSecret(seed, from, to)
        assertEquals("65bdece41503b6248a5229e017fd2662db67118aafefdfb90229dab80837456e", hex(r))
        assertEquals("4b3b11d2255cca9d86f97135f5f87c0d837ce65a7c8d26fa4a37b5d00c83d7c3", DeviceRidEpochs.ridEpoch(ssX, r, from, to, 2915))
        assertNotEquals(DeviceRidEpochs.ridEpoch(ssX, r, from, to, 2915), DeviceRidEpochs.ridEpoch(ssX, r, from, to, 2916))
        assertNotEquals(DeviceRidEpochs.ridEpoch(ssX, r, from, to, 2915), DeviceRidEpochs.ridEpoch(ssX, r, to, from, 2915))
    }

    @Test
    fun handshakeThenEveryEpochOwnAddressNoLoss() = runTest {
        val (aPc, _, bPhone) = setup()
        val clock = aPc.clock
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        val alicePc = bPhone.peerDev(aPc.me.addr.userId, aPc.me.addr.deviceId)
        val static12 = DeviceEnvelope.rid(aPc.me, bobPhone, aPc.me.addr, bobPhone.addr)
        // Both listen (plan created), the desktop writes first: constant address, the envelope carries its secret for Bob.
        aPc.receive(); bPhone.receive()
        aPc.send(bobPhone, "m0")
        assertEquals(static12, aPc.server.writes.last().first, "before Bob's secret — the static address")
        val got0 = bPhone.receive()
        assertEquals(listOf("m0"), texts(got0))
        assertTrue(got0.single().body.ridKey != null, "the first envelope offers the receiver's secret")
        // Bob replies — his envelope carries the secret for the desktop; from the next message the desktop writes to the epoch address.
        bPhone.send(alicePc, "r0")
        assertEquals(listOf("r0"), texts(aPc.receive()))
        val seen = LinkedHashMap<Long, MutableSet<String>>()
        val lost = mutableListOf<String>()
        for (i in 1..12) {
            aPc.send(bobPhone, "m$i")
            val (rid, _) = aPc.server.writes.last()
            seen.getOrPut(RendezvousV2.epochOf(clock.ms)) { mutableSetOf() } += rid
            assertNotEquals(static12, rid, "after Bob's secret — never the static address again")
            if (texts(bPhone.receive()) != listOf("m$i")) lost += "m$i"
            // Bob replies (also via epochs), no more "rk" envelopes.
            bPhone.send(alicePc, "r$i")
            val back = aPc.receive()
            assertEquals(listOf("r$i"), texts(back))
            assertTrue(back.all { it.body.ridKey == null }, "the secret is sent once")
            clock.ms += 200_000 // three messages per epoch (600 s)
        }
        assertTrue(lost.isEmpty(), "lost: $lost")
        assertTrue(seen.size >= 4, "crossed several boundaries: ${seen.keys}")
        assertTrue(seen.values.all { it.size == 1 }, "one address per epoch: $seen")
        assertEquals(seen.size, seen.values.flatten().toSet().size, "every epoch has its own address")
        // The server cannot link addresses of different epochs (PRF) and the constant one: check Bob has the same epoch addresses (computed independently).
        val plan = bPhone.mesh.recvPlan(bPhone.peers).filter { it.device.addr == aPc.me.addr }
        assertTrue(plan.any { it.epoch == RendezvousV2.epochOf(clock.ms - 200_000) && it.rid in seen.values.flatten() })
    }

    // Node clock (shared by all nodes in the test).
    private fun aPcClock(n: Node) = n.clock

    @Test
    fun oldReceiverStaysOnStaticByteForByte() = runTest {
        val (aPc, _, bPhone) = setup(aliceOn = true, bobOn = false)
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        val alicePc = bPhone.peerDev(aPc.me.addr.userId, aPc.me.addr.deviceId)
        val static12 = DeviceEnvelope.rid(aPc.me, bobPhone, aPc.me.addr, bobPhone.addr)
        val static21 = DeviceEnvelope.rid(bPhone.me, alicePc, bPhone.me.addr, alicePc.addr)
        aPc.receive(); bPhone.receive()
        // "Old" Bob: no epoch plan — listens on exactly the single legacy address per device.
        val bPlan = bPhone.mesh.recvPlan(bPhone.peers)
        assertTrue(bPlan.all { it.epoch == null }, "no epoch addresses without the switch")
        assertEquals(setOf(DeviceEnvelope.rid(bPhone.me, alicePc, alicePc.addr, bPhone.me.addr)), bPlan.filter { it.device.addr == alicePc.addr }.map { it.rid }.toSet())
        repeat(4) { i ->
            aPc.send(bobPhone, "m$i")
            bPhone.send(alicePc, "r$i")
            aPcClock(aPc).ms += 400_000
        }
        assertEquals(listOf("m0", "m1", "m2", "m3"), texts(bPhone.receive()))
        val back = aPc.receive()
        assertEquals(listOf("r0", "r1", "r2", "r3"), texts(back))
        assertTrue(back.all { it.body.ridKey == null }, "the old side never offers")
        assertEquals(setOf(static12, static21), aPc.server.writes.map { it.first }.toSet(), "only the old static addresses on the server")
        // The new desktop offered (in the first envelope), but old Bob did not understand it — the constant address stays.
        assertEquals(static21, bPhone.mesh.sendRid(alicePc), "the old side keeps writing the static address")
    }

    @Test
    fun switchOffOnSenderWritesStaticReceiverStillHears() = runTest {
        val (aPc, _, bPhone) = setup()
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        val alicePc = bPhone.peerDev(aPc.me.addr.userId, aPc.me.addr.deviceId)
        aPc.receive(); bPhone.receive()
        bPhone.send(alicePc, "hello"); aPc.receive()     // the desktop received Bob's secret
        aPc.send(bobPhone, "e1")
        assertNotEquals(DeviceEnvelope.rid(aPc.me, bobPhone, aPc.me.addr, bobPhone.addr), aPc.server.writes.last().first)
        aPc.epochsOn = false
        aPc.send(bobPhone, "s1")
        assertEquals(DeviceEnvelope.rid(aPc.me, bobPhone, aPc.me.addr, bobPhone.addr), aPc.server.writes.last().first, "switch off — static")
        // Different addresses are polled in turn — ordering between them is not guaranteed (as with rid2: static and epoch).
        assertEquals(setOf("e1", "s1"), texts(bPhone.receive()).toSet())
    }

    @Test
    fun receiverOfflineSeveralEpochsGetsEverything() = runTest {
        val (aPc, _, bPhone) = setup()
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        val alicePc = bPhone.peerDev(aPc.me.addr.userId, aPc.me.addr.deviceId)
        aPc.receive(); bPhone.receive()
        bPhone.send(alicePc, "hello"); aPc.receive()
        val sent = mutableListOf<String>()
        val rids = mutableSetOf<String>()
        // Bob is silent for 4 epochs (not polling); the desktop writes every 150 s.
        repeat(16) { i -> aPc.send(bobPhone, "o$i"); sent += "o$i"; rids += aPc.server.writes.last().first; aPcClock(aPc).ms += 150_000 }
        assertTrue(rids.size >= 4, "four epochs → four addresses: ${rids.size}")
        assertEquals(sent, texts(bPhone.receive()), "everything after coming back")
        // Drained epochs are released: the plan again has e−1, e, e+1 (+ the constant one).
        val plan = bPhone.mesh.recvPlan(bPhone.peers).filter { it.device.addr == alicePc.addr }
        assertEquals(4, plan.size, plan.map { it.epoch }.toString())
    }

    @Test
    fun receiverRestoredFromScratchHearsTheSameEpochAddresses() = runTest {
        val (aPc, _, bPhone) = setup()
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        val alicePc = bPhone.peerDev(aPc.me.addr.userId, aPc.me.addr.deviceId)
        aPc.receive(); bPhone.receive()
        bPhone.send(alicePc, "hello"); aPc.receive()
        aPc.send(bobPhone, "before"); assertEquals(listOf("before"), texts(bPhone.receive()))
        // Bob's phone restored from the phrase: same keys, empty storage (sessions, cursors, epoch records).
        aPcClock(aPc).ms += 900_000
        val restored = Node(bPhone.server, bPhone.me, bPhone.accounts, bPhone.clock)
        restored.mesh.own(0); restored.peers.forEach { restored.mesh.peer(it, 0) }
        aPc.send(bobPhone, "while-restoring")       // the desktop does not know about the restore — writes to the epoch
        aPcClock(aPc).ms += 700_000
        aPc.send(bobPhone, "after")
        val got = restored.receive()
        // Ratchet envelopes after session loss — "reset + retry" (as before); what matters is that they REACHED the recipient.
        val opened = texts(got)
        val retried = texts(aPc.receive().let { restored.receive() })
        assertTrue((opened + retried).containsAll(listOf("while-restoring", "after")), "nothing lost: $opened / $retried")
    }

    @Test
    fun senderLostSecretGetsItAgain() = runTest {
        val (aPc, _, bPhone) = setup()
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        val alicePc = bPhone.peerDev(aPc.me.addr.userId, aPc.me.addr.deviceId)
        aPc.receive(); bPhone.receive()
        bPhone.send(alicePc, "hello"); aPc.receive()
        aPc.send(bobPhone, "e"); bPhone.receive()
        // The desktop lost its epoch records (storage failure) — writes to the constant address; Bob hears it and re-offers (after a day/epoch).
        aPc.kv.m.keys.filter { it.startsWith("dvet:") }.forEach { aPc.kv.m.remove(it) }
        aPcClock(aPc).ms += 120_000
        aPc.send(bobPhone, "static-again")
        assertEquals(DeviceEnvelope.rid(aPc.me, bobPhone, aPc.me.addr, bobPhone.addr), aPc.server.writes.last().first)
        assertEquals(listOf("static-again"), texts(bPhone.receive()))
        bPhone.send(alicePc, "soon"); assertTrue(aPc.receive().all { it.body.ridKey == null }, "not before the gap")
        aPcClock(aPc).ms += DeviceRidEpochs.reofferGapMs(1)
        bPhone.send(alicePc, "later")
        assertTrue(aPc.receive().any { it.body.ridKey != null }, "re-offered after the gap")
        aPc.send(bobPhone, "epoch-again")
        assertNotEquals(DeviceEnvelope.rid(aPc.me, bobPhone, aPc.me.addr, bobPhone.addr), aPc.server.writes.last().first)
        assertEquals(listOf("epoch-again"), texts(bPhone.receive()))
    }

    @Test
    fun queuedEnvelopeCrossingTheBoundaryGoesToTheNewEpoch() = runTest {
        val (aPc, _, bPhone) = setup()
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        val alicePc = bPhone.peerDev(aPc.me.addr.userId, aPc.me.addr.deviceId)
        aPc.receive(); bPhone.receive()
        bPhone.send(alicePc, "hello"); aPc.receive()
        aPc.server.online = false
        aPc.send(bobPhone, "queued")
        assertEquals(1, aPc.mesh.outboxSize())
        aPcClock(aPc).ms += 8 * 600_000L // eight epochs offline (more than the recipient reads back)
        aPc.server.online = true
        aPc.mesh.flushOutbox()
        val now = RendezvousV2.epochOf(aPcClock(aPc).ms)
        val plan = bPhone.mesh.recvPlan(bPhone.peers).filter { it.device.addr == alicePc.addr }
        assertEquals(plan.single { it.epoch == now }.rid, aPc.server.writes.last().first, "re-addressed to the current epoch")
        assertEquals(listOf("queued"), texts(bPhone.receive()))
    }

    @Test
    fun spreadPutsEachDeviceAtItsOwnPointInTheWindowAndKeepsOrder() = runTest {
        val (aPc, aPhone, bPhone) = setup()
        aPc.spreadOn = true
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        val ownPhone = aPc.peerDev(aPc.me.addr.userId)
        val t0 = aPcClock(aPc).ms
        val writes0 = aPc.server.writes.size
        // Three messages in a row to two devices — queued with their own "not before" times.
        for (i in 0..2) aPc.mesh.deliver(listOf(MeshTarget(bobPhone, DeviceMesh.KIND_MSG), MeshTarget(ownPhone, DeviceMesh.KIND_OUT, conv = "c")),
            payload("s$i"), null, "message", spread = true)
        assertEquals(writes0, aPc.server.writes.size, "nothing is written at once")
        val nb = aPc.mesh.outboxNotBefore()
        assertEquals(6, nb.size)
        val window = app.umbera.core.network.FanOutJitter.windowMs(3)
        assertTrue(nb.all { it in t0..(t0 + window) }, "inside the window: ${nb.map { it - t0 }}")
        aPcClock(aPc).ms += window + 1
        aPc.mesh.flushOutbox()
        assertEquals(listOf("s0", "s1", "s2"), texts(bPhone.receive()), "order kept for one device")
        assertEquals(listOf("s0", "s1", "s2"), texts(aPhone.receive()))
        assertEquals(0, aPc.mesh.outboxSize())
        // Without the switch — immediately, as before.
        aPc.spreadOn = false
        aPc.send(bobPhone, "now", spread = true)
        assertEquals(0, aPc.mesh.outboxSize())
        assertEquals(listOf("now"), texts(bPhone.receive()))
    }

    @Test
    fun offerWithoutTrafficGoesAsServiceEnvelope() = runTest {
        val (aPc, _, bPhone) = setup()
        val bobPhone = aPc.peerDev(bPhone.me.addr.userId)
        aPc.receive(); bPhone.receive()
        // Bob never writes to Alice's desktop — the secret goes out as a service "rk" within the offerSpreadMs window.
        bPhone.mesh.maintainEpochs(bPhone.peers)
        aPcClock(aPc).ms += DeviceRidEpochs.offerSpreadMs() + 1
        bPhone.mesh.maintainEpochs(bPhone.peers)
        val got = aPc.receive()
        assertTrue(got.any { it.body.kind == DeviceMesh.KIND_SYS && it.body.ridKey != null }, got.map { it.body.kind }.toString())
        aPc.send(bobPhone, "x")
        assertNotEquals(DeviceEnvelope.rid(aPc.me, bobPhone, aPc.me.addr, bobPhone.addr), aPc.server.writes.last().first)
        assertEquals(listOf("x"), texts(bPhone.receive()))
        // No more offers.
        val n = aPc.server.writes.size
        aPcClock(aPc).ms += DeviceRidEpochs.offerSpreadMs() + 1
        bPhone.mesh.maintainEpochs(bPhone.peers)
        assertEquals(n, aPc.server.writes.size)
        assertNull(bPhone.mesh.outboxNotBefore().firstOrNull())
    }
}
