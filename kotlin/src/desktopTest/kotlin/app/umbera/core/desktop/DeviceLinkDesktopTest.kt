package app.umbera.core.desktop

import app.umbera.core.crypto.CommVaultRoots
import app.umbera.core.crypto.DeviceKey
import app.umbera.core.crypto.DeviceLinkCore
import app.umbera.core.crypto.DeviceLinkException
import app.umbera.core.crypto.DeviceTypes
import app.umbera.core.crypto.LinkBlob
import app.umbera.core.crypto.LinkKinds
import app.umbera.core.crypto.LinkSections
import app.umbera.core.crypto.LinkSession
import app.umbera.core.crypto.LinkState
import app.umbera.core.crypto.MlsEngine
import app.umbera.core.crypto.MlsIncoming
import app.umbera.core.crypto.MlsJoinOffer
import app.umbera.core.crypto.MlsJoinRequest
import app.umbera.core.crypto.RustCore
import app.umbera.core.crypto.secureRandomBytes
import java.io.File
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * End-to-end desktop ↔ phone linking in a single process via the Kotlin facade (JNA → libumbera_core from
 * desktopMain resources): QR, negotiation, matching verification codes, device certificate, package with history
 * and photos, the desktop joining an MLS group as a separate leaf, rejections on substitution/replay/timeout.
 */
class DeviceLinkDesktopTest {
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
    private fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    private val now = System.currentTimeMillis() / 1000

    private class Account(val secpPriv: ByteArray, val dsaSeed: ByteArray, val address: String)

    private fun account(): Account {
        // secp256k1: a random scalar (probability of an invalid one ~2^-128 — the core would reject it).
        val secp = secureRandomBytes(32)
        val dsa = RustCore.mldsa65GenerateKeypair()
        val address = RustCore.quantAddress(hex(RustCore.secp256k1PublicKey(secp)), hex(dsa.publicKey))
        return Account(secp, dsa.privateKey, address)
    }

    private class Linked(val pc: LinkSession, val phone: LinkSession)

    /** Full flow up to "Link" on both screens. */
    private fun link(): Linked {
        val pc = LinkSession.desktop(secureRandomBytes(16), "http://127.0.0.1:38080", now)
        assertTrue(pc.qrText().startsWith("umbera-link:"))
        assertTrue(pc.qrText().length < 200, "QR stays small: ${pc.qrText().length}")
        val phone = LinkSession.phone(pc.qrText(), now + 2)
        assertEquals("http://127.0.0.1:38080", phone.relayHint())
        assertContentEquals(pc.linkId(), phone.linkId())
        val accept = phone.phoneAccept(pc.offer(), now + 3)
        val confirm = pc.desktopAccept(accept, now + 4)
        phone.phoneConfirm(confirm, now + 4)
        assertEquals(LinkState.AWAITING_SAS, pc.state())
        assertEquals(LinkState.AWAITING_SAS, phone.state())
        val code = pc.sas()
        assertEquals(6, code.length)
        assertTrue(code.all { it.isDigit() })
        assertEquals(code, phone.sas(), "the same code on both screens")
        pc.confirmSas(now + 8)
        phone.confirmSas(now + 9)
        return Linked(pc, phone)
    }

    private fun jpeg(n: Int) = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0xE0.toByte()) + ByteArray(n) { (it % 251).toByte() }

    @Test
    fun phoneAndDesktopLinkAndTransfer() {
        val acct = account()
        val l = link()

        // Desktop keys → certificate from the phone.
        val deviceSeed = DeviceLinkCore.deviceSeedGenerate()
        val req = l.phone.openDeviceRequest(l.pc.deviceRequest(deviceSeed, DeviceTypes.DESKTOP, "Linux"))
        assertEquals(DeviceTypes.DESKTOP, req.deviceType)
        assertEquals(DeviceLinkCore.devicePublicKeys(deviceSeed), req.keys)
        // Account and desktop ids come from the server (/link/claim); the name is only in ciphertext under the account's device key.
        val userId = java.util.UUID.randomUUID().toString()
        val deviceId = java.util.UUID.randomUUID().toString()
        val syncKey = DeviceLinkCore.accountSyncKey(secureRandomBytes(32), secureRandomBytes(64))
        val labelSealed = DeviceLinkCore.deviceLabelSeal(syncKey, deviceId, req.deviceType, req.label)
        val cert = DeviceLinkCore.deviceCertIssue(req, userId, deviceId, acct.secpPriv, acct.dsaSeed, labelSealed, now)
        val got = l.pc.open(l.phone.seal(LinkKinds.DEVICE_CERT, cert))
        val mine = DeviceLinkCore.deviceCertVerifyForDevice(got, deviceSeed)
        assertEquals(acct.address, mine.accountAddress, "desktop learns its account from the certificate")
        assertEquals(userId, mine.userId)
        assertEquals(deviceId, mine.deviceId)
        assertEquals(listOf("ed25519", "ml-dsa-65", "x25519", "ml-kem-1024"), mine.wireKeys.map { it.alg })
        assertEquals(32, DeviceLinkCore.deviceKeysDigest(mine.wireKeys).size)
        // The peer verifies the device from the directory by the address it already has.
        val theirs = DeviceLinkCore.deviceListingVerify(
            mine.userId, mine.deviceId, mine.wireKeys, mine.primarySig, mine.pqSig,
            mine.accountSecp256k1, mine.accountMldsa65, acct.address,
        )
        assertEquals(DeviceLinkCore.devicePublicKeys(deviceSeed), theirs)
        val ex = assertFailsWith<DeviceLinkException> { DeviceLinkCore.deviceCertVerify(cert, account().address) }
        assertEquals(DeviceLinkException.Reason.MISMATCH, ex.reason)
        val noPq = assertFailsWith<DeviceLinkException> {
            DeviceLinkCore.deviceListingVerify(
                mine.userId, mine.deviceId, mine.wireKeys, mine.primarySig, ByteArray(0),
                mine.accountSecp256k1, mine.accountMldsa65, acct.address,
            )
        }
        assertEquals(DeviceLinkException.Reason.MISMATCH, noPq.reason)
        assertEquals("Linux", DeviceLinkCore.deviceLabelOpen(syncKey, deviceId, mine.labelSealed).label)
        // The device signature is verified against the keys from the certificate.
        val sig = DeviceLinkCore.deviceSign(deviceSeed, "sync", "hello".encodeToByteArray())
        assertTrue(DeviceLinkCore.deviceVerify(theirs, "sync", "hello".encodeToByteArray(), sig))

        // Package with history: profile, contact, chat, text, photo, Communities vault.
        val roots = DeviceLinkCore.commVaultRoots(secureRandomBytes(32), secureRandomBytes(64))
        val sent = listOf(
            Triple(LinkSections.PROFILE, ByteArray(0), """{"name":"Demo"}""".encodeToByteArray()),
            Triple(LinkSections.CONTACT, "c1".encodeToByteArray(), """{"name":"Alice"}""".encodeToByteArray()),
            Triple(LinkSections.CHAT, "chat1".encodeToByteArray(), """{"peer":"c1"}""".encodeToByteArray()),
            Triple(LinkSections.MESSAGE_TEXT, "m1".encodeToByteArray(), "Привет".encodeToByteArray()),
            Triple(LinkSections.MESSAGE_PHOTO, "m2".encodeToByteArray(), jpeg(900 * 1024)),
            Triple(LinkSections.ACCOUNT_SYNC, ByteArray(0), syncKey),
            Triple(LinkSections.COMM_VAULT, ByteArray(0), DeviceLinkCore.commVaultRecordBody(roots)),
        )
        val blobs = ArrayList<LinkBlob>()
        blobs += l.phone.packageBegin(includeHistory = true)
        for ((s, id, body) in sent) blobs += l.phone.packageAdd(s, id, body)
        blobs += l.phone.packageFinish()
        assertTrue(blobs.size >= 3, "header, parts, end: ${blobs.size}")
        assertTrue(blobs.all { it.data.size < 1024 * 1024 }, "every blob fits the relay limit")
        assertEquals("pkg_part", LinkKinds.wireName(blobs[1].kind))
        assertEquals(LinkKinds.PACKAGE_PART, LinkKinds.fromWireName("pkg_part"))
        val received = ArrayList<Triple<Int, ByteArray, ByteArray>>()
        var done = false
        for (b in blobs) {
            val p = l.pc.packageReceive(b)
            p.records.forEach { received += Triple(it.section, it.id, it.body) }
            done = p.done
        }
        assertTrue(done)
        assertEquals(sent.size, received.size)
        sent.zip(received).forEach { (a, b) ->
            assertEquals(a.first, b.first)
            assertContentEquals(a.second, b.second)
            assertContentEquals(a.third, b.third)
        }
        val gotRoots = DeviceLinkCore.commVaultRecordParse(received.last().third)
        assertContentEquals(
            DeviceLinkCore.commVaultEpochKeys(roots.v3, 11).encKey,
            DeviceLinkCore.commVaultEpochKeys(gotRoots.v3, 11).encKey,
        )
        l.phone.packageCheckAck(l.pc.packageAck())

        l.pc.close()
        l.phone.close()
        val closed = assertFailsWith<Exception> { l.pc.sas() }
        assertTrue(closed is IllegalStateException || closed is DeviceLinkException)
    }

    @Test
    fun desktopBecomesItsOwnMlsLeaf() {
        val gid = secureRandomBytes(32)
        val phoneMid = secureRandomBytes(32)
        val pcMid = secureRandomBytes(32)
        val phoneMls = MlsEngine(phoneMid)
        val bob = MlsEngine(secureRandomBytes(32))
        phoneMls.createGroup(gid)
        bob.processWelcome(phoneMls.addMembers(gid, listOf(bob.generateKeyPackage())).welcome)

        val l = link()
        val reqBlob = l.phone.seal(LinkKinds.MLS_JOIN_REQUESTS, DeviceLinkCore.mlsJoinRequestsEncode(listOf(MlsJoinRequest(gid, phoneMid))))
        val reqs = DeviceLinkCore.mlsJoinRequestsDecode(l.pc.open(reqBlob))
        val pcMls = MlsEngine(pcMid)
        val offers = reqs.map { MlsJoinOffer(it.gid, pcMid, pcMls.generateKeyPackage(), pcMls.siblingSign(it.gid, it.primaryMemberId, pcMid)) }
        val offer = DeviceLinkCore.mlsJoinOffersDecode(l.phone.open(l.pc.seal(LinkKinds.MLS_JOIN_OFFERS, DeviceLinkCore.mlsJoinOffersEncode(offers))))[0]
        assertTrue(DeviceLinkCore.mlsSiblingVerifyKeyPackage(phoneMid, offer))
        val primarySig = phoneMls.siblingSign(gid, phoneMid, pcMid)
        val add = phoneMls.addMembers(gid, listOf(offer.keyPackage))
        assertContentEquals(gid, pcMls.processWelcome(add.welcome))
        assertTrue(bob.processIncoming(gid, add.commit) is MlsIncoming.CommitApplied)
        assertTrue(bob.siblingVerify(gid, phoneMid, pcMid, primarySig, offer.deviceSiblingSig))
        assertFalse(bob.siblingVerify(gid, phoneMid, pcMid, offer.deviceSiblingSig, primarySig))
        assertEquals(3, bob.members(gid).size)
        assertTrue(bob.ownLeafMarked(gid) && pcMls.ownLeafMarked(gid))
        assertEquals(100u, phoneMls.leafLimit(gid), "everyone on the new core: up to 100 leaves")
        val fromPc = phoneMls.processIncoming(gid, pcMls.encrypt(gid, "с ПК".encodeToByteArray()))
        val app = fromPc as MlsIncoming.Application
        assertContentEquals(pcMid, app.senderIdentity)
        listOf(phoneMls, bob, pcMls).forEach { it.close() }
        l.pc.close()
        l.phone.close()
    }

    @Test
    fun substitutedDesktopShowsDifferentCodes() {
        val real = LinkSession.desktop(secureRandomBytes(16), "", now)
        val evilPhone = LinkSession.phone(real.qrText(), now)
        evilPhone.phoneConfirm(real.desktopAccept(evilPhone.phoneAccept(real.offer(), now), now), now)
        val evilPc = LinkSession.desktop(real.linkId(), "", now)
        val phone = LinkSession.phone(evilPc.qrText(), now)
        phone.phoneConfirm(evilPc.desktopAccept(phone.phoneAccept(evilPc.offer(), now), now), now)
        assertNotEquals(real.sas(), phone.sas())
        // QR and OFFER are no longer issued after negotiation.
        assertEquals(DeviceLinkException.Reason.STATE, assertFailsWith<DeviceLinkException> { real.qrText() }.reason)
        // And with the real QR the phone rejects a foreign OFFER immediately.
        val real2 = LinkSession.desktop(secureRandomBytes(16), "", now)
        val evil2 = LinkSession.desktop(real2.linkId(), "", now)
        val phone2 = LinkSession.phone(real2.qrText(), now)
        val e = assertFailsWith<DeviceLinkException> { phone2.phoneAccept(evil2.offer(), now) }
        assertEquals(DeviceLinkException.Reason.MISMATCH, e.reason)
        assertEquals(LinkState.CLOSED, phone2.state())
        listOf(real, evilPhone, evilPc, phone, real2, evil2, phone2).forEach { it.close() }
    }

    @Test
    fun tamperReplayExpiry() {
        val l = link()
        val b1 = l.phone.seal(LinkKinds.MLS_JOIN_REQUESTS, byteArrayOf(0, 0))
        val b2 = l.phone.seal(LinkKinds.MLS_JOIN_REQUESTS, byteArrayOf(0, 0))
        l.pc.open(b1)
        assertEquals(DeviceLinkException.Reason.REPLAY, assertFailsWith<DeviceLinkException> { l.pc.open(b1) }.reason)
        val bad = LinkBlob(b2.kind, b2.seq, b2.data.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() })
        assertEquals(DeviceLinkException.Reason.MISMATCH, assertFailsWith<DeviceLinkException> { l.pc.open(bad) }.reason)
        assertEquals(LinkState.CLOSED, l.pc.state())
        l.pc.close()
        l.phone.close()

        val pc = LinkSession.desktop(secureRandomBytes(16), "", now)
        val phone = LinkSession.phone(pc.qrText(), now)
        val accept = phone.phoneAccept(pc.offer(), now)
        assertEquals(DeviceLinkException.Reason.EXPIRED, assertFailsWith<DeviceLinkException> { pc.desktopAccept(accept, now + 61) }.reason)
        assertEquals(DeviceLinkException.Reason.MALFORMED, assertFailsWith<DeviceLinkException> { LinkSession.phone("https://evil", now) }.reason)
        pc.close()
        phone.close()
    }

    /** Core vectors (tests/vectors/link-vectors.json, communities/pqc/testdata/pq-vectors.json) — via the same facade. */
    @Test
    fun vectorsFromFiles() {
        val root = generateSequence(File("").absoluteFile) { it.parentFile }.first { File(it, "desktop/link-vectors.json").isFile }
        val v = Json.parseToJsonElement(File(root, "desktop/link-vectors.json").readText()).jsonObject
        val dev = v["device"]!!.jsonObject
        fun JsonObject.s(k: String) = this[k]!!.jsonPrimitive.content
        val inputs = v["inputs"]!!.jsonObject
        val info = DeviceLinkCore.deviceCertVerify(unhex(dev.s("cert")), dev.s("account_address"))
        assertEquals(dev.s("device_id"), info.deviceId)
        assertEquals(dev.s("user_id"), info.userId)
        assertEquals(dev.s("primary_sig"), hex(info.primarySig))
        assertEquals(dev.s("keys_digest"), hex(DeviceLinkCore.deviceKeysDigest(info.wireKeys)))
        assertEquals(dev.s("ed25519"), hex(DeviceLinkCore.devicePublicKeys(unhex(inputs.s("device_seed"))).ed25519))
        assertEquals(dev.s("account_address"), DeviceLinkCore.deviceCertVerifyForDevice(unhex(dev.s("cert")), unhex(inputs.s("device_seed"))).accountAddress)
        assertEquals("Linux", DeviceLinkCore.deviceLabelOpen(unhex(dev.s("sync_key")), info.deviceId, unhex(dev.s("label_sealed"))).label)
        // Server test vector.
        val serverKeys = listOf(DeviceKey("x25519", ByteArray(32) { 1 }), DeviceKey("ml-kem-1024", ByteArray(4) { 2 }))
        assertEquals("27ebe18be48a8c5b97f47d9c05e17020307921b9af324dae08d76fdba39f6848", hex(DeviceLinkCore.deviceKeysDigest(serverKeys)))

        val vault = Json.parseToJsonElement(File(root, "communities/pq-vectors.json").readText()).jsonObject["vault"]!!.jsonObject
        val roots: CommVaultRoots = DeviceLinkCore.commVaultRoots(unhex(vault.s("x25519_priv")), unhex(vault.s("mlkem_seed")))
        val legacy = DeviceLinkCore.commVaultLegacyKeys(roots.v2)
        assertEquals(vault.s("id"), hex(legacy.id))
        assertEquals(vault.s("auth_seed"), hex(legacy.authSeed))
        assertEquals(vault.s("enc_key"), hex(legacy.encKey))
    }
}
