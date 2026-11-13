package app.umbera.core.crypto

import app.umbera.core.util.B64
import app.umbera.core.util.WireJson
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.TimeSource

/**
 * Single-layer call signalling `callsig-v2`: negotiation by capability bit, accepting both
 * formats, signature and binding to the recipient, only under v3, strict decompression, size and time vs the old format.
 */
class CallSigV2Test {

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

    private val json = WireJson.json

    /** [a] pinned [b]'s keys and saw bits [bCaps] in its message (like MessageRepositoryImpl: pin + note). */
    private fun know(a: User, b: User, bCaps: Int) {
        a.ks.checkAndPinPeerKey(b.id, b.secp, b.x)
        a.ks.savePeerKyber(b.id, b.ek)
        assertEquals(PeerCapsVerdict.OK, a.ks.checkAndPinPeerWireCaps(b.id, bCaps, 1))
        a.ks.notePeerWireCaps(b.id, bCaps)
    }

    private val NEW = MessageEncryption.WIRE_CAP_SEAL_V3 or MessageEncryption.WIRE_CAP_CALLSIG_V2
    private val V3_ONLY = MessageEncryption.WIRE_CAP_SEAL_V3

    @BeforeTest fun on() { SecurityRollout.setAll(true) }
    @AfterTest fun restore() { SecurityRollout.setAll(true) }

    // ---- old format, as in CallRepositoryImpl.encryptSignaling + sendCallSignalViaRendezvous ----
    private fun oldSeal(from: User, to: User, t: String, cid: String, vid: Boolean, data: String?, encrypt: Boolean): String {
        val enc = if (encrypt && data != null) {
            val r = from.enc.encryptMessage(data, to.id, to.secp, to.x, type = "signaling", sequenceNumber = 0)
            buildJsonObject {
                put("encryptedData", r.encryptedData); put("iv", r.iv); put("signature", r.signature); put("ephemeralPublicKey", r.ephemeralPublicKey)
            }.toString()
        } else data
        val envJson = buildJsonObject {
            put("t", t); put("cid", cid); put("vid", vid)
            enc?.let { put("enc", it) }
            put("ts", kotlinx.datetime.Clock.System.now().toEpochMilliseconds())
        }.toString()
        val payload = from.enc.encryptMessageAsPayload(envJson, to.id, to.secp, to.x, type = "signaling", sequenceNumber = 0)
        return json.encodeToString(from.enc.createSealedSenderAuto(payload, from.id, to.x, to.ek, recipientId = to.id))
    }

    /** Receive as handleRendezvousCallSignal: (t, cid, plaintext data, format). */
    private fun open(to: User, wire: String, encrypted: Boolean): Triple<String, String?, String> {
        val r = to.enc.openSealedSenderFull(json.decodeFromString<MessageEncryption.SealedSenderPackage>(wire))
        to.enc.openCallSignalV2(r)?.let { return Triple(it.t, it.d, "callsig-v2/${r.sealedVersion}") }
        val env = json.parseToJsonElement(to.enc.decryptMessageFromSealedSender(r).content).jsonObject
        val enc = env["enc"]?.jsonPrimitive?.content
        val data = if (encrypted && enc != null) {
            val o = json.parseToJsonElement(enc).jsonObject
            to.enc.decryptMessageRaw(
                o["encryptedData"]!!.jsonPrimitive.content, o["iv"]!!.jsonPrimitive.content, o["signature"]!!.jsonPrimitive.content,
                o["ephemeralPublicKey"]!!.jsonPrimitive.content, r.senderSecp256k1PublicKey.hexToBytesT(),
            ).content.trimEnd(' ')
        } else enc
        return Triple(env["t"]!!.jsonPrimitive.content, data, "v1/${r.sealedVersion}")
    }

    private fun String.hexToBytesT(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    /** As CallRepositoryImpl.accountSend: the new format only when canSendCallSigV2. */
    private fun send(from: User, to: User, t: String, data: String?, encrypt: Boolean = true): String =
        if (from.enc.canSendCallSigV2(to.id, from.ks.getPeerKyber(to.id)))
            json.encodeToString(from.enc.sealCallSignalV2(to.id, to.x, to.ek, from.id, t, "cid-1", true, data, kotlinx.datetime.Clock.System.now().toEpochMilliseconds()))
        else oldSeal(from, to, t, "cid-1", true, data, encrypt)

    @Test fun newToNewUsesOneLayerAndBothDirectionsWork() {
        if (!rustCoreTestsEnabled()) return
        val a = User("alice"); val b = User("bob")
        know(a, b, NEW); know(b, a, NEW)
        val sdp = sampleOffer()
        val w = send(a, b, "offer", sdp)
        val (t, d, fmt) = open(b, w, true)
        assertEquals("offer", t); assertEquals(sdp, d); assertEquals("callsig-v2/v3", fmt)
        // The second-layer string arrives byte-for-byte.
        assertEquals(sdp.lines().first { it.startsWith("a=x-umbera-pq:") }, d!!.lines().first { it.startsWith("a=x-umbera-pq:") })
        val ans = sampleAnswer()
        val (t2, d2, f2) = open(a, send(b, a, "answer", ans), true)
        assertEquals("answer", t2); assertEquals(ans, d2); assertTrue(f2.startsWith("callsig-v2/"))
        // Labels without inner-layer encryption (share / reject busy / hangup without data).
        assertEquals("1", open(b, send(a, b, "share", "1", encrypt = false), false).second)
        assertNull(open(b, send(a, b, "hangup", null, encrypt = false), false).second)
    }

    @Test fun mixedPairsUseOldFormatBothWays() {
        if (!rustCoreTestsEnabled()) return
        // New (a) ↔ "old" (o): o does not announce the bit (its switches are as in 2.0.3), a has not seen it.
        val a = User("alice"); val o = User("oscar")
        know(a, o, V3_ONLY); know(o, a, NEW)
        val sdp = sampleOffer()
        val (_, d1, f1) = open(o, send(a, o, "offer", sdp), true)
        assertEquals(sdp, d1); assertTrue(f1.startsWith("v1/"), f1)
        // The old one sends the old format; the new one accepts it.
        SecurityRollout.setAll(false)
        val w = send(o, a, "answer", sampleAnswer())
        SecurityRollout.setAll(true)
        val (_, d2, f2) = open(a, w, true)
        assertEquals(sampleAnswer(), d2); assertTrue(f2.startsWith("v1/"), f2)
    }

    @Test fun bitAnnouncedOnlyWithSwitch() {
        if (!rustCoreTestsEnabled()) return
        val a = User("alice")
        assertTrue(a.enc.wireCaps() and MessageEncryption.WIRE_CAP_CALLSIG_V2 != 0)
        SecurityRollout.callSigV2 = false
        assertEquals(0, a.enc.wireCaps() and MessageEncryption.WIRE_CAP_CALLSIG_V2)
        SecurityRollout.callSigV2 = true
        SecurityRollout.sealV3Accept = false
        assertEquals(0, a.enc.wireCaps() and MessageEncryption.WIRE_CAP_CALLSIG_V2)
    }

    @Test fun switchOffSendsOldFormatToNewPeer() {
        if (!rustCoreTestsEnabled()) return
        val a = User("alice"); val b = User("bob")
        know(a, b, NEW); know(b, a, NEW)
        SecurityRollout.callSigV2 = false
        val (_, d, f) = open(b, send(a, b, "offer", sampleOffer()), true)
        assertEquals(sampleOffer(), d); assertTrue(f.startsWith("v1/v3"), f)
    }

    @Test fun peerDroppingBitFallsBackWithoutKeyChangedFlag() {
        if (!rustCoreTestsEnabled()) return
        val a = User("alice"); val b = User("bob")
        know(a, b, NEW)
        assertTrue(a.enc.canSendCallSigV2("bob", b.ek))
        // Its next message without the bit (switched off / back on a build without the format): old format, no alarm.
        assertEquals(PeerCapsVerdict.OK, a.ks.checkAndPinPeerWireCaps("bob", V3_ONLY, 2))
        a.ks.notePeerWireCaps("bob", V3_ONLY)
        assertFalse(a.ks.isPeerKeyChanged("bob"))
        assertFalse(a.enc.canSendCallSigV2("bob", b.ek))
        // Losing SEAL_V3 is still a downgrade.
        assertEquals(PeerCapsVerdict.DOWNGRADE, a.ks.checkAndPinPeerWireCaps("bob", 0, 3))
        // Only in the last message, without pinning: also not allowed.
        val c = User("carol")
        a.ks.checkAndPinPeerKey("carol", c.secp, c.x); a.ks.savePeerKyber("carol", c.ek)
        a.ks.checkAndPinPeerWireCaps("carol", V3_ONLY, 1); a.ks.notePeerWireCaps("carol", NEW)
        assertFalse(a.enc.canSendCallSigV2("carol", c.ek))
    }

    @Test fun signatureBindsSenderAndRecipient() {
        if (!rustCoreTestsEnabled()) return
        val a = User("alice"); val b = User("bob"); val c = User("carol")
        know(a, b, NEW); know(b, a, NEW); know(c, a, NEW)
        val pkg = a.enc.sealCallSignalV2("bob", b.x, b.ek, "alice", "offer", "cid", false, "sdp", 1L)
        val r = b.enc.openSealedSenderFull(pkg)
        assertNotNull(b.enc.openCallSignalV2(r))
        // Bob forwards a body signed by Alice to Carol (same sender and key, different recipient): rejected.
        assertFails { c.enc.openCallSignalV2(r) }
        // Corrupted blob: rejected.
        val blob = B64.decode(r.encryptedPayload.encryptedData).also { it[5] = (it[5].toInt() xor 1).toByte() }
        assertFails { b.enc.openCallSignalV2(r.copy(encryptedPayload = r.encryptedPayload.copy(encryptedData = B64.encode(blob)))) }
        // Foreign sender key in the envelope (the signature is not theirs): rejected.
        assertFails { b.enc.openCallSignalV2(r.copy(senderSecp256k1PublicKey = c.secp.toHexT())) }
        // Format other than v3/v3s (e.g. v2 outside): rejected.
        assertFails { b.enc.openCallSignalV2(r.copy(sealedVersion = "v2")) }
        assertFails { b.enc.openCallSignalV2(r.copy(sealedVersion = null)) }
    }

    private fun ByteArray.toHexT(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    @Test fun shortEnvelopeAfterAckCarriesSignals() {
        if (!rustCoreTestsEnabled()) return
        val a = User("alice"); val b = User("bob")
        know(a, b, NEW); know(b, a, NEW)
        assertEquals("callsig-v2/v3", open(b, send(a, b, "offer", sampleOffer()), true).third)
        // Bob's reply carries `sa` (pair secret acknowledgement); after it Alice sends short v3s.
        open(a, send(b, a, "answer", sampleAnswer()), true)
        val (_, d, f) = open(b, send(a, b, "ice", ICE), true)
        assertEquals(ICE, d); assertEquals("callsig-v2/v3s", f)
    }

    @Test fun strictUnpack() {
        if (!rustCoreTestsEnabled()) return
        val blob = CallSigV2.pack("""{"t":"offer"}""")
        assertEquals(0, blob.size % CallSigV2.PAD)
        assertEquals("""{"t":"offer"}""", CallSigV2.unpack(blob))
        assertFails { CallSigV2.unpack(blob.copyOf(blob.size - 1)) }
        assertFails { CallSigV2.unpack(blob.copyOf().also { it[it.size - 1] = 7 }) }
        assertFails { CallSigV2.unpack(blob.copyOf().also { it[0] = 2 }) }
        // "Bomb": 1 MB of zeros compresses to ~1 KB; decompression beyond MAX_BODY is rejected.
        assertFails { CallSigV2.unpack(CallSigV2.pack("x".repeat(CallSigV2.MAX_BODY + 1))) }
    }

    /** Measurement: wire size (envelope JSON, before P1 padding) and pack/unpack time, median of 30. */
    @Test fun sizesAndTimingReport() {
        if (!rustCoreTestsEnabled()) return
        val a = User("alice"); val b = User("bob"); val a2 = User("alice2"); val b2 = User("bob2")
        know(a, b, NEW); know(b, a, NEW)
        know(a2, b2, V3_ONLY); know(b2, a2, V3_ONLY)
        val rows = listOf("offer" to sampleOffer(), "answer" to sampleAnswer(), "ice" to ICE)
        println("CALLSIG REPORT | what | SDP, B | old, B | new, B | pack old/new, ms | unpack old/new, ms")
        for ((t, data) in rows) {
            val oldT = ArrayList<Double>(); val newT = ArrayList<Double>(); val oldO = ArrayList<Double>(); val newO = ArrayList<Double>()
            var oldLen = 0; var newLen = 0
            repeat(30) {
                var m = TimeSource.Monotonic.markNow()
                val wo = send(a2, b2, t, data); oldT += m.elapsedNow().inWholeMicroseconds / 1000.0; oldLen = wo.length
                m = TimeSource.Monotonic.markNow()
                val wn = send(a, b, t, data); newT += m.elapsedNow().inWholeMicroseconds / 1000.0; newLen = maxOf(newLen, wn.length)
                m = TimeSource.Monotonic.markNow(); assertEquals(data, open(b2, wo, true).second); oldO += m.elapsedNow().inWholeMicroseconds / 1000.0
                m = TimeSource.Monotonic.markNow(); assertEquals(data, open(b, wn, true).second); newO += m.elapsedNow().inWholeMicroseconds / 1000.0
            }
            fun med(l: List<Double>) = l.sorted()[l.size / 2]
            println("CALLSIG REPORT | $t | ${data.length} | $oldLen | $newLen | ${med(oldT)}/${med(newT)} | ${med(oldO)}/${med(newO)}")
            // SDP: several times smaller (≥ 4×); ICE is small, almost all its weight is the ML-KEM capsule of a full v3 (≥ 2×).
            assertTrue(newLen * (if (t == "ice") 2 else 4) < oldLen, "$t: $newLen vs $oldLen")
        }
    }

    companion object {
        private const val ICE = """{"candidate":"candidate:842163049 1 udp 1677729535 203.0.113.7 54400 typ srflx raddr 0.0.0.0 rport 0 generation 0 ufrag Hk3x network-cost 999","sdpMid":"0","sdpMLineIndex":0}"""

        private val pqOffer = B64.encode(secureRandomBytes(1600))
        private val pqAnswer = B64.encode(secureRandomBytes(1600))

        /** Offer like Android/desktop (Opus + VP8/VP9/H.264/AV1, RTX, FEC) with a second-layer string. */
        fun sampleOffer(): String = sdp(pqOffer, "actpass")
        fun sampleAnswer(): String = sdp(pqAnswer, "active")

        private fun sdp(pq: String, setup: String): String {
            val sb = StringBuilder()
            fun l(s: String) { sb.append(s).append("\r\n") }
            l("v=0"); l("o=- 4611731400430051336 2 IN IP4 127.0.0.1"); l("s=-"); l("t=0 0")
            l("a=group:BUNDLE 0 1"); l("a=extmap-allow-mixed"); l("a=msid-semantic: WMS stream")
            l("a=x-umbera-pq:$pq")
            l("m=audio 9 UDP/TLS/RTP/SAVPF 111 63 9 0 8 13 110 126"); l("c=IN IP4 0.0.0.0"); l("a=rtcp:9 IN IP4 0.0.0.0")
            l("a=ice-ufrag:Hk3x"); l("a=ice-pwd:8f0kQ1v2nJ4bX9pLzq6Rw3Ty"); l("a=ice-options:trickle renomination")
            l("a=fingerprint:sha-256 5C:9A:11:3F:7E:20:B4:61:0D:8E:AF:93:12:6C:4B:D7:E1:52:08:9F:3A:C6:77:B0:2D:E4:15:89:F3:6A:C1:0B")
            l("a=setup:$setup"); l("a=mid:0")
            listOf("urn:ietf:params:rtp-hdrext:ssrc-audio-level", "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
                "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01", "urn:ietf:params:rtp-hdrext:sdes:mid")
                .forEachIndexed { i, u -> l("a=extmap:${i + 1} $u") }
            l("a=sendrecv"); l("a=msid:stream audio0"); l("a=rtcp-mux")
            l("a=rtpmap:111 opus/48000/2"); l("a=rtcp-fb:111 transport-cc"); l("a=fmtp:111 minptime=10;useinbandfec=1")
            l("a=rtpmap:63 red/48000/2"); l("a=fmtp:63 111/111"); l("a=rtpmap:9 G722/8000"); l("a=rtpmap:0 PCMU/8000"); l("a=rtpmap:8 PCMA/8000")
            l("a=rtpmap:13 CN/8000"); l("a=rtpmap:110 telephone-event/48000"); l("a=rtpmap:126 telephone-event/8000")
            l("a=ssrc:3570614608 cname:4TOk42mSjXCkVIa6"); l("a=ssrc:3570614608 msid:stream audio0")
            val vpt = listOf(96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 127, 125, 39, 40, 45, 46, 98, 99, 112, 113, 114, 115, 116)
            l("m=video 9 UDP/TLS/RTP/SAVPF " + vpt.joinToString(" ")); l("c=IN IP4 0.0.0.0"); l("a=rtcp:9 IN IP4 0.0.0.0")
            l("a=ice-ufrag:Hk3x"); l("a=ice-pwd:8f0kQ1v2nJ4bX9pLzq6Rw3Ty"); l("a=ice-options:trickle renomination")
            l("a=fingerprint:sha-256 5C:9A:11:3F:7E:20:B4:61:0D:8E:AF:93:12:6C:4B:D7:E1:52:08:9F:3A:C6:77:B0:2D:E4:15:89:F3:6A:C1:0B")
            l("a=setup:$setup"); l("a=mid:1")
            listOf("urn:ietf:params:rtp-hdrext:toffset", "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time", "urn:3gpp:video-orientation",
                "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01", "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
                "http://www.webrtc.org/experiments/rtp-hdrext/video-content-type", "http://www.webrtc.org/experiments/rtp-hdrext/video-timing",
                "http://www.webrtc.org/experiments/rtp-hdrext/color-space", "urn:ietf:params:rtp-hdrext:sdes:mid",
                "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id")
                .forEachIndexed { i, u -> l("a=extmap:${i + 2} $u") }
            l("a=sendrecv"); l("a=msid:stream video0"); l("a=rtcp-mux"); l("a=rtcp-rsize")
            val codecs = listOf("VP8/90000", "VP9/90000", "H264/90000", "AV1/90000", "H265/90000")
            var pt = 0
            for (c in codecs) repeat(2) { k ->
                val p = vpt[pt++]; val rtx = vpt[pt++]
                l("a=rtpmap:$p $c")
                listOf("goog-remb", "transport-cc", "ccm fir", "nack", "nack pli").forEach { l("a=rtcp-fb:$p $it") }
                if (c.startsWith("H264")) l("a=fmtp:$p level-asymmetry-allowed=1;packetization-mode=${1 - k};profile-level-id=42e01f")
                if (c.startsWith("VP9")) l("a=fmtp:$p profile-id=$k")
                l("a=rtpmap:$rtx rtx/90000"); l("a=fmtp:$rtx apt=$p")
            }
            l("a=rtpmap:112 red/90000"); l("a=rtpmap:113 rtx/90000"); l("a=fmtp:113 apt=112"); l("a=rtpmap:114 ulpfec/90000")
            l("a=ssrc-group:FID 2231627014 632943048")
            listOf(2231627014L, 632943048L).forEach { s -> l("a=ssrc:$s cname:4TOk42mSjXCkVIa6"); l("a=ssrc:$s msid:stream video0") }
            return sb.toString()
        }
    }
}
