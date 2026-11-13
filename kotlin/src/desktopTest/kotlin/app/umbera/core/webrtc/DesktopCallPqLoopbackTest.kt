package app.umbera.core.webrtc

import app.umbera.core.config.AppSettingsCommon
import app.umbera.core.stash.MemoryKv
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The second, post-quantum call layer on real desktop WebRTC: X25519 + ML-KEM-1024 exchange via a line in the SDP,
 * audio and video frames are encrypted in FrameCryptor format, video arrives and decodes; with a wrong key frames
 * are dropped (the layer really is in the path); an "old version" peer (does not understand the line, answers without it)
 * connects as before, without the second layer; the conference branch has its own exchange. Plus an encryption latency measurement.
 */
class DesktopCallPqLoopbackTest {
    init {
        System.setProperty("umbera.call.audio", "headless")
        System.setProperty("umbera.call.camera", "pattern")
    }

    private fun settings() = AppSettingsCommon(MemoryKv())

    private enum class Peer { NEW, OLD, WRONG_KEY }

    /** A is always the new version; [bKind] — who is on the other side. Returns A's and B's counters and A's last frame number. */
    private fun oneToOne(bKind: Peer): Triple<LongArray?, LongArray?, Long> = runBlocking {
        val a = DesktopCallMediaEngine(settings())
        val b = DesktopCallMediaEngine(settings())
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        val negA = CallFrameE2ee.Negotiation("call-pq-test")
        try {
            a.initialize(); b.initialize()
            a.createPeerConnection(emptyList(), relayOnly = false)
            b.createPeerConnection(emptyList(), relayOnly = false)
            scope.launch { a.localIceCandidates.collect { b.addIceCandidate(it.candidate, it.sdpMid, it.sdpMLineIndex) } }
            scope.launch { b.localIceCandidates.collect { a.addIceCandidate(it.candidate, it.sdpMid, it.sdpMLineIndex) } }
            var bAnswerBlob: ByteArray? = null
            scope.launch {
                a.localSdp.collect { local ->
                    val wire = CallFrameE2ee.attach(local.description, negA.offer())
                    when (bKind) {
                        // Old version: does not understand the line and passes the SDP to WebRTC as is.
                        Peer.OLD -> b.setRemoteDescription(CallMediaEngine.SdpType.OFFER, wire)
                        else -> {
                            val negB = CallFrameE2ee.Negotiation("call-pq-test")
                            bAnswerBlob = negB.onOffer(assertNotNull(CallFrameE2ee.extract(wire)))
                            val k = assertNotNull(negB.keys)
                            if (bKind == Peer.WRONG_KEY) b.setFrameKeys(k.send, ByteArray(32) { 7 }) else b.setFrameKeys(k.send, k.recv)
                            b.setRemoteDescription(CallMediaEngine.SdpType.OFFER, CallFrameE2ee.strip(wire))
                        }
                    }
                    b.createAnswer()
                }
            }
            scope.launch {
                b.localSdp.collect { local ->
                    val wire = bAnswerBlob?.let { CallFrameE2ee.attach(local.description, it) } ?: local.description
                    negA.onAnswer(CallFrameE2ee.extract(wire))?.let { a.setFrameKeys(it.send, it.recv) }
                    a.setRemoteDescription(CallMediaEngine.SdpType.ANSWER, CallFrameE2ee.strip(wire))
                }
            }
            a.startLocalVideo(true)
            b.startLocalVideo(true)
            a.createOffer()
            withTimeout(20_000) {
                a.connectionState.first { it == CallMediaEngine.ConnectionState.CONNECTED }
                b.connectionState.first { it == CallMediaEngine.ConnectionState.CONNECTED }
            }
            // Frames at A come from B (B encrypts frames with its send key, A opens them with its receive key).
            val seq = withTimeoutOrNull(12_000) { DesktopVideoTracks.frames(DesktopVideoTracks.REMOTE).first { it != null && it.seq > 5 } }?.seq ?: 0L
            delay(1500)
            Triple(a.frameCryptoStats(), b.frameCryptoStats(), seq)
        } finally {
            scope.cancel()
            a.dispose(); b.dispose()
        }
    }

    @Test
    fun oneToOneFramesTravelThroughTheMlKemLayer() {
        val (a, b, seq) = oneToOne(Peer.NEW)
        assertNotNull(a); assertNotNull(b)
        assertTrue(seq > 5, "B's video decoded at A")
        assertTrue(a[0] > 5 && a[1] > 5, "A encrypts and opens frames: ${a.toList()}")
        assertTrue(b[0] > 5 && b[1] > 5, "B encrypts and opens frames: ${b.toList()}")
        assertEquals(0L, a[2], "nothing dropped at A")
        val perFrameUs = a[3] / 1000.0 / (a[0] + a[1])
        println("Desktop PQ layer: A frames out=${a[0]} in=${a[1]}, encrypt+decrypt average ${"%.1f".format(perFrameUs)} µs per frame")
        assertTrue(perFrameUs < 2000.0)
    }

    @Test
    fun wrongKeyDropsFramesSoTheLayerIsReallyInThePath() {
        val (a, b, _) = oneToOne(Peer.WRONG_KEY)
        assertNotNull(a); assertNotNull(b)
        // B opens A's frames with the wrong key — everything is dropped, nothing reaches the decoder.
        assertTrue(b[2] > 5 && b[1] == 0L, "B: ${b.toList()}")
    }

    @Test
    fun oldPeerWithoutTheLayerStillConnects() {
        val (a, b, seq) = oneToOne(Peer.OLD)
        assertNull(a, "answer without the line — A has the second layer off")
        assertNull(b)
        assertTrue(seq > 5, "a call with an old version works as before (WebRTC ignored the line in the offer)")
    }

    @Test
    fun conferenceLegUsesItsOwnExchange() = runBlocking {
        val a = DesktopConferenceMediaEngine(settings())
        val b = DesktopConferenceMediaEngine(settings())
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        val negA = CallFrameE2ee.Negotiation("conf:pq:A:B")
        var answerB: ByteArray? = null
        try {
            a.start(emptyList(), video = true, relayOnly = false)
            b.start(emptyList(), video = true, relayOnly = false)
            scope.launch {
                a.outboundSdp.collect {
                    if (it.isOffer) {
                        val wire = if (!a.peerFrameKeysActive("B")) CallFrameE2ee.attach(it.description, negA.offer()) else it.description
                        CallFrameE2ee.extract(wire)?.let { blob ->
                            val negB = CallFrameE2ee.Negotiation("conf:pq:A:B")
                            answerB = negB.onOffer(blob)
                            negB.keys?.let { k -> b.setPeerFrameKeys("A", k.send, k.recv) }
                        }
                        b.handleRemoteOffer("A", CallFrameE2ee.strip(wire))
                    } else b.handleRemoteAnswer("A", it.description)
                }
            }
            scope.launch {
                b.outboundSdp.collect {
                    if (it.isOffer) a.handleRemoteOffer("B", it.description)
                    else {
                        val wire = answerB?.let { x -> CallFrameE2ee.attach(it.description, x).also { answerB = null } } ?: it.description
                        if (negA.awaitingAnswer()) negA.onAnswer(CallFrameE2ee.extract(wire))?.let { k -> a.setPeerFrameKeys("B", k.send, k.recv) }
                        a.handleRemoteAnswer("B", CallFrameE2ee.strip(wire))
                    }
                }
            }
            scope.launch { a.outboundIce.collect { b.handleRemoteIce("A", it.sdpMid ?: "0", it.sdpMLineIndex, it.candidate) } }
            scope.launch { b.outboundIce.collect { a.handleRemoteIce("B", it.sdpMid ?: "0", it.sdpMLineIndex, it.candidate) } }
            a.addPeer("B", initiator = true)
            withTimeout(20_000) {
                while (a.connectedPeerIds() != setOf("B") || b.connectedPeerIds() != setOf("A")) delay(100)
            }
            withTimeout(20_000) { while ((a.peerVideoFrames()["B"] ?: 0L) < 5) delay(200) }
            val sa = assertNotNull(a.frameCryptoStats("B")); val sb = assertNotNull(b.frameCryptoStats("A"))
            assertTrue(sa[1] > 3 && sb[1] > 3 && sa[2] == 0L && sb[2] == 0L, "A ${sa.toList()} B ${sb.toList()}")
        } finally {
            scope.cancel()
            a.stop(); b.stop()
        }
    }

    @Test
    fun formatHelpersMatchWebrtc() {
        // PBKDF2-HMAC-SHA256, RFC 7914 §11 vector (P="passwd", S="salt", c=1).
        val dk = PcFrameCryptor.pbkdf2("passwd".encodeToByteArray(), "salt".encodeToByteArray(), 1, 64)
        assertEquals("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
            dk.joinToString("") { "%02x".format(it) })
        // RBSP: after two zeros before a byte ≤ 3 — 0x03; reverse — unchanged.
        val raw = byteArrayOf(0, 0, 1, 5, 0, 0, 0, 0, 3, 0, 0, 2, 9)
        val out = ByteArrayOutputStream().also { PcFrameCryptor.writeRbsp(raw, it) }.toByteArray()
        assertContentEquals(byteArrayOf(0, 0, 3, 1, 5, 0, 0, 3, 0, 0, 3, 3, 0, 0, 3, 2, 9), out)
        assertTrue(PcFrameCryptor.needsRbspUnescaping(out))
        assertContentEquals(raw, PcFrameCryptor.parseRbsp(out))
        // H.264: SPS (7), PPS (8), then IDR (5) — the clear part up to the second slice byte.
        val h264 = byteArrayOf(0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x68, 3, 0, 0, 0, 1, 0x65, 9, 9, 9, 9)
        assertEquals(listOf(4, 10, 16), PcFrameCryptor.naluStarts(h264))
        assertEquals(18, PcFrameCryptor.h264Unencrypted(h264))
        // SDP: the line goes before the first m= and is removed without a trace.
        val sdp = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\n"
        val withPq = CallFrameE2ee.attach(sdp, byteArrayOf(1, 2, 3))
        assertTrue(withPq.indexOf(CallFrameE2ee.ATTR) < withPq.indexOf("m=audio"))
        assertContentEquals(byteArrayOf(1, 2, 3), CallFrameE2ee.extract(withPq))
        assertEquals(sdp, CallFrameE2ee.strip(withPq))
    }
}
