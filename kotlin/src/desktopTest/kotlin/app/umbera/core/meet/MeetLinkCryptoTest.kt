package app.umbera.core.meet

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MeetLinkCryptoTest {

    @Test
    fun roomIdIsHundredBitsCrockford() {
        val ids = (1..2000).map { MeetLinks.newRoomId() }.toSet()
        assertEquals(2000, ids.size)
        ids.forEach { assertTrue(MeetLinks.validRoom(it), it) }
        // all 32 alphabet characters occur at every position: no missing bits
        for (pos in 0 until MeetLinks.ROOM_CHARS) assertTrue(ids.map { it[pos] }.toSet().size >= 30, "pos $pos")
    }

    @Test
    fun linkRoundTripAllForms() {
        val l = MeetLink(MeetLinks.newRoomId(), MeetLinks.newKey(), MeetLinks.newPass())
        assertEquals(l, MeetLinks.parse(l.url()))
        assertEquals(l, MeetLinks.parse(l.appUrl()))
        val frag = l.url().substringAfter('#')
        val pretty = MeetLinks.pretty(l.roomId)
        assertEquals(l, MeetLinks.parse("https://www.umbera.app/ru/m/${pretty.lowercase()}#$frag"))
        assertEquals(l, MeetLinks.parse("umbera://m/${l.roomId}/?x=1#$frag"))
        // as it arrives from the website opener on Android: intent://m/<room>%23k%3D…%26p%3D… → umbera://m/…
        val enc = "#$frag".replace("#", "%23").replace("=", "%3D").replace("&", "%26")
        assertEquals(l, MeetLinks.parse("umbera://m/$pretty$enc"))
        // O→0, I/L→1 when typed by hand
        val withO = l.roomId.replace('0', 'O').replace('1', 'l')
        assertEquals(l.roomId, MeetLinks.normalizeRoom(withO))
        val open = MeetLink(l.roomId, l.key)
        assertNull(MeetLinks.parse(open.url())!!.pass)
        assertTrue(!open.url().contains("&p="))
    }

    @Test
    fun badLinksRejectedButStillRecognised() {
        val room = MeetLinks.newRoomId()
        val noKey = "https://umbera.app/m/$room"
        assertNull(MeetLinks.parse(noKey))
        assertTrue(MeetLinks.isMeetLink(noKey)) // do not hand it to the browser/Communities: it is ours, but corrupted
        assertNull(MeetLinks.parse("https://umbera.app/m/$room#k=short"))
        assertNull(MeetLinks.parse("https://umbera.app/c/$room#k=" + "A".repeat(43)))
        assertNull(MeetLinks.parse("https://evil.example/m/$room#k=" + "A".repeat(43)))
        assertTrue(!MeetLinks.isMeetLink("https://umbera.app/j/abc#k=1"))
    }

    @Test
    fun keyNeverInDisplayOrLog() {
        val l = MeetLink(MeetLinks.newRoomId(), MeetLinks.newKey(), MeetLinks.newPass())
        assertTrue(!l.shown().contains("#"))
        assertTrue(!l.toString().contains("k="))
    }

    @Test
    fun findInMessageText() {
        val l = MeetLink(MeetLinks.newRoomId(), MeetLinks.newKey())
        assertEquals(l, MeetLinks.findIn("Конференция «Планёрка»\nВойти по ссылке: ${l.url()}\n"))
        assertNull(MeetLinks.findIn("просто текст https://umbera.app/c/abc"))
    }

    @Test
    fun sealOpenBoundToRoomAndKey() {
        val key = MeetLinks.newKey()
        val k = MeetCrypto.keys(key)
        val room = MeetLinks.newRoomId()
        val body = """{"y":"of","f":"abc","d":"${"v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\n".repeat(80)}"}"""
        val box = MeetCrypto.sealSignal(k, room, body)
        assertEquals(body, MeetCrypto.openSignal(k, room, box))
        // compression: SDP-like text ≥ 3× smaller
        assertTrue(box.size * 3 < body.length, "box ${box.size} vs ${body.length}")
        // different room (AAD), different key, different kind (meta), flipped byte: does not open
        assertNull(MeetCrypto.openSignal(k, MeetLinks.newRoomId(), box))
        assertNull(MeetCrypto.openSignal(MeetCrypto.keys(MeetLinks.newKey()), room, box))
        assertNull(MeetCrypto.openMeta(k, room, box))
        val bad = box.copyOf(); bad[bad.size - 5] = (bad[bad.size - 5].toInt() xor 1).toByte()
        assertNull(MeetCrypto.openSignal(k, room, bad))
        // meta and sig keys differ
        assertNotEquals(k.meta.toList(), k.sig.toList())
        // small signal: size is a multiple of 64 + header (1 + 12 + 16)
        val small = MeetCrypto.sealSignal(k, room, """{"y":"st","f":"a","mi":true}""")
        assertEquals(0, (small.size - 29) % 64)
        assertNotNull(MeetCrypto.openSignal(k, room, small))
    }

    @Test
    fun qrHasLogoHoleWithinLimit() {
        val l = MeetLink(MeetLinks.newRoomId(), MeetLinks.newKey(), MeetLinks.newPass())
        val q = MeetQrCode.build(l.url())
        val area = q.logoModules.toDouble() * q.logoModules / (q.size.toDouble() * q.size)
        assertTrue(area <= 0.20, "logo area $area")
        assertTrue(area >= 0.03, "logo too small to see: $area")
        assertEquals(q.size % 2, q.logoModules % 2)
        val from = (q.size - q.logoModules) / 2
        for (y in from until from + q.logoModules) for (x in from until from + q.logoModules) assertTrue(!q.dark(x, y))
    }
}
