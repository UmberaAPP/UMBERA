package app.umbera.core.meet

import app.umbera.core.crypto.secureRandomBytes
import app.umbera.core.util.B64
import kotlinx.coroutines.flow.MutableStateFlow

/**
 * Meeting link: `https://umbera.app/m/<room>#k=<key>[&p=<pass>]`, also `umbera://m/…`.
 *
 * - room: 20 Crockford base32 characters (100 bits of randomness), groups of 4 separated by "-" for readability;
 *   parsing ignores case, "-", and maps I/L→1 and O→0;
 * - key: 32 bytes base64url without "=", only in the fragment after "#" (the browser never sends it);
 * - pass: 16 bytes base64url, only for a closed meeting and only in an added person's personal link.
 */
class MeetLink(val roomId: String, val key: ByteArray, val pass: ByteArray? = null) {
    init {
        require(MeetLinks.validRoom(roomId)) { "room" }
        require(key.size == MeetLinks.KEY_BYTES) { "key" }
        require(pass == null || pass.size == MeetLinks.PASS_BYTES) { "pass" }
    }

    private fun fragment() = "k=" + B64.encodeUrlNoPad(key) + (pass?.let { "&p=" + B64.encodeUrlNoPad(it) } ?: "")

    /** For "Share", QR and messages. */
    fun url(): String = "https://${MeetLinks.HOST}/m/${MeetLinks.pretty(roomId)}#${fragment()}"

    /** For the opener on desktop/iOS (the app scheme). */
    fun appUrl(): String = "umbera://m/${MeetLinks.pretty(roomId)}#${fragment()}"

    /** Without the key: what may be shown in the UI (like "umbera.app/m/7KQ2-…"). */
    fun shown(): String = "${MeetLinks.HOST}/m/${MeetLinks.pretty(roomId)}"

    fun withPass(p: ByteArray?) = MeetLink(roomId, key, p)

    override fun equals(other: Any?) = other is MeetLink && other.roomId == roomId && other.key.contentEquals(key) &&
        ((other.pass == null && pass == null) || (other.pass != null && pass != null && other.pass.contentEquals(pass)))
    override fun hashCode() = roomId.hashCode()
    override fun toString() = "MeetLink(${shown()})" // key and pass never reach logs
}

object MeetLinks {
    const val HOST = "umbera.app"
    const val KEY_BYTES = 32
    const val PASS_BYTES = 16
    const val ROOM_CHARS = 20
    private const val ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" // Crockford

    /**
     * Link the app was opened with (system, browser, QR, tap in a chat). Set by the platform entry points
     * (Android UnifiedActivity, iOS umberaOpenCommunityLink, desktop PcLinks.open); the shared UI opens
     * the pending meeting and clears it.
     */
    val pending = MutableStateFlow<MeetLink?>(null)

    /** Put the link into [pending] if it is a meeting link. true means consumed (do not parse it further). */
    fun offer(raw: String?): Boolean {
        val l = parse(raw ?: return false) ?: return isMeetLink(raw) // looks like one but is corrupted: do not hand it to the browser/Communities
        // Log only the start of the room id, without the key and pass.
        app.umbera.core.util.Log.i("Meet", "link opened: room ${l.roomId.take(4)}…")
        pending.value = l
        return true
    }

    fun newRoomId(): String {
        val r = secureRandomBytes(13) // 104 bits, we take 100
        val sb = StringBuilder()
        var acc = 0; var bits = 0
        for (b in r) {
            acc = (acc shl 8) or (b.toInt() and 0xFF); bits += 8
            while (bits >= 5 && sb.length < ROOM_CHARS) { bits -= 5; sb.append(ALPHABET[(acc shr bits) and 31]) }
        }
        return sb.toString()
    }

    fun newKey(): ByteArray = secureRandomBytes(KEY_BYTES)

    /**
     * New link whose QR always scans: the code uses a mask without false "finder patterns" ([MeetQrCode.clean]).
     * All links are created this way (creation, new link), usually on the first attempt.
     */
    fun newScannableLink(): MeetLink {
        repeat(64) {
            val l = MeetLink(newRoomId(), newKey())
            if (MeetQrCode.clean(l.url())) return l
        }
        return MeetLink(newRoomId(), newKey())
    }

    /** Personal pass for link [base] whose QR always scans (like [newScannableLink]). */
    fun newScannablePass(base: MeetLink): ByteArray {
        repeat(64) {
            val p = newPass()
            if (MeetQrCode.clean(base.withPass(p).url())) return p
        }
        return newPass()
    }
    fun newPass(): ByteArray = secureRandomBytes(PASS_BYTES)

    fun validRoom(id: String) = id.length == ROOM_CHARS && id.all { it in ALPHABET }

    fun pretty(id: String) = id.chunked(4).joinToString("-")

    /** Normalize typed input to a room id: no "-", upper case, I/L→1, O→0. null if not a room. */
    fun normalizeRoom(s: String): String? {
        val t = s.uppercase().filter { it != '-' }.map { when (it) { 'I', 'L' -> '1'; 'O' -> '0'; else -> it } }.joinToString("")
        return t.takeIf { validRoom(it) }
    }

    /** Whether the string looks like a meeting link (for routing, even if the key is corrupted). */
    fun isMeetLink(raw: String): Boolean = pathOf(raw) != null

    private fun pathOf(raw: String): Pair<String, String>? {
        var t = raw.trim()
        // Website opener on Android (intent://m/<room>%23k%3D…): "#" is taken by the intent, so the fragment travels encoded in the path.
        if ('#' !in t && t.contains("%23", ignoreCase = true)) {
            t = t.replace("%23", "#", true).replace("%3D", "=", true).replace("%26", "&", true)
        }
        val rest = listOf("https://$HOST/", "https://www.$HOST/", "umbera://", "http://$HOST/")
            .firstOrNull { t.startsWith(it, ignoreCase = true) }?.let { t.substring(it.length) } ?: return null
        val noLang = rest.removePrefix("ru/").removePrefix("de/").removePrefix("it/").removePrefix("en/")
        if (!noLang.startsWith("m/", ignoreCase = true)) return null
        val body = noLang.substring(2)
        val path = body.substringBefore('#').substringBefore('?').trimEnd('/')
        val frag = if ('#' in body) body.substringAfter('#') else ""
        return path to frag
    }

    /** Parse a link. null if it is not a meeting link or the key is missing/corrupted. */
    fun parse(raw: String): MeetLink? {
        val (path, frag) = pathOf(raw) ?: return null
        val room = normalizeRoom(path) ?: return null
        val params = frag.split('&').mapNotNull { p -> p.split('=', limit = 2).takeIf { it.size == 2 }?.let { it[0] to it[1] } }.toMap()
        val key = params["k"]?.let { runCatching { B64.decodeUrlNoPad(it) }.getOrNull() }?.takeIf { it.size == KEY_BYTES } ?: return null
        val pass = params["p"]?.let { runCatching { B64.decodeUrlNoPad(it) }.getOrNull() }?.takeIf { it.size == PASS_BYTES }
        return MeetLink(room, key, pass)
    }

    /** Meeting links in message text (invitation card in newer versions). */
    fun findIn(text: String): MeetLink? =
        Regex("""(https://(www\.)?umbera\.app/m/[0-9A-Za-z-]+#[A-Za-z0-9_=&-]+)""").find(text)?.value?.let(::parse)
}
