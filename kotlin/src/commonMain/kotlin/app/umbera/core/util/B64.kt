package app.umbera.core.util

// Base64 helpers.

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalEncodingApi::class)
object B64 {
    private val urlNoPad = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
    private val urlDecodeAny = Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT_OPTIONAL)

    fun encode(bytes: ByteArray): String = Base64.Default.encode(bytes)

    fun decode(s: String): ByteArray {
        val clean = if (s.indexOf('\n') >= 0 || s.indexOf('\r') >= 0) {
            s.filter { it != '\n' && it != '\r' }
        } else s
        return Base64.Default.decode(clean)
    }

    fun decodeLenient(s: String): ByteArray = Base64.Mime.decode(s)

    fun encodeUrlNoPad(bytes: ByteArray): String = urlNoPad.encode(bytes)

    fun decodeUrlNoPad(s: String): ByteArray = urlDecodeAny.decode(s)
}
