package app.umbera.core.crypto

// Size padding for rendezvous payloads.

object RendezvousPadding {
    private const val TAG = "P1:"

    private val buckets = longArrayOf(1024, 2048, 4096, 8192, 16384)
    private const val stepAbove = 4096L

    private fun bucketFor(len: Long): Long {
        for (b in buckets) if (len <= b) return b

        return ((len + stepAbove - 1) / stepAbove) * stepAbove
    }

    fun pad(payload: String): String {
        val header = TAG + payload.length.toString() + ":"
        val body = header + payload
        val target = bucketFor(body.length.toLong()).toInt()
        if (body.length >= target) return body
        val sb = StringBuilder(target)
        sb.append(body)
        while (sb.length < target) sb.append('.')
        return sb.toString()
    }

    fun unpad(padded: String): String {
        if (!padded.startsWith(TAG)) return padded
        val lenEnd = padded.indexOf(':', TAG.length)
        if (lenEnd < 0) return padded
        val origLen = padded.substring(TAG.length, lenEnd).toIntOrNull() ?: return padded
        val start = lenEnd + 1
        val end = start + origLen
        if (end > padded.length) return padded
        return padded.substring(start, end)
    }
}
