package app.umbera.core.crypto

// Proof-of-work for anonymous rendezvous registration.

import kotlin.random.Random

object RendezvousPow {
    const val DEFAULT_BITS = 15

    fun challenge(rid: String, payload: String): String {
        val ph = Sha256Pure.hash(payload.encodeToByteArray())
        return rid + ":" + ph.toHexLower()
    }

    private fun leadingZeroBits(b: ByteArray): Int {
        var n = 0
        for (x in b) {
            val v = x.toInt() and 0xFF
            if (v == 0) {
                n += 8
                continue
            }
            var mask = 0x80
            while (mask != 0) {
                if (v and mask == 0) n++ else return n
                mask = mask ushr 1
            }
            return n
        }
        return n
    }

    fun verify(rid: String, payload: String, stamp: String, bits: Int): Boolean {
        if (bits <= 0) return true
        val h = Sha256Pure.hash((challenge(rid, payload) + ":" + stamp).encodeToByteArray())
        return leadingZeroBits(h) >= bits
    }

    fun solve(rid: String, payload: String, bits: Int, maxIterations: Long = 1L shl 26): String? {
        if (bits <= 0) return "0"
        val ch = challenge(rid, payload)

        val start = Random.nextLong(0L, 1L shl 40)
        var i = 0L
        while (i < maxIterations) {
            val s = (start + i).toString()
            val h = Sha256Pure.hash((ch + ":" + s).encodeToByteArray())
            if (leadingZeroBits(h) >= bits) return s
            i++
        }
        return null
    }

    private fun ByteArray.toHexLower(): String =
        joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
}
