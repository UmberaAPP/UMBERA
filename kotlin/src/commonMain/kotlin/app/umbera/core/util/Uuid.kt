package app.umbera.core.util

// Random UUID v4.

import app.umbera.core.crypto.secureRandomBytes

fun randomUuid4(): String {
    val b = secureRandomBytes(16)
    b[6] = ((b[6].toInt() and 0x0F) or 0x40).toByte()
    b[8] = ((b[8].toInt() and 0x3F) or 0x80).toByte()
    val hex = b.joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}"
}
