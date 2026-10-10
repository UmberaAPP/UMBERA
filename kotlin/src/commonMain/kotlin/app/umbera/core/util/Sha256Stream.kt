package app.umbera.core.util

// Streaming SHA-256.

expect class Sha256Stream() {
    fun update(data: ByteArray)

    fun digest(): ByteArray
}
