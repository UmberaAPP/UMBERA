package app.umbera.core.util

// Cross-platform lock.

expect class SyncLock() {
    fun lock()
    fun unlock()
}

inline fun <T> SyncLock.withLock(block: () -> T): T {
    lock()
    try {
        return block()
    } finally {
        unlock()
    }
}
