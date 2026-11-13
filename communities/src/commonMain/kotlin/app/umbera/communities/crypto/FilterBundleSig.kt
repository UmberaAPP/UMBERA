package app.umbera.communities.crypto

/**
 * Signature of the filter rules bundle (/v1/filters/bundle) and transparency log lines (/v1/filters/log) —
 * hybrid, like everything in Communities: ed25519 (signature / sig) AND ML-DSA-65 (pq_signature / pq_sig) over the same
 * bytes; both are required. Public keys — public_key and pq_public_key from /v1/filters/log; the phone
 * pins key_id = hex(sha256(ed25519_pub ‖ ml-dsa-65_pub))[:16] (LocalStore.pinnedBundleKey).
 */
object FilterBundleSig {
    fun keyId(edPub: ByteArray, pqPub: ByteArray): String = CommCrypto.hex(CommCrypto.sha256(edPub + pqPub)).substring(0, 16)

    /** Bundle: signatures over the bytes of the bundle field as received. */
    fun verifyBundle(edPub: ByteArray, pqPub: ByteArray, bundle: ByteArray, edSig: ByteArray, pqSig: ByteArray): Boolean =
        CommCrypto.verifyHybrid(edPub, pqPub, bundle, edSig, pqSig)

    /** Log line: signatures over "UMBERA-COMM-FILTER-LOG-v2:<version>:<sha256>:<prev>". */
    fun verifyLogEntry(edPub: ByteArray, pqPub: ByteArray, version: Long, sha256: String, prev: String, edSig: ByteArray, pqSig: ByteArray): Boolean =
        CommCrypto.verifyHybrid(edPub, pqPub, "UMBERA-COMM-FILTER-LOG-v2:$version:$sha256:$prev".encodeToByteArray(), edSig, pqSig)
}
