package app.umbera.core.crypto

import app.umbera.core.util.B64
import app.umbera.core.util.WireJson
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * RECOVERY PHRASE AND PRIVATE KEY (2026-10-16) — like a crypto wallet.
 *
 * - Phrase: 12 BIP-39 words (128 bits of entropy + checksum), generated ONLY on the
 *   device from the system CSPRNG. All four account keys are derived deterministically
 *   from the entropy (HKDF-SHA256, a separate context for each): secp256k1, X25519,
 *   ML-KEM-1024 (64-byte seed), ML-DSA-65 (32-byte seed). The same phrase always gives
 *   the same keys — therefore the same account on the server (keys = identity).
 * - Private key: the string `UMBERA-KEY-1.<base64url>` — all four private keys in full.
 *   Needed for accounts created BEFORE the phrase (their keys are random and cannot be
 *   derived from a phrase), and as a second way to sign in for new ones.
 * - Recovery file: plain JSON (no password — a product decision, so people don't lose
 *   access by forgetting it) with the phrase (if any) and the private key. Whoever has
 *   the file owns the account.
 *
 * The server sees none of this: only public keys and a signature leave the device.
 */
object RecoverySeed {
    private const val ENTROPY_BYTES = 16
    private const val SALT = "umbera-recovery-seed-v1"
    const val KEY_PREFIX = "UMBERA-KEY-1."
    const val FILE_VERSION = "umbera-recovery-v1"

    /** All four private keys (seed form for the PQ ones) + their public halves. */
    class Identity(
        val secp256k1Private: ByteArray,
        val x25519Private: ByteArray,
        val kyberSeed: ByteArray,
        val dilithiumSeed: ByteArray,
    ) {
        val secp256k1Public: ByteArray get() = Secp256k1.getPublicKey(secp256k1Private)
        val x25519Public: ByteArray get() = X25519.getPublicKey(x25519Private)
        val kyberPublic: ByteArray get() = RustCore.mlkem1024PublicKey(kyberSeed)
        val dilithiumPublic: ByteArray get() = RustCore.mldsa65PublicKey(dilithiumSeed)
    }

    // ── phrase ───────────────────────────────────────────────────────────────

    /** A new 12-word phrase — only from the device's system random number generator. */
    fun generateWords(): String = wordsFromEntropy(secureRandomBytes(ENTROPY_BYTES))

    /** Parse a phrase: null if a word is not in the wordlist, the count is not 12/24, or the checksum fails. */
    fun entropyFromWords(phrase: String): ByteArray? {
        val words = phrase.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
        if (words.size != 12 && words.size != 24) return null
        val list = Bip39Words.list
        val indexes = words.map { w -> list.indexOf(w).also { if (it < 0) return null } }
        val bits = StringBuilder()
        indexes.forEach { bits.append(it.toString(2).padStart(11, '0')) }
        val entBits = words.size * 11 * 32 / 33
        val csBits = entBits / 32
        val entropy = ByteArray(entBits / 8) { i -> bits.substring(i * 8, i * 8 + 8).toInt(2).toByte() }
        val expected = checksumBits(entropy, csBits)
        if (bits.substring(entBits, entBits + csBits) != expected) return null
        return entropy
    }

    fun isValidPhrase(phrase: String): Boolean = entropyFromWords(phrase) != null

    private fun wordsFromEntropy(entropy: ByteArray): String {
        val csBits = entropy.size * 8 / 32
        val bits = StringBuilder()
        entropy.forEach { b -> bits.append((b.toInt() and 0xFF).toString(2).padStart(8, '0')) }
        bits.append(checksumBits(entropy, csBits))
        val list = Bip39Words.list
        return (0 until bits.length / 11).joinToString(" ") { i ->
            list[bits.substring(i * 11, i * 11 + 11).toInt(2)]
        }
    }

    private fun checksumBits(entropy: ByteArray, csBits: Int): String {
        val h = RustCore.sha256(entropy)
        val sb = StringBuilder()
        h.forEach { b -> sb.append((b.toInt() and 0xFF).toString(2).padStart(8, '0')) }
        return sb.substring(0, csBits)
    }

    // ── keys from the phrase ─────────────────────────────────────────────────

    /** Deterministic derivation of all four keys from the phrase entropy. */
    fun identityFromEntropy(entropy: ByteArray): Identity {
        val salt = SALT.encodeToByteArray()
        fun derive(info: String, len: Int) = RustCore.hkdfSha256(entropy, salt, info.encodeToByteArray(), len.toUInt())
        // secp256k1: the scalar must be within the group order (miss probability ~2^-128) —
        // on a miss, use the next context.
        var secp: ByteArray? = null
        var n = 0
        while (secp == null) {
            val cand = derive(if (n == 0) "secp256k1" else "secp256k1/$n", 32)
            secp = try { Secp256k1.getPublicKey(cand); cand } catch (_: RustCoreException) { null }
            n++
        }
        return Identity(
            secp256k1Private = secp,
            x25519Private = derive("x25519", 32),
            kyberSeed = derive("mlkem1024", Kyber1024.PRIVATE_KEY_SIZE),
            dilithiumSeed = derive("mldsa65", Dilithium3.PRIVATE_KEY_SIZE),
        )
    }

    fun identityFromWords(phrase: String): Identity? = entropyFromWords(phrase)?.let { identityFromEntropy(it) }

    // ── private key as a string ──────────────────────────────────────────────

    @Serializable
    private data class KeyBundle(
        @SerialName("s") val secp: String,
        @SerialName("x") val x25519: String,
        @SerialName("k") val kyber: String,
        @SerialName("d") val dilithium: String,
    )

    fun identityToKeyString(id: Identity): String =
        KEY_PREFIX + B64.encodeUrlNoPad(
            WireJson.json.encodeToString(
                KeyBundle(B64.encode(id.secp256k1Private), B64.encode(id.x25519Private), B64.encode(id.kyberSeed), B64.encode(id.dilithiumSeed))
            ).encodeToByteArray()
        )

    fun identityFromKeyString(key: String): Identity? = runCatching {
        val raw = key.trim()
        if (!raw.startsWith(KEY_PREFIX)) return null
        val json = B64.decodeUrlNoPad(raw.removePrefix(KEY_PREFIX)).decodeToString()
        val b = WireJson.json.decodeFromString<KeyBundle>(json)
        val id = Identity(B64.decode(b.secp), B64.decode(b.x25519), B64.decode(b.kyber), B64.decode(b.dilithium))
        require(id.secp256k1Private.size == 32 && id.x25519Private.size == 32)
        require(id.kyberSeed.size == Kyber1024.PRIVATE_KEY_SIZE && id.dilithiumSeed.size == Dilithium3.PRIVATE_KEY_SIZE)
        id
    }.getOrNull()

    // ── recovery file (plain JSON) ───────────────────────────────────────────

    @Serializable
    data class RecoveryFile(
        @SerialName("format") val format: String = FILE_VERSION,
        @SerialName("app") val app: String = "Umbera",
        @SerialName("warning") val warning: String =
            "Anyone who has this file owns the account. Keep it in a safe place.",
        @SerialName("seed_phrase") val seedPhrase: String? = null,
        @SerialName("private_key") val privateKey: String,
        @SerialName("nickname") val nickname: String? = null,
        @SerialName("user_id") val userId: String? = null,
        @SerialName("quant_address") val quantAddress: String? = null,
        @SerialName("created") val created: String? = null,
    )

    fun fileToJson(f: RecoveryFile): String = WireJson.json.encodeToString(f)

    /** Parse a recovery file; null if it is not ours. */
    fun fileFromJson(text: String): RecoveryFile? = runCatching {
        val f = WireJson.json.decodeFromString<RecoveryFile>(text.trim())
        if (f.format != FILE_VERSION) null else f
    }.getOrNull()

    /** The message signed for key login (the server builds the same one). */
    fun loginMessage(nonce: String): ByteArray = "umbera-key-login-v1|$nonce".encodeToByteArray()
}
