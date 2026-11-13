package app.umbera.core.crypto

/**
 * Platform-neutral facade over the shared Rust MLS group engine + AMF message
 * franking (core: MlsClient object, amf_* functions).
 *
 * Mirrors the UniFFI-generated Kotlin surface (uniffi.umbera_core.MlsClient /
 * amf*) 1:1 so call sites migrate mechanically:
 *  - Android actual delegates to the UniFFI JNA bindings, unchanged from the
 *    pre-KMP wiring (byte-identical output).
 *  - iOS actual hand-lowers/lifts the UniFFI C scaffolding through cinterop
 *    against libumbera_core.a, following the same RustBuffer ABI RustCore.ios.kt
 *    established for the primitives (contract version + per-function API
 *    checksums verified at first use).
 *
 * All functions are PLAIN BLOCKING, exactly like the UniFFI binding — callers
 * (e.g. an MlsManager port) own dispatch/serialization (Android's MlsManager
 * wraps every call in a Mutex on a coroutine).
 *
 * Errors: MlsError/AmfError from Rust (and Rust panics) surface as
 * [RustCoreException] on BOTH platforms, with the same message text.
 */
expect class MlsEngine {

    /** Brand-new identity. `identity` = our stable per-group leaf id bytes (memberId). */
    constructor(identity: ByteArray)

    /** Serialize the whole identity+groups for our SQLCipher store. */
    fun exportState(): ByteArray

    /** Our Ed25519 signature public key (identifies our leaf to peers). */
    fun signaturePublicKey(): ByteArray

    /** Produce a fresh KeyPackage (serialized) to hand to whoever will add us to a group. */
    fun generateKeyPackage(): ByteArray

    /**
     * Create a new group with our chosen 32-byte group id (`gid`). We become the
     * single initial member (admin handled at the app layer, not by MLS).
     */
    fun createGroup(gid: ByteArray)

    /**
     * Add members by their serialized KeyPackages → returns Commit (for existing
     * members) + Welcome (for the new ones). We merge our own commit immediately.
     */
    fun addMembers(gid: ByteArray, keyPackages: List<ByteArray>): MlsCommitBundle

    /** Remove members by leaf index → Commit to fan out. We merge our own commit. */
    fun removeMembers(gid: ByteArray, leafIndices: List<UInt>): ByteArray

    /** Plain rekey (post-compromise security) with no membership change → Commit. */
    fun updateKeys(gid: ByteArray): ByteArray

    /** Join a group from a Welcome we received → returns the group id we joined. */
    fun processWelcome(welcomeBytes: ByteArray): ByteArray

    /** Encrypt an application payload (chat message / control) for the group. */
    fun encrypt(gid: ByteArray, plaintext: ByteArray): ByteArray

    /**
     * Feed an inbound MLS message to a group: decrypts application payloads and
     * applies membership Commits. Classifies the outcome.
     */
    fun processIncoming(gid: ByteArray, message: ByteArray): MlsIncoming

    /**
     * [processIncoming] plus the sender's leaf (verified by OpenMLS). If [allowedHandshakeSenders] is set,
     * a Commit/Proposal is accepted only from a leaf with those credentials (memberId); otherwise the Commit is not merged
     * ([MlsIncoming.CommitRejected], epoch unchanged) and a Proposal yields [MlsIncoming.Ignored]. null — no check.
     */
    fun processIncomingWithSender(gid: ByteArray, message: ByteArray, allowedHandshakeSenders: List<ByteArray>?): MlsIncomingWithSender

    /**
     * Derive a fresh symmetric secret bound to the current epoch (e.g. a conference
     * media key). Rotates automatically every time the group rekeys.
     */
    fun exportSecret(gid: ByteArray, label: String, length: UInt): ByteArray

    /** Current epoch number (advances on every membership change / rekey). */
    fun epoch(gid: ByteArray): ULong

    /** Member identities (leaf credential bytes = memberIds) + their leaf indices. */
    fun members(gid: ByteArray): List<MlsMemberInfo>

    /**
     * Linked devices: sign the "sibling" link (phone leaf ↔ desktop leaf in group
     * [gid]) with our own leaf key. Our memberId is one of the two.
     */
    fun siblingSign(gid: ByteArray, primaryMemberId: ByteArray, deviceMemberId: ByteArray): ByteArray

    /**
     * How many MLS leaves the group may currently have: 100 if all members are on the new core,
     * otherwise 20 (phones on the old core would reject a Commit with a 21st leaf). Add a desktop to the group
     * only if it fits within this limit. The app counts "20 people" by people.
     */
    fun leafLimit(gid: ByteArray): UInt

    /** Whether our leaf carries the new-core marker; if not, call [updateKeys] and send the Commit. */
    fun ownLeafMarked(gid: ByteArray): Boolean

    /**
     * X-Wing: a KeyPackage in ciphersuite [suite] ([MlsSuites.LEGACY] or [MlsSuites.XWING]).
     * The same leaf (memberId, signature key) issues packages for both suites.
     */
    fun generateKeyPackageFor(suite: UShort): ByteArray

    /** The same leaf (memberId and signature key), without groups — for migrating a group to another suite. */
    fun spawnSameIdentity(): MlsEngine

    /** New group in ciphersuite [suite]. */
    fun createGroupFor(gid: ByteArray, suite: UShort)

    /** The group's ciphersuite (RFC 9420 code). */
    fun groupCiphersuite(gid: ByteArray): UShort

    /** All group leaves support [suite] (for X-Wing — the new-core marker on every leaf). */
    fun membersSupport(gid: ByteArray, suite: UShort): Boolean

    /** Verify the link against the leaf keys of the group's current tree (both signatures). */
    fun siblingVerify(
        gid: ByteArray,
        primaryMemberId: ByteArray,
        deviceMemberId: ByteArray,
        primarySig: ByteArray,
        deviceSig: ByteArray,
    ): Boolean

    /**
     * Release the underlying Rust Arc handle. Further calls throw
     * IllegalStateException (same semantics as the UniFFI binding's destroy()).
     * Safe to call more than once. A GC-driven cleaner also frees the handle if
     * close() is never called.
     */
    fun close()

    companion object {
        /** Restore from a previously exported state blob (see [exportState]). */
        fun fromState(blob: ByteArray): MlsEngine
    }
}

/** Mirrors uniffi.umbera_core.CommitBundle. */
class MlsCommitBundle(
    val commit: ByteArray,
    val welcome: ByteArray,
)

/** Mirrors uniffi.umbera_core.SenderLeaf: the sender leaf of an incoming frame. */
class MlsSenderLeaf(
    val leafIndex: UInt,
    val identity: ByteArray,
)

/** Mirrors uniffi.umbera_core.IncomingWithSender. */
class MlsIncomingWithSender(
    val incoming: MlsIncoming,
    val sender: MlsSenderLeaf?,
)

/** Mirrors uniffi.umbera_core.MemberInfo. */
class MlsMemberInfo(
    val leafIndex: UInt,
    val identity: ByteArray,
)

/**
 * Classified result of feeding an inbound MLS message to the group.
 * Mirrors uniffi.umbera_core.Incoming (Rust enum `Incoming`) variant-for-variant.
 */
sealed class MlsIncoming {
    /**
     * A decrypted application payload (a real chat message/control).
     *
     * [senderIdentity] is the sender OpenMLS AUTHENTICATED while decrypting (its leaf
     * credential = that member's memberId bytes). Callers must check the sender the
     * payload CLAIMS against this before acting on it: MLS alone only proves the
     * message came from some member of the epoch, so trusting the claimed value let any
     * member act as an admin (audit K-1).
     */
    class Application(val plaintext: ByteArray, val senderIdentity: ByteArray) : MlsIncoming()

    /** A membership change (Commit) was applied; the epoch advanced. */
    object CommitApplied : MlsIncoming()

    /**
     * A Commit was REFUSED because it would push the group past MAX_GROUP_MEMBERS
     * (audit finding #1). It was NOT merged — the epoch did not advance.
     */
    object CommitRejected : MlsIncoming()

    /** A proposal was stored (awaiting a Commit). Nothing to show yet. */
    object Proposal : MlsIncoming()

    /** Our own message echoed back / not for us / stale epoch — ignore. */
    object Ignored : MlsIncoming()
}

/** An AMF identity keypair (Ristretto). Mirrors uniffi.umbera_core.AmfKeyPair (field order: secret, public). */
class AmfKeyPair(
    val secret: ByteArray,
    val public: ByteArray,
)

/**
 * AMF message-franking crypto (verifiable abuse reports; server stays blind).
 * Mirrors the top-level uniffi.umbera_core.amf* functions 1:1 — the full set the
 * Android AmfManager uses (keygen/keypairFromSeed/commit/frank/verify/judge)
 * plus publicOf/forge (deniability proof, exercised by tests).
 */
expect object AmfFfi {

    /** New AMF identity keypair. Private stays on-device; public is shared E2E. */
    fun amfKeygen(): AmfKeyPair

    /**
     * Deterministic keypair from a seed (e.g. the group's MLS-exported secret) —
     * the GROUP "receiver" designated-verifier key. Scalar = reduce(SHA512(domain || seed)).
     */
    fun amfKeypairFromSeed(seed: ByteArray): AmfKeyPair

    /** Public key for a secret (helper for tests / key derivation). */
    fun amfPublicOf(secret: ByteArray): ByteArray

    /** Per-message binding commitment: HMAC-SHA256(frankKey, plaintext). */
    fun amfCommit(frankKey: ByteArray, msg: ByteArray): ByteArray

    /**
     * Sender franks a message: an AMF signature verifiable by the receiver,
     * openable by the judge, deniable to everyone else.
     */
    fun amfFrank(skS: ByteArray, pkR: ByteArray, pkJ: ByteArray, msg: ByteArray): ByteArray

    /** Receiver-side verification: the OR-proof is valid. (Deniable: a receiver forgery also passes.) */
    fun amfVerify(pkS: ByteArray, pkR: ByteArray, pkJ: ByteArray, msg: ByteArray, sig: ByteArray): Boolean

    /**
     * Judge-side adjudication: OR-proof valid AND the judge tag decrypts to PkS.
     * A receiver forgery encrypts PkR → false → the sender can't be framed.
     */
    fun amfJudge(pkS: ByteArray, pkR: ByteArray, skJ: ByteArray, msg: ByteArray, sig: ByteArray): Boolean

    /** Receiver forgery (knows skR) — proves deniability: amfVerify accepts it, amfJudge rejects it. */
    fun amfForge(pkS: ByteArray, skR: ByteArray, pkJ: ByteArray, msg: ByteArray): ByteArray
}

/** MLS ciphersuites (RFC 9420 codes), from the core. */
object MlsSuites {
    /** X25519 + AES-128-GCM + SHA-256 + Ed25519 — all store builds. */
    val LEGACY: UShort by lazy { MlsKeyPackages.suiteLegacy() }
    /** X-Wing (X25519 + ML-KEM-768) + ChaCha20-Poly1305 + SHA-256 + Ed25519. */
    val XWING: UShort by lazy { MlsKeyPackages.suiteXwing() }
}

/** What the core knows about a KeyPackage before adding it (signature and lifetime verified). */
class MlsKeyPackageInfo(val ciphersuite: UShort, val identity: ByteArray, val supportsXwing: Boolean)

/** Free MLS core functions for ciphersuites and KeyPackages. */
expect object MlsKeyPackages {
    fun suiteLegacy(): UShort
    fun suiteXwing(): UShort
    /** Parse and validate a KeyPackage; on error — [RustCoreException]. */
    fun info(keyPackage: ByteArray): MlsKeyPackageInfo
}

/** Call frame keys from the hybrid exchange (core/src/callkey.rs). */
class CallFrameKeys(val send: ByteArray, val recv: ByteArray, val check: ByteArray)
class CallPqKeypair(val public: ByteArray, val secret: ByteArray)
class CallPqResponse(val answer: ByteArray, val keys: CallFrameKeys)

/** Second, post-quantum call layer: X25519 + ML-KEM-1024 per connection pair. */
expect object CallPq {
    fun keypair(): CallPqKeypair
    fun respond(callId: String, initiatorPublic: ByteArray): CallPqResponse
    fun finish(callId: String, secret: ByteArray, initiatorPublic: ByteArray, answer: ByteArray): CallFrameKeys
}
