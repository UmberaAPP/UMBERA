package app.umbera.core.crypto

/**
 * Linked devices (desktop ↔ phone): a facade over the Rust core (core/src/devlink).
 *
 * Protocol and formats: see the protocol description. All cryptography lives in the core: linking
 * session secrets never reach Kotlin and are wiped on [LinkSession.close], on any
 * mismatch and on timeout. Android and desktop go through the generated uniffi bindings
 * (JNA), iOS through a hand-written uniffi C-ABI wrapper (like [RustCore] and [MlsEngine]).
 *
 * Desktop flow: [LinkSession.desktop] → show [LinkSession.qrText], send [LinkSession.offer]
 * → [LinkSession.desktopAccept] (phone's ACCEPT) → send CONFIRM → [LinkSession.sas] on screen →
 * user taps "Link" → [LinkSession.confirmSas] → [LinkSession.deviceRequest] → certificate →
 * [LinkSession.packageReceive] until `done` → [LinkSession.packageAck].
 * Phone flow: [LinkSession.phone] (QR text) → [LinkSession.phoneAccept] (OFFER) →
 * [LinkSession.phoneConfirm] → [LinkSession.sas] → "Link" → [LinkSession.confirmSas] →
 * [LinkSession.openDeviceRequest] → [DeviceLinkCore.deviceCertIssue] (user_id, device_id from /link/claim)
 * → seal(DEVICE_CERT) →
 * packageBegin / packageAdd / packageFinish → [LinkSession.packageCheckAck].
 *
 * All calls are blocking and fast (except ML-DSA, ~ms); errors are [DeviceLinkException].
 */

/** Linking blob kinds (the relay's kind field). The values are part of the format and match the core. */
object LinkKinds {
    const val OFFER = 1
    const val ACCEPT = 2
    const val CONFIRM = 3
    const val DEVICE_REQUEST = 16
    const val DEVICE_CERT = 17
    const val MLS_JOIN_REQUESTS = 18
    const val MLS_JOIN_OFFERS = 19
    const val PACKAGE_HEADER = 32
    const val PACKAGE_PART = 33
    const val PACKAGE_END = 34
    const val PACKAGE_ACK = 35
    const val ABORT = 48

    /**
     * Kind name for the relay (the server's `kind` is a string `^[a-z][a-z0-9_]{0,15}$`).
     * The blob AAD contains the numeric kind; the name is transport only.
     */
    fun wireName(kind: Int): String = names[kind] ?: throw DeviceLinkException(DeviceLinkException.Reason.MALFORMED, "unknown kind $kind")

    fun fromWireName(name: String): Int =
        byName[name] ?: throw DeviceLinkException(DeviceLinkException.Reason.MALFORMED, "unknown kind name $name")

    private val names = mapOf(
        OFFER to "offer", ACCEPT to "accept", CONFIRM to "confirm",
        DEVICE_REQUEST to "dev_request", DEVICE_CERT to "dev_cert",
        MLS_JOIN_REQUESTS to "mls_requests", MLS_JOIN_OFFERS to "mls_offers",
        PACKAGE_HEADER to "pkg_header", PACKAGE_PART to "pkg_part", PACKAGE_END to "pkg_end", PACKAGE_ACK to "pkg_ack",
        ABORT to "abort",
    )
    private val byName = names.entries.associate { (k, v) -> v to k }
}

/** Transfer package sections. */
object LinkSections {
    const val PROFILE = 1
    const val CONTACT = 2
    const val CHAT = 3
    const val MESSAGE_TEXT = 4
    const val MESSAGE_PHOTO = 5
    const val MLS_WELCOME = 6
    const val COMM_VAULT = 7
    const val COMM_MEMBERSHIP = 8
    /** account_sync_key (32 B): shared key of the account's devices (device names). */
    const val ACCOUNT_SYNC = 9
    /** History photos via /api/blob (reference and key, ≤ 4 KiB) when the package exceeds 63 MiB. */
    const val PHOTO_BLOB_REF = 10
}

object DeviceTypes {
    const val PHONE = 1
    const val DESKTOP = 2
}

object LinkLimits {
    const val QR_TTL_SECS = 60L
    const val SAS_TTL_SECS = 180L
    const val PHOTO_MAX_BYTES = 16 * 1024 * 1024
    const val PACKAGE_MAX_BYTES = 63L * 1024 * 1024
    const val LABEL_MAX_BYTES = 64
}

/** Blob for the relay: the server sees only these three fields. */
class LinkBlob(val kind: Int, val seq: Long, val data: ByteArray) {
    init {
        require(kind in 0..255) { "kind must fit in a byte" }
        require(seq >= 0) { "seq must be non-negative" }
    }
}

enum class LinkRole { DESKTOP, PHONE }

enum class LinkState { AWAITING_ACCEPT, AWAITING_OFFER, AWAITING_CONFIRM, AWAITING_SAS, ESTABLISHED, CLOSED }

/** Linking failure. [reason] says what exactly; on MISMATCH/EXPIRED the core has already destroyed the session. */
class DeviceLinkException(val reason: Reason, detail: String) : Exception("${reason.name.lowercase()}: $detail") {
    enum class Reason { MALFORMED, EXPIRED, MISMATCH, REPLAY, STATE, CRYPTO }
}

class DevicePublicKeys(
    val ed25519: ByteArray,
    val mldsa65: ByteArray,
    val x25519: ByteArray,
    val mlkem1024: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is DevicePublicKeys && ed25519.contentEquals(other.ed25519) && mldsa65.contentEquals(other.mldsa65) &&
            x25519.contentEquals(other.x25519) && mlkem1024.contentEquals(other.mlkem1024)

    override fun hashCode(): Int = ed25519.contentHashCode()
}

class DeviceRequest(val deviceType: Int, val label: String, val keys: DevicePublicKeys)

/** Device key in the server format `{alg, key}` (order matters). */
class DeviceKey(val alg: String, val key: ByteArray)

/**
 * Verified device certificate. [wireKeys], [primarySig], [pqSig], [labelSealed] are exactly what
 * the desktop sends to /api/devices/link/register; [userId] and [accountAddress] are the desktop's account.
 */
class DeviceCertInfo(
    val userId: String,
    val deviceId: String,
    val keys: DevicePublicKeys,
    val wireKeys: List<DeviceKey>,
    val primarySig: ByteArray,
    val pqSig: ByteArray,
    val accountSecp256k1: ByteArray,
    val accountMldsa65: ByteArray,
    val accountAddress: String,
    val labelSealed: ByteArray,
    val issuedAt: Long,
)

class DeviceLabel(val deviceType: Int, val label: String)

class DeviceEncryptionKeys(val x25519Private: ByteArray, val mlkem1024Seed: ByteArray)

class PackageRecord(val section: Int, val id: ByteArray, val body: ByteArray)

/** Records collected from the latest blob. Commit to the database only on [done]. */
class PackageProgress(
    val records: List<PackageRecord>,
    val done: Boolean,
    val includeHistory: Boolean,
    val parts: Int,
    val bytes: Long,
)

class CommVaultRoots(val v3: ByteArray, val v2: ByteArray)

class CommVaultKeys(val id: ByteArray, val authSeed: ByteArray, val encKey: ByteArray)

class MlsJoinRequest(val gid: ByteArray, val primaryMemberId: ByteArray)

class MlsJoinOffer(
    val gid: ByteArray,
    val deviceMemberId: ByteArray,
    val keyPackage: ByteArray,
    val deviceSiblingSig: ByteArray,
)

/**
 * One side of a link. After [close] (or any MISMATCH/EXPIRED) the object is dead: secrets
 * are wiped, further calls yield STATE. [close] is mandatory once the session is no longer needed
 * (QR refreshed, linking finished): it wipes secrets and frees the core object.
 */
expect class LinkSession {
    fun role(): LinkRole
    fun state(): LinkState
    fun linkId(): ByteArray
    fun relayHint(): String
    fun issuedAt(): Long

    /** Desktop: text for the QR ("umbera-link:" + base64url, ~150 characters). */
    fun qrText(): String

    /** Desktop: OFFER blob (ML-KEM-1024 key), may be resent. */
    fun offer(): LinkBlob

    /** Phone: OFFER → ACCEPT. */
    fun phoneAccept(offer: LinkBlob, nowSecs: Long): LinkBlob

    /** Desktop: ACCEPT → CONFIRM (no later than 60 s after the QR was shown). */
    fun desktopAccept(accept: LinkBlob, nowSecs: Long): LinkBlob

    /** Phone: verify CONFIRM. */
    fun phoneConfirm(confirm: LinkBlob, nowSecs: Long)

    /** Verification code, 6 digits, identical on both screens. */
    fun sas(): String

    /** The user tapped "Link" (within 180 s after the code appeared). */
    fun confirmSas(nowSecs: Long)

    fun seal(kind: Int, plaintext: ByteArray): LinkBlob
    fun open(blob: LinkBlob): ByteArray

    fun deviceRequest(deviceSeed: ByteArray, deviceType: Int, label: String): LinkBlob
    fun openDeviceRequest(blob: LinkBlob): DeviceRequest

    fun packageBegin(includeHistory: Boolean): LinkBlob
    fun packageAdd(section: Int, id: ByteArray, body: ByteArray): List<LinkBlob>
    fun packageFinish(): List<LinkBlob>
    fun packageReceive(blob: LinkBlob): PackageProgress
    fun packageAck(): LinkBlob
    fun packageCheckAck(blob: LinkBlob)

    /** Wipe secrets and free the core object. Safe to call repeatedly. */
    fun close()

    companion object {
        /** Desktop: new session (ephemeral keys). link_id is 16..32 bytes. */
        fun desktop(linkId: ByteArray, relayHint: String, nowSecs: Long): LinkSession

        /** Phone: session from a scanned QR. */
        fun phone(qrText: String, nowSecs: Long): LinkSession
    }
}

/** Session-less functions: device keys and certificate, revocation, Communities vault, MLS requests. */
expect object DeviceLinkCore {
    fun deviceSeedGenerate(): ByteArray
    fun devicePublicKeys(deviceSeed: ByteArray): DevicePublicKeys
    fun deviceEncryptionKeys(deviceSeed: ByteArray): DeviceEncryptionKeys
    fun deviceSign(deviceSeed: ByteArray, context: String, message: ByteArray): ByteArray
    fun deviceVerify(keys: DevicePublicKeys, context: String, message: ByteArray, signature: ByteArray): Boolean

    /** Phone: certificate for the desktop. [userId] is one's own id, [deviceId] comes from /link/claim (lowercase UUID). */
    fun deviceCertIssue(
        request: DeviceRequest,
        userId: String,
        deviceId: String,
        accountSecp256k1Private: ByteArray,
        accountMldsa65Seed: ByteArray,
        labelSealed: ByteArray,
        issuedAt: Long,
    ): ByteArray
    fun deviceCertVerify(cert: ByteArray, expectedAccountAddress: String): DeviceCertInfo
    fun deviceCertVerifyForDevice(cert: ByteArray, deviceSeed: ByteArray): DeviceCertInfo

    /** Peer: device from /api/anon/devices → keys that can be encrypted to. */
    fun deviceListingVerify(
        userId: String,
        deviceId: String,
        wireKeys: List<DeviceKey>,
        primarySig: ByteArray,
        pqSig: ByteArray,
        accountSecp256k1: ByteArray,
        accountMldsa65: ByteArray,
        expectedAccountAddress: String,
    ): DevicePublicKeys
    fun deviceWireKeys(keys: DevicePublicKeys): List<DeviceKey>
    fun deviceKeysDigest(wireKeys: List<DeviceKey>): ByteArray

    fun accountSyncKey(accountX25519Private: ByteArray, accountMlkemSeed: ByteArray): ByteArray
    fun deviceLabelSeal(syncKey: ByteArray, deviceId: String, deviceType: Int, label: String): ByteArray
    fun deviceLabelOpen(syncKey: ByteArray, deviceId: String, sealed: ByteArray): DeviceLabel
    fun linkIsStillImage(bytes: ByteArray): Boolean

    fun commVaultRoots(accountX25519Private: ByteArray, accountMlkemSeed: ByteArray): CommVaultRoots
    fun commVaultEpochKeys(rootV3: ByteArray, epoch: Int): CommVaultKeys
    fun commVaultLegacyKeys(rootV2: ByteArray): CommVaultKeys
    fun commVaultRecordBody(roots: CommVaultRoots): ByteArray
    fun commVaultRecordParse(body: ByteArray): CommVaultRoots

    fun mlsJoinRequestsEncode(requests: List<MlsJoinRequest>): ByteArray
    fun mlsJoinRequestsDecode(bytes: ByteArray): List<MlsJoinRequest>
    fun mlsJoinOffersEncode(offers: List<MlsJoinOffer>): ByteArray
    fun mlsJoinOffersDecode(bytes: ByteArray): List<MlsJoinOffer>
    fun mlsSiblingVerifyKeyPackage(primaryMemberId: ByteArray, offer: MlsJoinOffer): Boolean
}
