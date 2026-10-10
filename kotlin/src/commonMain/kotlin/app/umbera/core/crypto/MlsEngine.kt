package app.umbera.core.crypto

// Platform-neutral facade over the MLS engine.

expect class MlsEngine {
    constructor(identity: ByteArray)

    fun exportState(): ByteArray

    fun signaturePublicKey(): ByteArray

    fun generateKeyPackage(): ByteArray

    fun createGroup(gid: ByteArray)

    fun addMembers(gid: ByteArray, keyPackages: List<ByteArray>): MlsCommitBundle

    fun removeMembers(gid: ByteArray, leafIndices: List<UInt>): ByteArray

    fun updateKeys(gid: ByteArray): ByteArray

    fun processWelcome(welcomeBytes: ByteArray): ByteArray

    fun encrypt(gid: ByteArray, plaintext: ByteArray): ByteArray

    fun processIncoming(gid: ByteArray, message: ByteArray): MlsIncoming

    fun exportSecret(gid: ByteArray, label: String, length: UInt): ByteArray

    fun epoch(gid: ByteArray): ULong

    fun members(gid: ByteArray): List<MlsMemberInfo>

    fun close()

    companion object {
        fun fromState(blob: ByteArray): MlsEngine
    }
}

class MlsCommitBundle(
    val commit: ByteArray,
    val welcome: ByteArray,
)

class MlsMemberInfo(
    val leafIndex: UInt,
    val identity: ByteArray,
)

sealed class MlsIncoming {
    class Application(val plaintext: ByteArray, val senderIdentity: ByteArray) : MlsIncoming()

    object CommitApplied : MlsIncoming()

    object CommitRejected : MlsIncoming()

    object Proposal : MlsIncoming()

    object Ignored : MlsIncoming()
}

class AmfKeyPair(
    val secret: ByteArray,
    val public: ByteArray,
)

expect object AmfFfi {
    fun amfKeygen(): AmfKeyPair

    fun amfKeypairFromSeed(seed: ByteArray): AmfKeyPair

    fun amfPublicOf(secret: ByteArray): ByteArray

    fun amfCommit(frankKey: ByteArray, msg: ByteArray): ByteArray

    fun amfFrank(skS: ByteArray, pkR: ByteArray, pkJ: ByteArray, msg: ByteArray): ByteArray

    fun amfVerify(pkS: ByteArray, pkR: ByteArray, pkJ: ByteArray, msg: ByteArray, sig: ByteArray): Boolean

    fun amfJudge(pkS: ByteArray, pkR: ByteArray, skJ: ByteArray, msg: ByteArray, sig: ByteArray): Boolean

    fun amfForge(pkS: ByteArray, skR: ByteArray, pkJ: ByteArray, msg: ByteArray): ByteArray
}
