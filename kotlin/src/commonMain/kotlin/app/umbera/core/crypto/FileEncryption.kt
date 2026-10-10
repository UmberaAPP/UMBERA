package app.umbera.core.crypto

// End-to-end encryption of attachments.

import app.umbera.core.util.WireJson
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

import app.umbera.core.util.B64
import app.umbera.core.util.Log
import app.umbera.core.util.BuildFlags
import app.umbera.core.util.SyncLock
import app.umbera.core.util.withLock

class FileEncryption(
    private val secureKeyStorage: LocalKeyStore
) {
    companion object {
        private const val TAG = "FileEncryption"

        private const val CHUNK_SIZE = 256 * 1024
        private const val PROTOCOL_VERSION = "file-v1"
        private const val FILE_RATCHET_VERSION = "file-ratchet-v1"

        private val PADDING_SIZES = intArrayOf(
            32 * 1024,
            64 * 1024,
            128 * 1024,
            256 * 1024,
            512 * 1024,
            1024 * 1024,
            2 * 1024 * 1024,
            5 * 1024 * 1024,
            10 * 1024 * 1024,
            20 * 1024 * 1024,
            50 * 1024 * 1024,
            100 * 1024 * 1024
        )
    }

    private val json = WireJson.json

    private val fileNumberCounters = HashMap<String, Int>()
    private val countersLock = SyncLock()

    init {
        loadPersistedCounters()
    }

    private fun loadPersistedCounters() {
        val persistedCounters = secureKeyStorage.getAllFileNumberCounters()
        countersLock.withLock {
            persistedCounters.forEach { (conversationId, counter) ->
                fileNumberCounters[conversationId] = counter
            }
        }
        if (BuildFlags.DEBUG && persistedCounters.isNotEmpty()) {
            Log.d(TAG, "Loaded ${persistedCounters.size} persisted file counters")
        }
    }

    @Serializable
    data class EncryptedChunk(
        val chunkIndex: Int,
        val ciphertext: String,
        val iv: String,
        val authTag: String,
        val paddedSize: Int
    )

    @Serializable
    data class FileMetadata(
        val fileId: String,
        val fileName: String,
        val mimeType: String,
        val fileSize: Long,
        val chunkCount: Int,
        val timestamp: Long
    )

    @Serializable
    data class EncryptedFile(
        val version: String = PROTOCOL_VERSION,
        val fileId: String,
        val encryptedMetadata: String,
        val metadataIv: String,
        val metadataAuthTag: String,
        val chunks: List<EncryptedChunk>,
        val fileSignature: String,
        val messageCounter: Int,

        val ephemeralPublicKey: String,
        val fileNumber: Int,
        val fileRatchetVersion: String = FILE_RATCHET_VERSION,
        val ratchetTimestamp: Long,

        val fileKey: ByteArray? = null
    )

    @Serializable
    data class FileUploadRequest(
        val receiverId: String,
        val fileId: String,
        val encryptedMetadata: String,
        val metadataIv: String,
        val metadataAuthTag: String,
        val fileSignature: String,
        val messageCounter: Int,
        val chunks: List<ChunkData>,
        val protocolVersion: String,

        val ephemeralPublicKey: String,
        val fileNumber: Int,
        val fileRatchetVersion: String,
        val ratchetTimestamp: Long,

        val sealedPackage: String? = null
    )

    @Serializable

    data class ChunkData(
        val chunkIndex: Int,
        val ciphertext: String,
        val iv: String,
        val authTag: String,
        val paddedSize: Int
    )

    fun encryptFile(
        fileData: ByteArray,
        fileName: String,
        mimeType: String,
        conversationId: String,
        recipientX25519PublicKey: ByteArray
    ): EncryptedFile {
        if (BuildFlags.DEBUG) Log.d(TAG, "Encrypting file: size=${fileData.size}")

        try {
            val ephemeral = X25519.generateKeyPair()
            val ephemeralPublicKeyHex = ephemeral.publicKey.toHex()
            if (BuildFlags.DEBUG) Log.d(TAG, "Generated ephemeral X25519 key for file")

            val fileNumber = getNextFileNumber(conversationId)
            val timestamp = kotlinx.datetime.Clock.System.now().toEpochMilliseconds()

            val sharedSecret = X25519.computeSharedSecret(ephemeral.privateKey, recipientX25519PublicKey)
            val fileKey = deriveFileKeyFromSharedSecret(sharedSecret, fileNumber)

            val fileId = app.umbera.core.util.randomUuid4()

            val chunkCount = (fileData.size + CHUNK_SIZE - 1) / CHUNK_SIZE
            val metadata = FileMetadata(
                fileId = fileId,
                fileName = fileName,
                mimeType = mimeType,
                fileSize = fileData.size.toLong(),
                chunkCount = chunkCount,
                timestamp = timestamp
            )
            val metadataJson = json.encodeToString(metadata)
            val metadataBytes = metadataJson.encodeToByteArray()

            val metadataIv = generateIv()
            val encryptedMetadata = AesGcm.encryptWithTag(
                metadataBytes,
                fileKey,
                metadataIv
            )

            val chunks = mutableListOf<EncryptedChunk>()
            for (i in 0 until chunkCount) {
                val start = i * CHUNK_SIZE
                val end = minOf(start + CHUNK_SIZE, fileData.size)
                val chunkData = fileData.copyOfRange(start, end)

                val chunkKey = deriveChunkKey(fileKey, i)
                val chunkIv = generateIv()

                val encryptedChunk = AesGcm.encryptWithTag(
                    chunkData,
                    chunkKey,
                    chunkIv
                )

                val paddedCiphertext = addPadding(encryptedChunk.ciphertext)

                chunks.add(
                    EncryptedChunk(
                        chunkIndex = i,
                        ciphertext = B64.encode(paddedCiphertext),
                        iv = chunkIv.toHex(),
                        authTag = encryptedChunk.authTag.toHex(),
                        paddedSize = paddedCiphertext.size
                    )
                )
            }

            val myPrivateKey = secureKeyStorage.getSecp256k1PrivateKey()
                ?: throw IllegalStateException("No secp256k1 private key found")

            val fileHash = hashFile(
                ephemeralPublicKeyHex,
                fileNumber,
                timestamp,
                encryptedMetadata.ciphertext,
                chunks
            )
            val signature = Secp256k1.sign(fileHash.hexToBytes(), myPrivateKey)

            if (BuildFlags.DEBUG) Log.d(TAG, "File encrypted: chunks=${chunks.size}")

            return EncryptedFile(
                version = PROTOCOL_VERSION,
                fileId = fileId,
                encryptedMetadata = B64.encode(encryptedMetadata.ciphertext),
                metadataIv = metadataIv.toHex(),
                metadataAuthTag = encryptedMetadata.authTag.toHex(),
                chunks = chunks,
                fileSignature = signature.toHexString(),
                messageCounter = fileNumber,
                ephemeralPublicKey = ephemeralPublicKeyHex,
                fileNumber = fileNumber,
                fileRatchetVersion = FILE_RATCHET_VERSION,
                ratchetTimestamp = timestamp,
                fileKey = fileKey
            )
        } catch (e: Exception) {
            if (BuildFlags.DEBUG) Log.e(TAG, "Failed to encrypt file", e)
            throw RuntimeException("File encryption failed: ${e.message}", e)
        }
    }

    fun decryptFile(
        encryptedFile: EncryptedFile,
        senderSecp256k1PublicKey: ByteArray
    ): Pair<ByteArray, FileMetadata> {
        if (BuildFlags.DEBUG) Log.d(TAG, "Decrypting file")

        try {
            val fileHash = hashFile(
                encryptedFile.ephemeralPublicKey,
                encryptedFile.fileNumber,
                encryptedFile.ratchetTimestamp,
                B64.decode(encryptedFile.encryptedMetadata),
                encryptedFile.chunks
            )
            val signature = Secp256k1.Signature.fromHexString(encryptedFile.fileSignature)
            if (!Secp256k1.verify(fileHash.hexToBytes(), signature, senderSecp256k1PublicKey)) {
                throw SecurityException("Invalid file signature")
            }
            if (BuildFlags.DEBUG) Log.d(TAG, "File signature verified")

            val myX25519PrivateKey = secureKeyStorage.getX25519PrivateKey()
                ?: throw IllegalStateException("No X25519 private key found")
            val senderEphemeralPublicKey = encryptedFile.ephemeralPublicKey.hexToBytes()

            val sharedSecret = X25519.computeSharedSecret(myX25519PrivateKey, senderEphemeralPublicKey)
            val fileKey = deriveFileKeyFromSharedSecret(sharedSecret, encryptedFile.fileNumber)

            val metadataBytes = AesGcm.decryptWithTag(
                B64.decode(encryptedFile.encryptedMetadata),
                encryptedFile.metadataAuthTag.hexToBytes(),
                encryptedFile.metadataIv.hexToBytes(),
                fileKey
            )
            val metadata = json.decodeFromString<FileMetadata>(metadataBytes.decodeToString())
            if (BuildFlags.DEBUG) Log.d(TAG, "Metadata decrypted")

            val decryptedChunks = mutableListOf<ByteArray>()
            for (chunk in encryptedFile.chunks) {
                val chunkKey = deriveChunkKey(fileKey, chunk.chunkIndex)

                val paddedCiphertext = B64.decode(chunk.ciphertext)
                val ciphertext = removePadding(paddedCiphertext)

                val decryptedChunk = AesGcm.decryptWithTag(
                    ciphertext,
                    chunk.authTag.hexToBytes(),
                    chunk.iv.hexToBytes(),
                    chunkKey
                )
                decryptedChunks.add(decryptedChunk)
            }

            val totalSize = decryptedChunks.sumOf { it.size }
            val fileData = ByteArray(totalSize)
            var offset = 0
            for (chunk in decryptedChunks) {
                chunk.copyInto(fileData, destinationOffset = offset)
                offset += chunk.size
            }

            if (BuildFlags.DEBUG) Log.d(TAG, "File decrypted: size=${fileData.size}")
            return Pair(fileData, metadata)
        } catch (e: Exception) {
            if (BuildFlags.DEBUG) Log.e(TAG, "Failed to decrypt file", e)
            throw RuntimeException("File decryption failed: ${e.message}", e)
        }
    }

    fun decryptFileWithKey(
        encryptedFile: EncryptedFile,
        savedFileKey: ByteArray
    ): Pair<ByteArray, FileMetadata> {
        if (BuildFlags.DEBUG) Log.d(TAG, "Decrypting own file with saved key")

        try {
            val metadataBytes = AesGcm.decryptWithTag(
                B64.decode(encryptedFile.encryptedMetadata),
                encryptedFile.metadataAuthTag.hexToBytes(),
                encryptedFile.metadataIv.hexToBytes(),
                savedFileKey
            )
            val metadata = json.decodeFromString<FileMetadata>(metadataBytes.decodeToString())
            if (BuildFlags.DEBUG) Log.d(TAG, "Metadata decrypted")

            val decryptedChunks = mutableListOf<ByteArray>()
            for (chunk in encryptedFile.chunks) {
                val chunkKey = deriveChunkKey(savedFileKey, chunk.chunkIndex)

                val paddedCiphertext = B64.decode(chunk.ciphertext)
                val ciphertext = removePadding(paddedCiphertext)

                val decryptedChunk = AesGcm.decryptWithTag(
                    ciphertext,
                    chunk.authTag.hexToBytes(),
                    chunk.iv.hexToBytes(),
                    chunkKey
                )
                decryptedChunks.add(decryptedChunk)
            }

            val totalSize = decryptedChunks.sumOf { it.size }
            val fileData = ByteArray(totalSize)
            var offset = 0
            for (chunk in decryptedChunks) {
                chunk.copyInto(fileData, destinationOffset = offset)
                offset += chunk.size
            }

            if (BuildFlags.DEBUG) Log.d(TAG, "Own file decrypted: size=${fileData.size}")
            return Pair(fileData, metadata)
        } catch (e: Exception) {
            if (BuildFlags.DEBUG) Log.e(TAG, "Failed to decrypt own file", e)
            throw RuntimeException("Own file decryption failed: ${e.message}", e)
        }
    }

    fun createUploadRequest(
        encryptedFile: EncryptedFile,
        receiverId: String,
        sealedPackage: String? = null
    ): FileUploadRequest {
        return FileUploadRequest(
            receiverId = receiverId,
            fileId = encryptedFile.fileId,
            encryptedMetadata = encryptedFile.encryptedMetadata,
            metadataIv = encryptedFile.metadataIv,
            metadataAuthTag = encryptedFile.metadataAuthTag,
            fileSignature = encryptedFile.fileSignature,
            messageCounter = encryptedFile.messageCounter,
            chunks = encryptedFile.chunks.map { chunk ->
                ChunkData(
                    chunkIndex = chunk.chunkIndex,
                    ciphertext = chunk.ciphertext,
                    iv = chunk.iv,
                    authTag = chunk.authTag,
                    paddedSize = chunk.paddedSize
                )
            },
            protocolVersion = encryptedFile.version,
            ephemeralPublicKey = encryptedFile.ephemeralPublicKey,
            fileNumber = encryptedFile.fileNumber,
            fileRatchetVersion = encryptedFile.fileRatchetVersion,
            ratchetTimestamp = encryptedFile.ratchetTimestamp,
            sealedPackage = sealedPackage
        )
    }

    private fun getNextFileNumber(conversationId: String): Int {
        val newValue = countersLock.withLock {
            val current = fileNumberCounters[conversationId]
                ?: secureKeyStorage.getFileNumberCounter(conversationId)
            (current + 1).also { fileNumberCounters[conversationId] = it }
        }

        secureKeyStorage.saveFileNumberCounter(conversationId, newValue)
        return newValue
    }

    private fun deriveFileKey(ephemeralPrivateKey: ByteArray, fileNumber: Int): ByteArray =

        RustCore.hmacSha256(
            ephemeralPrivateKey, "file-key-v1".encodeToByteArray() + fileNumber.toBigEndianBytes()
        )

    private fun deriveFileKeyFromSharedSecret(sharedSecret: ByteArray, fileNumber: Int): ByteArray =
        RustCore.hmacSha256(
            sharedSecret, "file-key-v1".encodeToByteArray() + fileNumber.toBigEndianBytes()
        )

    private fun deriveChunkKey(fileKey: ByteArray, chunkIndex: Int): ByteArray =
        RustCore.hmacSha256(fileKey, "chunk-$chunkIndex".encodeToByteArray())

    private fun generateIv(): ByteArray = secureRandomBytes(12)

    private fun addPadding(data: ByteArray): ByteArray {
        val targetSize = findPaddingSize(data.size + 4)
        val paddingLength = targetSize - data.size - 4

        val lengthBytes = ByteArray(4)
        lengthBytes[0] = ((data.size shr 24) and 0xFF).toByte()
        lengthBytes[1] = ((data.size shr 16) and 0xFF).toByte()
        lengthBytes[2] = ((data.size shr 8) and 0xFF).toByte()
        lengthBytes[3] = (data.size and 0xFF).toByte()

        val padding = if (paddingLength > 0) {
            secureRandomBytes(paddingLength)
        } else {
            ByteArray(0)
        }

        return lengthBytes + data + padding
    }

    private fun removePadding(paddedData: ByteArray): ByteArray {
        if (paddedData.size < 4) {
            throw SecurityException("Invalid padded data: too short (< 4 bytes)")
        }

        val length = ((paddedData[0].toInt() and 0xFF) shl 24) or
                     ((paddedData[1].toInt() and 0xFF) shl 16) or
                     ((paddedData[2].toInt() and 0xFF) shl 8) or
                     (paddedData[3].toInt() and 0xFF)

        if (length < 0) {
            throw SecurityException("Invalid padded data: negative length")
        }

        val maxAllowedLength = CHUNK_SIZE + 1024
        if (length > maxAllowedLength) {
            throw SecurityException("Invalid padded data: length exceeds maximum ($length > $maxAllowedLength)")
        }

        if (length > paddedData.size - 4) {
            throw SecurityException("Invalid padded data: length exceeds available data ($length > ${paddedData.size - 4})")
        }

        return paddedData.copyOfRange(4, 4 + length)
    }

    private fun findPaddingSize(length: Int): Int {
        for (size in PADDING_SIZES) {
            if (size >= length + 1) {
                return size
            }
        }

        val maxSize = PADDING_SIZES.last()
        return ((length / maxSize) + 1) * maxSize
    }

    private fun hashFile(
        ephemeralPublicKey: String,
        fileNumber: Int,
        timestamp: Long,
        encryptedMetadata: ByteArray,
        chunks: List<EncryptedChunk>
    ): String {
        val md = app.umbera.core.util.Sha256Stream()
        md.update(ephemeralPublicKey.encodeToByteArray())
        md.update(fileNumber.toString().encodeToByteArray())
        md.update(timestamp.toString().encodeToByteArray())

        md.update(encryptedMetadata.toHex().encodeToByteArray())
        for (chunk in chunks) {
            md.update(chunk.ciphertext.encodeToByteArray())
        }
        return md.digest().joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }
    }

    private fun ByteArray.toHex(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0) { "Hex string must have even length" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun Int.toBigEndianBytes(): ByteArray {
        return byteArrayOf(
            (this shr 24).toByte(),
            (this shr 16).toByte(),
            (this shr 8).toByte(),
            this.toByte()
        )
    }
}
