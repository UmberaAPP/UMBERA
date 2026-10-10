package app.umbera.core.call

// End-to-end encryption of call setup (SDP and ICE), excerpted from the call repository of the apps.
// SDP carries the DTLS fingerprints of both phones. It is encrypted with the same scheme as messages
// and signed by the sender, so the server can neither read nor alter it. Encrypted SDP travels
// through the anonymous mailbox channel (see docs/PROOF.md, Section 2).

private fun encryptSignaling(data: String, peerUserId: String): String? {
    return try {
        val peerKeys = peerKeysCacheGet(peerUserId) ?: run {
            if (BuildFlags.DEBUG) Log.e(TAG, "No peer keys for user")
            return null
        }

        val result = messageEncryption.encryptMessage(
            content = data,
            recipientId = peerUserId,
            recipientPublicKey = peerKeys.first,
            recipientX25519PublicKey = peerKeys.second,
            type = "signaling",
            sequenceNumber = 0
        )

        buildJsonObject {
            put("encryptedData", result.encryptedData)
            put("iv", result.iv)
            put("signature", result.signature)
            put("ephemeralPublicKey", result.ephemeralPublicKey)
        }.toString()
    } catch (e: Exception) {
        if (BuildFlags.DEBUG) Log.e(TAG, "Failed to encrypt signaling", e)
        null
    }
}

private fun decryptSignaling(encryptedData: String?, peerUserId: String): String? {
    if (encryptedData.isNullOrEmpty()) {
        Log.e(TAG, ">>> decryptSignaling: encrypted payload is empty (peer=$peerUserId)")
        return null
    }

    return try {
        val peerKeys = peerKeysCacheGet(peerUserId) ?: run {
            Log.e(TAG, ">>> decryptSignaling: no peer keys cached for $peerUserId — call setPeerKeys() first")
            return null
        }

        val encrypted = try {
            json.parseToJsonElement(encryptedData).jsonObject
        } catch (e: Exception) {
            Log.e(TAG, ">>> decryptSignaling: envelope JSON parse failed (len=${encryptedData.length})", e)
            return null
        }

        val encData = encrypted.str("encryptedData")
        val iv = encrypted.str("iv")
        val signature = encrypted.str("signature")
        val ephPubKey = encrypted.str("ephemeralPublicKey")
        if (encData == null || iv == null || signature == null || ephPubKey == null) {
            Log.e(TAG, ">>> decryptSignaling: envelope missing field(s): " +
                    "encData=${encData != null} iv=${iv != null} sig=${signature != null} ephPub=${ephPubKey != null}")
            return null
        }

        val decrypted = try {
            messageEncryption.decryptMessageRaw(
                encryptedData = encData,
                iv = iv,
                signature = signature,
                ephemeralPublicKey = ephPubKey,
                senderPublicKey = peerKeys.first
            )
        } catch (e: Exception) {
            Log.e(TAG, ">>> decryptSignaling: decryptMessageRaw threw (peer=$peerUserId, sigLen=${signature.length})", e)
            return null
        }

        val content = decrypted.content
        if (content.isNullOrEmpty()) {
            Log.e(TAG, ">>> decryptSignaling: decryption returned empty content (peer=$peerUserId)")
            return null
        }
        Log.w(TAG, ">>> decryptSignaling: OK, plaintext len=${content.length}")
        content
    } catch (e: Exception) {
        Log.e(TAG, ">>> decryptSignaling: unexpected failure", e)
        null
    }
}
