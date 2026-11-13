package app.umbera.core.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * audit B-9: a peer's cryptoVersion / kyberPublicKey arrive from the directory
 * UNAUTHENTICATED (the KT leaf covers only the identity keys), so the client
 * persistently pins the strongest capabilities ever observed and treats any
 * served DOWNGRADE like an identity-key change (send refuses via the
 * peer-key-changed flag). Pure key-value logic — runs on the JVM without the
 * native core.
 */
class PeerCryptoCapsPinTest {

    /** In-memory SecureKvStore — same semantics as SharedPreferences. */
    private class FakeKvStore : SecureKvStore {
        val map = HashMap<String, Any>()
        override fun getString(key: String): String? = map[key] as? String
        override fun putString(key: String, value: String) { map[key] = value }
        override fun getBoolean(key: String, default: Boolean): Boolean = map[key] as? Boolean ?: default
        override fun putBoolean(key: String, value: Boolean) { map[key] = value }
        override fun getInt(key: String, default: Int): Int = map[key] as? Int ?: default
        override fun putInt(key: String, value: Int) { map[key] = value }
        override fun getLong(key: String, default: Long): Long = map[key] as? Long ?: default
        override fun putLong(key: String, value: Long) { map[key] = value }
        @Suppress("UNCHECKED_CAST")
        override fun getStringSet(key: String): Set<String>? = map[key] as? Set<String>
        override fun putStringSet(key: String, value: Set<String>) { map[key] = value }
        override fun contains(key: String): Boolean = map.containsKey(key)
        override fun remove(key: String) { map.remove(key) }
        override fun allKeys(): Set<String> = map.keys.toSet()
        override fun clear() { map.clear() }
    }

    private fun keystore() = SecureKeyStoreCommon(FakeKvStore(), { false })

    private val peer = "peer-user-1"

    @Test
    fun first_resolve_pins_served_capabilities() {
        val ks = keystore()
        assertNull(ks.getPinnedPeerCryptoCaps(peer))

        assertFalse(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = true))

        assertEquals(PeerCryptoCaps(ratchetCapable = true, hasKyberKey = true), ks.getPinnedPeerCryptoCaps(peer))
        assertFalse(ks.isPeerKeyChanged(peer))
    }

    @Test
    fun downgrade_is_rejected_and_flags_peer_key_changed() {
        val ks = keystore()
        ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = true)

        // Hostile directory omits BOTH cryptoVersion and the Kyber key.
        assertTrue(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = false, hasKyberKey = false))

        // The send path's existing gate must now refuse (PeerKeyChangedException).
        assertTrue(ks.isPeerKeyChanged(peer))
        // And the pin keeps the STRONG capability set — it is never lowered silently.
        assertEquals(PeerCryptoCaps(ratchetCapable = true, hasKyberKey = true), ks.getPinnedPeerCryptoCaps(peer))
    }

    @Test
    fun losing_only_the_kyber_key_is_also_a_downgrade() {
        val ks = keystore()
        ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = false, hasKyberKey = true)

        assertTrue(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = false, hasKyberKey = false))
        assertTrue(ks.isPeerKeyChanged(peer))
    }

    @Test
    fun losing_only_ratchet_capability_is_also_a_downgrade() {
        val ks = keystore()
        ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = false)

        assertTrue(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = false, hasKyberKey = false))
        assertTrue(ks.isPeerKeyChanged(peer))
    }

    @Test
    fun upgrade_is_accepted_and_repins_upward() {
        val ks = keystore()
        // Legacy peer first seen with no capabilities at all.
        assertFalse(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = false, hasKyberKey = false))
        assertEquals(PeerCryptoCaps(ratchetCapable = false, hasKyberKey = false), ks.getPinnedPeerCryptoCaps(peer))

        // The peer genuinely upgrades (publishes Kyber, advertises v3) → allowed.
        assertFalse(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = true))
        assertEquals(PeerCryptoCaps(ratchetCapable = true, hasKyberKey = true), ks.getPinnedPeerCryptoCaps(peer))
        assertFalse(ks.isPeerKeyChanged(peer))

        // …and from then on the higher pin is enforced.
        assertTrue(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = false))
    }

    @Test
    fun unpinned_peer_with_no_capabilities_behaves_as_before() {
        val ks = keystore()
        // Brand-new legacy peer: nothing pinned, nothing served → no refusal,
        // classical send path stays reachable exactly as pre-fix.
        assertFalse(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = false, hasKyberKey = false))
        assertFalse(ks.isPeerKeyChanged(peer))
        // But the observation IS recorded (an empty capability set is a valid pin).
        assertEquals(PeerCryptoCaps(ratchetCapable = false, hasKyberKey = false), ks.getPinnedPeerCryptoCaps(peer))
    }

    @Test
    fun repeated_identical_resolves_are_stable() {
        val ks = keystore()
        repeat(3) {
            assertFalse(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = false))
        }
        assertEquals(PeerCryptoCaps(ratchetCapable = true, hasKyberKey = false), ks.getPinnedPeerCryptoCaps(peer))
        assertFalse(ks.isPeerKeyChanged(peer))
    }

    @Test
    fun accepting_a_changed_peer_key_resets_the_capability_pin() {
        // acceptPeerKey hashes the new fingerprint via the native core, so this
        // runs only where the Rust library is loadable (device / native targets).
        if (!rustCoreTestsEnabled()) return
        val ks = keystore()
        ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = true)
        assertTrue(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = false, hasKyberKey = false))

        // The user verified the peer out-of-band and accepted the new identity:
        // TOFU restarts for capabilities too, so a genuine reinstall on an older
        // build cannot wedge the channel in an accept-loop.
        ks.acceptPeerKey(peer, ByteArray(33) { 1 }, ByteArray(32) { 2 })
        assertFalse(ks.isPeerKeyChanged(peer))
        assertNull(ks.getPinnedPeerCryptoCaps(peer))

        // Next resolve re-pins whatever the (now accepted) peer actually serves.
        assertFalse(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = false, hasKyberKey = false))
        assertEquals(PeerCryptoCaps(ratchetCapable = false, hasKyberKey = false), ks.getPinnedPeerCryptoCaps(peer))
    }

    // ── all capabilities from the peer's messages, the second call layer, X-Wing groups ──

    private val ALL = MessageEncryption.WIRE_CAPS or MessageEncryption.WIRE_CAP_PQ_RATCHET

    @kotlin.test.BeforeTest fun enforce() { SecurityRollout.capsDowngradeBlocks = true }
    @kotlin.test.AfterTest fun relax() { SecurityRollout.capsDowngradeBlocks = false }

    @Test
    fun switched_off_behaves_like_before() {
        SecurityRollout.capsDowngradeBlocks = false
        val ks = keystore()
        ks.checkAndPinPeerWireCaps(peer, ALL, 1_000)
        assertEquals(PeerCapsVerdict.OK, ks.checkAndPinPeerWireCaps(peer, 0, 2_000))
        assertFalse(ks.checkAndPinPeerCallPq(peer, hasLayer = true)); assertFalse(ks.checkAndPinPeerCallPq(peer, hasLayer = false))
        assertFalse(ks.isPeerKeyChanged(peer))
    }

    @Test
    fun wire_caps_pin_up_and_a_downgrade_flags_the_peer() {
        val ks = keystore()
        assertEquals(PeerCapsVerdict.OK, ks.checkAndPinPeerWireCaps(peer, MessageEncryption.WIRE_CAP_V4, 1_000))
        // The peer updated: more bits — pinned upwards without a window.
        assertEquals(PeerCapsVerdict.OK, ks.checkAndPinPeerWireCaps(peer, ALL, 2_000))
        assertFalse(ks.isPeerKeyChanged(peer))
        assertEquals(ALL and PINNED_WIRE_CAPS, ks.getPinnedPeerCryptoCaps(peer)!!.wire)
        // A new message without the v4 ratchet (substitution / downgrade) — treated as a key change.
        assertEquals(PeerCapsVerdict.DOWNGRADE, ks.checkAndPinPeerWireCaps(peer, ALL and MessageEncryption.WIRE_CAP_PQ_RATCHET.inv(), 3_000))
        assertTrue(ks.isPeerKeyChanged(peer))
        // The pin did not go down.
        assertEquals(ALL and PINNED_WIRE_CAPS, ks.getPinnedPeerCryptoCaps(peer)!!.wire)
        // Without file padding (WIRE_CAP_V4) — same.
        val ks2 = keystore()
        ks2.checkAndPinPeerWireCaps(peer, ALL, 1_000)
        assertEquals(PeerCapsVerdict.DOWNGRADE, ks2.checkAndPinPeerWireCaps(peer, 0, 2_000))
        assertTrue(ks2.isPeerKeyChanged(peer))
    }

    @Test
    fun an_older_message_with_fewer_caps_is_not_a_downgrade() {
        val ks = keystore()
        // A message after the update raised the pin at time 5000.
        assertEquals(PeerCapsVerdict.OK, ks.checkAndPinPeerWireCaps(peer, ALL, 5_000))
        // A message sent BEFORE the update (sitting in the queue) or an old one replayed by the server — does not count.
        assertEquals(PeerCapsVerdict.STALE, ks.checkAndPinPeerWireCaps(peer, 0, 4_000))
        assertFalse(ks.isPeerKeyChanged(peer))
        // But a new one with fewer bits — a downgrade.
        assertEquals(PeerCapsVerdict.DOWNGRADE, ks.checkAndPinPeerWireCaps(peer, 0, 6_000))
    }

    @Test
    fun same_caps_after_reinstall_or_restore_do_not_flag() {
        val ks = keystore()
        ks.checkAndPinPeerWireCaps(peer, ALL, 1_000)
        // Restored the account from the phrase on the same version: same bits (ML-KEM key from the phrase) — no window.
        repeat(3) { assertEquals(PeerCapsVerdict.OK, ks.checkAndPinPeerWireCaps(peer, ALL, 2_000L + it)) }
        assertFalse(ks.isPeerKeyChanged(peer))
        // Extra, not-yet-pinned bits of future versions break nothing.
        assertEquals(PeerCapsVerdict.OK, ks.checkAndPinPeerWireCaps(peer, ALL or 0x100, 3_000))
        assertEquals(PeerCapsVerdict.OK, ks.checkAndPinPeerWireCaps(peer, ALL, 4_000))
    }

    @Test
    fun directory_pin_and_wire_pin_do_not_erase_each_other() {
        val ks = keystore()
        ks.checkAndPinPeerWireCaps(peer, ALL, 1_000)
        assertFalse(ks.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = true))
        ks.checkAndPinPeerCallPq(peer, hasLayer = true)
        ks.checkAndPinPeerXwing(peer, hasXwing = true)
        val p = ks.getPinnedPeerCryptoCaps(peer)!!
        assertTrue(p.ratchetCapable && p.hasKyberKey && p.callPq && p.xwingGroups)
        assertEquals(ALL and PINNED_WIRE_CAPS, p.wire)
        // The legacy "rk" value is read as before.
        val ks3 = keystore()
        assertFalse(ks3.checkAndPinPeerCryptoCaps(peer, ratchetCapable = true, hasKyberKey = true))
        assertEquals(PeerCryptoCaps(ratchetCapable = true, hasKyberKey = true), ks3.getPinnedPeerCryptoCaps(peer))
    }

    @Test
    fun call_layer_and_xwing_pins() {
        val ks = keystore()
        // A peer without the layer from the very start (old version) — not a downgrade.
        assertFalse(ks.checkAndPinPeerCallPq(peer, hasLayer = false))
        assertFalse(ks.checkAndPinPeerCallPq(peer, hasLayer = true))
        assertFalse(ks.isPeerKeyChanged(peer))
        assertTrue(ks.checkAndPinPeerCallPq(peer, hasLayer = false))
        assertTrue(ks.isPeerKeyChanged(peer))

        val ks2 = keystore()
        assertFalse(ks2.checkAndPinPeerXwing(peer, hasXwing = false))
        assertFalse(ks2.checkAndPinPeerXwing(peer, hasXwing = true))
        assertTrue(ks2.checkAndPinPeerXwing(peer, hasXwing = false))
        assertTrue(ks2.isPeerKeyChanged(peer))
    }

    @Test
    fun accepting_after_a_wire_downgrade_restarts_the_pin_and_applies_what_he_sent() {
        if (!rustCoreTestsEnabled()) return
        val ks = keystore()
        ks.checkAndPinPeerWireCaps(peer, ALL, 1_000)
        ks.notePeerWireCaps(peer, ALL)
        assertEquals(PeerCapsVerdict.DOWNGRADE, ks.checkAndPinPeerWireCaps(peer, MessageEncryption.WIRE_CAP_V4, 2_000))
        // He really did install an old version — the user confirmed.
        ks.acceptPeerKey(peer, ByteArray(33) { 1 }, ByteArray(32) { 2 })
        assertFalse(ks.isPeerKeyChanged(peer))
        assertFalse(ks.peerHasWireCap(peer, MessageEncryption.WIRE_CAP_PQ_RATCHET))
        assertTrue(ks.peerHasWireCap(peer, MessageEncryption.WIRE_CAP_V4))
        // From here on no windows, unless it drops further.
        assertEquals(PeerCapsVerdict.OK, ks.checkAndPinPeerWireCaps(peer, MessageEncryption.WIRE_CAP_V4, 3_000))
        assertFalse(ks.isPeerKeyChanged(peer))
    }
}
