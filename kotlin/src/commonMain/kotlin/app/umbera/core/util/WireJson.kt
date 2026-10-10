package app.umbera.core.util

// JSON configuration for wire formats.

import kotlinx.serialization.json.Json

object WireJson {
    val json: Json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
        encodeDefaults = true
        coerceInputValues = true
    }
}
