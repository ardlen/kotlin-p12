package com.atom.sgwregistry.builder

import com.atom.sgwregistry.model.RegistryContainer
import com.atom.sgwregistry.model.SignerAttrs
import com.atom.sgwregistry.util.EPOCH_INSTANT
import com.atom.sgwregistry.util.formatVerTimestamp
import com.atom.sgwregistry.util.isEpoch
import com.atom.sgwregistry.util.parseVerTimestamp
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

/**
 * ATOM VER (OID `1.3.6.1.4.1.99999.1.2`) — версия реестра в authenticatedAttributes.
 */
object VerAttribute {
    fun formatText(timestamp: Instant, version: Int): String = "${formatVerTimestamp(timestamp)}:V$version"

    fun parseText(value: String): Pair<Instant, Int> {
        val trimmed = value.trim()
        val idx = trimmed.lastIndexOf(":V")
        if (idx <= 0) {
            throw IllegalArgumentException(
                "Invalid VER format (expected yyyy-MM-dd HH:mm:ss:Vn): $value",
            )
        }
        val tsStr = trimmed.substring(0, idx)
        val version = trimmed.substring(idx + 2).toIntOrNull()
            ?: throw IllegalArgumentException(
                "Invalid VER version in (expected Vn): $value",
            )
        if (version <= 0) {
            throw IllegalArgumentException("VER version must be positive (V$version)")
        }
        val timestamp = try {
            parseVerTimestamp(tsStr)
        } catch (e: Exception) {
            throw IllegalArgumentException(
                "Invalid VER timestamp (expected yyyy-MM-dd HH:mm:ss): $tsStr",
                e,
            )
        }
        return timestamp to version
    }

    fun requirePresent(attrs: SignerAttrs) {
        require(attrs.verVersion > 0) {
            "VER is required (version must be V1 or greater, got V${attrs.verVersion})"
        }
        require(!isEpoch(attrs.verTimestamp)) {
            "VER timestamp is required (yyyy-MM-dd HH:mm:ss)"
        }
    }

    fun bumpForRegistryUpdate(attrs: SignerAttrs): SignerAttrs {
        requirePresent(attrs)
        val previousVersion = attrs.verVersion
        val nextVersion = previousVersion + 1
        require(nextVersion == previousVersion + 1) {
            "VER version increment overflow from V$previousVersion"
        }
        val now = Clock.System.now()
        return attrs.copy(
            verTimestamp = Instant.fromEpochSeconds(now.epochSeconds),
            verVersion = nextVersion,
        )
    }

    fun resolveForRegistryUpdate(container: RegistryContainer, signerAttrsOverride: SignerAttrs?): SignerAttrs {
        val fromContainer = RegistryConverters.extractSignerAttrs(container)
        val merged = if (signerAttrsOverride == null) {
            fromContainer
        } else {
            fromContainer.copy(
                vin = signerAttrsOverride.vin.ifBlank { fromContainer.vin },
                uid = signerAttrsOverride.uid.ifBlank { fromContainer.uid },
            )
        }
        return bumpForRegistryUpdate(merged)
    }
}
