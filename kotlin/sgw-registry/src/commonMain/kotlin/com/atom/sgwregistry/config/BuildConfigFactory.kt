package com.atom.sgwregistry.config

import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.model.BuildConfig
import com.atom.sgwregistry.model.SafeBagInput
import com.atom.sgwregistry.util.EPOCH_INSTANT
import com.atom.sgwregistry.util.parseRfc3339Instant
import kotlinx.datetime.Instant
import kotlinx.serialization.json.Json

/**
 * Сборка [BuildConfig] на всех платформах (без java.io).
 * JVM [ConfigLoader] читает файлы и делегирует сюда.
 */
object BuildConfigFactory {
    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
    }

    fun parseConfig(jsonText: String): RegistryConfig =
        json.decodeFromString<RegistryConfig>(jsonText)

    /**
     * Прямой вариант для мобильных: все PEM уже в [ByteArray] (assets, bundle, API).
     */
    fun toBuildConfig(
        vin: String,
        uid: String,
        verTimestamp: Instant,
        verVersion: Int,
        signerCertPem: ByteArray,
        signerKeyPem: ByteArray,
        safeBags: List<SafeBagPemInput>,
    ): BuildConfig {
        require(vin.isNotBlank()) { "vin required" }
        require(uid.isNotBlank()) { "uid required" }
        require(verVersion > 0) { "VER version must be positive" }
        return BuildConfig(
            signerCertDer = PemEncoding.decodePemOrDer(signerCertPem),
            signerKey = PlatformCrypto.parseEcPrivateKey(signerKeyPem),
            vin = vin,
            verTimestamp = verTimestamp,
            verVersion = verVersion,
            uid = uid,
            safeBags = safeBags.map { it.toSafeBagInput() },
        )
    }

    /** JSON с inline PEM (`signerCertPem`, `certPem`) — типичный ответ backend API. */
    fun toBuildConfigFromInlinePem(cfg: RegistryConfig): BuildConfig {
        validateConfig(cfg, requireFilePaths = false)
        val signerCertPem = cfg.signerCertPem!!.encodeToByteArray()
        val signerKeyPem = cfg.signerKeyPem!!.encodeToByteArray()
        return BuildConfig(
            signerCertDer = PemEncoding.decodePemOrDer(signerCertPem),
            signerKey = PlatformCrypto.parseEcPrivateKey(signerKeyPem),
            vin = cfg.vin,
            verTimestamp = parseRfc3339(cfg.verTimestamp),
            verVersion = cfg.verVersion,
            uid = cfg.uid,
            safeBags = cfg.safeBags.map { sb ->
                val certPem = sb.certPem!!.encodeToByteArray()
                toSafeBagInput(certPem, sb)
            },
        )
    }

    /**
     * JSON с путями (`signerCert`, `safeBags[].cert`); PEM загружается через [loadPem].
     * На Android/iOS [loadPem] читает assets/bundle по относительному пути.
     */
    fun toBuildConfig(cfg: RegistryConfig, loadPem: (String) -> ByteArray): BuildConfig {
        validateConfig(cfg, requireFilePaths = true)
        val signerCertPem = if (!cfg.signerCertPem.isNullOrBlank()) {
            cfg.signerCertPem.encodeToByteArray()
        } else {
            loadPem(cfg.signerCert)
        }
        val signerKeyPem = if (!cfg.signerKeyPem.isNullOrBlank()) {
            cfg.signerKeyPem.encodeToByteArray()
        } else {
            loadPem(cfg.signerKey)
        }
        return BuildConfig(
            signerCertDer = PemEncoding.decodePemOrDer(signerCertPem),
            signerKey = PlatformCrypto.parseEcPrivateKey(signerKeyPem),
            vin = cfg.vin,
            verTimestamp = parseRfc3339(cfg.verTimestamp),
            verVersion = cfg.verVersion,
            uid = cfg.uid,
            safeBags = cfg.safeBags.map { sb ->
                val certPem = if (!sb.certPem.isNullOrBlank()) {
                    sb.certPem.encodeToByteArray()
                } else {
                    loadPem(sb.cert)
                }
                toSafeBagInput(certPem, sb)
            },
        )
    }

    fun decodeLocalKeyId(s: String?): ByteArray? {
        if (s.isNullOrBlank()) return null
        return try {
            PemEncoding.decodeSkidHex(s)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    fun parseRfc3339(s: String?): Instant {
        if (s.isNullOrBlank()) return EPOCH_INSTANT
        return parseRfc3339Instant(s)
    }

    private fun validateConfig(cfg: RegistryConfig, requireFilePaths: Boolean) {
        val hasCertPem = !cfg.signerCertPem.isNullOrBlank()
        val hasKeyPem = !cfg.signerKeyPem.isNullOrBlank()
        require(hasCertPem || cfg.signerCert.isNotBlank()) { "signerCert/signerCertPem required" }
        require(hasKeyPem || cfg.signerKey.isNotBlank()) { "signerKey/signerKeyPem required" }
        require(cfg.vin.isNotBlank()) { "vin required" }
        require(cfg.uid.isNotBlank()) { "uid required" }
        if (requireFilePaths && !hasCertPem) require(cfg.signerCert.isNotBlank()) { "signerCert path required" }
        if (requireFilePaths && !hasKeyPem) require(cfg.signerKey.isNotBlank()) { "signerKey path required" }
        cfg.safeBags.forEachIndexed { i, sb ->
            val hasPem = !sb.certPem.isNullOrBlank()
            require(hasPem || sb.cert.isNotBlank()) { "safeBags[$i].cert or certPem required" }
        }
    }

    private fun toSafeBagInput(certPem: ByteArray, sb: SafeBagConfigEntry): SafeBagInput {
        val certDer = PemEncoding.decodePemOrDer(certPem)
        var localKeyId = decodeLocalKeyId(sb.localKeyID)
        if (localKeyId == null && certDer.isNotEmpty()) {
            localKeyId = PlatformCrypto.getSubjectKeyId(PlatformCrypto.parseCertificate(certDer))
                .takeIf { it.isNotEmpty() }
        }
        return SafeBagInput(
            certDer = certDer,
            roleName = sb.roleName,
            roleNotBefore = parseRfc3339(sb.roleNotBefore),
            roleNotAfter = parseRfc3339(sb.roleNotAfter),
            localKeyId = localKeyId,
        )
    }

    private fun SafeBagPemInput.toSafeBagInput(): SafeBagInput {
        val certDer = PemEncoding.decodePemOrDer(certPem)
        val skid = localKeyId ?: PlatformCrypto.getSubjectKeyId(PlatformCrypto.parseCertificate(certDer))
            .takeIf { it.isNotEmpty() }
        return SafeBagInput(
            certDer = certDer,
            roleName = roleName,
            roleNotBefore = roleNotBefore,
            roleNotAfter = roleNotAfter,
            localKeyId = skid,
        )
    }
}

/** Один SafeBag: PEM сертификата роли + метаданные (mobile / API). */
data class SafeBagPemInput(
    val certPem: ByteArray,
    val roleName: String,
    val roleNotBefore: Instant,
    val roleNotAfter: Instant,
    val localKeyId: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SafeBagPemInput) return false
        return certPem.contentEquals(other.certPem) &&
            roleName == other.roleName &&
            roleNotBefore == other.roleNotBefore &&
            roleNotAfter == other.roleNotAfter &&
            (localKeyId == null && other.localKeyId == null ||
                localKeyId != null && other.localKeyId != null && localKeyId.contentEquals(other.localKeyId))
    }

    override fun hashCode(): Int {
        var result = certPem.contentHashCode()
        result = 31 * result + roleName.hashCode()
        result = 31 * result + roleNotBefore.hashCode()
        result = 31 * result + roleNotAfter.hashCode()
        result = 31 * result + (localKeyId?.contentHashCode() ?: 0)
        return result
    }
}
