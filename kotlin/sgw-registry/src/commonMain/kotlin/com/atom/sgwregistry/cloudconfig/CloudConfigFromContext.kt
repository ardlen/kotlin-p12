/**
 * Сборка подписанного `cloud_configuration` из invitation / resp-context.
 */
package com.atom.sgwregistry.cloudconfig

import com.atom.sgwregistry.crypto.PemEncoding
import com.atom.sgwregistry.crypto.PlatformCrypto
import com.atom.sgwregistry.crypto.SigningKey
import com.atom.sgwregistry.model.CloudBrokerConfigBody
import com.atom.sgwregistry.model.CloudBrokerConfigPayload
import com.atom.sgwregistry.model.CloudBrokerEndpointPayload
import com.atom.sgwregistry.model.CloudConfigResignRequest
import com.atom.sgwregistry.model.CloudConfigurationDto
import com.atom.sgwregistry.model.InvitationContextJson
import com.atom.sgwregistry.model.InvitationContextResponse
import com.atom.sgwregistry.model.MobDevCloudConfigResponse
import com.atom.sgwregistry.model.VehicleCloudConfigurationDraft
import com.atom.sgwregistry.parser.RegistryParser
import kotlinx.serialization.json.Json

object CloudConfigFromContext {
    private val payloadJson = Json {
        encodeDefaults = true
        explicitNulls = false
    }

    fun parseInvitationResponse(bytes: ByteArray): InvitationContextResponse =
        InvitationContextJson.parse(bytes)

    fun parseInvitationResponse(text: String): InvitationContextResponse =
        InvitationContextJson.parse(text)

    /**
     * UID листового сертификата из `context.ownership_registry`.
     *
     * На практике invitation отдаёт **PFX v3** (`-----BEGIN CMS-----` с INTEGER 3 + SignedData),
     * а не standalone ContentInfo как у `cloud_config_pem`.
     */
    fun extractOwnerIdFromOwnershipCms(ownershipRegistryPem: String): String {
        require(ownershipRegistryPem.isNotBlank()) { "ownership_registry is empty" }
        val der = PemEncoding.decodePemOrDer(ownershipRegistryPem.encodeToByteArray())
        val candidates = ArrayList<ByteArray>()
        try {
            val container = if (looksLikePfx(der)) {
                RegistryParser.parse(der)
            } else {
                CloudConfigCms.parsePem(der).toRegistryContainer()
            }
            container.signerCertDer?.let { candidates.add(it) }
            candidates.addAll(container.certificatesDer)
        } catch (_: Exception) {
            // fallback ниже
        }
        for (certDer in candidates) {
            extractUidFromSubject(PlatformCrypto.parseCertificate(certDer).subject)?.let { return it }
        }
        for (certDer in scanCertificates(der)) {
            extractUidFromSubject(PlatformCrypto.parseCertificate(certDer).subject)?.let { return it }
        }
        throw IllegalStateException("UID not found in ownership_registry leaf certificate")
    }

    fun extractUidFromSubject(subject: String): String? {
        val match = UID_IN_SUBJECT.find(subject) ?: return null
        return match.groupValues[1].trim().takeIf { it.isNotEmpty() }
    }

    /**
     * snake_case draft → компактный camelCase `cloud_config_json`.
     *
     * @param payloadVersion если задан — поле `v`; иначе `draft.currentVersion`
     */
    fun buildCloudConfigJson(
        draft: VehicleCloudConfigurationDraft,
        payloadVersion: Int? = null,
    ): String {
        val rootCas = draft.cloudBroker.rootCas
        require(rootCas.isNotEmpty()) { "vehicle_cloud_configuration.cloud_broker.root_cas is empty" }
        require(rootCas.all { looksLikePemCertificate(it) }) {
            "root_cas must contain PEM certificates (got placeholder or invalid value)"
        }
        val baseDomain = draft.cloudBroker.endpoint.baseDomain
        require(baseDomain.isNotBlank()) { "endpoint.base_domain is blank" }
        val payload = CloudBrokerConfigPayload(
            v = payloadVersion ?: draft.currentVersion,
            cloudBroker = CloudBrokerConfigBody(
                rootCAs = rootCas,
                endpoint = CloudBrokerEndpointPayload(
                    fqdnConstrAlg = draft.cloudBroker.endpoint.fqdnConstrAlg,
                    baseDomain = baseDomain,
                ),
            ),
        )
        return payloadJson.encodeToString(CloudBrokerConfigPayload.serializer(), payload)
    }

    /**
     * DTO без подписи (`cloud_config_pem` пустой).
     */
    fun buildUnsignedConfiguration(
        response: InvitationContextResponse,
        payloadVersion: Int? = null,
        configurationId: String? = null,
        ownerId: String? = null,
    ): CloudConfigurationDto {
        val draft = response.context.vehicleCloudConfiguration
        val json = buildCloudConfigJson(draft, payloadVersion)
        val resolvedOwnerId = ownerId
            ?: extractOwnerIdFromOwnershipCms(response.context.ownershipRegistry)
        return CloudConfigurationDto(
            rootCas = draft.cloudBroker.rootCas,
            id = configurationId ?: response.id,
            vin = response.vin,
            ownerId = resolvedOwnerId,
            version = (payloadVersion ?: draft.currentVersion).toString(),
            baseDomain = draft.cloudBroker.endpoint.baseDomain,
            cloudConfigJson = json,
            cloudConfigPem = "",
        )
    }

    /**
     * Сборка payload + CMS-подпись owner-ключом (`resign` с пересборкой eContent из JSON).
     *
     * @param alignOwnerIdWithSigner если true и в subject подписанта есть UID — `owner_id` берётся оттуда
     *   (нужно, когда signing cert ≠ leaf из ownership_registry).
     */
    fun buildAndSign(
        response: InvitationContextResponse,
        signerCertDer: ByteArray,
        signerKey: SigningKey,
        payloadVersion: Int? = null,
        configurationId: String? = null,
        ownerId: String? = null,
        alignOwnerIdWithSigner: Boolean = false,
    ): CloudConfigurationDto {
        val unsigned = buildUnsignedConfiguration(
            response = response,
            payloadVersion = payloadVersion,
            configurationId = configurationId,
            ownerId = ownerId,
        )
        val resolvedOwnerId = when {
            ownerId != null -> ownerId
            alignOwnerIdWithSigner -> {
                val uid = extractUidFromSubject(PlatformCrypto.parseCertificate(signerCertDer).subject)
                uid ?: unsigned.ownerId
            }
            else -> unsigned.ownerId
        }
        val pem = CloudConfigCms.resignToPem(
            CloudConfigResignRequest(
                jsonPayload = unsigned.cloudConfigJson,
                signerCertDer = signerCertDer,
                signerKey = signerKey,
            ),
        )
        return unsigned.copy(ownerId = resolvedOwnerId, cloudConfigPem = pem)
    }

    fun toMobDevResponse(dto: CloudConfigurationDto): MobDevCloudConfigResponse =
        MobDevCloudConfigResponse(cloudConfiguration = dto)

    fun encodeMobDevResponse(dto: CloudConfigurationDto, pretty: Boolean = true): String {
        val json = Json {
            prettyPrint = pretty
            encodeDefaults = true
            explicitNulls = false
        }
        return json.encodeToString(
            MobDevCloudConfigResponse.serializer(),
            toMobDevResponse(dto),
        ) + "\n"
    }

    private fun looksLikePemCertificate(pem: String): Boolean {
        if (!pem.contains("BEGIN CERTIFICATE")) return false
        val body = pem.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("-----") }
            .joinToString("")
        return body.length >= 32 && body.none { it == '<' || it == '>' }
    }

    /** PFX: SEQUENCE { INTEGER version, ContentInfo ... }; CMS ContentInfo starts with OID. */
    private fun looksLikePfx(der: ByteArray): Boolean {
        if (der.size < 6 || der[0].toInt() and 0xFF != 0x30) return false
        val lenInfo = readDerLength(der, 1) ?: return false
        val contentStart = lenInfo.second
        return contentStart < der.size && (der[contentStart].toInt() and 0xFF) == 0x02
    }

    private fun scanCertificates(der: ByteArray): List<ByteArray> {
        val out = ArrayList<ByteArray>()
        var i = 0
        while (i < der.size - 4) {
            if (der[i].toInt() and 0xFF != 0x30) {
                i++
                continue
            }
            val lenInfo = readDerLength(der, i + 1)
            if (lenInfo == null) {
                i++
                continue
            }
            val end = lenInfo.second + lenInfo.first
            if (lenInfo.first in 100..8192 && end <= der.size) {
                val candidate = der.copyOfRange(i, end)
                val parsed = try {
                    PlatformCrypto.parseCertificate(candidate)
                    true
                } catch (_: Exception) {
                    false
                }
                if (parsed) {
                    out.add(candidate)
                    i = end
                    continue
                }
            }
            i++
        }
        return out
    }

    /** @return Pair(contentLength, contentOffset) */
    private fun readDerLength(buf: ByteArray, offset: Int): Pair<Int, Int>? {
        if (offset >= buf.size) return null
        val b = buf[offset].toInt() and 0xFF
        if (b < 0x80) return b to (offset + 1)
        val n = b and 0x7F
        if (n == 0 || n > 3 || offset + 1 + n > buf.size) return null
        var len = 0
        for (k in 1..n) {
            len = (len shl 8) or (buf[offset + k].toInt() and 0xFF)
        }
        return len to (offset + 1 + n)
    }

    private val UID_IN_SUBJECT = Regex("""(?i)(?:^|,)\s*UID=([^,]+)""")
}
